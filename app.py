from __future__ import annotations

import json
import os
import io
import hashlib
import hmac
import re
from datetime import date, timedelta
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd
import streamlit as st
from streamlit.errors import StreamlitSecretNotFoundError

from services import can, create_polc_report, current_identity, queue_notification
from storage import Store

st.set_page_config(
    page_title="AIMS｜泛服務業營運診斷",
    page_icon=":material/monitoring:",
    layout="wide",
    initial_sidebar_state="expanded",
)


AIMS_URL = (
    "https://script.google.com/macros/s/"
    "AKfycbyEcIdYh0H6XHVxyfl7Olmr1comVe7KcMFN2oLXDRKRri87m5mzrlQrlySj5fJ4oSxl/exec"
)
SHIFTWISE_URL = "https://shiftwise-scheduler.streamlit.app/"


def apply_aims_style() -> None:
    st.markdown(
        """
        <style>
        [data-testid="stSidebar"] { border-right: 1px solid #1e3a52; }
        [data-testid="stMetric"] { background: #0d1b2a; border: 1px solid #21445e;
            border-radius: 12px; padding: 14px; }
        .aims-kicker { color: #38bdf8; letter-spacing: .12em; font-size: .78rem;
            font-weight: 700; text-transform: uppercase; }
        .aims-hero { background: linear-gradient(135deg, #102a43 0%, #07111f 75%);
            border: 1px solid #21445e; border-radius: 18px; padding: 30px; }
        .aims-hero h1 { margin: 6px 0 10px; font-size: 2.2rem; }
        .aims-card { background: #0d1b2a; border: 1px solid #21445e;
            border-radius: 12px; padding: 16px; min-height: 116px; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def get_store() -> Store:
    try:
        database_url = st.secrets.get("AIMS_DATABASE_URL", None)
    except StreamlitSecretNotFoundError:
        database_url = None
    store = Store(database_url=database_url)
    store.initialize()
    return store


def secret_value(name: str, default: str = "") -> str:
    try:
        value = st.secrets.get(name, default)
    except StreamlitSecretNotFoundError:
        return default
    return str(value or default)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        salt_hex, digest_hex = encoded.split("$", 1)
        expected = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 240_000).hex()
        return hmac.compare_digest(expected, digest_hex)
    except (ValueError, TypeError):
        return False


def oidc_enabled() -> bool:
    try:
        auth = st.secrets.get("auth", {})
    except StreamlitSecretNotFoundError:
        return False
    return bool(auth.get("client_id") and auth.get("client_secret") and auth.get("server_metadata_url"))


def sync_oidc_identity() -> None:
    if not oidc_enabled() or not st.user.is_logged_in:
        return
    email = str(getattr(st.user, "email", "") or "").strip().lower()
    name = str(getattr(st.user, "name", "") or email or "Google 使用者")
    admin_emails = {item.strip().lower() for item in secret_value("AIMS_ADMIN_EMAILS").split(",") if item.strip()}
    auditor_emails = {item.strip().lower() for item in secret_value("AIMS_AUDITOR_EMAILS").split(",") if item.strip()}
    role = "admin" if email in admin_emails else "auditor" if email in auditor_emails else "manager"
    st.session_state["authenticated"] = True
    st.session_state["account"] = email or name
    st.session_state["display_name"] = name
    st.session_state["role"] = role
    st.session_state["auth_provider"] = "google_oidc"


def record_audit(action: str, detail: str) -> None:
    identity = current_identity(st.session_state)
    get_store().add_audit(identity.account, action, detail)
    events = st.session_state.setdefault("audit_events", [])
    events.insert(0, {"時間": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M"), "帳號": identity.account, "動作": action, "摘要": detail})
    st.session_state["audit_events"] = events[:100]


def render_login() -> bool:
    left, right = st.columns([1.15, 0.85], gap="large")
    with left:
        st.markdown(
            """
            <div class="aims-hero">
              <div class="aims-kicker">⚡ AIMS · Enterprise Edition</div>
              <h1>門市現場卓越營運的<br>智能決策中樞</h1>
              <p>將客訴、流程斷點、人力與服務品質，整理成可執行、可追蹤的門市改善閉環。</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.space("medium")
        with st.container(horizontal=True):
            st.markdown("🎯 **Plan**<br><small>客訴多軌分析與改善規劃</small>", unsafe_allow_html=True)
            st.markdown("⏱️ **Organize**<br><small>接觸點與工位斷點</small>", unsafe_allow_html=True)
            st.markdown("🛡️ **Control**<br><small>防呆雙簽與 SOP 固化</small>", unsafe_allow_html=True)
    with right:
        with st.container(border=True):
            st.subheader("歡迎登入工作台")
            st.caption("請驗證企業管理者身分以存取決策中樞")
            if oidc_enabled():
                st.info("正式模式：使用 Google 企業帳號登入。")
                if st.button("使用 Google 登入", type="primary", width="stretch"):
                    st.login()
            else:
                login_tab, apply_tab = st.tabs(["企業帳密登入", "申請企業帳號"])
                with login_tab:
                    account = st.text_input("登入帳號", placeholder="公司信箱或門市代號", key="login_account")
                    password = st.text_input("安全密碼", type="password", placeholder="請輸入密碼", key="login_password")
                    if st.button("進入 AIMS 決策工作台", type="primary", width="stretch"):
                        user = get_store().authenticate_user(account.strip().lower()) if account.strip() else None
                        if user and verify_password(password, user["password_hash"]):
                            st.session_state["authenticated"] = True
                            st.session_state["account"] = user["account"]
                            st.session_state["display_name"] = user["company_name"]
                            st.session_state["role"] = user["role"]
                            st.session_state["auth_provider"] = "enterprise_password"
                            record_audit("企業登入", user["company_name"])
                            st.rerun()
                        else:
                            st.error("帳號或密碼不正確。請先申請企業帳號，或確認輸入內容。")
                with apply_tab:
                    company = st.text_input("企業／門市名稱", placeholder="例如：安心美容有限公司", key="apply_company")
                    account = st.text_input("申請登入帳號", placeholder="建議使用公司信箱", key="apply_account")
                    password = st.text_input("設定登入密碼", type="password", placeholder="至少 8 個字元", key="apply_password")
                    confirm = st.text_input("再次輸入密碼", type="password", key="apply_confirm")
                    if st.button("送出企業申請", type="primary", width="stretch"):
                        normalized = account.strip().lower()
                        if not company.strip() or not normalized or not password:
                            st.error("請完整填寫企業名稱、帳號與密碼。")
                        elif not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$|^[a-z0-9][a-z0-9._-]{2,30}$", normalized):
                            st.error("帳號請使用公司 Email 或英數字門市代號。")
                        elif len(password) < 8 or password != confirm:
                            st.error("密碼至少 8 個字元，且兩次輸入必須一致。")
                        else:
                            try:
                                get_store().create_user(company.strip(), normalized, hash_password(password))
                                record_audit("企業申請", f"{company.strip()} · {normalized}")
                                st.success("企業帳號已建立，現在可切換到「企業帳密登入」使用。")
                            except ValueError as exc:
                                st.error(str(exc))
            if st.button("免註冊・一鍵體驗示範帳號", width="stretch"):
                st.session_state["authenticated"] = True
                st.session_state["account"] = "store001"
                st.session_state["demo_mode"] = True
                st.session_state["role"] = "manager"
                st.session_state["auth_provider"] = "demo"
                record_audit("登入", "示範帳號登入")
                st.rerun()
            try:
                oidc_provider = "Google" if oidc_enabled() else ""
            except StreamlitSecretNotFoundError:
                oidc_provider = ""
            if oidc_provider:
                st.caption(f"企業登入已設定：{oidc_provider}")
                if st.button(f"使用 {oidc_provider} 登入", width="stretch"):
                    st.login()
            st.caption("企業帳號會寫入目前設定的 PostgreSQL／Supabase；未設定時使用本機 SQLite。示範帳號僅供體驗。")
    return bool(st.session_state.get("authenticated", False))


def sample_operations() -> pd.DataFrame:
    today = date.today()
    rows = []
    services = [
        ("台北信義店", "美容服務", 148000, 92, 87),
        ("台中公益店", "餐飲服務", 121500, 84, 79),
        ("高雄左營店", "健身服務", 96500, 76, 82),
        ("新竹竹北店", "生活服務", 88500, 71, 74),
    ]
    for offset in range(7):
        day = today - timedelta(days=6 - offset)
        for branch, category, revenue, utilization, satisfaction in services:
            rows.append(
                {
                    "日期": day,
                    "門市": branch,
                    "服務類型": category,
                    "營收": revenue + offset * 1800,
                    "人力利用率": min(utilization + offset, 99),
                    "顧客滿意度": satisfaction + (offset % 3),
                    "預約數": 42 + offset * 2,
                }
            )
    return pd.DataFrame(rows)


def sample_shifts() -> pd.DataFrame:
    start = date.today()
    names = ["王小美", "陳志明", "林怡君", "張家豪", "許雅婷", "李冠廷"]
    branches = ["台北信義店", "台中公益店", "高雄左營店"]
    rows = []
    for index in range(18):
        shift_date = start + timedelta(days=index % 7)
        rows.append(
            {
                "日期": shift_date,
                "門市": branches[index % len(branches)],
                "員工": names[index % len(names)],
                "班別": ["早班", "晚班", "全日"][index % 3],
                "開始": ["09:00", "13:00", "10:00"][index % 3],
                "結束": ["18:00", "22:00", "19:00"][index % 3],
                "狀態": "已排班" if index % 5 else "待確認",
            }
        )
    return pd.DataFrame(rows)


def sample_complaints() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"案件編號": "CS-2401", "日期": date.today(), "門市": "台北信義店", "來源": "Google 評論", "客訴內容": "尖峰時段等候時間過久，現場沒有人說明。", "嚴重度": "高", "狀態": "待分析"},
            {"案件編號": "CS-2402", "日期": date.today(), "門市": "台中公益店", "來源": "櫃檯回報", "客訴內容": "預約資訊與現場安排不一致。", "嚴重度": "中", "狀態": "分析中"},
            {"案件編號": "CS-2403", "日期": date.today(), "門市": "高雄左營店", "來源": "問卷", "客訴內容": "服務人員態度良好，但交接資訊不完整。", "嚴重度": "中", "狀態": "已結案"},
            {"案件編號": "CS-2404", "日期": date.today(), "門市": "台北信義店", "來源": "LINE", "客訴內容": "付款後未收到明確的服務完成通知。", "嚴重度": "低", "狀態": "待分析"},
        ]
    )


def sample_process_events() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"案件編號": "ORD-001", "日期": date.today(), "門市": "台北信義店", "階段": "預約確認", "開始": "11:42", "結束": "11:48", "負責角色": "櫃檯", "結果": "完成"},
            {"案件編號": "ORD-001", "日期": date.today(), "門市": "台北信義店", "階段": "到店報到", "開始": "12:02", "結束": "12:14", "負責角色": "接待", "結果": "等待偏長"},
            {"案件編號": "ORD-001", "日期": date.today(), "門市": "台北信義店", "階段": "主要施作", "開始": "12:18", "結束": "13:02", "負責角色": "服務人員", "結果": "完成"},
            {"案件編號": "ORD-002", "日期": date.today(), "門市": "台中公益店", "階段": "預約確認", "開始": "14:10", "結束": "14:16", "負責角色": "櫃檯", "結果": "完成"},
            {"案件編號": "ORD-002", "日期": date.today(), "門市": "台中公益店", "階段": "服務交接", "開始": "14:52", "結束": "15:18", "負責角色": "現場主管", "結果": "交接缺欄"},
        ]
    )


def sample_mini_bundle() -> dict[str, pd.DataFrame]:
    return {
        "營運資料": sample_operations().tail(4).copy(),
        "排班資料": sample_shifts().head(6).copy(),
        "客訴資料": sample_complaints().copy(),
        "流程事件": sample_process_events().copy(),
    }


@st.cache_data(ttl="10m")
def load_demo_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    return sample_operations(), sample_shifts()


def parse_uploaded_file(uploaded_file: st.runtime.uploaded_file_manager.UploadedFile) -> pd.DataFrame:
    suffix = uploaded_file.name.lower()
    if suffix.endswith(".csv"):
        return pd.read_csv(uploaded_file)
    if suffix.endswith((".xlsx", ".xls")):
        return pd.read_excel(uploaded_file)
    raise ValueError("目前支援 CSV 或 Excel 檔案。")


def canonicalize_columns(data: pd.DataFrame, data_kind: str) -> pd.DataFrame:
    aliases = {
        "日期": ["日期", "date", "day", "排班日期", "服務日期"],
        "門市": ["門市", "分店", "店鋪", "據點", "branch", "store", "location"],
        "營收": ["營收", "收入", "銷售額", "revenue", "sales", "amount"],
        "人力利用率": ["人力利用率", "利用率", "人力使用率", "utilization", "staff_utilization"],
        "顧客滿意度": ["顧客滿意度", "滿意度", "評分", "satisfaction", "rating"],
        "預約數": ["預約數", "預約量", "訂單數", "appointments", "bookings"],
        "員工": ["員工", "姓名", "人員", "employee", "staff", "worker"],
        "班別": ["班別", "班次", "shift", "shift_name"],
        "開始": ["開始", "開始時間", "上班時間", "start", "start_time"],
        "結束": ["結束", "結束時間", "下班時間", "end", "end_time"],
        "狀態": ["狀態", "排班狀態", "status"],
    }
    required = (
        {"日期", "門市", "營收", "人力利用率", "顧客滿意度", "預約數"}
        if data_kind == "營運資料"
        else {"日期", "門市", "員工", "班別", "開始", "結束", "狀態"}
    )
    normalized = data.copy()
    normalized.columns = [str(column).strip() for column in normalized.columns]
    lower_to_original = {column.casefold(): column for column in normalized.columns}
    rename = {}
    for canonical, candidates in aliases.items():
        if canonical in normalized.columns:
            continue
        for candidate in candidates:
            original = lower_to_original.get(candidate.casefold())
            if original is not None:
                rename[original] = canonical
                break
    normalized = normalized.rename(columns=rename)
    missing = sorted(required - set(normalized.columns))
    if missing:
        raise ValueError(f"{data_kind}缺少必要欄位：{', '.join(missing)}")
    normalized["日期"] = pd.to_datetime(normalized["日期"], errors="coerce").dt.date
    if normalized["日期"].isna().any():
        raise ValueError("日期欄位包含無法辨識的值，請使用 YYYY-MM-DD 格式。")
    if data_kind == "營運資料":
        for column in ("營收", "人力利用率", "顧客滿意度", "預約數"):
            normalized[column] = pd.to_numeric(normalized[column], errors="coerce")
        if normalized[["營收", "人力利用率", "顧客滿意度", "預約數"]].isna().any().any():
            raise ValueError("營運數值欄位包含無法辨識的值，請檢查營收、利用率、滿意度與預約數。")
    return normalized


def template_csv(data_kind: str) -> bytes:
    if data_kind == "營運資料":
        frame = pd.DataFrame(
            [
                {
                    "日期": "2026-10-01",
                    "門市": "台北信義店",
                    "服務類型": "美容服務",
                    "營收": 148000,
                    "人力利用率": 92,
                    "顧客滿意度": 87,
                    "預約數": 42,
                }
            ]
        )
    else:
        frame = pd.DataFrame(
            [
                {
                    "日期": "2026-10-01",
                    "門市": "台北信義店",
                    "員工": "王小美",
                    "班別": "早班",
                    "開始": "09:00",
                    "結束": "18:00",
                    "狀態": "已排班",
                }
            ]
        )
    return frame.to_csv(index=False).encode("utf-8-sig")


def fetch_json(url: str) -> object:
    request = Request(url, headers={"User-Agent": "AIMS-operations-suite/1.0"})
    with urlopen(request, timeout=15) as response:
        content_type = response.headers.get("content-type", "")
        body = response.read().decode("utf-8")
    if "json" in content_type or body.lstrip().startswith(("{", "[")):
        return json.loads(body)
    return {"raw_text": body}


def normalize_imported_data(payload: object) -> pd.DataFrame:
    if isinstance(payload, list):
        return pd.json_normalize(payload)
    if isinstance(payload, dict):
        for key in ("data", "rows", "records", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return pd.json_normalize(value)
        return pd.DataFrame([payload])
    return pd.DataFrame({"資料": [str(payload)]})


def add_audit_event(action: str, detail: str) -> None:
    events = st.session_state.setdefault("audit_events", [])
    events.insert(
        0,
        {
            "時間": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M"),
            "帳號": st.session_state.get("account", "store001"),
            "動作": action,
            "摘要": detail,
        },
    )
    st.session_state["audit_events"] = events[:100]


def schedule_insights(shifts: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    grouped = (
        shifts.groupby(["日期", "門市"], as_index=False)
        .agg(班次數=("員工", "size"), 人員數=("員工", "nunique"))
        .sort_values(["日期", "門市"])
    )
    pending = (
        shifts[shifts["狀態"].astype(str).str.contains("待|pending|未", case=False, na=False)]
        .groupby(["日期", "門市"], as_index=False)
        .size()
        .rename(columns={"size": "待確認班次"})
    )
    coverage = grouped.merge(pending, on=["日期", "門市"], how="left").fillna({"待確認班次": 0})
    coverage["覆蓋狀態"] = coverage["待確認班次"].apply(
        lambda value: "需處理" if value > 0 else "已覆蓋"
    )
    duplicates = shifts[
        shifts.duplicated(subset=["日期", "門市", "員工", "開始", "結束"], keep=False)
    ].sort_values(["日期", "門市", "員工"])
    return coverage, duplicates


def data_quality_report(data: pd.DataFrame, data_kind: str) -> pd.DataFrame:
    rows = []
    for column in data.columns:
        missing = int(data[column].isna().sum())
        duplicate = int(data.duplicated(subset=[column]).sum()) if len(data) else 0
        rows.append(
            {
                "欄位": column,
                "資料型別": str(data[column].dtype),
                "缺失筆數": missing,
                "完整率": round((1 - missing / len(data)) * 100, 1) if len(data) else 0,
                "用途": data_kind,
                "狀態": "需修正" if missing else "正常",
                "重複值筆數": duplicate,
            }
        )
    return pd.DataFrame(rows)


def export_docx(title: str, sections: list[tuple[str, str]]) -> bytes:
    from docx import Document

    document = Document()
    document.add_heading(title, level=0)
    document.add_paragraph("AIMS 智能營運決策中樞｜示範報告")
    for heading, content in sections:
        document.add_heading(heading, level=1)
        document.add_paragraph(content)
    output = io.BytesIO()
    document.save(output)
    return output.getvalue()


def export_pdf(title: str, sections: list[tuple[str, str]]) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas

    output = io.BytesIO()
    pdf = canvas.Canvas(output, pagesize=A4)
    width, height = A4
    font_path = r"C:\Windows\Fonts\msjh.ttc"
    font_name = "Helvetica"
    if os.path.exists(font_path):
        pdfmetrics.registerFont(TTFont("MicrosoftJhengHei", font_path))
        font_name = "MicrosoftJhengHei"
    pdf.setFont(font_name, 16)
    y = height - 50
    pdf.drawString(45, y, title)
    y -= 30
    pdf.setFont(font_name, 10)
    for heading, content in sections:
        if y < 70:
            pdf.showPage()
            pdf.setFont(font_name, 10)
            y = height - 50
        pdf.setFont(font_name, 12)
        pdf.drawString(45, y, heading)
        y -= 20
        pdf.setFont(font_name, 10)
        for line in content.splitlines() or [""]:
            pdf.drawString(55, y, line[:85])
            y -= 16
    pdf.save()
    return output.getvalue()


def render_sidebar() -> str:
    with st.sidebar:
        st.markdown("## ⚡ AIMS")
        st.caption("智能營運決策中樞")
        st.success("🟢 系統與資料庫連線中")
        if st.button("載入完整示範案例", icon=":material/dataset:"):
            st.session_state["demo_complaints"] = sample_complaints()
            st.session_state["demo_case_loaded"] = True
            record_audit("載入示範案例", "客訴、POLC、排班模擬資料")
            st.rerun()
        if st.button("載入模擬資料範例", icon=":material/experiment:"):
            bundle = sample_mini_bundle()
            st.session_state["mini_bundle"] = bundle
            st.session_state["imported_operations"] = canonicalize_columns(bundle["營運資料"], "營運資料")
            st.session_state["imported_shifts"] = canonicalize_columns(bundle["排班資料"], "排班資料")
            st.session_state["demo_complaints"] = bundle["客訴資料"]
            st.session_state["demo_process_events"] = bundle["流程事件"]
            st.session_state["demo_case_loaded"] = True
            record_audit("載入模擬資料範例", "營運、排班、客訴、流程事件")
            st.rerun()
        if st.session_state.get("demo_case_loaded"):
            st.caption("🧪 示範案例已載入")
        st.markdown(" ")
        page = st.radio(
            "工作區",
            [
                "營運中樞與個人檔案",
                "資料清洗與格式檢核",
                "1. 客訴多軌分析 (Plan)",
                "2. 接觸點與工位斷點 (Organize)",
                "3. 幹部領導作戰卡 (Lead)",
                "4. 接觸點防呆雙簽 (Control)",
                "POLC 終極全景改善白皮書",
                "智慧排班",
                "資料匯入",
            ],
            format_func=lambda item: {
                "營運中樞與個人檔案": "🏠 營運中樞與個人檔案",
                "資料清洗與格式檢核": "🧹 資料清洗與格式檢核",
                "1. 客訴多軌分析 (Plan)": "🎯 1. 客訴多軌分析 (Plan)",
                "2. 接觸點與工位斷點 (Organize)": "⏱️ 2. 接觸點與工位斷點 (Organize)",
                "3. 幹部領導作戰卡 (Lead)": "👥 3. 幹部領導作戰卡 (Lead)",
                "4. 接觸點防呆雙簽 (Control)": "🛡️ 4. 接觸點防呆雙簽 (Control)",
                "POLC 終極全景改善白皮書": "🏆 POLC 終極全景改善白皮書",
                "智慧排班": ":material/calendar_month:  智慧排班",
                "資料匯入": ":material/cloud_upload:  資料匯入",
            }[item],
            label_visibility="collapsed",
        )
        st.markdown(" ")
        st.container(border=True).markdown(
            f"**資料模式**\n\n展示資料／可匯入實際資料\n\n"
            f"帳號：{st.session_state.get('display_name', st.session_state.get('account', 'store001'))}\n\n"
            f"角色：{st.session_state.get('role', 'manager')}"
        )
        if st.button("登出", icon=":material/logout:"):
            record_audit("登出", "離開 AIMS 工作台")
            if oidc_enabled() and st.user.is_logged_in:
                st.logout()
            st.session_state["authenticated"] = False
            st.rerun()
        st.caption("AIMS prototype · v0.4 · interactive workflow")
    return page


def render_header(title: str, subtitle: str) -> None:
    left, right = st.columns([4, 1], vertical_alignment="bottom")
    with left:
        st.title(title)
        st.caption(subtitle)
    with right:
        st.button("匯出報表", icon=":material/download:", width="stretch")


def render_overview(operations: pd.DataFrame) -> None:
    account = st.session_state.get("account", "store001")
    st.markdown(f"### 忠孝旗艦店（展示）　<small>現場店長 · {account}</small>", unsafe_allow_html=True)
    st.caption("中央託管總表 · 已連線　｜　最後更新：剛剛")
    render_header("營運中樞與個人檔案", "把人力、營收與服務品質放在同一個決策畫面。")
    latest = operations[operations["日期"] == operations["日期"].max()]
    revenue = int(latest["營收"].sum())
    utilization = latest["人力利用率"].mean()
    satisfaction = latest["顧客滿意度"].mean()
    bookings = int(latest["預約數"].sum())
    with st.container(horizontal=True):
        st.metric("今日營收", f"${revenue:,.0f}", "+8.4%", border=True)
        st.metric("人力利用率", f"{utilization:.0f}%", "+3.1%", border=True)
        st.metric("顧客滿意度", f"{satisfaction:.1f}/100", "+2.6%", border=True)
        st.metric("今日預約", f"{bookings}", "+12%", border=True)

    col1, col2 = st.columns(2)
    with col1:
        with st.container(border=True):
            st.subheader("營收趨勢")
            trend = operations.groupby("日期", as_index=False)["營收"].sum()
            st.area_chart(trend.set_index("日期"), y="營收", height=230)
            booking_trend = operations.groupby("日期", as_index=False)["預約數"].sum()
            st.caption("預約量趨勢")
            st.line_chart(booking_trend.set_index("日期"), y="預約數", height=150)
    with col2:
        with st.container(border=True):
            st.subheader("門市營運健康度")
            health = (
                latest.assign(健康度=lambda frame: (frame["人力利用率"] + frame["顧客滿意度"]) / 2)
                [["門市", "健康度", "營收"]]
                .sort_values("健康度", ascending=False)
            )
            st.dataframe(
                health,
                hide_index=True,
                column_config={
                    "健康度": st.column_config.ProgressColumn(
                        "健康度", min_value=0, max_value=100, format="%.0f"
                    ),
                    "營收": st.column_config.NumberColumn("營收", format="$%d"),
                },
            )
            st.caption("健康度比較")
            st.bar_chart(health.set_index("門市")[["健康度"]], y="健康度", height=180)

    with st.container(border=True):
        st.subheader("🧭 POLC 現代管理實務推進路線")
        st.caption("依循實戰順序逐步推動門市改善，資料會由各模組匯入同一條稽核鏈。")
        route = st.columns(6)
        for index, (icon, label, detail) in enumerate(
            [
                ("🧹", "前置守門", "資料清洗"),
                ("🎯", "Plan 規劃", "客訴分析"),
                ("⏱️", "Organize 組織", "斷點排查"),
                ("👥", "Lead 領導", "幹部作戰卡"),
                ("🛡️", "Control 控制", "防呆雙簽"),
                ("🏆", "終極結案", "改善白皮書"),
            ]
        ):
            with route[index]:
                st.markdown(f"**{icon} {label}**")
                st.caption(detail)

    with st.container(border=True):
        st.subheader("📋 門市決策閉環審計台帳")
        st.caption("所有改善報告、作戰卡與結案紀錄集中於此，保留完整追蹤鏈。")
        events = st.session_state.get("audit_events")
        if events:
            st.dataframe(pd.DataFrame(events), hide_index=True)
        else:
            st.dataframe(
                pd.DataFrame(
                    {
                        "發布時間": ["尚無真實發布紀錄"],
                        "所屬階段模組": ["可由 POLC 模組建立"],
                        "改善方案摘要": ["匯入實際資料後開始追蹤"],
                        "閉環狀態": ["待建立"],
                    }
                ),
                hide_index=True,
            )
    with st.container(border=True):
        st.subheader("🔔 通知中心")
        st.caption("通知會先進入佇列；部署後可由背景工作者送往 Email、LINE 或 Teams。")
        identity = current_identity(st.session_state)
        with st.form("notification_form"):
            channel = st.selectbox("渠道", ["email", "line", "teams"])
            recipient = st.text_input("收件人", placeholder="Email、LINE user ID 或 Teams webhook")
            message = st.text_input("訊息", value="AIMS 有新的營運改善任務待處理。")
            if st.form_submit_button("加入通知佇列", icon=":material/notifications:"):
                try:
                    queue_notification(get_store(), identity, channel, recipient, message)
                    st.success("通知已加入佇列。")
                except (PermissionError, ValueError) as exc:
                    st.error(str(exc))
        if events:
            st.download_button(
                "下載審計紀錄",
                data=pd.DataFrame(events).to_csv(index=False).encode("utf-8-sig"),
                file_name="aims_audit_log.csv",
                mime="text/csv",
                icon=":material/download:",
            )

    with st.container(border=True):
        st.subheader("今日診斷建議")
        st.success("台北信義店的人力利用率與滿意度同步上升，建議將高峰時段服務流程複製到其他門市。")
        st.warning("高雄左營店週末晚班預約量偏高，建議優先補足 1 名具備多技能的服務人員。")


def render_schedule(shifts: pd.DataFrame) -> None:
    render_header("智慧排班", "接續 Shiftwise 的排班資料，集中檢視人力缺口與班表狀態。")
    action, source = st.columns([1, 2], vertical_alignment="center")
    with action:
        st.link_button("開啟 Shiftwise 排班系統", SHIFTWISE_URL, icon=":material/open_in_new:")
    with source:
        st.caption("建議從 Shiftwise 匯出 CSV，再到「資料匯入」套用；此頁會立即使用已套用的資料。")
    if st.session_state.get("last_sync_job"):
        st.caption(f"最近同步工作：{st.session_state['last_sync_job']}（佇列／可由背景 worker 執行）")
    col1, col2 = st.columns([1, 2])
    with col1:
        selected_branch = st.selectbox("門市", ["全部"] + sorted(shifts["門市"].unique().tolist()))
        selected_status = st.multiselect(
            "班表狀態",
            sorted(shifts["狀態"].unique().tolist()),
            default=sorted(shifts["狀態"].unique().tolist()),
        )
    filtered = shifts.copy()
    if selected_branch != "全部":
        filtered = filtered[filtered["門市"] == selected_branch]
    if selected_status:
        filtered = filtered[filtered["狀態"].isin(selected_status)]
    with col2:
        st.metric("目前顯示班次", f"{len(filtered)} 班", border=True)
    coverage, duplicates = schedule_insights(filtered)
    metric_a, metric_b, metric_c = st.columns(3)
    with metric_a:
        st.metric("待確認班次", f"{int(filtered['狀態'].astype(str).str.contains('待|pending|未', case=False, na=False).sum())}", border=True)
    with metric_b:
        st.metric("排班日／門市組合", f"{len(coverage)}", border=True)
    with metric_c:
        st.metric("疑似重複班次", f"{len(duplicates)}", border=True)
    with st.container(border=True):
        st.subheader("排班覆蓋與風險")
        coverage_chart = coverage.groupby("日期", as_index=False).agg(
            已覆蓋=("覆蓋狀態", lambda values: int((values == "已覆蓋").sum())),
            需處理=("覆蓋狀態", lambda values: int((values == "需處理").sum())),
        )
        if not coverage_chart.empty:
            st.caption("每日門市覆蓋狀態")
            st.bar_chart(coverage_chart.set_index("日期"), y=["已覆蓋", "需處理"], height=190)
        st.dataframe(
            coverage,
            hide_index=True,
            column_config={
                "日期": st.column_config.DateColumn("日期", format="YYYY-MM-DD"),
                "覆蓋狀態": st.column_config.TextColumn("覆蓋狀態"),
            },
        )
        if len(duplicates):
            st.warning("發現相同日期、門市、人員與時段的重複班次，請先確認後再發布。")
        else:
            st.success("目前沒有發現完全重複的班次。")
    with st.container(border=True):
        st.dataframe(
            filtered.sort_values(["日期", "門市", "開始"]),
            hide_index=True,
            column_config={
                "日期": st.column_config.DateColumn("日期", format="YYYY-MM-DD"),
                "狀態": st.column_config.TextColumn("狀態"),
            },
        )
        st.download_button(
            "下載目前篩選班表",
            data=filtered.to_csv(index=False).encode("utf-8-sig"),
            file_name="aims_filtered_schedule.csv",
            mime="text/csv",
            icon=":material/download:",
        )
    st.caption("正式串接時，請從 Shiftwise 匯出 CSV 後上傳，或提供受控 API endpoint；不會擅自讀取帳號密碼。")


def render_module_page(page: str) -> None:
    labels = {
        "資料清洗與格式檢核": ("資料清洗與格式檢核", "流水帳與客訴體檢、欄位對齊、缺失修補"),
        "1. 客訴多軌分析 (Plan)": ("客訴多軌分析", "多軌收集、語意降噪與 PDCA 改善規劃"),
        "2. 接觸點與工位斷點 (Organize)": ("接觸點與工位斷點", "P90 快篩、泳道斷點與職掌劃分"),
        "3. 幹部領導作戰卡 (Lead)": ("幹部領導作戰卡", "當班方針、工位防呆卡與突發安撫"),
        "4. 接觸點防呆雙簽 (Control)": ("接觸點防呆雙簽", "防呆雙簽、缺失存查與結案固化"),
        "POLC 終極全景改善白皮書": ("POLC 終極全景改善白皮書", "全歷程儀表板、成效對比與決策簡報"),
    }
    title, subtitle = labels[page]
    render_header(title, subtitle)
    complaints = st.session_state.get("demo_complaints", sample_complaints())
    if page == "2. 接觸點與工位斷點 (Organize)":
        steps = [
            "2-1 營運紀錄與標準定義",
            "2-2 尖峰等候與人手測算",
            "2-3 接觸點泳道流程圖",
            "2-4 80/20 卡關真因排查",
            "2-5 敏捷對策防呆檢驗",
            "2-6 改善公文報告生成",
        ]
        if "organize_step" not in st.session_state:
            st.session_state["organize_step"] = steps[0]
        st.subheader("Organize 子流程")
        st.caption("依序完成 2-1 到 2-6；每一步都可直接點選，不會被隱藏在其他頁面。")
        step_columns = st.columns(6)
        for index, step_name in enumerate(steps):
            with step_columns[index]:
                if st.button(
                    step_name.split(" ", 1)[0],
                    key=f"organize_step_button_{index}",
                    type="primary" if st.session_state["organize_step"] == step_name else "secondary",
                    width="stretch",
                ):
                    st.session_state["organize_step"] = step_name
                    st.rerun()
        step = st.session_state["organize_step"]
        st.info(f"目前步驟：{step}")
        if step == "2-1 營運紀錄與標準定義":
            st.subheader("營運紀錄與標準定義")
            st.caption("先提供現場紀錄，再由主管定義尖峰區間與可接受服務標準。")
            col1, col2 = st.columns(2)
            with col1:
                source_text = st.text_area(
                    "貼上門市現有紀錄",
                    value="12:30 客人大量湧入，櫃檯確認單據卡住，施作區材料不足等待補貨。",
                    height=160,
                )
            with col2:
                peak_start = st.time_input("尖峰開始", value=None)
                peak_end = st.time_input("尖峰結束", value=None)
                service_target = st.number_input("服務等待標準（分鐘）", min_value=1, value=15)
            if st.button("建立營運標準", type="primary", icon=":material/tune:"):
                st.session_state["operations_definition"] = {
                    "紀錄": source_text,
                    "尖峰": f"{peak_start or '未設定'}–{peak_end or '未設定'}",
                    "等待標準": service_target,
                }
                record_audit("建立營運標準", f"等待標準 {service_target} 分鐘")
                st.success("標準已建立，可進入 2-2 進行尖峰人手測算。")
            if "operations_definition" in st.session_state:
                definition = st.session_state["operations_definition"]
                st.success(f"標準狀態：已建立（等待標準 {definition['等待標準']} 分鐘，尖峰 {definition['尖峰']}）。")
        elif step == "2-2 尖峰等候與人手測算":
            st.subheader("尖峰等候與人手測算")
            data = pd.DataFrame(
                {
                    "時段": ["11:30–12:00", "12:00–12:30", "12:30–13:00", "17:00–17:30"],
                    "到店人數": [18, 26, 34, 22],
                    "可用人數": [3, 3, 3, 4],
                    "平均等待分鐘": [8, 14, 26, 12],
                }
            )
            st.dataframe(data, hide_index=True)
            selected = st.selectbox("要優先處理的尖峰時段", data["時段"])
            target = st.number_input("目標等待分鐘", min_value=1, value=15)
            row = data[data["時段"] == selected].iloc[0]
            gap = max(0, int(row["平均等待分鐘"] - target))
            metric_a, metric_b = st.columns(2)
            with metric_a:
                st.metric("預估等待超標", f"{gap} 分鐘", border=True)
            with metric_b:
                st.metric("人力缺口估計", f"{max(0, round(row['到店人數'] / 20))} 人" if gap else "0 人", border=True)
            st.caption("尖峰時段到店量與平均等待")
            st.bar_chart(data.set_index("時段")[["到店人數", "平均等待分鐘"]], height=220)
            if st.button("產生人手調度建議", type="primary", icon=":material/groups:"):
                extra = max(1, round(row["到店人數"] / 20)) if gap else 0
                st.session_state["staffing_recommendation"] = {
                    "時段": selected,
                    "缺口": gap,
                    "支援人員": extra,
                }
                st.success(f"{selected} 建議增加 {extra} 名支援人員，並將櫃檯與交接工位設為優先。")
                record_audit("完成尖峰人手測算", f"{selected} · 缺口 {extra} 人")
            if "staffing_recommendation" in st.session_state:
                result = st.session_state["staffing_recommendation"]
                st.success(f"測算結果：{result['時段']}，等待超標 {result['缺口']} 分鐘，建議增加 {result['支援人員']} 名支援人員。")
        elif step == "2-3 接觸點泳道流程圖":
            st.subheader("接觸點泳道流程圖")
            flow = pd.DataFrame(
                {
                    "順序": [1, 2, 3, 4, 5],
                    "接觸點": ["預約確認", "到店報到", "需求受理", "主要施作", "成果交接／結帳"],
                    "責任角色": ["櫃檯", "接待", "服務人員", "服務人員", "主管／櫃檯"],
                    "輸入": ["預約單", "顧客", "需求紀錄", "服務標準", "完成結果"],
                    "輸出": ["確認通知", "報到狀態", "服務單", "成果", "結案通知"],
                }
            )
            st.caption("由左至右為顧客旅程；每張卡片標示該接觸點的責任角色與交付物。")
            for _, item in flow.iterrows():
                with st.container(border=True):
                    step_col, point_col, role_col, output_col = st.columns([0.5, 1.5, 1.2, 1.5])
                    with step_col:
                        st.markdown(f"### {int(item['順序'])}")
                    with point_col:
                        st.markdown(f"**{item['接觸點']}**")
                        st.caption(f"輸入：{item['輸入']}")
                    with role_col:
                        st.markdown("責任角色")
                        st.caption(item["責任角色"])
                    with output_col:
                        st.markdown("交付輸出")
                        st.caption(item["輸出"])
            st.dataframe(flow, hide_index=True)
            st.caption("可將每個接觸點匯出後交給各工位主管確認責任邊界。")
            st.download_button("下載泳道流程 CSV", flow.to_csv(index=False).encode("utf-8-sig"), "aims_swimlane.csv", "text/csv")
        elif step == "2-4 80/20 卡關真因排查":
            st.subheader("80/20 卡關真因排查")
            causes = pd.DataFrame(
                {
                    "真因": ["交接欄位不完整", "尖峰未分流", "材料補給延遲", "付款通知漏發", "其他"],
                    "案件數": [11, 8, 5, 3, 1],
                    "4M1E": ["法", "法／環", "料", "機／法", "待分類"],
                }
            )
            causes["累積比例"] = causes["案件數"].cumsum() / causes["案件數"].sum() * 100
            chart_col, table_col = st.columns([1.2, 1])
            with chart_col:
                st.caption("案件數與累積比例")
                st.bar_chart(causes.set_index("真因")[["案件數"]], y="案件數", height=220)
                st.line_chart(causes.set_index("真因")[["累積比例"]], y="累積比例", height=180)
            with table_col:
                st.dataframe(causes, hide_index=True)
            if st.button("鎖定前 20% 真因", type="primary", icon=":material/filter_alt:"):
                st.session_state["top_causes"] = causes.head(2)
                st.success("已鎖定：交接欄位不完整、尖峰未分流。可進入 2-5 建立敏捷對策。")
            if "top_causes" in st.session_state:
                st.dataframe(st.session_state["top_causes"], hide_index=True)
        elif step == "2-5 敏捷對策防呆檢驗":
            st.subheader("敏捷對策防呆檢驗")
            countermeasures = pd.DataFrame(
                {
                    "期限": ["24–48 小時", "1–2 週", "1–3 個月"],
                    "對策": ["交接雙簽與尖峰分流話術", "彈性補位與班表調節", "SOP 固化與訓練驗收"],
                    "責任人": ["當班主管", "店長", "營運主管"],
                    "驗收指標": ["等待 ≤ 15 分鐘", "P90 降低 20%", "雙簽完成率 100%"],
                }
            )
            edited = st.data_editor(countermeasures, hide_index=True, key="organize_countermeasures")
            if st.button("確認對策可行性", type="primary", icon=":material/task_alt:"):
                st.session_state["countermeasures_confirmed"] = True
                record_audit("確認敏捷對策", f"{len(edited)} 項")
                st.success("對策已確認，下一步可生成改善公文。")
            if st.session_state.get("countermeasures_confirmed"):
                st.success("對策狀態：已確認，可進入 2-6。")
        else:
            st.subheader("改善公文報告生成")
            report = pd.DataFrame(
                {
                    "段落": ["現況", "真因", "短期措施", "中期措施", "長期固化", "驗收指標"],
                    "內容": [
                        "尖峰等待與交接流程造成服務延遲。",
                        "交接欄位不完整、尖峰沒有分流。",
                        "導入交接雙簽與尖峰話術。",
                        "調整班表並建立浮動支援工位。",
                        "將標準寫入 SOP 並完成訓練驗收。",
                        "等待 ≤ 15 分鐘、P90 降低 20%、雙簽率 100%。",
                    ],
                }
            )
            st.dataframe(report, hide_index=True)
            if st.button("建立改善公文", type="primary", icon=":material/article:"):
                st.session_state["organize_report"] = report
                record_audit("建立改善公文", "Organize 2-6")
                st.success("改善公文已建立，並寫入 POLC 審計台帳。")
            generated_report = st.session_state.get("organize_report")
            if isinstance(generated_report, pd.DataFrame):
                st.success("改善公文狀態：已建立，可下載。")
                sections = [(row["段落"], row["內容"]) for _, row in generated_report.iterrows()]
                st.download_button("下載改善公文 CSV", generated_report.to_csv(index=False).encode("utf-8-sig"), "aims_improvement_report.csv", "text/csv", key="download_organize_csv")
                st.download_button("下載改善公文 DOCX", export_docx("AIMS 改善公文", sections), "aims_improvement_report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", key="download_organize_docx")
                st.download_button("下載改善公文 PDF", export_pdf("AIMS 改善公文", sections), "aims_improvement_report.pdf", "application/pdf", key="download_organize_pdf")
        return
    if page == "資料清洗與格式檢核":
        st.subheader("資料健康檢查")
        quality = data_quality_report(complaints, "客訴資料")
        st.metric("客訴資料完整率", f"{quality['完整率'].mean():.1f}%", border=True)
        st.dataframe(quality, hide_index=True)
        with st.container(border=True):
            st.subheader("待修正資料")
            st.dataframe(complaints[complaints.isna().any(axis=1)] if complaints.isna().any(axis=1).any() else complaints.head(0), hide_index=True)
    elif page == "1. 客訴多軌分析 (Plan)":
        st.subheader("客訴多軌分析")
        severity = complaints.groupby("嚴重度", as_index=False).size().rename(columns={"size": "案件數"})
        st.bar_chart(severity, x="嚴重度", y="案件數")
        st.dataframe(complaints, hide_index=True)
        if st.button("執行 4M1E 語意降噪", type="primary", icon=":material/auto_awesome:"):
            st.session_state["analysis_result"] = pd.DataFrame(
                [
                    {"案件編號": "CS-2401", "主因類別": "法（流程）", "關鍵斷點": "尖峰排隊未設置分流與告知", "建議": "建立尖峰分流話術與等候看板"},
                    {"案件編號": "CS-2402", "主因類別": "人（人員）", "關鍵斷點": "預約交接未雙重確認", "建議": "新增預約交接雙簽"},
                    {"案件編號": "CS-2403", "主因類別": "法（流程）", "關鍵斷點": "跨班交接欄位不完整", "建議": "建立交接清單"},
                ]
            )
        if "analysis_result" in st.session_state:
            st.success("分析完成：已抽取客觀事實並標記 4M1E 主因。")
            st.dataframe(st.session_state["analysis_result"], hide_index=True)
            st.download_button(
                "下載 4M1E 分析結果",
                st.session_state["analysis_result"].to_csv(index=False).encode("utf-8-sig"),
                "aims_4m1e_analysis.csv",
                "text/csv",
                key="download_4m1e",
            )
    elif page == "2. 接觸點與工位斷點 (Organize)":
        st.subheader("P90 泳道斷點快篩")
        process = pd.DataFrame(
            {"服務接觸點": ["預約確認", "到店報到", "服務交接", "付款結案"], "P90 分鐘": [18, 12, 26, 9], "責任工位": ["櫃檯", "接待", "現場主管", "櫃檯"], "風險": ["高", "中", "高", "低"]}
        )
        st.dataframe(process, hide_index=True)
        st.bar_chart(process, x="服務接觸點", y="P90 分鐘")
        st.warning("服務交接 P90 為 26 分鐘，為目前最高風險斷點。")
    elif page == "3. 幹部領導作戰卡 (Lead)":
        st.subheader("今日幹部作戰卡")
        st.info("尖峰時段：17:00–19:30　｜　主責：現場主管　｜　目標：等候時間低於 15 分鐘")
        cols = st.columns(3)
        for col, title_text, detail in zip(cols, ["開班前", "尖峰中", "異常時"], ["確認人力與預約名單", "每 15 分鐘更新等待狀態", "主管在 3 分鐘內介入"]):
            with col:
                with st.container(border=True):
                    st.subheader(title_text)
                    st.checkbox(detail, key=f"playbook_{title_text}")
        st.text_area("主管口頭指令", value="今天先確保預約交接雙簽，超過 15 分鐘主動告知顧客。")
        if st.button("產生今日作戰卡", type="primary", icon=":material/assignment:"):
            st.session_state["lead_playbook_created"] = True
            record_audit("產生幹部作戰卡", "Lead")
            st.success("今日作戰卡已產生，可依三個時段逐項確認。")
        if st.session_state.get("lead_playbook_created"):
            st.success("作戰卡狀態：已產生，可依三個時段逐項確認。")
    elif page == "4. 接觸點防呆雙簽 (Control)":
        st.subheader("防呆雙簽驗收")
        checks = pd.DataFrame(
            {"檢核項目": ["預約資料與現場名單一致", "交接欄位完整", "付款完成通知已發送", "異常案件已由主管覆核"], "責任人": ["櫃檯", "現場主管", "櫃檯", "店長"], "狀態": ["待覆核", "待覆核", "已完成", "待覆核"]}
        )
        edited = st.data_editor(checks, hide_index=True, key="control_checks")
        if st.button("發布防呆驗收結果", type="primary", icon=":material/verified:"):
            st.session_state["control_result"] = {
                "completed": int((edited["狀態"] == "已完成").sum()),
                "total": len(edited),
            }
            record_audit("發布防呆驗收", f"{int((edited['狀態'] == '已完成').sum())}/{len(edited)} 項完成")
            st.success("驗收結果已寫入審計台帳。")
        if "control_result" in st.session_state:
            result = st.session_state["control_result"]
            st.success(f"驗收狀態：已發布（{result['completed']}/{result['total']} 項完成）。")
    elif page == "POLC 終極全景改善白皮書":
        st.subheader("改善白皮書預覽")
        report = pd.DataFrame(
            {"階段": ["Plan", "Organize", "Lead", "Control"], "主要發現": ["客訴集中於等待與交接", "交接 P90 最高", "尖峰缺少即時指揮", "雙簽尚未全面完成"], "成果指標": ["4 件客訴完成分類", "P90 26 分鐘", "已建立 3 張作戰卡", "1/4 項完成"]}
        )
        st.dataframe(report, hide_index=True)
        if st.button("產生改善白皮書 CSV", type="primary", icon=":material/article:"):
            st.session_state["polc_report"] = report
            record_audit("產生 POLC 白皮書", "Plan / Organize / Lead / Control")
        generated_report = st.session_state.get("polc_report")
        if isinstance(generated_report, pd.DataFrame):
            st.success("白皮書狀態：已產生，可下載。")
            sections = [(row["階段"], f"{row['主要發現']}；成果指標：{row['成果指標']}") for _, row in generated_report.iterrows()]
            st.download_button("下載白皮書 CSV", generated_report.to_csv(index=False).encode("utf-8-sig"), "aims_polc_report.csv", "text/csv", key="download_polc_csv")
            st.download_button("下載白皮書 DOCX", export_docx("AIMS POLC 改善白皮書", sections), "aims_polc_report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", key="download_polc_docx")
            st.download_button("下載白皮書 PDF", export_pdf("AIMS POLC 改善白皮書", sections), "aims_polc_report.pdf", "application/pdf", key="download_polc_pdf")
    with st.container(border=True):
        st.subheader("目前工作區")
        st.info("以上為可操作的模擬案例。匯入實際資料後，這些表格與分析會改用你的資料。")
        st.text_area("管理者備註", placeholder="記錄本次改善假設、責任人與驗收條件…")
        if st.button("建立示範改善任務", type="primary", icon=":material/add_task:"):
            identity = current_identity(st.session_state)
            try:
                create_polc_report(
                    get_store(),
                    identity,
                    page,
                    f"{page} 改善任務",
                    "由管理者建立的待驗證改善任務。",
                )
                record_audit("建立改善任務", page)
            except PermissionError as exc:
                st.error(str(exc))
                return
            st.success("已建立示範任務；正式版將寫入中央資料庫並保留稽核紀錄。")


def render_import(operations: pd.DataFrame, shifts: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    render_header("資料匯入", "匯入實際營運與排班資料，預覽後再套用到 AIMS。")
    st.info("建議先使用 CSV / Excel 匯入。Google Apps Script 若提供 JSON endpoint，可直接貼上 URL；Shiftwise 可先匯出排班 CSV。")
    with st.container(border=True):
        st.subheader("🧪 模擬資料範例")
        st.caption("使用一組完整的展示案例快速體驗欄位、分析與 POLC 流程；可下載後修改。")
        mini_bundle = sample_mini_bundle()
        mini_kind = st.selectbox("選擇範例資料", list(mini_bundle.keys()), key="mini_kind")
        mini_data = mini_bundle[mini_kind]
        col1, col2 = st.columns([2, 1])
        with col1:
            st.dataframe(mini_data.head(8), hide_index=True)
        with col2:
            st.metric("範例筆數", f"{len(mini_data)} 筆", border=True)
            st.download_button(
                "下載模擬範例",
                data=mini_data.to_csv(index=False).encode("utf-8-sig"),
                file_name=f"aims_mini_{mini_kind}.csv",
                mime="text/csv",
                icon=":material/download:",
            )
            if st.button("套用模擬資料", icon=":material/input:"):
                if mini_kind == "營運資料":
                    operations = canonicalize_columns(mini_data, "營運資料")
                elif mini_kind == "排班資料":
                    shifts = canonicalize_columns(mini_data, "排班資料")
                elif mini_kind == "客訴資料":
                    st.session_state["demo_complaints"] = mini_data
                st.session_state["imported_operations"] = operations
                st.session_state["imported_shifts"] = shifts
                record_audit("套用模擬資料", mini_kind)
                st.success(f"已套用模擬資料：{mini_kind}")
    tab_file, tab_url = st.tabs(["檔案匯入", "API URL 匯入"])
    with tab_file:
        data_kind = st.radio("資料類型", ["營運資料", "排班資料"], horizontal=True)
        st.download_button(
            "下載欄位範本",
            data=template_csv(data_kind),
            file_name="aims_營運資料範本.csv" if data_kind == "營運資料" else "aims_排班資料範本.csv",
            mime="text/csv",
            icon=":material/download:",
        )
        uploaded = st.file_uploader("上傳營運或排班資料", type=["csv", "xlsx", "xls"])
        if uploaded is not None:
            try:
                imported = canonicalize_columns(parse_uploaded_file(uploaded), data_kind)
                st.success(f"已讀取 {len(imported):,} 筆資料。")
                quality = data_quality_report(imported, data_kind)
                complete_rate = quality["完整率"].mean()
                st.metric("資料完整率", f"{complete_rate:.1f}%", border=True)
                if complete_rate < 100:
                    st.warning("資料包含缺失值，建議修正後再套用。")
                else:
                    st.success("必要欄位完整，可套用。")
                with st.expander("查看資料品質檢查"):
                    st.dataframe(quality, hide_index=True)
                st.dataframe(imported.head(100), hide_index=True)
                if st.button("套用這批資料", type="primary", icon=":material/save:"):
                    if data_kind == "營運資料":
                        operations = imported
                    else:
                        shifts = imported
                    st.session_state["imported_operations"] = operations
                    st.session_state["imported_shifts"] = shifts
                    record_audit("匯入資料", f"{data_kind} · {len(imported):,} 筆")
                    if data_kind == "排班資料":
                        st.session_state["last_sync_job"] = get_store().add_job(
                            "shiftwise_csv",
                            {"filename": uploaded.name, "rows": len(imported)},
                        )
                    st.success("資料已套用到本次工作階段。")
            except (ValueError, pd.errors.ParserError, ImportError, UnicodeDecodeError) as exc:
                st.error(f"匯入失敗：{exc}")
    with tab_url:
        source = st.selectbox("快速選擇來源", ["Google Apps Script AIMS", "自訂 JSON endpoint"])
        url = AIMS_URL if source == "Google Apps Script AIMS" else st.text_input("JSON URL")
        if st.button("讀取來源", icon=":material/cloud_download:"):
            if not url.strip():
                st.error("請先提供 URL。")
            else:
                try:
                    imported = normalize_imported_data(fetch_json(url.strip()))
                    st.session_state["url_import_preview"] = imported
                    st.success(f"已讀取 {len(imported):,} 筆資料。")
                except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
                    st.error(f"讀取來源失敗：{exc}")
        preview = st.session_state.get("url_import_preview")
        if isinstance(preview, pd.DataFrame):
            st.dataframe(preview.head(100), hide_index=True)
            st.caption("URL 匯入目前只做安全預覽；欄位對應完成後再套用，避免外部資料直接覆寫本地資料。")
    return operations, shifts


def main() -> None:
    apply_aims_style()
    sync_oidc_identity()
    if oidc_enabled() and not st.user.is_logged_in:
        render_login()
        return
    if not st.session_state.get("authenticated"):
        render_login()
        return
    if "imported_operations" not in st.session_state:
        operations, shifts = load_demo_data()
    else:
        operations = st.session_state["imported_operations"]
        shifts = st.session_state["imported_shifts"]
    page = render_sidebar()
    if page == "營運中樞與個人檔案":
        render_overview(operations)
    elif page in {
        "資料清洗與格式檢核",
        "1. 客訴多軌分析 (Plan)",
        "2. 接觸點與工位斷點 (Organize)",
        "3. 幹部領導作戰卡 (Lead)",
        "4. 接觸點防呆雙簽 (Control)",
        "POLC 終極全景改善白皮書",
    }:
        render_module_page(page)
    elif page == "智慧排班":
        render_schedule(shifts)
    else:
        operations, shifts = render_import(operations, shifts)
        st.session_state["imported_operations"] = operations
        st.session_state["imported_shifts"] = shifts


if __name__ == "__main__":
    main()
