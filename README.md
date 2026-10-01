# AIMS 泛服務業營運診斷原型

這是一個可執行的 Streamlit 原型，將 AIMS 的管理入口、POLC 營運工作台、營運儀表板，以及 Shiftwise 排班資料匯入集中在同一個工作區。

## 啟動

```powershell
python -m pip install -r requirements.txt
streamlit run app.py
```

## 目前功能

- 營運總覽：營收、人力利用率、顧客滿意度、預約數與門市健康度。
- 智慧排班：依門市與狀態篩選班表，連結 Shiftwise。
- 資料匯入：CSV / Excel 上傳，及 JSON endpoint 預覽。
- 下載營運資料與排班資料 CSV 範本。
- 自動辨識常見中文、英文欄位名稱，並在套用前檢查必要欄位與數值格式。
- 排班覆蓋率、待確認班次與疑似重複班次分析。
- 匯入資料完整率與欄位品質報告。
- 篩選後班表與審計紀錄 CSV 匯出。
- POLC 改善任務、資料匯入與操作紀錄的工作階段審計追蹤。
- Organize 公文與 POLC 白皮書可匯出 CSV、DOCX、PDF。
- PostgreSQL／Supabase 儲存適配器，未設定連線時使用本機 SQLite。
- OIDC 登入掛接點（Google／Microsoft 由 `.streamlit/secrets.toml` 設定）。
- 企業申請與帳密登入：申請資料會寫入 PostgreSQL／Supabase；未設定時使用本機 SQLite。
- 通知佇列與同步工作佇列，可交給部署平台的 cron／worker 執行。
- Email、LINE、Teams 與 Shiftwise API provider adapter，預設為 dry-run。
- Docker 啟動設定與環境變數範本。
- 內建示範資料，可在接上真實資料前先驗證流程。

## 真實資料接法

1. 從 Shiftwise 匯出 CSV，在「資料匯入」上傳並選擇「排班資料」。
2. 將 Google Apps Script 改成輸出 JSON 的受控 endpoint，再於「API URL 匯入」讀取。
3. 正式環境應增加登入、角色權限、欄位映射、資料庫與金流 webhook；目前原型不會要求或保存帳號密碼。
4. 目前先不啟用訂閱與收費，優先完成 AIMS 工作台與實際排班資料導入。

## 強化方向

目前可透過 `AIMS_DATABASE_URL` 接 PostgreSQL／Supabase；未設定時會使用 `aims_local.db`。請複製 [.streamlit/secrets.toml.example](./.streamlit/secrets.toml.example) 為 `.streamlit/secrets.toml`，再填入連線與 OIDC 設定。真正的 Shiftwise API、Email、LINE、Teams provider 仍需要你提供 API 權限與部署環境，系統會先將工作寫入可重試佇列，不會假裝已送出。

### Supabase + Google 正式模式

1. 在 Supabase 建立 project，從 Database settings 取得 SSL connection string。
2. 在 `.streamlit/secrets.toml` 設定 `AIMS_DATABASE_URL`。
3. 在 Google Cloud Console 建立 OAuth Client（Web application）。
4. 將 `http://localhost:8501/oauth2callback` 加入 Google 的 Authorized redirect URIs。
5. 將 `client_id`、`client_secret` 與 Google OIDC metadata URL 填入 `[auth]`。
6. 部署後，把 redirect URI 改成正式網域的 `/oauth2callback`，並同步更新 Google Cloud 設定。
7. 可用 `AIMS_ADMIN_EMAILS` 與 `AIMS_AUDITOR_EMAILS` 指定角色，其餘已登入帳號預設為 manager。

啟用 `[auth]` 後，系統會停用本機帳密登入，只保留 Google OIDC 與示範帳號入口；所有真正資料操作仍會寫入 PostgreSQL 審計表。

### 企業申請與帳密登入

未設定 OIDC 時，登入頁提供「申請企業帳號」：

1. 填寫企業／門市名稱、登入帳號與至少 8 個字元的密碼。
2. 送出後即可使用「企業帳密登入」。
3. 密碼以 PBKDF2-SHA256 雜湊保存，不會寫入明文。
4. 正式環境請設定 `AIMS_DATABASE_URL`，讓帳號跨部署重啟持久保存；未設定時帳號只存在本機 SQLite。

若啟用 `[auth]` 的 Google OIDC，正式環境會優先使用企業單一登入；企業帳密申請入口則保留給未啟用 OIDC 的模式。

### 背景工作

```powershell
python worker.py
```

`worker.py` 會初始化持久化佇列，之後可由 Windows 工作排程器、GitHub Actions、Cloud Run Job 或其他 worker 執行 provider adapter。

### 第三方 provider

請複製 [.env.example](./.env.example) 為部署平台的環境設定。`AIMS_DRY_RUN=true` 時，worker 只會驗證佇列流程，不會對外發送；確認 secrets 正確後才改為 `false`。Teams 收件人欄位應填 webhook URL，LINE 填 user ID，Email 填收件地址。Shiftwise 若提供受控 JSON API，可設定 `SHIFTWISE_API_URL` 與 `SHIFTWISE_API_TOKEN`。

### Docker

```powershell
docker build -t aims-suite .
docker run --env-file .env --publish 8501:8501 aims-suite
```

### 匯入欄位

營運資料至少需要：`日期`、`門市`、`營收`、`人力利用率`、`顧客滿意度`、`預約數`。

排班資料至少需要：`日期`、`門市`、`員工`、`班別`、`開始`、`結束`、`狀態`。

「資料匯入」頁面提供可直接下載的 CSV 範本；也會自動對應 `分店`、`branch`、`staff`、`start_time` 等常見欄位別名。
