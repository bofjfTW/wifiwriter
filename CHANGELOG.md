# Changelog

本檔案記錄 `wifiwriter` 專案之版本變更、功能新增與問題修正。

---

## [v0.4.0] — 2026-11-11

### 新增功能 (`Added`)
- **富邦 e+ 校園網路實機診斷 v0.4 (`src/fubon_v04.py`)**：Phase A Preflight、單次完整下載三階段驗證（傳輸 / PE + SHA-256 / Authenticode）、Phase C 低負載穩定性多輪檢查、Phase D Windows 事件唯讀關聯、A–J 根因分析報告；私有原始報告輸出至專案外目錄。
- **去識別化實測報告** `docs/field-tests/2026-11-11-campus-fubon/`（`summary.md`、`evidence.json`），Run ID `fubon_v04_campus_20261111_122058`。
- **專案 Skill `github-safe-sync`**（`.agents/skills/github-safe-sync/`）：測試 → 隱私掃描 → 明確路徑 Commit → 推送功能分支 → 遠端 SHA 驗證 → PR。
- `AGENTS.md` 新增 `Mandatory GitHub Safe Sync` 規範。
- 新增 `tests/test_fubon_v04.py`、`tests/test_github_safe_sync.py`（含暫存 Git repo + 本地 bare remote 之同步流程測試）。

### 修正與強化 (`Changed` / `Fixed`)
- `src/privacy.py`：白名單只額外開放 `.agents/skills/github-safe-sync/`；任何路徑下之原始診斷報告檔名一律拒絕；新增拒絕 `.zip`、`.csv`、`.jsonl`、`.tmp`、`.partial`；新增 `--repo-root` 參數。
- `src/privacy.py`：修正 IP 掃描之版本號排除規則過寬（前文含任一字母 `v` 即略過，例如 `server <IP>`）造成漏報。
- `scripts/sync_github.ps1`：驗證 `origin` URL、提交前執行測試、推送前檢查遠端分歧（禁止 force push）、推送後以 `git ls-remote` 驗證遠端 SHA，並以不同 exit code 區分失敗原因；工作樹乾淨時跳過、不建立空 Commit。

---

## [v0.3.0] — 2026-11-11

### 新增功能 (`Added`)
- **富邦證券「富邦e+電腦版」免登入官方安裝檔下載與雙網路比較 (`fubon-eplus`)：**
  - 從富邦官方產品頁 `https://www.fbs.com.tw/eplus/pc` 自動解析「下載富邦e+電腦版」下方 `Download` 按鈕（`#download_pc_app`）之實際下載連結（`FB_ePlus_setup.exe`），並拒絕將同頁面的 Microsoft Visual C++ 元件（`vcredist_x86.exe`、`vc_redist.x86.exe`）、PDF 手冊、富邦 e01 或行動版誤當作主程式代測。
  - 分開記錄「官方產品頁能否開啟」與「安裝檔能否完整取得」，依序執行低負載 `HTTP HEAD` 標頭檢查與完整 `HTTP GET` 下載（帶入 `no-cache` 標頭，每輪另存全新暫存子目錄）。
  - 嚴格檢查檔案 Magic Bytes（`MZ` PE 執行檔 vs HTML 登入頁／攔阻頁）與 `Content-Length` 位元組大小核對；單做 `HEAD`、部分下載或收到 HTML 網頁皆不會誤判為下載成功。
  - 計算完整檔案 `SHA-256` 並透過唯讀 `Get-AuthenticodeSignature` 驗證數位簽章狀態與簽署者，全程只下載、不安裝、不啟動、不登入。
  - 執行第二輪手機行動數據熱點（`--network hotspot`）時，自動檢查 Windows 預設路由（`0.0.0.0/0`）是否仍走校園有線網路，防止流量未真正經過熱點時產生無效對照。
  - 自動產生完全獨立（不混入既有凱基資料）之繁體中文並排比較報告（`fubon_eplus_report.md`、`fubon_eplus_report.json`、`fubon_eplus_comparison.csv`），未執行項目統一標示為 `未測`，兩輪 `SHA-256` 一致時明確標示「兩次取得的檔案內容一致」。
- **免登入實機診斷框架 (`noauth` / `noauth-compare`)：**
  - 新增 `src/noauth.py` 支援 Mode A (`download-only` 預設) 與 Mode B (`prelogin`，具強制使用者授權閘門 `--confirm-user-consent-launch`)。
  - 新增 16 項免登入與富邦e+邊界驗收自動化測試 (`tests/test_noauth_v03.py`)。

### 修正與強化 (`Fixed & Changed`)
- **下載與未登入狀態判定修正 (`src/analyzer.py`)：**
  - 修正 `classify_download_evidence`：明確區分 `HTTP HEAD 200` 與完整 `HTTP GET` 下載，防止將 `HEAD` 成功直接視為完整安裝檔可下載。
  - 修正 `classify_application_evidence`：對處於未登入狀態 (`prelogin` / `unauthenticated`) 之程序標記為 `證據不足`，絕不誤判為交易連線正常。
- **隱私與版控防護強化 (`.gitignore`, `src/privacy.py`, `scripts/sync_github.ps1`)：**
  - 於 `.gitignore` 與 `src/privacy.py` 明確封鎖 `.exe`、`.msi`、`.part` 等安裝檔與暫存目錄，確保安裝程式與實測紀錄只留在本機。

---

## [v0.2.0] — 2026-11-10

### 新增與修正
- 建立雙頻率監控 (`scripts/monitor_connections.ps1`)、手動斷線標記 (`mark`)、八大事件分類、TLS 錯誤細分、真實 Socket 持續時間統計及科學 A/B 可比性檢核。
- 新增 `src/privacy.py` 敏感資訊掃描器與 `scripts/sync_github.ps1` 白名單同步防護，取消無條件自動推送 `main` 與 `git add -A`。

---

## [v0.1.0] — 2026-11-10

### 初始版本
- 建立 Windows 校園網路環境唯讀蒐集、公開網站與連線限制檢查基礎架構。

