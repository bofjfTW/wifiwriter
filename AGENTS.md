# Workspace Guidelines & GitHub Auto-Sync Policy

## 1. GitHub 定期同步規則（最高優先工作流規範）

- **遠端儲存庫（Remote Repository）：** `https://github.com/bofjfTW/wifiwriter.git`（分支：`main`）
- **自動定期上傳義務：**
  - 每當完成功能新增、程式碼修改、文件更新或產生新的正式診斷報告里程碑時，Agent **必須主動執行隱私遮罩檢查並將變更 commit 與 push 上傳至 `origin main`**（或呼叫 `.\scripts\sync_github.ps1`），無須等待使用者再次提醒。

## 2. 上傳前隱私與安全檢查（強制執行）

每次執行 `git add` / `git commit` / `git push` 之前，必須確認：
1. 任何即將提交的檔案（特別是 `reports/` 與 `network_environment.*`）**不得包含未遮罩之本機使用者名稱、電腦主機名稱、完整校園/內網客戶端 IP、MAC/BSSID 位址，或任何金融帳號/憑證/Session 敏感資訊**。
2. 暫存執行檔與快取（如 `__pycache__/`、`*.pyc`、`reports/monitor_stop.flag`、`reports/monitor_state.json`、`config/targets.json`）維持於 `.gitignore` 排除狀態。
