# Workspace Guidelines & GitHub Safe Sync Policy (v0.2+)

## 1. GitHub 分支與同步安全規範（最高優先級）

- **遠端儲存庫（Remote Repository）：** `https://github.com/bofjfTW/wifiwriter.git`
- **禁止無條件自動推送 `main`：**
  - **已取消** v0.1「每次完成里程碑自動推送至 `origin main`」之舊規。
  - 所有功能開發、錯誤修正與報告架構調整，必須在獨立功能或修復分支（例如 `fix/diagnostic-reliability-v02`）進行，並透過 Pull Request 合併，**不得直接推送或強制覆寫（`git push --force`）`main` 分支**。
- **禁止使用 `git add -A` / `git add .`：**
  - 嚴禁使用無限制的全域暫存指令，避免將本機診斷紀錄、監控日誌或個人網路組態意外提交至公開儲存庫。

## 2. 允許提交與嚴格排除之檔案範圍

- **GitHub 僅允許提交：**
  1. 程式碼與腳本（`src/`、`scripts/`、`.github/`）
  2. 專案文件與驗證報告（`README.md`、`AGENTS.md`、`docs/`、`requirements.txt`、`.gitignore`、`reports/.gitkeep`），包含去識別化實測報告 `docs/field-tests/`
  3. 經人工與自動化檢查之設定範例（`config/targets.example.json`）
  4. 純合成測試資料與單元測試（`tests/`）
  5. 專案 Skill：僅限 `.agents/skills/github-safe-sync/`（其他 `.agents/` 內容不開放）
- **嚴禁提交至 GitHub（必須維持於 `.gitignore`）：**
  - 本機診斷與監控產物：`reports/internal/`、`reports/sanitized/`、`reports/*.json`、`reports/*.md`、`reports/*.html`、`reports/*.csv`、`reports/*.jsonl`、`reports/*.log`
  - 根目錄本機環境快照：`network_environment.json`、`network_environment.md`
  - 個人目標設定、憑證與暫存檔：`config/targets.json`、`*.pfx`、`*.cer`、`*.key`、`*.pcap*`、`*.etl`、`*.dmp`

## 3. 上傳前強制敏感資訊掃描

每次執行 `git commit` 或呼叫 `.\scripts\sync_github.ps1` 前，必須通過敏感資訊掃描器檢查：

```powershell
python -m src.privacy --check-staged
```

確認暫存區檔案**完全不含**：
- 本機真實路徑（如 `C:\Users\<真實帳號>`）、Windows 使用者帳號或電腦主機名稱
- 金融帳號、身分證字號、密碼、Session Token、Cookie、API Key 或私鑰
- 未遮罩之 MAC / BSSID 位址、本機內網 IP（RFC1918 / CGNAT）或可識別個人端點之校園網路位址

### Mandatory GitHub Safe Sync

每次完成 wifiwriter 開發任務且有可發布變更時，最終回覆前必須執行 `$github-safe-sync`（見 [.agents/skills/github-safe-sync/SKILL.md](.agents/skills/github-safe-sync/SKILL.md)）：測試 → 隱私掃描 → 明確路徑 Commit → 推送目前功能分支 → 驗證遠端 SHA → 建立或更新 PR。不得推送 `main`、不得 force push、不得自動合併 PR。
