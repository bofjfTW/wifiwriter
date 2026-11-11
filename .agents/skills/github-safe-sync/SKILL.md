---
name: github-safe-sync
description: Automatically validate, safely commit, and push completed Codex development changes to the approved GitHub feature branch after each task. Exclude sensitive reports, credentials, and private machine data.
---

# github-safe-sync

將 wifiwriter 已完成的開發成果安全同步到 `https://github.com/bofjfTW/wifiwriter`。

## 1. 觸發條件

- 每次完成 wifiwriter 開發任務（程式碼、測試、文件、去識別化實測報告）且有可發布變更時，在最終回覆前執行。
- 只有診斷資料、原始報告或安裝檔變更時：**不得同步**，回報 `SKIP`。
- 工作樹乾淨或無暫存變更：回報 `SKIP: no changes`，不建立空 Commit。

## 2. Git 狀態檢查

```powershell
git remote -v
git branch --show-current
git status --short
git fetch origin
```

- `origin` 必須符合 `github.com/bofjfTW/wifiwriter`。
- 目前分支不得為 `main` / `master`；不得 detached HEAD。

## 3. 測試流程

```powershell
python -m unittest discover -s tests -v
```

任何失敗即中止，不 Commit、不 Push。

## 4. 隱私檢查

```powershell
python -m src.privacy --check-staged
```

必須 0 violations：無本機使用者路徑、帳號、主機名、MAC/BSSID、RFC1918/CGNAT/TANet 未遮罩 IP、Token、密碼、Cookie、私鑰、身分證字號。

## 5. 檔案白名單

允許：`src/`、`scripts/`、`tests/`、`docs/`（含 `docs/field-tests/` 去識別化報告）、`.github/`、`.agents/skills/github-safe-sync/`、`README.md`、`AGENTS.md`、`CHANGELOG.md`、`requirements.txt`、`.gitignore`、`config/targets.example.json`、`reports/.gitkeep`。

拒絕：`reports/**`（除 `.gitkeep`）、原始診斷報告檔名、`*.exe`、`*.msi`、`*.zip`、`*.csv`、`*.jsonl`、`*.log`、`*.pcap*`、`*.etl`、`*.dmp`、`*.pfx`、`*.key`、`*.pem`、`config/targets.json`、私有報告目錄內容。

**禁止** `git add -A`、`git add .`；只能逐一指定路徑。

## 6. Git Commit

```powershell
.\scripts\sync_github.ps1 -Paths <file1>,<file2> -CommitMessage "<type>: <summary>" -DryRun
.\scripts\sync_github.ps1 -Paths <file1>,<file2> -CommitMessage "<type>: <summary>"
```

Commit 訊息使用 Conventional Commits（`feat:`、`fix:`、`docs:`、`test:`、`chore:`）。

## 7. Git Push

- 只推送目前功能／修復分支：`git push -u origin <branch>`。
- **禁止** `--force` / `--force-with-lease`；推送前檢查 `origin/<branch>` 是否為 HEAD 祖先。

## 8. 遠端驗證

```powershell
git ls-remote --heads origin <branch>
git rev-parse HEAD
```

兩者 SHA 必須一致。

## 9. Pull Request 更新或建立

- 若分支已有開啟中的 PR：推送即更新，留言說明本次變更（可選）。
- 若無：以 `gh pr create --base main --head <branch>` 建立；`gh` 不可用時回報 PR 建立網址 `https://github.com/bofjfTW/wifiwriter/pull/new/<branch>`。
- **不得自動合併** PR。

## 10. 失敗與衝突處理

| 狀況 | 處理 |
|---|---|
| 測試失敗 | 中止（exit 5），回報失敗測試 |
| 隱私掃描失敗 | 中止（exit 2），移除違規檔案暫存 |
| 位於 main | 中止（exit 3） |
| remote URL 不符 | 中止（exit 4） |
| 遠端分歧 non-fast-forward | 中止（exit 6），不 force push，請使用者決定 rebase/merge |
| 認證失敗 | 中止（exit 7），請使用者重新登入 GitHub 認證 |
| 遠端 SHA 不一致 | 中止（exit 8） |

## 11. 最終回報格式

```text
GITHUB_SYNC:
- status: PUSHED | SKIPPED | ABORTED
- branch: <branch>
- commit: <sha>
- remote_verified: true|false
- pull_request: <url>
- files: <list>
- tests: <passed>/<total>
- privacy_scan: PASSED|FAILED
```

公開報告規則見 [references/report-publishing.md](references/report-publishing.md)。

