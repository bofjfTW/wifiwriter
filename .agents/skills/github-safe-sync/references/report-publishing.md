# 實測報告雙層發布規則

## 私有層（不得上傳）

- 位置：專案外之本機私有報告目錄（例如桌面 `wifiwriter_private_reports/`）或 `reports/internal/`。
- 內容：完整原始 JSON/MD/CSV、未遮罩 IP、網卡名稱、事件原文、下載之安裝檔。
- 原始報告不得覆寫、不得移入 Git 工作樹的允許路徑。

## 公開層（可上傳）

- 位置：`docs/field-tests/<YYYY-MM-DD>-<env>-<target>/`
  - `summary.md`：10 節（目的、日期與 Run ID、Git Commit、範圍與限制、實際執行測試、結果統計、異常類型、根因分析、已確認/未確認、最終結論）。
  - `evidence.json`：`schema_version`、`test_date`、`run_id`、`git_commit`、`environment_label`、`application_name`、`download_transport_status`、`downloaded_bytes`、`content_length`、`sha256`、`signature_status`、`signer`、`dns_results`、`tcp_results`、`tls_results`、`http_results`、`error_counts`、`incomplete_checks`、`evidence_limitations`。
- 日期使用實測時的台灣日期，不使用發布日期。

## 去識別化檢查清單

- [ ] 無 `C:\Users\<真實帳號>` 路徑、無使用者帳號與主機名稱
- [ ] 校園 / 內網 IP 一律寫成 `163.xxx.xxx.xxx` 等四段遮罩形式（不得保留任何數字第四段）
- [ ] 無 MAC / BSSID / 網卡序號
- [ ] 無 Token、Cookie、密碼、帳號、身分證字號
- [ ] 公開伺服器 IP（如官方網站）與官方 URL、SHA-256、簽署者可保留
- [ ] 未測項目明確標為 `NOT_TESTED`，不得以模擬資料填補
- [ ] `python -m src.privacy --check-staged` 0 violations

