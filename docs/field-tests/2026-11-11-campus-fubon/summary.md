# 富邦 e+ 電腦版 — 校園網路免登入實機診斷（去識別化公開摘要）

> 本文件由本機私有原始報告人工整理並去識別化，**不含**本機路徑、使用者帳號、主機名稱、MAC/BSSID、未遮罩校園 IP 或任何憑證。原始報告保留於本機私有目錄，未上傳 GitHub。

## 1. 實驗目的

確認台灣大學校園網路是否會阻擋、截斷、竄改或明顯限速「富邦 e+ 電腦版」官方產品頁及官方安裝檔下載，並在免登入、不安裝、不執行的前提下，界定哪些斷線原因可被排除、哪些仍需後續驗證。

## 2. 測試日期與 Run ID

| 項目 | 值 |
|---|---|
| Run ID | `fubon_v04_campus_20261111_122058` |
| 開始時間 (UTC+8) | 2026-11-11 12:20:58 +08:00 |
| 結束時間 (UTC+8) | 2026-11-11 12:25:16 +08:00 |
| 執行狀態 | `SUCCESS`（Exit Code 0） |

## 3. 測試所用 Git Commit

- 分支：`fix/fubon-campus-diagnostics-v04`
- 基底 Commit：`f89f1eb`（實測時 v0.4 程式碼尚未提交，為工作目錄版本；同步提交於本分支之 v0.4 Commit）
- 執行指令：`python src/diagnostics.py fubon-eplus --network campus --campus-only --max-download-mib 200`

## 4. 測試範圍及安全限制

- 只測校園網路（`--campus-only`）；手機熱點 = **`NOT_TESTED`**，不做跨網路 A/B 結論。
- 不登入、不安裝、不執行富邦 e+；不讀取或操作任何金融資料。
- 不掃描校園網段或連接埠；不提升系統管理員權限；不修改防火牆或 Proxy。
- 只使用富邦官方產品頁 `https://www.fbs.com.tw/eplus/pc` 與其 Download 按鈕實際連結。

## 5. 真正執行的測試

| 階段 | 內容 |
|---|---|
| Phase A Preflight | 產品頁 GET、按鈕連結解析、DNS / TCP / TLS / HTTP HEAD |
| Phase B 完整下載 | 單次完整 HTTP GET 安裝檔 + 三階段驗證（傳輸 / PE 結構與 SHA-256 / Authenticode） |
| Phase C 穩定性 | 5 輪、間隔 60 秒之低負載 DNS / TCP / TLS / HEAD（富邦 2 目標 + Microsoft、GitHub 對照組） |
| Phase D 系統事件 | 唯讀查詢最近 60 分鐘 Windows 網路相關事件 |

網路環境（遮罩）：有線乙太網路 1 Gbps、TANet 校園網段（`163.xxx.xxx.xxx`）、無 Proxy / PAC / VPN。

## 6. 實測結果與統計

| 檢查項目 | 結果 |
|---|---|
| 官方產品頁 | HTTP 200，48.52 ms，成功解析按鈕連結 `https://www.fbs.com.tw/wcm/new_web/download_app/FB_ePlus_setup.exe` |
| DNS | `www.fbs.com.tw` → 210.208.96.55（公開 IP），0.2 ms |
| TCP 443 | 3.74 ms |
| TLS | TLSv1.2、`DHE-RSA-AES256-GCM-SHA384`、18.75 ms；簽發者 TWCA SSL Certification Authority；疑似代簽 = False |
| HTTP HEAD | 200，36.79 ms，Content-Length 77,822,080，Accept-Ranges bytes |
| 完整 GET | 200，實收 77,822,080 bytes（74.22 MiB），與 Content-Length 一致，7.88 秒，平均 79.01 Mbps，重試 0 次 |
| SHA-256 | `2beb299444912762264ab8ddb036f63a177a570e9451d48aa32b93fb1cbb6894` |
| PE 結構 | 有效，x86 (IMAGE_FILE_MACHINE_I386) |
| Authenticode | `Valid`；簽署者 富邦綜合證券股份有限公司；發證 GlobalSign GCC R45 CodeSigning CA 2020 |
| 總判定 | `VERIFIED_OFFICIAL_INSTALLER` |

Phase C（5 輪 × 60 秒）：

| 目標 | DNS | TCP（平均 / 最大 ms） | TLS | HEAD |
|---|---|---|---|---|
| 富邦產品頁 | 100% | 100%（28.04 / 42.42） | 100% | 100% |
| 富邦安裝檔 HEAD | 100% | 100%（20.89 / 29.13） | 100% | 100% |
| Microsoft 對照 | 100% | 100%（22.57 / 30.71） | 100% | 100% |
| GitHub 對照 | 100% | 100%（59.44 / 95.92） | 100% | 100% |

## 7. 異常與錯誤類型

- 主動探測異常：**0 筆**（DNS / TCP / TLS / HTTP / 下載皆無失敗或逾時）。
- Windows 事件（最近 60 分鐘）：DNS 1014 逾時 0、網卡斷線 0、NetworkProfile 變更 0、睡眠/喚醒 0。
- Security 5152/5157 封包丟棄稽核：**未取得**（需管理員權限，依規範不提權）。

## 8. 根本原因分析

- 校園網路未阻擋富邦官網，未截斷或替換安裝檔，未對 `www.fbs.com.tw:443` 進行 SSL 代簽，也無明顯限速。
- 「官網／下載通道被校園封鎖」、「DNS 污染」、「HTTPS 憑證替換」、「本機 Proxy/VPN/網卡閃斷」在本次時間窗內可排除。
- 若交易軟體實際使用時斷線，較可能的原因落在**啟動／登入後**的專屬行情與委託長連線：非 443 通訊埠出站限制、校園 NAT/防火牆長連線 Idle Timeout、應用層心跳逾時。以上**尚未驗證**。

## 9. 已確認與未確認事項

**已確認**：官方產品頁可開啟；安裝檔完整下載且通過三階段驗證；5 分鐘短週期內富邦 443 端點無間歇性失敗；本機無 Proxy/VPN 與網卡事件。

**未確認**：
1. 富邦 e+ 啟動後之更新／版本伺服器連線。
2. 登入／憑證驗證通道（可能為非 443 埠）。
3. 行情推播與委託回報長連線是否被阻擋。
4. 校園 NAT 對長時間低流量 TCP Session 之 Idle Timeout。
5. 應用層心跳在校園網路下是否逾時。
6. 手機熱點 A/B 對照（`NOT_TESTED`）。
7. Windows Security 封包丟棄稽核（需管理員權限）。

## 10. 最終結論

本次校園網路實測以高信心證明：**校園網路並未封鎖富邦官網與官方安裝檔下載，也未對其 HTTPS 進行憑證代簽或限速**。但下載成功**不能**推論登入後交易連線一定正常；兩者的主機、通訊埠與連線生命週期不同。下一步最小風險做法是由使用者自行開啟富邦 e+ 停留在未登入畫面，以唯讀 `Get-NetTCPConnection` 記錄程式發起的遠端端點與 TCP 狀態變化。

