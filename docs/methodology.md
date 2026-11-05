# 診斷方法論與科學取證規範 (`docs/methodology.md` — v0.2)

## 1. 核心科學與工程原則

1. **應用層證據與獨立探測嚴格分離：**
   - 對伺服器通訊埠的獨立 TCP 探測失敗（`KGI_PROBE_FAILURE`）**不等於**交易軟體發生斷線。
   - 唯有具備可信交易程式狀態來源或使用者即時標記（`KGI_APPLICATION_DISCONNECT_REPORTED`）之事件，方能計入「已確認交易斷線」。
2. **協定中立，拒絕無根據推論：**
   - 當 TCP `443` 三方交握成功，但標準 TLS 交握發生逾時（`TLS_HANDSHAKE_TIMEOUT`）、重置（`TLS_HANDSHAKE_RESET`）、EOF（`TLS_HANDSHAKE_EOF`）或協定錯誤（`TLS_PROTOCOL_ERROR`）時，在缺乏官方協定文件或授權封包證據前，應用層協定一律標記為 `UNKNOWN`。
   - 絕不因標準 TLS 交握失敗就直接宣稱伺服器使用特定專屬二進位協定，亦不據此推論校園防火牆正在執行應用程式識別（App-ID）或 NAT 閒置回收。
3. **多因子程序身分驗證：**
   - 不單憑 `axis.exe` 檔名認定連線歸屬；綜合檢查執行檔安裝路徑、Authenticode 數位簽章（`KGI Securities Co. Ltd.`）、PID、程序建立時間（`StartTime`）與父子程序樹。
   - 將遠端連線明確區分為：`observed_active`（實際觀察到的活躍交易/行情端點）、`static_ini_candidate`（靜態 `tab/YELLOWPAGE.INI` 候選端點）與 `unverified_remote`（如內嵌 WebView2 子程序連線至外部未確認用途端點）。
4. **雙頻率低負載設計：**
   - **被動狀態取樣（預設每 5 秒）：** 純本機讀取程序狀態、TCP Socket 生滅與網卡狀態，零網路封包負載。
   - **主動低負載探測（預設每 30 秒）：** 僅對允許之凱基端點與單一公開對照端點執行單次 DNS + TCP 建連測試，杜絕高頻率掃描。

---

## 2. 八大標準監控事件分類

| 事件代碼 | 定義與觸發條件 | 是否計入「已確認交易斷線」 |
| --- | --- | --- |
| `NETWORK_INTERFACE_DOWN` | 本機主要網路介面斷開或失去預設閘道 | 否（屬底層介面中斷事件） |
| `CONTROL_ENDPOINT_FAILURE` | 公開對照端點（如 Microsoft）主動探測失敗 | 否（屬對照組連線異常） |
| `KGI_PROBE_FAILURE` | 對凱基端點的獨立主動 DNS/TCP 探測失敗 | **否**（僅標記為探測異常） |
| `KGI_SOCKET_DISCONNECTED` | 觀察到屬於已驗證凱基程序之既有 Established Socket 結束 | **否**（無應用層證據前可能為短連線正常輪替） |
| `KGI_PROCESS_EXITED` | 已驗證之凱基交易程式退出執行 | **否**（與網路層 Socket 中斷嚴格分開） |
| `KGI_APPLICATION_DISCONNECT_REPORTED` | 使用者執行 `mark --event kgi-disconnected` 或可信應用層來源確認斷線 | **是** |
| `KGI_RECONNECTED` | 斷線後重新建立交易連線或使用者執行 `mark --event kgi-reconnected` | 否（屬恢復事件） |
| `UNKNOWN_EVENT` | 證據不足或無法歸入上述類別之異常 | 否 |

---

## 3. 連線持續時間與 A/B 比較嚴謹規範

- **禁止虛假平均時長公式：** 已徹底移除 `總監控秒數 ÷ (斷線次數 + 1)` 估算式。僅針對監控期間**同時完整觀測到建立（Open）與結束（Close）**之 TCP Socket 計算可辨識存活秒數；若連線於監控前即存在或於結束時仍存活而無法精確界定，統一誠實標示為「`無法精確估計`」。
- **A/B 對照七大前置檢核：** `compare_ab_results()` 於比較前強制驗證：(1) 雙邊樣本數 `> 0`、(2) `label` 與實際偵測網路環境相符、(3) 測試皆正常結束且資料完整、(4) 被動/主動取樣間隔一致、(5) 測試期間凱基程式實際執行、(6) 實際觀察到 Established Socket、(7) 雙邊測試時長具可比性（比例介於 `0.5x ~ 2.0x` 且達最低門檻）。任一項未通過即拒絕輸出環境歸因結論。
- **標準化每小時事件率與保守結論：** 同步計算每小時斷線率（`次/小時`）；觀測期間 `0` 次斷線僅表述為「本次觀測期間未發生」；即使校園網路與手機熱點差異顯著，亦僅能支持「問題與校園網路環境有關」，不能直接證明學校防火牆存在刻意封鎖政策。
