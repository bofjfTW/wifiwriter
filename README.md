# wifiwriter — 校園網路與金融交易軟體（富邦e+電腦版／凱基新超級大三元）連線診斷系統

本專案是一套專為 **Windows 10 / 11 大學校園網路環境**設計的**唯讀、低負載、非侵入式連線診斷、官方安裝檔完整性驗證與科學 A/B 對照系統**。

同時支援兩大核心診斷流程：
1. **富邦證券「富邦e+電腦版」免登入官方安裝檔下載與雙網路（校園網路 vs 手機行動數據熱點）比較 (`fubon-eplus`)**
2. **凱基證券「新超級大三元」免登入診斷 (`noauth` / `noauth-compare`) 與雙頻率即時斷線關聯監控 (`monitor` / `mark` / `compare`)**

> **安全、隱私與合規邊界：**
> - **零侵入性：** 絕不掃描校園網段、不執行未授權 Port Scan、不發送高頻率或洪泛流量、不繞過校園網路政策、不修改防火牆/DNS/Proxy/網卡設定。
> - **零金融敏感存取（免登入安全保證）：** 免登入下載測試全程**只下載、不安裝、不啟動、不登入**任何證券帳戶；絕不讀取、解密或擷取交易帳密、憑證、Cookie、Session Token、畫面報價或委託內容。
> - **內外資料嚴格分離與防洩漏：** 本機診斷與安裝檔暫存預設存放於專案外的私人目錄（或經 `.gitignore` 與 `src/privacy.py` 雙重攔截的 `reports/`），嚴禁將安裝檔或原始診斷紀錄上傳至公開 GitHub。

---

## 專案目錄結構

```text
wifiwriter/
├── .github/workflows/ci.yml        # GitHub Actions 離線單元測試與隱私掃描工作流程
├── AGENTS.md                       # 分支開發與 Git 提交隱私安全規範 (禁止自動推 main)
├── CHANGELOG.md                    # 版本變更紀錄 (v0.1 -> v0.2 -> v0.3)
├── README.md                       # 專案總覽與 Windows 實戰操作教學
├── requirements.txt                # Python >= 3.10 標準函式庫說明（零第三方套件依賴）
├── config/
│   └── targets.example.json        # 經審查之公開白名單網站、應用程式與 HEAD 下載設定範本
├── scripts/
│   ├── collect_network.ps1         # 唯讀蒐集 Windows 網路介面、路由、防火牆、Proxy 與系統事件
│   ├── check_restrictions.ps1      # 公開白名單網站、指定程式與低負載 HEAD 下載檢查
│   ├── inspect_kgi.ps1             # 多因子驗證凱基程序身分與三類遠端端點分級
│   ├── monitor_connections.ps1     # 雙頻率監控（5 秒被動 Socket 追蹤 + 30 秒主動探測）與生命週期保護
│   └── sync_github.ps1             # 白名單路徑暫存 + 敏感資訊掃描同步工具（禁止 git add -A 與直推 main）
├── src/
│   ├── diagnostics.py              # CLI 主程式（fubon-eplus / noauth / noauth-compare / env / check / kgi / monitor / mark / compare / report / simulate / all）
│   ├── noauth.py                   # 富邦e+與凱基免登入官方頁面解析、完整安裝檔下載、SHA-256 / Authenticode 唯讀驗證與 A/B 比較
│   ├── analyzer.py                 # 八大事件分類、TLS 細分、真實 Socket 時長、科學 A/B 檢核與三層證據分級
│   ├── privacy.py                  # 敏感資訊掃描器與內外分享資料深層去識別化模組
│   └── report_generator.py         # Markdown / JSON / CSV / 離線安全 HTML 報告產生器（含事件時間線）
├── tests/
│   ├── test_diagnostics.py         # 17 項 v0.2 離線單元測試與 PowerShell 生命週期整合測試
│   ├── test_noauth_v03.py          # 16 項 v0.3 免登入與富邦e+下載邊界驗收測試
│   └── fixtures/                   # RFC 5737 合成測試資料（零真實個人或金融端點）
├── docs/
│   ├── methodology.md              # 科學取證方法論、事件分類與證據分級規範
│   ├── troubleshooting.md          # Windows 實機操作 SOP、手動標記與 A/B 實驗手冊
│   └── v0.2_validation_report.md   # 修正驗證報告與 Git 歷史隱私風險評估
└── reports/
    └── .gitkeep                    # 本機輸出目錄（所有實測產物與安裝檔皆排除版控）
```

---

## 富邦e+ 免登入下載測試

### 1. 專案功能介紹
針對**富邦證券「富邦e+電腦版」**，提供獨立且不受既有其他券商資料干擾的雙網路（**校園網路 vs 手機行動數據熱點**）官方安裝檔下載驗證：
- **官方入口動態解析：** 從富邦證券官方產品頁 `https://www.fbs.com.tw/eplus/pc` 自動定位「下載富邦e+電腦版」下方的 `Download` 按鈕（`#download_pc_app`），提取實際安裝檔網址（`FB_ePlus_setup.exe`），並嚴格排除同頁面上的 Microsoft Visual C++ 元件（`vcredist_x86.exe` / `vc_redist.x86.exe`）、PDF 手冊、富邦 e01、行動版或憑證工具。
- **分開記錄「官方產品頁能否開啟」與「安裝檔能否完整取得」：** 先執行低負載 `HTTP HEAD` 標頭診斷，再以 `Cache-Control: no-cache` 執行完整 `HTTP GET` 將安裝檔下載至全新的本機暫存子目錄。
- **嚴格檔案內容與大小核對：** 單做 `HEAD`、部分下載截斷（實收位元組不符 `Content-Length`），或收到 `HTTP 200` 但內容是 HTML 校園登入頁／攔阻頁（非 `MZ` Windows PE 執行檔），一律判定為下載失敗。
- **唯讀完整性與數位簽章驗證：** 對完整下載之檔案計算 `SHA-256`，並透過 PowerShell `Get-AuthenticodeSignature` 唯讀驗證簽章狀態（如 `Valid`）與簽署者（`富邦綜合證券股份有限公司`），**全程絕不執行、不安裝、不啟動該檔案**。
- **預設路由防呆檢查：** 執行第二輪手機熱點測試時，自動檢查 Windows `0.0.0.0/0` 預設路由是否仍走校園有線網路（避免插著網路線時流量未真正經過手機熱點）。

### 2. Windows 環境需求與相依套件
- **作業系統：** Windows 10 / Windows 11（內建 Windows PowerShell 5.1，供唯讀呼叫 `Get-NetRoute` 與 `Get-AuthenticodeSignature`）
- **Python 版本：** Python 3.10 以上
- **安裝或執行所需依賴：** **零第三方套件依賴**（100% 使用 Python 標準函式庫 `urllib.request`、`hashlib`、`ssl`、`socket`、`subprocess`、`csv`、`json`，無須執行 `pip install`）。

### 3. 如何執行校園網路測試（第一輪）
在電腦連接校園網路時，於專案根目錄開啟 PowerShell 執行：

```powershell
python src/diagnostics.py fubon-eplus --network campus
```

*(若富邦官方網頁未來改版導致無法自動解析按鈕連結，可在瀏覽器開啟 `https://www.fbs.com.tw/eplus/pc` 點擊「下載富邦e+電腦版」下方的 `Download` 按鈕，按 `Ctrl+J` 對下載項目按右鍵「複製下載連結」，再附加 `--override-download-url "<實際下載網址>"` 執行。)*

### 4. 如何執行手機熱點測試（第二輪）
1. 請先將手機關閉 Wi-Fi、開啟個人行動數據熱點。
2. **拔除電腦的校園有線網路線**（或暫時停用「乙太網路」介面），確認電腦流量確實改走手機熱點路由（可執行 `Get-NetRoute -DestinationPrefix "0.0.0.0/0"` 檢查）。
3. 執行第二輪指令（程式會自動驗證預設路由非校園有線網路，並另存至全新暫存目錄，不沿用第一輪快取）：

```powershell
python src/diagnostics.py fubon-eplus --network hotspot
```

### 5. 如何產生 A/B 比較報告
每一輪執行完成後皆會自動更新並排比較報告；若需在不重新下載的情況下，單獨讀取本機既有兩輪紀錄重新產生比較表（Markdown、JSON、CSV），請執行：

```powershell
python src/diagnostics.py fubon-eplus --compare-only
```

### 6. 如何查看與判讀結果
報表預設儲存於本機專案外之私人目錄 `..\wifiwriter_private_reports\fubon_eplus\`（或由 `--output-dir` 指定之目錄）：
- `fubon_eplus_report.md`：繁體中文兩輪並排比較表（未執行項目明確標示為 `未測`）。
- `fubon_eplus_report.json`：包含兩輪台灣時間、預設路由、`HEAD`/`GET` 狀態、耗時、實收位元組、`Content-Length` 核對、檔案類型、`SHA-256` 與 `Get-AuthenticodeSignature` 簽章詳情之結構化資料。
- `fubon_eplus_comparison.csv`：可供試算表匯入的兩輪指標對照表。
- **判讀原則：**
  - 若兩輪均完整取得安裝檔且 `SHA-256` 完全相同，報告會明確顯示 **「兩次取得的檔案內容一致」**，代表校園網路並未阻擋、截斷或竄改富邦e+電腦版官方安裝檔。
  - 若僅校園網路失敗，報告會明確指出差異發生的步驟（例如：步驟 1 產品頁開啟失敗、步驟 2 按鈕解析失敗、步驟 3 收到 HTML 攔阻頁，或步驟 4 下載中途截斷大小不符）。

### 7. 哪些限制無法在未登入狀態下驗證
- **官方安裝檔可完整下載 ≠ 交易軟體登入後連線正常：** 下載測試走的是富邦官網標準 HTTPS (`www.fbs.com.tw:443`)，而安裝並啟動看盤軟體後的即時報價與委託回報可能連接不同的專屬交易伺服器與通訊埠。
- **無法驗證登入後長連線穩定度：** 未安裝、未啟動、未登入狀態下，無法驗證校園網路 NAT / 防火牆是否會在長時間看盤時回收閒置 TCP 長連線（Idle Timeout），亦無法驗證帳號認證後之伺服器分派或跨裝置同帳號互踢行為。

---

## 凱基證券「新超級大三元」免登入診斷與即時監控教學

請在專案根目錄開啟 PowerShell 執行：

### 0. 執行凱基免登入實機診斷 (`noauth` / `noauth-compare`)

```powershell
# 校園網路免登入診斷（預設 Mode A: download-only，不安裝、不啟動、不登入）
python src/diagnostics.py noauth --mode download-only --network campus

# 切換手機熱點後執行同條件免登入對照
python src/diagnostics.py noauth --mode download-only --network hotspot

# 產生校園網路 (A) vs 手機熱點 (B) 免登入科學對照報告與 CSV
python src/diagnostics.py noauth-compare
```

### 1. 執行可重現的離線模擬斷線驗收測試（免開交易軟體、零真實金融連線）

```powershell
python src/diagnostics.py simulate
```

一次驗證兩大關鍵行為：
1. **凱基未啟動 + 主動探測失敗** → 輸出 `KGI_PROBE_FAILURE`（`探測失敗，尚無交易程式斷線證據`），`confirmed_trading_disconnect_count = 0`。
2. **凱基執行中斷線 + 手動標記** → 自動關聯前後程序身分、Socket 歸零、主動探測與 Windows 系統事件。

### 2. 一鍵執行本機唯讀基準診斷

```powershell
python src/diagnostics.py all
```

自動共享單一 `Run ID` 依序完成 `env` → `check` → `kgi` → `report`（任一步驟子程序非零結束碼即中止並寫入安全 `error_summary.json`，絕不載入舊報告偽裝成功）。
- 內部完整報告：`reports/internal/<run_id>/diagnostic_report.{md,html,json}`
- 對外分享遮罩版：`reports/sanitized/<run_id>/diagnostic_report.{md,html,json}`

### 3. 開啟「新超級大三元」執行雙頻率即時監控與手動斷線標記

1. 先關閉手機上的同帳號看盤 App（避免跨裝置互踢），手動開啟並登入電腦版「新超級大三元」停留在一般看盤畫面。
2. 啟動校園網路 30 分鐘背景監控（**被動每 5 秒**觀察驗證通過之凱基程序與 TCP Socket 生滅；**主動每 30 秒**執行低負載 DNS/TCP 探測）：
   ```powershell
   python src/diagnostics.py monitor start --label campus --passive-interval 5 --active-interval 30 --duration 1800
   ```
3. **當您親眼看到軟體畫面跳出斷線或行情停止更新時**，立即執行手動標記：
   ```powershell
   python src/diagnostics.py mark --event kgi-disconnected --note "盤中報價中斷"
   ```
   當軟體重連恢復時，標記恢復時間：
   ```powershell
   python src/diagnostics.py mark --event kgi-reconnected --note "自動重連恢復"
   ```
4. 隨時查詢背景監控健康狀態（會同時驗證 PID 與程序建立時間，自動偵測背景異常結束）：
   ```powershell
   python src/diagnostics.py monitor status
   ```
5. 滿 30 分鐘自動結束，或手動優雅停止並原子寫入完整統計與事件時間線：
   ```powershell
   python src/diagnostics.py monitor stop
   ```

### 4. 切換個人手機熱點執行對照實驗（測試 B）並進行科學比較

```powershell
# 切換至個人手機熱點並重新登入新超級大三元後，以相同設定執行 30 分鐘監控：
python src/diagnostics.py monitor start --label hotspot --passive-interval 5 --active-interval 30 --duration 1800

# 雙環境皆完成後，執行 7 項科學可比性前置檢核與每小時標準化斷線率比較：
python src/diagnostics.py compare

# 產生最新整合研究報告（含 10 欄位事件時間線與 7 大核心問題實證回答）：
python src/diagnostics.py report
```

---

## 執行自動化測試與隱私檢查

```powershell
# 執行全部離線單元測試與 Windows PowerShell 監控生命週期整合測試
python -m unittest discover -s tests -v

# 掃描工作區已追蹤檔案是否符合 Git 白名單與零敏感資訊規範
python -m src.privacy
```

---

## 延伸閱讀

- 科學診斷方法論與事件分類定義：[docs/methodology.md](./docs/methodology.md)
- Windows 實機排查與 A/B 實驗操作手冊：[docs/troubleshooting.md](./docs/troubleshooting.md)
- v0.2 驗證報告與 Git 歷史隱私風險評估：[docs/v0.2_validation_report.md](./docs/v0.2_validation_report.md)
