# 壓力測試（Campus Network Diagnostic）— 校園網路與凱基證券「新超級大三元」連線診斷系統

本專案是一套專為 **Windows 10/11 大學校園網路環境**設計的**唯讀、低負載、非侵入式網路診斷與證據蒐集工具**。

主要任務為找出**凱基證券「新超級大三元」交易軟體（`SUPERTSC64.exe` / `axis.exe`）在學校網路環境經常斷線、連線中斷或重新連線的真正原因**，透過自動化環境辨識、公開對照檢查、實際端點協定檢測、30 秒週期斷線監控及「學校網路 vs 手機熱點」A/B 對照實驗，產出嚴謹可重現的技術報告。

> **安全與合規聲明：**
> - 本工具**絕不**掃描校園網段、不執行大規模 Port Scan、不發送高負載/洪泛流量、不繞過任何校園認證或防火牆政策。
> - **絕不**修改本機防火牆、DNS、Proxy、路由或 Windows Defender 設定（純唯讀檢查）。
> - **絕不**讀取、解密或擷取任何金融交易帳密、憑證、Session Token 或委託內容。
> - 對本機 IP、主機名稱、使用者帳號、MAC/BSSID 自動進行隱私遮罩，且所有報告 100% 儲存在本機，不上傳任何外部伺服器。

---

## 專案目錄結構

```text
壓力測試/
├── README.md                       # 專案總覽與完整使用教學（本檔案）
├── requirements.txt                # 依賴說明（核心 100% 使用標準庫，免安裝第三方套件）
├── network_environment.json        # 第一階段：本機網路環境辨識結果 (JSON)
├── network_environment.md          # 第一階段：本機網路環境辨識報告 (Markdown)
├── config/
│   └── targets.example.json        # 白名單網站、本機程式與授權 HEAD 下載檢測設定範本
├── scripts/
│   ├── collect_network.ps1         # 唯讀蒐集 Windows 網路介面、路由、防火牆、Proxy 與事件
│   ├── inspect_kgi.ps1             # 自動探索新超級大三元執行檔、數位簽章、PID 與實際連線端點
│   ├── check_restrictions.ps1      # 網站、應用程式與低負載 HEAD 檔案下載限制檢查
│   └── monitor_connections.ps1     # 每 30 秒低負載連線監控（支援背景啟動、查詢與安全停止）
├── src/
│   ├── __init__.py
│   ├── diagnostics.py              # CLI 主程式、安全權限檢查、操作日誌與協定探測整合
│   ├── analyzer.py                 # 隱私遮罩、五級限制證據分類、A~G 根因決策與 A/B 比較引擎
│   └── report_generator.py         # 輸出 Markdown、JSON、CSV 及離線 HTML 視覺化報告
├── tests/
│   └── test_diagnostics.py         # 單元測試套件（遮罩、分類邏輯、根因規則、報告輸出）
├── reports/
│   ├── diagnostic_report.md        # 完整研究報告 (Markdown)
│   ├── diagnostic_report.html      # 離線視覺化診斷儀表板 (HTML)
│   ├── diagnostic_report.json      # 完整結構化證據包 (JSON)
│   ├── diagnostic_summary.csv      # 網站、程式、下載與凱基端點總表 (CSV, Excel 相容)
│   ├── ab_comparison.csv           # 學校網路 vs 手機熱點八大指標對照表 (CSV)
│   └── operations.log              # 經遮罩之操作稽核日誌
└── docs/
    ├── methodology.md              # 診斷方法論、協定機轉與科學舉證規範
    └── troubleshooting.md          # 故障排除 SOP、A/B 實驗流程與學校網管申請範本
```

---

## 環境需求

- **作業系統：** Windows 10 / Windows 11（內建 PowerShell 5.1）
- **Python：** Python 3.10 以上（實測 Python 3.12，完全使用內建標準函式庫，無須 `pip install` 任何外部套件）
- **執行權限：** 一般使用者權限即可執行全部檢查（不需管理員提權）

---

## CLI 快速使用教學

請在專案根目錄（`壓力測試/`）開啟 PowerShell 或終端機執行：

### 0. 一鍵執行完整安全唯讀基準診斷（推薦首次執行）

```powershell
python src/diagnostics.py all
```

自動依序完成：網路環境辨識 -> 網站/程式/下載限制檢查 -> 凱基「新超級大三元」端點與協定深度檢測 -> 輸出 Markdown / JSON / CSV / HTML 完整報告。

### 1. 單獨一鍵蒐集電腦網路環境

```powershell
python src/diagnostics.py env
```

輸出 `network_environment.json` 與 `network_environment.md`（同步存於根目錄與 `reports/`）。

### 2. 檢查指定網站、本機程式與官方端點下載限制

```powershell
# 使用預設白名單 config/targets.example.json
python src/diagnostics.py check

# 若需自訂測試目標，可複製 config/targets.example.json 為 config/targets.json 修改後執行：
python src/diagnostics.py check --targets config/targets.json
```

### 3. 深度檢測凱基「新超級大三元」與開始/停止斷線監控

```powershell
# 3a. 單次深度檢查凱基安裝檔、簽章、程序與伺服器端點協定
python src/diagnostics.py kgi

# 3b. 開始每 30 秒低負載背景監控（請先手動開啟新超級大三元）
# 學校網路測試（測試 A，預設監控 1800 秒 = 30 分鐘）：
python src/diagnostics.py monitor start --label campus --interval 30 --duration 1800

# 查詢目前背景監控狀態與已記錄樣本數：
python src/diagnostics.py monitor status

# 手動提前安全停止監控並結算統計：
python src/diagnostics.py monitor stop
```

### 4. 進行手機熱點對照實驗並匯入比較

```powershell
# 切換至個人手機熱點後，手動開啟新超級大三元並執行測試 B：
python src/diagnostics.py monitor start --label hotspot --interval 30 --duration 1800

# 測試完成後（或手動 monitor stop 後），一鍵匯入雙環境結果產生對照報告：
python src/diagnostics.py compare

# 亦可指定特定歷史監控 JSON 檔案進行匯入比較：
python src/diagnostics.py compare --campus reports/monitor_campus_latest.json --hotspot reports/monitor_hotspot_latest.json
```

### 5. 重新產生所有格式報告（Markdown / JSON / CSV / HTML）

```powershell
python src/diagnostics.py report
```

---

## 執行單元測試

```powershell
python -m unittest discover -s tests -v
```

---

## 延伸閱讀

- 診斷設計邏輯與 NGFW 非標準協定分析：[docs/methodology.md](./docs/methodology.md)
- A/B 對照操作步驟與計中申請信範本：[docs/troubleshooting.md](./docs/troubleshooting.md)
- 最新完整研究報告：[reports/diagnostic_report.md](./reports/diagnostic_report.md)

