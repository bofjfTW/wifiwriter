# wifiwriter v0.2 — 校園網路與凱基證券「新超級大三元」高可信度連線診斷系統

本專案是一套專為 **Windows 10 / 11 大學校園網路環境**設計的**唯讀、低負載、非侵入式連線診斷與科學 A/B 對照系統**。

核心目標為：**精確判斷凱基證券「新超級大三元」交易軟體在校園網路的真實斷線事件，並將斷線時間點與本機程序、TCP Socket 生滅、DNS/TCP 探測及 Windows 網路事件建立可追溯關聯，而非僅測試伺服器 TCP Port 是否可連通。**

> **安全、隱私與合規邊界：**
> - **零侵入性：** 絕不掃描校園網段、不執行未授權 Port Scan、不發送高頻率或洪泛流量、不繞過校園網路政策、不修改防火牆/DNS/Proxy/網卡設定。
> - **零金融敏感存取：** 絕不讀取、解密或擷取交易帳密、憑證、Cookie、Session Token、畫面報價或委託內容；絕不自動登入或下單。
> - **內外資料嚴格分離與防洩漏：** 內部完整診斷產物存於 `reports/internal/<run_id>/`，對外去識別化遮罩版存於 `reports/sanitized/<run_id>/`；兩者皆由 `.gitignore` 與 `src/privacy.py` 雙重攔截，嚴禁自動上傳至公開 GitHub。

---

## 專案目錄結構

```text
wifiwriter/
├── .github/workflows/ci.yml        # GitHub Actions 離線單元測試與隱私掃描工作流程
├── AGENTS.md                       # 分支開發與 Git 提交隱私安全規範 (禁止自動推 main)
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
│   ├── diagnostics.py              # CLI 主程式（env / check / kgi / monitor / mark / compare / report / simulate / all）
│   ├── analyzer.py                 # 八大事件分類、TLS 細分、真實 Socket 時長、科學 A/B 檢核與三層證據分級
│   ├── privacy.py                  # 敏感資訊掃描器與內外分享資料深層去識別化模組
│   └── report_generator.py         # Markdown / JSON / CSV / 離線安全 HTML 報告產生器（含事件時間線）
├── tests/
│   ├── test_diagnostics.py         # 17 項離線單元測試與 PowerShell 生命週期整合測試
│   └── fixtures/                   # RFC 5737 合成測試資料（零真實個人或金融端點）
├── docs/
│   ├── methodology.md              # v0.2 科學取證方法論、事件分類與證據分級規範
│   ├── troubleshooting.md          # Windows 實機操作 SOP、手動標記與 A/B 30 分鐘實驗手冊
│   └── v0.2_validation_report.md   # v0.2 修正驗證報告與 Git 歷史隱私風險評估
└── reports/
    └── .gitkeep                    # 本機輸出目錄（internal/ 與 sanitized/ 均已排除版控）
```

---

## 環境需求

- **作業系統：** Windows 10 / Windows 11（內建 Windows PowerShell 5.1）
- **Python：** Python 3.10 以上（100% 使用內建標準函式庫，無須 `pip install` 外部套件）
- **執行權限：** 一般使用者權限即可執行全部唯讀檢查與監控（如需管理員權限或封包擷取，須另行評估並取得使用者同意，本工具預設不啟用）

---

## Windows 實際操作教學（CLI 完整指令）

請在專案根目錄開啟 PowerShell 執行：

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
