# Windows 實機操作與故障排除手冊 (`docs/troubleshooting.md` — v0.2)

## 一、執行前安全與控制變數準備

1. **排除同帳號跨裝置互踢：**
   - 進行電腦版「新超級大三元」監控前，請先關閉手機端看盤 App（包含背景重連），避免同一組帳號跨裝置登入導致伺服器主動踢除舊連線。
2. **全程手動登入一次即可：**
   - 請您本人手動開啟並登入「新超級大三元」，停留在一般看盤畫面即可；**切勿**使用任何自動登入腳本，測試期間亦無須送出任何交易委託。
3. **本機網卡電源管理檢查（選用、手動）：**
   - 可於 Windows「裝置管理員 -> 網路介面卡 -> 內容 -> 電源管理」確認是否勾選「允許電腦關閉這個裝置以節省電源」，避免長時段無操作時系統休眠切斷連線。

---

## 二、標準 A/B 實驗操作步驟（建議各 30 分鐘）

### 階段 A：校園網路 30 分鐘即時監控

1. 確認電腦連接於**學校網路**，並已手動登入「新超級大三元」。
2. 在專案根目錄開啟 PowerShell，啟動背景監控（被動 5 秒取樣 Socket + 主動 30 秒低負載探測，共 1800 秒）：
   ```powershell
   python src/diagnostics.py monitor start --label campus --passive-interval 5 --active-interval 30 --duration 1800
   ```
3. 確認背景監控正常運作（檢查 PID 與程序啟動時間）：
   ```powershell
   python src/diagnostics.py monitor status
   ```
4. **關鍵步驟 — 觀察到斷線或恢復時手動標記：**
   - 一旦畫面出現斷線提示或報價卡住中斷：
     ```powershell
     python src/diagnostics.py mark --event kgi-disconnected --note "校園網路看盤斷線"
     ```
   - 畫面重新連線恢復正常時：
     ```powershell
     python src/diagnostics.py mark --event kgi-reconnected --note "已恢復連線"
     ```
5. 30 分鐘期滿將自動完成結算；若需提前結束，請執行優雅停止（確保所有緩衝資料原子寫入）：
   ```powershell
   python src/diagnostics.py monitor stop
   ```

### 階段 B：個人手機熱點 30 分鐘對照監控

1. 先正常關閉「新超級大三元」。
2. 中斷學校有線/無線網路，將同一台電腦改連至**個人手機熱點**。
3. 重新手動開啟並登入「新超級大三元」，停留於相同看盤畫面。
4. 以**完全相同**的取樣間隔參數執行 30 分鐘監控：
   ```powershell
   python src/diagnostics.py monitor start --label hotspot --passive-interval 5 --active-interval 30 --duration 1800
   ```
   （如熱點期間亦發生斷線，請同樣執行 `python src/diagnostics.py mark --event kgi-disconnected`。）
5. 結束後執行對照與報告更新：
   ```powershell
   python src/diagnostics.py compare
   python src/diagnostics.py report
   ```

---

## 三、Windows 10 / 11 本機整合測試流程（開發與驗收用）

在不影響真實交易與不修改系統設定的前提下，可依序執行以下指令驗證整套系統：

```powershell
# 1. 檢查 Git 提交白名單與敏感資訊掃描器（應為 0 violations）
python -m src.privacy

# 2. 執行 17 項自動化單元測試與 PowerShell 監控生命週期測試（重複啟動阻擋、優雅停止、異常結束偵測）
python -m unittest discover -s tests -v

# 3. 執行離線模擬斷線驗收測試（驗證未啟動探測失敗不誤判 + 手動標記時間關聯）
python src/diagnostics.py simulate

# 4. 執行實機唯讀環境與凱基安裝檢查（產物寫入 reports/internal/<run_id>/ 與 reports/sanitized/<run_id>/）
python src/diagnostics.py all
```

---

## 四、向學校網路管理單位洽詢之客觀技術說明範本

若經完整 A/B 實驗確認「個人手機熱點於相近交易時段未發生斷線，而校園網路重複發生已確認交易斷線，且斷線當下本機介面與公開對照網站皆正常」，可攜帶 `reports/sanitized/<run_id>/diagnostic_report.md`（對外去識別化遮罩版）向學校計中洽詢：

> **主旨：** 合法簽章證券桌面軟體（凱基證券新超級大三元）長連線中斷問題協助查詢
>
> **說明：**
> 您好，我在校內使用具合法數位簽章之凱基證券「新超級大三元」桌面程式（`SUPERTSC64.exe` / `axis.exe`）時發生連線中斷。經同一台電腦於相近時段切換個人手機熱點進行 30 分鐘同條件對照測試，觀測期間熱點未發生斷線，而校內網路發生斷線且當下一般公開網頁連線正常。
>
> 本機唯讀診斷顯示該軟體設定連線至 `gtstrade.kgieworld.com.tw`、`gtsquot.kgieworld.com.tw`、`gtsftrade.kgieworld.com.tw`、`gtsfquot.kgieworld.com.tw` 之 TCP `443` 與 `80` 埠（初次 TCP 三方交握可連通，但標準 TLS 交握未完成，實際應用層協定屬廠商規格）。想請教校內出口防火牆或 NAT 設備針對上述網域之非標準 HTTPS 長連線，是否有相關連線逾時或協定檢查紀錄可供協助確認？附上已遮罩個人資訊之時間線紀錄供參，謝謝。
