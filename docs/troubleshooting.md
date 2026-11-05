# 凱基證券「新超級大三元」校園網路斷線排查與實測操作手冊 (`docs/troubleshooting.md`)

## 一、快速排查檢核清單（免更動學校防火牆）

1. **確認沒有「同帳號跨裝置重複登入」：**
   - 若您電腦開啟「新超級大三元」的同時，手機上的「凱基隨身 e 策略」App 在背景刷新或收到推播自動重連，證券主機可能因同一身分證字號重複建立交易/行情 Session 而將電腦端連線踢除。
   - **對策：** 進行測試與看盤時，先將手機看盤 App 登出或強制關閉背景執行。

2. **檢查 Intel I219-V 乙太網卡省電與 EEE（Energy Efficient Ethernet）設定：**
   - 本機實測網卡為 `Intel(R) Ethernet Connection (7) I219-V`。Intel I219 系列在部分校園交換器（Switch）上若啟用「節能乙太網路 (EEE)」或「允許電腦關閉這個裝置以節省電源」，偶爾會發生微秒級鏈路重協商導致長連線中斷。
   - **本機檢查方式（手動選用）：** 開啟「裝置管理員」->「網路介面卡」-> 雙擊 `Intel(R) Ethernet Connection (7) I219-V` ->「電源管理」取消勾選省電關閉；若仍有瞬斷，可於「進階」檢視 `Energy Efficient Ethernet` 狀態。

3. **執行「學校網路 vs 手機熱點」標準 A/B 對照實驗：**
   - 嚴格遵守安全規範：**請您本人手動登入一次看盤畫面即可，切勿撰寫腳本自動登入、切勿頻繁重複登入、測試期間無須下單。**

---

## 二、學校網路（測試 A）與個人手機熱點（測試 B）標準操作流程

### 步驟 1：測試 A（學校網路監控 30 分鐘）

1. 確認電腦連接於**學校網路**，手動開啟「新超級大三元」進入看盤畫面。
2. 在專案目錄開啟 PowerShell 或命令提示字元，啟動背景監控（每 30 秒低負載取樣一次，持續 1800 秒 = 30 分鐘）：
   ```powershell
   python src/diagnostics.py monitor start --label campus --interval 30 --duration 1800
   ```
3. 期間可隨時查詢監控進度：
   ```powershell
   python src/diagnostics.py monitor status
   ```
4. 若已捕捉到斷線事件並想提前結束監控，可手動安全停止：
   ```powershell
   python src/diagnostics.py monitor stop
   ```
   結果將自動儲存至 `reports/monitor_campus_latest.json` 及對應 `.csv` / `.jsonl`。

### 步驟 2：測試 B（個人手機熱點監控 30 分鐘）

1. 先正常關閉「新超級大三元」。
2. 拔除學校網路線（或中斷校園 Wi-Fi），將同一台電腦連接至您的**個人手機熱點**（Wi-Fi 或 USB 網路共用）。
3. 再次手動開啟「新超級大三元」停留在相同看盤畫面。
4. 啟動手機熱點背景監控：
   ```powershell
   python src/diagnostics.py monitor start --label hotspot --interval 30 --duration 1800
   ```
5. 完成後（或手動執行 `python src/diagnostics.py monitor stop`），結果將儲存至 `reports/monitor_hotspot_latest.json`。

### 步驟 3：一鍵匯入並產生 A/B 比較分析報告

```powershell
python src/diagnostics.py compare
```

系統將自動比對 8 項指標並更新：
- `reports/diagnostic_report.md`（完整研究報告）
- `reports/diagnostic_report.html`（離線視覺化報表，可直接用瀏覽器開啟）
- `reports/ab_comparison.csv`（Excel 可直接開啟之對照表）

---

## 三、提供給學校計中 / 網路管理員之正式申請範本

若經步驟 1～3 證實「手機熱點完全穩定（0 斷線），僅學校網路頻繁斷線」，可攜帶 `reports/diagnostic_report.md` 中的證據向學校計算機與網路中心提出協助請求（**切勿嘗試自行繞過防火牆**）：

> **主旨：** 學術研究/個人合法金融軟體（凱基證券新超級大三元）長連線頻繁中斷排查協助申請
>
> **說明：**
> 您好，我在校內使用合法簽章之凱基證券「新超級大三元」桌面端軟體（`SUPERTSC64.exe` / `axis.exe`）時，經常發生連線中斷與重新連線；經同一台電腦切換個人手機熱點進行 A/B 對照測試後連線穩定。
>
> 經本機端點非侵入式診斷確認：初次 DNS 解析與 TCP 80/443 三方交握均可連通，但該軟體於 TCP `443` 與 `80` 埠上採用證券專屬加密長連線協定（非標準 HTTP / 非標準 TLS ClientHello）。若校方次世代防火牆（NGFW）對 Port 80/443 啟用嚴格 HTTP/TLS 協定合規檢查（App-ID / Protocol Enforcement / SSL Inspection）或對 `unknown-tcp` 設定較短的 Session Idle Timeout，可能導致連線於建立後被定期重置。
>
> 懇請協助確認下列凱基官方伺服器端點是否觸發防火牆協定過濾或短連線逾時政策：
> - `gtstrade.kgieworld.com.tw` (`210.61.188.55`) — TCP `443`, `80`
> - `gtsquot.kgieworld.com.tw` (`210.61.188.54`) — TCP `443`, `80`
> - `gtsftrade.kgieworld.com.tw` (`210.61.188.57`) — TCP `443`, `80`
> - `gtsfquot.kgieworld.com.tw` (`210.61.188.56`) — TCP `443`, `80`
> - 斷線發生時間與本機診斷紀錄詳如附件報表（已遮罩個人敏感資訊）。

