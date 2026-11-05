# Windows 本機網路環境自動辨識報告 (`network_environment.md`)

- **蒐集時間：** `2026-11-05T22:17:22.7067060+08:00`
- **執行模式：** 唯讀、非侵入式本機檢查（未修改任何系統設定，未掃描校園網段）
- **管理員權限狀態：** `否 (一般使用者權限)`

## 1. Windows 系統與電源資訊

| 項目 | 內容 |
| --- | --- |
| 作業系統版本 | Microsoft Windows 10 專業版 (22H2) |
| 建置組建 (Build.UBR) | `10.0.19045` (Build `19045.6466`) |
| 系統架構 | 64 位元 |
| 主機名稱（已遮罩） | `DES***AE` |
| 使用者帳號（已遮罩） | `w***l` |
| 上次開機時間 | `2026-10-29T01:48:43.5033200+08:00` |
| 目前電源計畫 | 電源配置 GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (高效能) |

## 2. 主要連線介面、IP、遮罩與預設閘道

- **目前主要連線媒介：** **Ethernet**（介面：`乙太網路`）
- **被動環境特徵推論：** `Campus_TANet_Or_Enterprise_Network`

| 介面名稱 | 媒介類型 | 網路分類 | 本機 IPv4（遮罩） | 子網路遮罩 | 預設閘道（遮罩） | IPv6 數量 |
| --- | --- | --- | --- | --- | --- | --- |
| vEthernet (WSL) | Ethernet | Unknown | `172.30.xxx.xxx` (Private_RFC1918_ClassB) | `255.255.240.0` (/20) | 無 | 0 |
| 乙太網路 | Ethernet | Public | `163.13.xxx.xxx` (TANet_Taiwan_Academic_IPv4) | `255.255.255.0` (/24) | `163.13.xxx.xxx` | 0 |

## 3. DNS 伺服器設定

| 介面 | DNS 位址（遮罩保護內網位址） | 位址類型 | 知名公開 DNS |
| --- | --- | --- | --- |
| vEthernet (WSL) | `fec0:0:xxxx:xxxx::xxxx` | `Public_IPv4` | 否 |
| vEthernet (WSL) | `fec0:0:xxxx:xxxx::xxxx` | `Public_IPv4` | 否 |
| vEthernet (WSL) | `fec0:0:xxxx:xxxx::xxxx` | `Public_IPv4` | 否 |
| 乙太網路 | `163.13.xxx.xxx` | `TANet_Taiwan_Academic_IPv4` | 否 |
| 乙太網路 | `8.8.4.4` | `Public_WellKnown_DNS` | 是 |

## 4. 網路介面卡硬體、驅動與省電設定

| 名稱 | 介面卡型號 | 狀態 | 連線速率 | 驅動版本 | 允許省電關閉網卡 |
| --- | --- | --- | --- | --- | --- |
| vEthernet (WSL) | Hyper-V Virtual Ethernet Adapter | `Up` | `10 Gbps` | `10.0.19041.1` | `不適用/未提供` |
| 乙太網路 | Intel(R) Ethernet Connection (7) I219-V | `Up` | `1 Gbps` | `12.18.9.11` | `不適用/未提供` |

## 5. Windows 防火牆狀態與相關規則（唯讀）

| 設定檔 (Profile) | 啟用狀態 | 預設對內動作 | 預設對外動作 |
| --- | --- | --- | --- |
| Domain | `啟用` | `NotConfigured` | `NotConfigured` |
| Private | `啟用` | `NotConfigured` | `NotConfigured` |
| Public | `啟用` | `NotConfigured` | `NotConfigured` |

- **啟用中之對外封鎖（Outbound Block）規則總數：** `3`
- **與凱基 / 新超級大三元相關之防火牆規則數：** `0`

## 6. 系統 Proxy、WinHTTP Proxy 與 PAC 設定

- **WinINET 系統 Proxy 啟用：** `False`
- **WinINET Proxy 伺服器：** `無`
- **PAC 自動組態網址 (AutoConfigURL)：** `無`
- **WPAD 自動偵測設定：** `False`
- **WinHTTP 狀態：** `Current WinHTTP proxy settings:      Direct access (no proxy server).`
- **環境變數 Proxy (HTTP_PROXY/HTTPS_PROXY)：** `{}`

## 7. 路由表與凱基目標路由檢查

| 測試目標 | 解析目標 IP | 出站介面 | 下一跳閘道（遮罩） |
| --- | --- | --- | --- |
| Public_DNS_8.8.8.8 (`8.8.8.8`) | `8.8.8.8` | `乙太網路` | `163.13.xxx.xxx` |
| KGI_Quote_gtsquot.kgieworld.com.tw (`gtsquot.kgieworld.com.tw`) | `210.61.188.54` | `乙太網路` | `163.13.xxx.xxx` |
| KGI_Trade_gtstrade.kgieworld.com.tw (`gtstrade.kgieworld.com.tw`) | `210.61.188.55` | `乙太網路` | `163.13.xxx.xxx` |

## 8. Wi-Fi 訊號與近期系統網路事件（過去 24 小時）

- 目前未使用 Wi-Fi 連線（有線網路或無線介面未連線）。
- **過去 24 小時 WLAN 事件數：** `0`
- **過去 24 小時 NetworkProfile 連斷線事件數：** `0`
- **過去 24 小時 DNS Client 1014 逾時事件數：** `0`
- **過去 24 小時 系統睡眠/待命事件數：** `0`

## 9. VPN、校園認證與端點資安軟體

- **已設定 VPN 設定檔數：** `0`
- **虛擬/VPN 網卡介面數：** `0`
- **執行中之 VPN / 代理程序：** `無`
- **有線 802.1X 驗證服務 (`dot3svc`) 執行中：** `False`
- **已註冊之防毒/防火牆產品：** Windows Defender (AntiVirus)
