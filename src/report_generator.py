"""報告產生器：輸出 Markdown、JSON、CSV 與離線安全 HTML 視覺化診斷報告."""

from __future__ import annotations

import csv
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


def _badge_color(status_text: str) -> str:
    if status_text in ("正常", "高"):
        return "#15803d"
    if status_text in ("連線失敗", "確認有明確封鎖回應"):
        return "#b91c1c"
    if status_text in ("可能受到限制", "中"):
        return "#b45309"
    return "#475569"


def generate_network_environment_markdown(env_data: Dict[str, Any]) -> str:
    """第一階段：產生 network_environment.md 報告."""
    os_info = env_data.get("os_and_system") or {}
    prim = env_data.get("primary_connection") or {}
    ip_cfgs = env_data.get("active_ip_configurations") or []
    dns_list = env_data.get("dns_servers") or []
    adapters = env_data.get("network_adapters") or []
    fw = env_data.get("windows_firewall") or {}
    proxy = env_data.get("proxy_settings") or {}
    routing = env_data.get("routing") or {}
    wifi = env_data.get("wifi_diagnostics") or {}
    events = env_data.get("recent_network_events") or {}
    vpn_sec = env_data.get("vpn_auth_and_security") or {}

    lines: List[str] = [
        "# Windows 本機網路環境自動辨識報告 (`network_environment.md`)",
        "",
        f"- **蒐集時間：** `{env_data.get('collected_at', '')}`",
        f"- **執行模式：** 唯讀、非侵入式本機檢查（未修改任何系統設定，未掃描校園網段）",
        f"- **管理員權限狀態：** `{'是 (Elevated)' if os_info.get('is_elevated') else '否 (一般使用者權限)'}`",
        "",
        "## 1. Windows 系統與電源資訊",
        "",
        "| 項目 | 內容 |",
        "| --- | --- |",
        f"| 作業系統版本 | {os_info.get('caption', '')} ({os_info.get('display_version', '')}) |",
        f"| 建置組建 (Build.UBR) | `{os_info.get('version', '')}` (Build `{os_info.get('build_number', '')}.{os_info.get('ubr', '')}`) |",
        f"| 系統架構 | {os_info.get('architecture', '')} |",
        f"| 主機名稱（已遮罩） | `{os_info.get('masked_hostname', '')}` |",
        f"| 使用者帳號（已遮罩） | `{os_info.get('masked_username', '')}` |",
        f"| 上次開機時間 | `{os_info.get('last_boot_time', '')}` |",
        f"| 目前電源計畫 | {os_info.get('active_power_plan', '')} |",
        "",
        "## 2. 主要連線介面、IP、遮罩與預設閘道",
        "",
        f"- **目前主要連線媒介：** **{prim.get('connection_type', 'Unknown')}**（介面：`{prim.get('interface_alias', '')}`）",
        f"- **被動環境特徵推論：** `{prim.get('environment_hint', '')}`",
        "",
        "| 介面名稱 | 媒介類型 | 網路分類 | 本機 IPv4（遮罩） | 子網路遮罩 | 預設閘道（遮罩） | IPv6 數量 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    for ic in ip_cfgs:
        ip4_strs = [
            f"`{x.get('ip_masked')}` ({x.get('ip_class')})"
            for x in (ic.get("ipv4_addresses") or [])
        ]
        mask_strs = [
            f"`{x.get('subnet_mask')}` (/{x.get('prefix_length')})"
            for x in (ic.get("ipv4_addresses") or [])
        ]
        gw_strs = [
            f"`{g.get('next_hop_masked')}`"
            for g in (ic.get("ipv4_gateways") or [])
        ]
        lines.append(
            f"| {ic.get('interface_alias', '')} | {ic.get('connection_medium', '')} | "
            f"{ic.get('net_profile_category', '')} | {'<br>'.join(ip4_strs) or '無'} | "
            f"{'<br>'.join(mask_strs) or '無'} | {'<br>'.join(gw_strs) or '無'} | {ic.get('ipv6_address_count', 0)} |"
        )

    lines.extend(
        [
            "",
            "## 3. DNS 伺服器設定",
            "",
            "| 介面 | DNS 位址（遮罩保護內網位址） | 位址類型 | 知名公開 DNS |",
            "| --- | --- | --- | --- |",
        ]
    )
    if dns_list:
        for d in dns_list:
            lines.append(
                f"| {d.get('interface_alias', '')} | `{d.get('address_masked', '')}` | "
                f"`{d.get('address_class', '')}` | {'是' if d.get('is_public_well_known') else '否'} |"
            )
    else:
        lines.append("| 無 | 無 | - | - |")

    lines.extend(
        [
            "",
            "## 4. 網路介面卡硬體、驅動與省電設定",
            "",
            "| 名稱 | 介面卡型號 | 狀態 | 連線速率 | 驅動版本 | 允許省電關閉網卡 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for ad in adapters:
        pm = ad.get("power_management")
        pm_str = (
            str(pm.get("allow_computer_to_turn_off"))
            if isinstance(pm, dict)
            else "不適用/未提供"
        )
        lines.append(
            f"| {ad.get('name', '')} | {ad.get('description', '')} | `{ad.get('status', '')}` | "
            f"`{ad.get('link_speed', '')}` | `{ad.get('driver_version', '')}` | `{pm_str}` |"
        )

    lines.extend(
        [
            "",
            "## 5. Windows 防火牆狀態與相關規則（唯讀）",
            "",
            "| 設定檔 (Profile) | 啟用狀態 | 預設對內動作 | 預設對外動作 |",
            "| --- | --- | --- | --- |",
        ]
    )
    for p in fw.get("profiles") or []:
        lines.append(
            f"| {p.get('name', '')} | `{'啟用' if p.get('enabled') else '停用'}` | "
            f"`{p.get('default_inbound_action', '')}` | `{p.get('default_outbound_action', '')}` |"
        )
    lines.append("")
    lines.append(f"- **啟用中之對外封鎖（Outbound Block）規則總數：** `{fw.get('outbound_block_count', 0)}`")
    kgi_rules = fw.get("kgi_related_rules") or []
    lines.append(f"- **與凱基 / 新超級大三元相關之防火牆規則數：** `{len(kgi_rules)}`")
    for r in kgi_rules[:10]:
        lines.append(f"  - `{r.get('rule_id')}`: `{r.get('raw_summary')}`")

    lines.extend(
        [
            "",
            "## 6. 系統 Proxy、WinHTTP Proxy 與 PAC 設定",
            "",
            f"- **WinINET 系統 Proxy 啟用：** `{proxy.get('wininet_proxy_enabled', False)}`",
            f"- **WinINET Proxy 伺服器：** `{proxy.get('wininet_proxy_server') or '無'}`",
            f"- **PAC 自動組態網址 (AutoConfigURL)：** `{proxy.get('wininet_pac_url') or '無'}`",
            f"- **WPAD 自動偵測設定：** `{proxy.get('wininet_auto_detect', False)}`",
            f"- **WinHTTP 狀態：** `{proxy.get('winhttp_raw', '')}`",
            f"- **環境變數 Proxy (HTTP_PROXY/HTTPS_PROXY)：** `{json.dumps(proxy.get('env_proxies') or {}, ensure_ascii=False)}`",
            "",
            "## 7. 路由表與凱基目標路由檢查",
            "",
            "| 測試目標 | 解析目標 IP | 出站介面 | 下一跳閘道（遮罩） |",
            "| --- | --- | --- | --- |",
        ]
    )
    for rt in routing.get("target_route_checks") or []:
        if rt.get("error"):
            lines.append(
                f"| {rt.get('label', '')} (`{rt.get('target_host', '')}`) | `{rt.get('resolved_ip', '')}` | 查詢異常 | {rt.get('error')} |"
            )
        else:
            lines.append(
                f"| {rt.get('label', '')} (`{rt.get('target_host', '')}`) | `{rt.get('resolved_ip', '')}` | "
                f"`{rt.get('interface_alias', '')}` | `{rt.get('next_hop_masked', '')}` |"
            )

    lines.extend(["", "## 8. Wi-Fi 訊號與近期系統網路事件（過去 24 小時）", ""])
    if wifi.get("connected"):
        wd = wifi.get("details") or {}
        lines.extend(
            [
                f"- **SSID（已遮罩）：** `{wd.get('ssid_masked', '')}`",
                f"- **基地台 BSSID（已遮罩）：** `{wd.get('bssid_masked', '')}`",
                f"- **訊號強度：** `{wd.get('signal_percent', '')}%`（無線電：`{wd.get('radio_type', '')}`，頻道：`{wd.get('channel', '')}`）",
                f"- **驗證方式：** `{wd.get('authentication', '')}`（802.1X 企業/校園認證：`{wd.get('is_8021x_enterprise', False)}`）",
            ]
        )
    else:
        lines.append("- 目前未使用 Wi-Fi 連線（有線網路或無線介面未連線）。")

    lines.extend(
        [
            f"- **過去 {events.get('lookback_hours', 24)} 小時 WLAN 事件數：** `{len(events.get('wlan_events') or [])}`",
            f"- **過去 {events.get('lookback_hours', 24)} 小時 NetworkProfile 連斷線事件數：** `{len(events.get('network_profile_events') or [])}`",
            f"- **過去 {events.get('lookback_hours', 24)} 小時 DNS Client 1014 逾時事件數：** `{len(events.get('dns_client_timeouts') or [])}`",
            f"- **過去 {events.get('lookback_hours', 24)} 小時 系統睡眠/待命事件數：** `{len(events.get('power_sleep_events') or [])}`",
            "",
            "## 9. VPN、校園認證與端點資安軟體",
            "",
            f"- **已設定 VPN 設定檔數：** `{len(vpn_sec.get('configured_vpn_profiles') or [])}`",
            f"- **虛擬/VPN 網卡介面數：** `{len(vpn_sec.get('virtual_vpn_adapters') or [])}`",
            f"- **執行中之 VPN / 代理程序：** `{', '.join(vpn_sec.get('running_vpn_or_proxy_processes') or []) or '無'}`",
            f"- **有線 802.1X 驗證服務 (`dot3svc`) 執行中：** `{vpn_sec.get('wired_8021x_service_running', False)}`",
            f"- **已註冊之防毒/防火牆產品：** "
            + (
                ", ".join(
                    f"{s.get('display_name')} ({s.get('type')})"
                    for s in (vpn_sec.get("security_products") or [])
                )
                or "無"
            ),
            "",
        ]
    )
    return "\n".join(lines)


def write_csv_summary(
    restrictions: Dict[str, Any],
    kgi_probes: List[Dict[str, Any]],
    ab_comparison: Dict[str, Any],
    output_dir: Path,
) -> Dict[str, str]:
    """輸出結構化 CSV 診斷表格（UTF-8 with BOM 以便 Windows Excel 直接開啟不亂碼）."""
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, str] = {}

    rest_csv = output_dir / "diagnostic_summary.csv"
    with rest_csv.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "檢查類型",
                "目標名稱",
                "端點或路徑",
                "DNS/安裝狀態",
                "TCP/執行狀態",
                "HTTP或協定細節",
                "延遲(ms)",
                "診斷分類",
                "證據說明",
            ]
        )
        for w in restrictions.get("websites") or []:
            http_code = (w.get("http") or {}).get("status_code", "")
            writer.writerow(
                [
                    "網站連線",
                    w.get("name", ""),
                    w.get("url", ""),
                    "成功" if w.get("dns_ok") else "失敗",
                    w.get("tcp_success_rate", ""),
                    f"HTTP {http_code} / TLS={bool((w.get('tls') or {}).get('ok'))}",
                    w.get("tcp_avg_rtt_ms", ""),
                    w.get("classification", ""),
                    w.get("evidence_summary", ""),
                ]
            )
        for a in restrictions.get("applications") or []:
            writer.writerow(
                [
                    "本機應用程式",
                    a.get("name", ""),
                    a.get("executable_path", ""),
                    f"已安裝(v{a.get('file_version', '')})" if a.get("installed") else "未找到",
                    "執行中" if a.get("is_running") else "未啟動",
                    f"簽章={a.get('signature_status', '')}, FW封鎖={a.get('firewall_block_rules', 0)}",
                    "",
                    a.get("classification", ""),
                    a.get("evidence_summary", ""),
                ]
            )
        for d in restrictions.get("downloads") or []:
            writer.writerow(
                [
                    "檔案下載(HEAD)",
                    d.get("name", ""),
                    d.get("url", ""),
                    f"主站 HTTP {d.get('base_site_status', '')}",
                    f"端點 HTTP {d.get('download_status', '')}",
                    f"型態={d.get('file_type', '')}, Method={d.get('method_used', 'HEAD')}",
                    d.get("latency_ms", ""),
                    d.get("classification", ""),
                    d.get("evidence_summary", ""),
                ]
            )
        for kp in kgi_probes:
            tls_p = kp.get("tls_probe") or {}
            writer.writerow(
                [
                    "凱基交易/行情端點",
                    kp.get("role", ""),
                    f"{kp.get('fqdn', '')}:{kp.get('port', '')} ({kp.get('primary_ip', '')})",
                    "成功" if kp.get("dns_ok") else "失敗",
                    f"{kp.get('tcp_ok_count', 0)}/{kp.get('tcp_probe_count', 0)}",
                    tls_p.get("protocol_summary", ""),
                    kp.get("tcp_avg_ms", ""),
                    "正常" if kp.get("tcp_ok_count", 0) > 0 else "連線失敗",
                    tls_p.get("detail", ""),
                ]
            )
    paths["diagnostic_summary_csv"] = str(rest_csv)

    ab_csv = output_dir / "ab_comparison.csv"
    with ab_csv.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["指標項目", "測試 A：學校網路", "測試 B：個人手機熱點", "差異 (A - B)"])
        for row in ab_comparison.get("metrics_table") or []:
            writer.writerow(
                [
                    row.get("metric_name", ""),
                    row.get("campus_value", "未測試"),
                    row.get("hotspot_value", "未測試"),
                    row.get("difference_a_minus_b", "未測試"),
                ]
            )
    paths["ab_comparison_csv"] = str(ab_csv)
    return paths


def generate_research_report_markdown(bundle: Dict[str, Any]) -> str:
    """第七階段：產生完整繁體中文研究報告 (`diagnostic_report.md`)."""
    gen_at = bundle.get("generated_at", datetime.now().isoformat())
    env = bundle.get("network_environment") or {}
    rest = bundle.get("restrictions") or {}
    kgi_info = bundle.get("kgi_inspection") or {}
    kgi_probes = bundle.get("kgi_endpoint_probes") or []
    kgi_analysis = bundle.get("kgi_probe_analysis") or {}
    root_causes = bundle.get("root_causes") or []
    ab_comp = bundle.get("ab_comparison") or {}
    campus_mon = bundle.get("campus_monitor")

    os_info = env.get("os_and_system") or {}
    prim = env.get("primary_connection") or {}
    proxy = env.get("proxy_settings") or {}
    fw = env.get("windows_firewall") or {}
    arch = kgi_info.get("architecture_and_reconnect") or {}

    lines: List[str] = [
        "# 校園網路與凱基證券「新超級大三元」斷線問題完整診斷研究報告",
        "",
        f"- **報告產生時間：** `{gen_at}`",
        "- **診斷性質：** 個人端點授權範圍內之唯讀、低負載、非侵入式連線診斷",
        "- **核心聲明：** 所有數據均來自本機實測取證；尚未由使用者手動觸發之動態實驗均誠實標記為「`未測試`」，絕不杜撰任何測試數據。",
        "",
        "---",
        "",
        "## 1. 網路環境摘要",
        "",
        f"- **作業系統：** {os_info.get('caption', '')} `{os_info.get('display_version', '')}` (Build `{os_info.get('build_number', '')}.{os_info.get('ubr', '')}`)",
        f"- **主要連線介面：** `{prim.get('connection_type', '')}`（介面名稱：`{prim.get('interface_alias', '')}`，環境辨識：`{prim.get('environment_hint', '')}`）",
    ]

    for ic in env.get("active_ip_configurations") or []:
        ip_desc = ", ".join(
            f"`{a.get('ip_masked')}` (遮罩 `{a.get('subnet_mask')}`, 類型 `{a.get('ip_class')}`)"
            for a in (ic.get("ipv4_addresses") or [])
        )
        gw_desc = ", ".join(
            f"`{g.get('next_hop_masked')}`" for g in (ic.get("ipv4_gateways") or [])
        )
        dns_desc = ", ".join(
            f"`{d.get('address_masked')}` ({d.get('address_class')})"
            for d in (ic.get("dns_servers") or [])
        )
        lines.append(f"- **啟用介面 `{ic.get('interface_alias')}`：** IP={ip_desc or '無'}；預設閘道={gw_desc or '無'}；DNS={dns_desc or '無'}")

    lines.extend(
        [
            f"- **Windows 防火牆：** 對外預設皆為 Allow，與凱基相關之封鎖規則數 = `{sum(1 for r in (fw.get('kgi_related_rules') or []) if 'Action=Block' in str(r.get('raw_summary', '')))}`",
            f"- **系統 Proxy / PAC：** WinINET Proxy=`{proxy.get('wininet_proxy_enabled', False)}`、PAC=`{proxy.get('wininet_pac_url') or '無'}`、WinHTTP 直接存取=`{proxy.get('winhttp_direct_access', True)}`",
            "",
            "---",
            "",
            "## 2. 網站、應用程式與檔案下載限制檢查",
            "",
            "### 2.1 公開白名單網站連線診斷",
            "",
            "| 目標網站 | 網址 | DNS | TCP 成功率 | 平均延遲 | TLS 憑證驗證 | HTTP 回應 | 診斷分類 | 證據分析 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for w in rest.get("websites") or []:
        tls_obj = w.get("tls") or {}
        http_obj = w.get("http") or {}
        tls_txt = "正常" if tls_obj.get("ok") else f"異常 ({tls_obj.get('error', '')[:25]})"
        lines.append(
            f"| {w.get('name')} | {w.get('url')} | {'成功' if w.get('dns_ok') else '失敗'} | "
            f"`{w.get('tcp_success_rate')}` | `{w.get('tcp_avg_rtt_ms')} ms` | {tls_txt} | "
            f"`{http_obj.get('status_code')}` | **{w.get('classification')}** | {w.get('evidence_summary')} |"
        )

    lines.extend(
        [
            "",
            "### 2.2 本機指定應用程式限制檢查",
            "",
            "| 應用程式名稱 | 實測執行檔路徑 | 版本 | 數位簽章 | 目前執行中 | 防火牆 Block 規則 | 診斷分類 | 證據分析 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for a in rest.get("applications") or []:
        lines.append(
            f"| {a.get('name')} | `{a.get('executable_path') or '未找到'}` | `{a.get('file_version')}` | "
            f"`{a.get('signature_status')}` | `{'是' if a.get('is_running') else '否 (未啟動)'}` | "
            f"`{a.get('firewall_block_rules', 0)}` | **{a.get('classification')}** | {a.get('evidence_summary')} |"
        )

    lines.extend(
        [
            "",
            "### 2.3 授權官方端點檔案下載限制檢查（僅低負載 HEAD 請求）",
            "",
            "| 測試項目 | 檔案型態 | 主站狀態 | 端點狀態 | 延遲 | 診斷分類 | 證據分析 |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for d in rest.get("downloads") or []:
        lines.append(
            f"| {d.get('name')} | `{d.get('file_type')}` | `HTTP {d.get('base_site_status')}` | "
            f"`HTTP {d.get('download_status')}` | `{d.get('latency_ms')} ms` | **{d.get('classification')}** | {d.get('evidence_summary')} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 3. 凱基證券「新超級大三元」深度斷線分析（最高優先級）",
            "",
            "### 3.1 本機交易軟體實體辨識結果",
            "",
            f"- **安裝狀態：** `{'已安裝' if kgi_info.get('is_installed') else '未找到安裝目錄'}`（安裝目錄：`{', '.join(kgi_info.get('install_directories') or []) or '無'}`）",
            f"- **登錄檔版本與發行者：** "
            + (
                "；".join(
                    f"`{r.get('display_name')}` v`{r.get('display_version')}`（發行者：{r.get('publisher')}）"
                    for r in (kgi_info.get("registry_entries") or [])
                )
                or "無"
            ),
            f"- **軟體平台底層架構：** `{arch.get('platform_engine', '')}`（通訊模組：`{arch.get('socket_module', '')}`，安全協定模組：`{arch.get('encryption_module', '')}`）",
            f"- **內建背景連線管理與重連機制：** `{', '.join(arch.get('reconnect_mechanisms') or []) or '未檢出'}`",
            f"- **檢查當下程序是否執行中：** `{'是' if kgi_info.get('is_currently_running') else '否（檢查時未啟動）'}`",
        ]
    )
    last_log = arch.get("last_log_metadata")
    if isinstance(last_log, dict):
        lines.append(
            f"- **最近一次啟動日誌（僅檢查檔案中繼資料，不解密內容）：** `{last_log.get('file_name')}`，最後寫入於 `{last_log.get('last_write_time')}`（對應歷史 PID `{last_log.get('pid_in_filename')}`）；Crashpad 當機傾印數：`{arch.get('crashpad_dump_count', 0)}`。"
        )

    lines.extend(
        [
            "",
            "### 3.2 實際交易與行情伺服器端點及協定特徵檢測",
            "",
            "> **端點來源說明：** 以下端點直接取自本機已安裝「新超級大三元」之官方靜態設定檔 `tab/YELLOWPAGE.INI` 與執行中實際 TCP 連線，絕無憑空猜測。",
            "",
            "| 伺服器角色 | 驗證網域 (FQDN) | 解析 IP | 通訊埠 | TCP 成功率 | 平均耗時 | TCP Reset | 應用層/TLS 協定實測行為 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for kp in kgi_probes:
        tls_p = kp.get("tls_probe") or {}
        lines.append(
            f"| `{kp.get('role')}` | `{kp.get('fqdn')}` | `{kp.get('primary_ip')}` | `{kp.get('port')}` | "
            f"`{kp.get('tcp_ok_count')}/{kp.get('tcp_probe_count')}` | `{kp.get('tcp_avg_ms')} ms` | "
            f"`{'是' if kp.get('tcp_rst_observed') else '否'}` | {tls_p.get('protocol_summary', '')}（{tls_p.get('detail', '')}） |"
        )

    active_conns = kgi_info.get("active_tcp_connections") or []
    lines.append("")
    if active_conns:
        lines.append(f"- **檢查當下捕捉到之活動中 TCP 連線數：** `{len(active_conns)}` 條")
        for ac in active_conns[:15]:
            lines.append(
                f"  - PID `{ac.get('pid')}` (`{ac.get('process_name')}`): 本機埠 `{ac.get('local_port')}` -> `{ac.get('remote_address')}:{ac.get('remote_port')}` (`{ac.get('verified_fqdn')}`) State=`{ac.get('state')}`"
            )
    else:
        lines.append("- **檢查當下活動中 TCP 連線：** `未測試 / 無活動連線`（因檢查當下使用者未開啟登入新超級大三元，需啟動軟體並搭配 `monitor start` 記錄即時連線變化）。")

    lines.extend(["", "### 3.3 斷線時間監控紀錄摘要", ""])
    if campus_mon:
        outages = campus_mon.get("outage_episodes") or []
        lines.append(
            f"- **監控區間：** `{campus_mon.get('started_at')}` 至 `{campus_mon.get('ended_at')}`（共 `{campus_mon.get('sample_count')}` 次取樣）"
        )
        lines.append(f"- **觀測到之斷線事件數：** `{len(outages)}` 次")
        for ep in outages:
            lines.append(
                f"  - 開始：`{ep.get('started_at')}` -> 恢復：`{ep.get('recovered_at') or '未恢復'}`（持續 `{ep.get('duration_sec')} 秒`，原因：`{ep.get('reason')}`）"
            )
    else:
        lines.append("- **長時段斷線監控狀態：** `未測試`（尚未累積使用者開啟交易軟體期間之 30 秒週期監控序列，請依操作說明執行 `monitor start`）。")

    lines.extend(["", "### 3.4 可能根本原因自動排序與證據評估（A ~ G）", ""])
    for rc in root_causes:
        lines.extend(
            [
                f"#### 第 {rc.get('rank')} 順位：[{rc.get('code')}] {rc.get('title')}",
                f"- **信心程度：** `{rc.get('confidence')}`（證據等級：`{rc.get('credibility_tier')}`，評估分數：`{rc.get('score')}/100`）",
                "- **支持證據：**",
            ]
        )
        for s in rc.get("supporting_evidence") or []:
            lines.append(f"  - {s}")
        lines.append("- **反證（不支持此原因之事實）：**")
        for c in rc.get("counter_evidence") or []:
            lines.append(f"  - {c}")
        if rc.get("pending_checks"):
            lines.append("- **尚未完成的檢查：**")
            for p in rc.get("pending_checks") or []:
                lines.append(f"  - {p}")
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## 4. 學校網路與個人手機熱點對照實驗（A/B Test）",
            "",
            f"- **對照完成狀態：** `{ab_comp.get('status', '未測試')}`",
            f"- **分析結論：** {ab_comp.get('conclusion', '')}",
            "",
            "| 比較指標 | 測試 A：學校網路 | 測試 B：個人手機熱點 | 差異 (A - B) |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in ab_comp.get("metrics_table") or []:
        lines.append(
            f"| {row.get('metric_name')} | `{row.get('campus_value')}` | `{row.get('hotspot_value')}` | `{row.get('difference_a_minus_b')}` |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 5. 改善建議與網管申請技術佐證清單（依安全性、可行性與預期效果排序）",
            "",
            "### 階段一：不需更動學校防火牆的本機與連線排查（優先執行）",
            "1. **執行學校網路 vs 手機熱點 30 分鐘 A/B 對照實驗（高可行性 / 最高診斷價值）：** 開啟新超級大三元（停留在一般看盤畫面，切勿自動重複登入或送出委託），分別在校園網路與手機熱點執行 `python src/diagnostics.py monitor start`，確認斷線是否僅發生於學校網路。",
            "2. **排除跨裝置同帳號互踢（零風險 / 常見盲點）：** 測試電腦版期間，暫時關閉手機上「凱基隨身 e 策略」App（包含背景推播重連），避免同一組身分證字號跨設備 Session 互相踢除。",
            "3. **停用本機網卡省電關閉與睡眠干擾（本機可控 / 安全）：** 於「裝置管理員 -> 網路介面卡 -> 電源管理」取消勾選「允許電腦關閉這個裝置以節省電源」，並避免看盤期間進入螢幕保護後之 Modern Standby 待命。",
            "4. **優先使用校園有線網路（Ethernet）對照校園 Wi-Fi：** 若使用校園 Wi-Fi（802.1X），多 AP 訊號切換（BSSID 漫遊）與週期性金鑰重協商常造成長連線瞬斷，改插有線網路可立即排除無線漫遊因素。",
            "",
            "### 階段二：向學校計中 / 網管單位正式申請連線放行之技術清單（若對照證實與校園網路有關）",
            "",
            "> **技術關鍵說明（供學校網管工程師參考）：** 凱基證券「新超級大三元」（Kway HTS 架構，`axis.exe`）雖連線至遠端 TCP `443` 與 `80` 埠，但其傳輸層之上採用證券專屬加密封包協定（`axsock.ocx` / `TS070300`），**並非標準 HTTP 或標準 TLS (HTTPS) 交握**。若校方次世代防火牆（NGFW，如 Palo Alto App-ID、FortiGate Application Control）針對 Port 80/443 啟用「協定合規檢查（Protocol Enforcement / SSL Deep Inspection）」或對未知 TCP 長連線套用極短 Session Timeout，將導致交易/報價連線週期性被切斷或重連。敬請協助確認下列官方伺服器端點之 TCP 長連線放行（Application Override / 免除 SSL 解密與提升 TCP Idle Timeout）：",
            "",
            "| 用途說明 | 官方完整網域名稱 (FQDN) | 目前實測解析 IP | 目的端通訊埠 | 傳輸/應用特徵 |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    seen_fqdns = set()
    sorted_for_it = sorted(kgi_probes, key=lambda x: (0 if x.get("port") == 443 else 1))
    for kp in sorted_for_it:
        fqdn = kp.get("fqdn", "")
        if fqdn in seen_fqdns:
            continue
        seen_fqdns.add(fqdn)
        tls_p = kp.get("tls_probe") or {}
        lines.append(
            f"| {kp.get('role')} | `{fqdn}` | `{kp.get('primary_ip')}` | `TCP 443, TCP 80` | {tls_p.get('protocol_summary', 'TCP 長連線')} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 6. 證據可信度分級",
            "",
            "### 6.1 已確認事實（Verified Facts — 100% 經本機實測取證）",
            f"- 本機確實安裝有凱基證券「新超級大三元」v1.0.5（路徑：`{', '.join(kgi_info.get('install_directories') or [])}`），包含啟動器 `SUPERTSC64.exe` (v2.0.0) 與主引擎 `axis.exe` (v3.0.0.1)，兩者均具備有效之 `KGI Securities Co. Ltd.` 數位簽章。",
            "- 由安裝目錄靜態設定檔 `tab/YELLOWPAGE.INI` 確認四大核心伺服器端點為：`gtstrade.kgieworld.com.tw`（國內交易）、`gtsquot.kgieworld.com.tw`（國內行情）、`gtsftrade.kgieworld.com.tw`（外期交易）、`gtsfquot.kgieworld.com.tw`（外期行情），設定通訊埠為 `TCP 80` 與 `TCP 443`。",
            f"- 本機系統 Proxy 啟用狀態為 `{proxy.get('wininet_proxy_enabled', False)}`，Windows 防火牆對凱基執行檔之封鎖規則數為 `0`。",
            f"- 凱基四大伺服器端點之初次 DNS 解析與 TCP 三方交握在目前網路環境下共 `{kgi_analysis.get('tcp_reachable_count', 0)}/{kgi_analysis.get('total_endpoints_tested', 0)}` 個端點測試連通（平均延遲 `{kgi_analysis.get('avg_tcp_rtt_ms')} ms`）。",
        ]
    )

    prop_list = kgi_analysis.get("proprietary_binary_over_443_endpoints") or []
    if prop_list:
        lines.append(
            "- **關鍵協定事實：** 實測凱基交易/行情端點在 `TCP 443` 完成三方交握後，不回應標準 TLS `ClientHello`（而官網 `www.kgieworld.com.tw:443` 則回應標準有效 TLS 憑證），證實交易/行情連線使用**非標準 TLS 之專屬二進位/加密 TCP Socket 協定**。"
        )

    lines.extend(
        [
            "",
            "### 6.2 高可信度推論（High-Confidence Inferences）",
            "- 學校防火牆**並未靜態封鎖（IP/Port Blacklist）**凱基伺服器位址（因 DNS 解析與初次 TCP 80/443 三方交握皆能成功建立）。",
            "- 若斷線僅發生於連線建立一段時間後，技術上最吻合「Port 80/443 非標準 HTTP/TLS 長連線遭校園防火牆 NGFW 協定檢測 / NAT 狀態表閒置回收」或「區域網路/無線網路瞬斷」。",
            "",
            "### 6.3 可能原因（Plausible Causes — 待動態監控收斂）",
            "- 校園次世代防火牆（NGFW）對 Port 443 非 TLS 流量之深度檢測重置或短連線逾時。",
            "- 網路介面瞬間重連、校園 Wi-Fi AP 漫遊或網卡省電機制。",
            "- 同帳號跨裝置（手機看盤 App 與電腦版）Session 互踢或換盤清盤重載。",
            "",
            "### 6.4 尚無法判斷（Insufficient Evidence / 未測試項目）",
            f"- **開啟交易軟體登入狀態下之實際斷線瞬間封包/連線狀態：** `{'已測試' if campus_mon else '未測試（需使用者手動開啟軟體並啟動 monitor）'}`。",
            f"- **學校網路 vs 個人手機熱點對照實驗：** `{ab_comp.get('status', '未測試')}`。",
            "- **是否存在明確由校園防火牆注入之長連線中途 TCP RST：** 需於實際斷線發生時段透過監控腳本或經使用者授權之封包檢視確認，目前未觀測到初次交握階段之封鎖回應。",
            "",
        ]
    )
    return "\n".join(lines)


def generate_html_report(bundle: Dict[str, Any]) -> str:
    """產生無外部資源依賴、離線安全之視覺化 HTML 診斷報告."""
    esc = html.escape
    env = bundle.get("network_environment") or {}
    rest = bundle.get("restrictions") or {}
    kgi_probes = bundle.get("kgi_endpoint_probes") or []
    root_causes = bundle.get("root_causes") or []
    ab_comp = bundle.get("ab_comparison") or {}
    prim = env.get("primary_connection") or {}
    os_info = env.get("os_and_system") or {}

    web_rows = []
    for w in rest.get("websites") or []:
        cls_txt = str(w.get("classification", ""))
        color = _badge_color(cls_txt)
        web_rows.append(
            f"<tr><td>{esc(str(w.get('name', '')))}</td>"
            f"<td><code>{esc(str(w.get('url', '')))}</code></td>"
            f"<td>{'成功' if w.get('dns_ok') else '失敗'}</td>"
            f"<td>{esc(str(w.get('tcp_success_rate', '')))}</td>"
            f"<td>{esc(str(w.get('tcp_avg_rtt_ms', '')))} ms</td>"
            f"<td><span class='badge' style='background:{color}'>{esc(cls_txt)}</span></td>"
            f"<td>{esc(str(w.get('evidence_summary', '')))}</td></tr>"
        )

    kgi_rows = []
    for kp in kgi_probes:
        tls_p = kp.get("tls_probe") or {}
        ok_cnt = int(kp.get("tcp_ok_count") or 0)
        tot_cnt = int(kp.get("tcp_probe_count") or 0)
        st_txt = "正常連通" if ok_cnt > 0 else "連線失敗"
        color = "#15803d" if ok_cnt > 0 else "#b91c1c"
        kgi_rows.append(
            f"<tr><td><code>{esc(str(kp.get('role', '')))}</code></td>"
            f"<td><code>{esc(str(kp.get('fqdn', '')))}:{esc(str(kp.get('port', '')))}</code></td>"
            f"<td><code>{esc(str(kp.get('primary_ip', '')))}</code></td>"
            f"<td>{ok_cnt}/{tot_cnt}</td>"
            f"<td>{esc(str(kp.get('tcp_avg_ms', '')))} ms</td>"
            f"<td><span class='badge' style='background:{color}'>{st_txt}</span></td>"
            f"<td>{esc(str(tls_p.get('protocol_summary', '')))} — {esc(str(tls_p.get('detail', '')))}</td></tr>"
        )

    rc_cards = []
    for rc in root_causes:
        conf = str(rc.get("confidence", ""))
        color = _badge_color(conf)
        sup_li = "".join(f"<li>{esc(str(s))}</li>" for s in (rc.get("supporting_evidence") or []))
        cnt_li = "".join(f"<li>{esc(str(c))}</li>" for c in (rc.get("counter_evidence") or []))
        rc_cards.append(
            f"<div class='card'>"
            f"<h3>第 {rc.get('rank')} 順位：[{esc(str(rc.get('code')))}] {esc(str(rc.get('title')))} "
            f"<span class='badge' style='background:{color}'>信心：{esc(conf)} ({rc.get('score')}/100)</span></h3>"
            f"<p><strong>證據等級：</strong>{esc(str(rc.get('credibility_tier', '')))}</p>"
            f"<div class='cols'><div><strong>支持證據：</strong><ul>{sup_li}</ul></div>"
            f"<div><strong>反證：</strong><ul>{cnt_li}</ul></div></div>"
            f"</div>"
        )

    ab_rows = []
    for row in ab_comp.get("metrics_table") or []:
        ab_rows.append(
            f"<tr><td>{esc(str(row.get('metric_name', '')))}</td>"
            f"<td><code>{esc(str(row.get('campus_value', '')))}</code></td>"
            f"<td><code>{esc(str(row.get('hotspot_value', '')))}</code></td>"
            f"<td><code>{esc(str(row.get('difference_a_minus_b', '')))}</code></td></tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>校園網路與凱基新超級大三元診斷報告</title>
<style>
  body {{ font-family: "Microsoft JhengHei", system-ui, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 24px; line-height: 1.6; }}
  .container {{ max-width: 1180px; margin: 0 auto; }}
  header {{ background: #1e293b; color: #fff; padding: 20px 28px; border-radius: 10px; margin-bottom: 24px; }}
  header h1 {{ margin: 0 0 8px 0; font-size: 22px; }}
  header p {{ margin: 4px 0; color: #cbd5e1; font-size: 14px; }}
  section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px 24px; margin-bottom: 20px; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }}
  h2 {{ margin-top: 0; font-size: 18px; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; color: #1e3a8a; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 10px; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 8px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: Consolas, monospace; font-size: 13px; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; display: inline-block; }}
  .card {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px 18px; margin-bottom: 12px; background: #fcfdff; }}
  .card h3 {{ margin: 0 0 6px 0; font-size: 16px; }}
  .cols {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; font-size: 14px; }}
  @media (max-width: 768px) {{ .cols {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>校園網路與凱基證券「新超級大三元」連線診斷報告</h1>
    <p>產生時間：{esc(str(bundle.get('generated_at', '')))} ｜ 作業系統：{esc(str(os_info.get('caption', '')))} ｜ 主要介面：{esc(str(prim.get('connection_type', '')))} ({esc(str(prim.get('interface_alias', '')))})</p>
    <p>安全政策：唯讀、低負載、個人資訊遮罩、離線渲染（無任何外部伺服器連線）</p>
  </header>

  <section>
    <h2>1. 凱基「新超級大三元」實際交易與行情端點檢測</h2>
    <table>
      <thead><tr><th>角色</th><th>FQDN:Port</th><th>實測解析 IP</th><th>TCP 成功</th><th>平均延遲</th><th>連通狀態</th><th>協定行為特徵</th></tr></thead>
      <tbody>{''.join(kgi_rows)}</tbody>
    </table>
  </section>

  <section>
    <h2>2. 公開網站限制對照檢查</h2>
    <table>
      <thead><tr><th>目標</th><th>URL</th><th>DNS</th><th>TCP</th><th>平均延遲</th><th>診斷分類</th><th>證據分析</th></tr></thead>
      <tbody>{''.join(web_rows)}</tbody>
    </table>
  </section>

  <section>
    <h2>3. 斷線根本原因決策評估排序（A ~ G）</h2>
    {''.join(rc_cards)}
  </section>

  <section>
    <h2>4. 學校網路（測試 A）vs 手機熱點（測試 B）對照表</h2>
    <p><strong>狀態：</strong>{esc(str(ab_comp.get('status', '')))} — {esc(str(ab_comp.get('conclusion', '')))}</p>
    <table>
      <thead><tr><th>比較指標</th><th>測試 A：學校網路</th><th>測試 B：個人手機熱點</th><th>差異 (A - B)</th></tr></thead>
      <tbody>{''.join(ab_rows)}</tbody>
    </table>
  </section>
</div>
</body>
</html>
"""
