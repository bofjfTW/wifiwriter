"""報告產生器 (v0.2)：輸出 Markdown、JSON、CSV 與離線安全 HTML 診斷報告（含事件時間線與七大問題實證回答）."""

from __future__ import annotations

import csv
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from src.analyzer import (
    STATUS_NOT_TESTED,
    TIER_CONDITIONAL_INFERENCE,
    TIER_CONFIRMED_FACT,
    TIER_UNVERIFIED_HYPOTHESIS,
    answer_seven_diagnostic_questions,
    mask_sensitive_text,
)


def _badge_color(status_text: str) -> str:
    if status_text in ("正常", TIER_CONFIRMED_FACT, "SUCCESS"):
        return "#15803d"
    if status_text in ("連線失敗", "確認有明確封鎖回應", "FAILED"):
        return "#b91c1c"
    if status_text in ("可能受到限制", TIER_CONDITIONAL_INFERENCE, "PARTIAL"):
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
        f"- **Run ID：** `{env_data.get('run_id', 'N/A')}`",
        f"- **蒐集時間：** `{env_data.get('collected_at', '')}`",
        f"- **步驟狀態：** `{env_data.get('run_status', 'SUCCESS')}`",
        "- **執行模式：** 唯讀、非侵入式本機檢查（未修改任何系統設定，未掃描校園網段）",
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
        lines.append(f"  - `{r.get('rule_id')}`: `{mask_sensitive_text(str(r.get('raw_summary', '')))}`")

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
            "- **已註冊之防毒/防火牆產品：** "
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
    event_timeline: List[Dict[str, Any]] | None = None,
) -> Dict[str, str]:
    """輸出結構化 CSV 診斷表格（含 diagnostic_summary.csv、ab_comparison.csv 與 event_timeline.csv）."""
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, str] = {}

    rest_csv = output_dir / "diagnostic_summary.csv"
    with rest_csv.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "檢查類型",
                "目標名稱",
                "端點來源分類",
                "端點或路徑",
                "DNS/安裝狀態",
                "TCP/執行狀態",
                "TLS狀態與協定分類",
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
                    "whitelist_website",
                    w.get("url", ""),
                    "成功" if w.get("dns_ok") else "失敗",
                    w.get("tcp_success_rate", ""),
                    f"HTTP {http_code} / TLS={bool((w.get('tls') or {}).get('ok'))}",
                    w.get("tcp_avg_rtt_ms", ""),
                    w.get("classification", ""),
                    mask_sensitive_text(str(w.get("evidence_summary", ""))),
                ]
            )
        for a in restrictions.get("applications") or []:
            writer.writerow(
                [
                    "本機應用程式",
                    a.get("name", ""),
                    "local_application",
                    mask_sensitive_text(str(a.get("executable_path", ""))),
                    f"已安裝(v{a.get('file_version', '')})" if a.get("installed") else "未找到",
                    "執行中" if a.get("is_running") else "未啟動",
                    f"簽章={a.get('signature_status', '')}, FW封鎖={a.get('firewall_block_rules', 0)}",
                    "",
                    a.get("classification", ""),
                    mask_sensitive_text(str(a.get("evidence_summary", ""))),
                ]
            )
        for d in restrictions.get("downloads") or []:
            writer.writerow(
                [
                    "檔案下載(HEAD)",
                    d.get("name", ""),
                    "authorized_download",
                    d.get("url", ""),
                    f"主站 HTTP {d.get('base_site_status', '')}",
                    f"端點 HTTP {d.get('download_status', '')}",
                    f"型態={d.get('file_type', '')}, Method={d.get('method_used', 'HEAD')}",
                    d.get("latency_ms", ""),
                    d.get("classification", ""),
                    mask_sensitive_text(str(d.get("evidence_summary", ""))),
                ]
            )
        for kp in kgi_probes:
            tls_p = kp.get("tls_probe") or {}
            tls_st = tls_p.get("tls_status", "TLS_NOT_TESTED")
            app_proto = tls_p.get("application_protocol", "UNKNOWN")
            writer.writerow(
                [
                    "凱基端點探測",
                    kp.get("role", ""),
                    kp.get("endpoint_source", "static_ini_candidate"),
                    f"{kp.get('fqdn', '')}:{kp.get('port', '')} ({kp.get('primary_ip', '')})",
                    "成功" if kp.get("dns_ok") else "失敗",
                    f"{kp.get('tcp_ok_count', 0)}/{kp.get('tcp_probe_count', 0)}",
                    f"TLS={tls_st} / Protocol={app_proto}",
                    kp.get("tcp_avg_ms", ""),
                    "TCP可連通" if kp.get("tcp_ok_count", 0) > 0 else "連線失敗",
                    mask_sensitive_text(str(tls_p.get("detail", ""))),
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
                    row.get("campus_value", STATUS_NOT_TESTED),
                    row.get("hotspot_value", STATUS_NOT_TESTED),
                    row.get("difference_a_minus_b", STATUS_NOT_TESTED),
                ]
            )
    paths["ab_comparison_csv"] = str(ab_csv)

    tl_csv = output_dir / "event_timeline.csv"
    with tl_csv.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Timestamp",
                "Run ID",
                "Network Profile",
                "Process Identity",
                "Event Type",
                "Observed State",
                "Supporting Evidence",
                "Alternative Explanations",
                "Confidence Classification",
                "Evidence Source",
            ]
        )
        for ev in event_timeline or []:
            writer.writerow(
                [
                    ev.get("timestamp", ""),
                    ev.get("run_id", ""),
                    ev.get("network_profile", ""),
                    mask_sensitive_text(str(ev.get("process_identity", ""))),
                    ev.get("event_type", ""),
                    mask_sensitive_text(str(ev.get("observed_state", ""))),
                    mask_sensitive_text(str(ev.get("supporting_evidence", ""))),
                    mask_sensitive_text(str(ev.get("alternative_explanations", ""))),
                    ev.get("confidence_classification", ""),
                    ev.get("evidence_source", ""),
                ]
            )
    paths["event_timeline_csv"] = str(tl_csv)
    return paths


def generate_research_report_markdown(bundle: Dict[str, Any]) -> str:
    """產生完整繁體中文研究報告 (v0.2：含七大問題回答、10 欄位事件時間線與嚴格三層證據分級)."""
    gen_at = bundle.get("generated_at", datetime.now().isoformat())
    run_id = bundle.get("run_id", "run_unknown")
    overall_status = bundle.get("overall_status", "PARTIAL")
    step_statuses = bundle.get("step_statuses") or {}

    env = bundle.get("network_environment") or {}
    rest = bundle.get("restrictions") or {}
    kgi_info = bundle.get("kgi_inspection") or {}
    kgi_probes = bundle.get("kgi_endpoint_probes") or []
    kgi_analysis = bundle.get("kgi_probe_analysis") or {}
    root_causes = bundle.get("root_causes") or []
    ab_comp = bundle.get("ab_comparison") or {}
    campus_mon = bundle.get("campus_monitor")
    timeline = bundle.get("event_timeline") or (campus_mon or {}).get("event_timeline") or []
    qa_list = bundle.get("seven_questions") or answer_seven_diagnostic_questions(bundle)

    os_info = env.get("os_and_system") or {}
    prim = env.get("primary_connection") or {}
    proxy = env.get("proxy_settings") or {}
    fw = env.get("windows_firewall") or {}
    arch = kgi_info.get("architecture_and_reconnect") or {}

    lines: List[str] = [
        "# 校園網路與凱基證券「新超級大三元」斷線問題診斷研究報告 (`v0.2`)",
        "",
        f"- **Run ID：** `{run_id}`",
        f"- **報告產生時間：** `{gen_at}`",
        f"- **本次診斷整體資料狀態：** `{overall_status}`",
        f"- **各階段執行狀態：** `{json.dumps(step_statuses, ensure_ascii=False)}`",
        "- **科學與安全聲明：** 本報告僅依據本機唯讀實測證據產生；單獨 TCP 探測失敗不計入交易斷線；TCP 443 標準 TLS 失敗不推論為專屬協定或防火牆攔截；未完成之實驗均標示為 `NOT_TESTED` 或 `PARTIAL`。",
        "",
        "---",
        "",
        "## 0. 七大核心診斷問題實證回答",
        "",
        "| 核心問題 | 實證回答 |",
        "| --- | --- |",
    ]
    for qa in qa_list:
        lines.append(
            f"| **{qa.get('question', '')}** | {mask_sensitive_text(str(qa.get('answer', '')))} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 1. 網路環境摘要",
            "",
            f"- **作業系統：** {os_info.get('caption', '')} `{os_info.get('display_version', '')}` (Build `{os_info.get('build_number', '')}.{os_info.get('ubr', '')}`)",
            f"- **主要連線介面：** `{prim.get('connection_type', 'NOT_TESTED')}`（介面名稱：`{prim.get('interface_alias', '')}`，環境特徵：`{prim.get('environment_hint', '')}`）",
        ]
    )

    for ic in env.get("active_ip_configurations") or []:
        ip_desc = ", ".join(
            f"`{a.get('ip_masked')}` (遮罩 `{a.get('subnet_mask')}`, 類型 `{a.get('ip_class')}`)"
            for a in (ic.get("ipv4_addresses") or [])
        )
        gw_desc = ", ".join(f"`{g.get('next_hop_masked')}`" for g in (ic.get("ipv4_gateways") or []))
        dns_desc = ", ".join(
            f"`{d.get('address_masked')}` ({d.get('address_class')})" for d in (ic.get("dns_servers") or [])
        )
        lines.append(
            f"- **啟用介面 `{ic.get('interface_alias')}`：** IP={ip_desc or '無'}；預設閘道={gw_desc or '無'}；DNS={dns_desc or '無'}"
        )

    lines.extend(
        [
            f"- **Windows 防火牆：** 與凱基相關之封鎖規則數 = `{sum(1 for r in (fw.get('kgi_related_rules') or []) if 'Action=Block' in str(r.get('raw_summary', '')))}`",
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
        tls_txt = "正常" if tls_obj.get("ok") else f"異常 ({str(tls_obj.get('error', ''))[:25]})"
        lines.append(
            f"| {w.get('name')} | {w.get('url')} | {'成功' if w.get('dns_ok') else '失敗'} | "
            f"`{w.get('tcp_success_rate')}` | `{w.get('tcp_avg_rtt_ms')} ms` | {tls_txt} | "
            f"`{http_obj.get('status_code')}` | **{w.get('classification')}** | {mask_sensitive_text(str(w.get('evidence_summary', '')))} |"
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
            f"| {a.get('name')} | `{mask_sensitive_text(str(a.get('executable_path') or '未找到'))}` | `{a.get('file_version')}` | "
            f"`{a.get('signature_status')}` | `{'是' if a.get('is_running') else '否 (未啟動)'}` | "
            f"`{a.get('firewall_block_rules', 0)}` | **{a.get('classification')}** | {mask_sensitive_text(str(a.get('evidence_summary', '')))} |"
        )

    lines.extend(
        [
            "",
            "### 2.3 授權官方端點檔案下載限制檢查（低負載 HEAD）",
            "",
            "| 測試項目 | 檔案型態 | 主站狀態 | 端點狀態 | 延遲 | 診斷分類 | 證據分析 |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for d in rest.get("downloads") or []:
        lines.append(
            f"| {d.get('name')} | `{d.get('file_type')}` | `HTTP {d.get('base_site_status')}` | "
            f"`HTTP {d.get('download_status')}` | `{d.get('latency_ms')} ms` | **{d.get('classification')}** | {mask_sensitive_text(str(d.get('evidence_summary', '')))} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 3. 凱基證券「新超級大三元」程序驗證與連線診斷",
            "",
            "### 3.1 多因子程序身分與安裝驗證",
            "",
            f"- **安裝狀態：** `{'已安裝' if kgi_info.get('is_installed') else '未找到安裝目錄'}`（目錄：`{', '.join(mask_sensitive_text(str(x)) for x in (kgi_info.get('install_directories') or [])) or '無'}`）",
            f"- **檢查當下驗證通過之凱基程序執行中：** `{'是' if kgi_info.get('is_currently_running') else '否（未啟動）'}`",
            f"- **遠端端點分級統計：** 實際觀測活躍端點 `{len(kgi_info.get('observed_active_endpoints') or [])}` 組 ｜ 靜態 INI 候選端點 `{len(kgi_info.get('configured_endpoints') or [])}` 組 ｜ 用途待確認之遠端端點 `{len(kgi_info.get('unverified_remote_endpoints') or [])}` 組",
            f"- **靜態組態背景機制：** `{', '.join(arch.get('reconnect_mechanisms') or []) or '未檢出'}`",
            "",
            "### 3.2 端點低負載探測與 TLS 細分行為（不作未授權協定推論）",
            "",
            "| 來源分類 | 伺服器角色 | 目標 FQDN/IP | Port | TCP 成功率 | 平均 RTT | TCP RST | TLS 探測細分狀態 | 應用層協定判定 | 原始觀測說明 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for kp in kgi_probes:
        tls_p = kp.get("tls_probe") or {}
        lines.append(
            f"| `{kp.get('endpoint_source', 'static_ini_candidate')}` | `{kp.get('role')}` | `{kp.get('fqdn')}` (`{kp.get('primary_ip')}`) | `{kp.get('port')}` | "
            f"`{kp.get('tcp_ok_count')}/{kp.get('tcp_probe_count')}` | `{kp.get('tcp_avg_ms')} ms` | "
            f"`{'是' if kp.get('tcp_rst_observed') else '否'}` | `{tls_p.get('tls_status', 'TLS_NOT_TESTED')}` | "
            f"`{tls_p.get('application_protocol', 'UNKNOWN')}` | {mask_sensitive_text(str(tls_p.get('detail', '')))} |"
        )

    lines.extend(["", "### 3.3 監控統計摘要（被動 5 秒 Socket 追蹤 + 主動 30 秒低負載探測）", ""])
    if campus_mon:
        cm = campus_mon.get("metrics") or {}
        lines.extend(
            [
                f"- **監控 Run ID / 狀態：** `{campus_mon.get('run_id', 'N/A')}` / `{campus_mon.get('run_status', 'N/A')}`（完整性：`{campus_mon.get('data_completeness', 'N/A')}`）",
                f"- **取樣數與總時長：** `{campus_mon.get('sample_count', 0)}` 次取樣，共 `{campus_mon.get('total_duration_sec', 0)}` 秒",
                f"- **已確認交易斷線次數（僅計算具備應用層/使用者回報證據者）：** `{cm.get('confirmed_trading_disconnect_count', 0)}` 次（每小時率：`{cm.get('confirmed_disconnects_per_hour', 'N/A')}`）",
                f"- **使用者手動標記斷線 / 恢復次數：** `{cm.get('user_reported_disconnect_count', 0)}` 次 / `{cm.get('user_reported_reconnect_count', 0)}` 次",
                f"- **實際觀察到之 Socket 建立 / 結束次數：** 建立 `{cm.get('observed_socket_open_count', 0)}` 次 ／ 結束 `{cm.get('observed_socket_close_count', 0)}` 次",
                f"- **可辨識的連線持續時間：** `{cm.get('identifiable_connection_duration_display', '無法精確估計')}`",
                f"- **獨立主動探測成功率（凱基 TCP / DNS / 公開對照）：** `{cm.get('independent_kgi_probe_success_rate_pct', 'N/A')}%` / `{cm.get('independent_dns_success_rate_pct', 'N/A')}%` / `{cm.get('independent_control_probe_success_rate_pct', 'N/A')}%`",
                f"- **無法分類之事件數 (`UNKNOWN_EVENT`)：** `{cm.get('unknown_event_count', 0)}` 次",
            ]
        )
    else:
        lines.append("- **監控狀態：** `NOT_TESTED`（尚未載入本次校園網路長時段監控紀錄）。")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 4. 事件時間線（Event Timeline）",
            "",
            "| Timestamp | Run ID | Network Profile | Process Identity | Event Type | Observed State | Supporting Evidence | Alternative Explanations | Confidence Classification | Evidence Source |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    if timeline:
        for ev in timeline[:100]:
            lines.append(
                f"| `{ev.get('timestamp', '')}` | `{ev.get('run_id', '')}` | `{ev.get('network_profile', '')}` | "
                f"`{mask_sensitive_text(str(ev.get('process_identity', '')))}` | **`{ev.get('event_type', '')}`** | "
                f"{mask_sensitive_text(str(ev.get('observed_state', '')))} | {mask_sensitive_text(str(ev.get('supporting_evidence', '')))} | "
                f"{mask_sensitive_text(str(ev.get('alternative_explanations', '')))} | `{ev.get('confidence_classification', '')}` | `{ev.get('evidence_source', '')}` |"
            )
    else:
        lines.append("| - | - | - | - | `NONE` | 目前無觸發之異常或標記事件 | - | - | - | - |")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 5. 可能原因客觀評估（A ~ G，附可追溯原始證據來源）",
            "",
        ]
    )
    for rc in root_causes:
        lines.extend(
            [
                f"### 第 {rc.get('rank')} 順位：[{rc.get('code')}] {rc.get('title')}",
                f"- **證據分級：** `{rc.get('evidence_tier')}`",
                f"- **可追溯原始資料欄位：** `{', '.join(rc.get('evidence_refs') or [])}`",
                "- **支持觀測：**",
            ]
        )
        for s in rc.get("supporting_evidence") or []:
            lines.append(f"  - {mask_sensitive_text(str(s))}")
        lines.append("- **反證或限制說明：**")
        for c in rc.get("counter_evidence") or []:
            lines.append(f"  - {mask_sensitive_text(str(c))}")
        if rc.get("pending_checks"):
            lines.append("- **待完成驗證：**")
            for p in rc.get("pending_checks") or []:
                lines.append(f"  - {mask_sensitive_text(str(p))}")
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## 6. 學校網路（測試 A）與手機熱點（測試 B）科學對照實驗",
            "",
            f"- **對照檢核狀態：** `{ab_comp.get('status', STATUS_NOT_TESTED)}`（科學可比性通過：`{ab_comp.get('is_scientifically_comparable', False)}`）",
            f"- **分析結論：** {mask_sensitive_text(str(ab_comp.get('conclusion', '')))}",
            "",
        ]
    )
    if ab_comp.get("validation_checks"):
        lines.extend(
            [
                "### 6.1 A/B 可比性前置檢核結果",
                "",
                "| 檢核項目 | 通過 | 檢核細節 |",
                "| --- | --- | --- |",
            ]
        )
        for ch in ab_comp.get("validation_checks") or []:
            lines.append(
                f"| `{ch.get('check')}` | `{'PASS' if ch.get('passed') else 'FAIL'}` | {mask_sensitive_text(str(ch.get('detail', '')))} |"
            )
        lines.append("")

    lines.extend(
        [
            "### 6.2 對照指標表（含每小時標準化事件率）",
            "",
            "| 比較指標 | 測試 A：學校網路 | 測試 B：個人手機熱點 | 差異 (A - B) |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in ab_comp.get("metrics_table") or []:
        lines.append(
            f"| {row.get('metric_name')} | `{row.get('campus_value')}` | `{row.get('hotspot_value')}` | `{row.get('difference_a_minus_b')}` |"
        )

    # Section 7: 嚴格三層證據分級彙整
    confirmed_facts: List[str] = [
        f"本機安裝檢查：`{'已安裝' if kgi_info.get('is_installed') else '未找到'}`；執行檢查當下凱基程序運行狀態：`{bool(kgi_info.get('is_currently_running'))}`。",
        f"本機系統 WinINET Proxy 啟用狀態：`{proxy.get('wininet_proxy_enabled', False)}`；針對凱基執行檔之本機防火牆封鎖規則數：`{sum(1 for r in (fw.get('kgi_related_rules') or []) if 'Action=Block' in str(r.get('raw_summary', '')))}`。",
        f"靜態候選與活躍端點 TCP 探測連通數：`{kgi_analysis.get('tcp_reachable_count', 0)}/{kgi_analysis.get('total_endpoints_tested', 0)}`（未知應用層協定端點數：`{len(kgi_analysis.get('unknown_protocol_endpoints') or [])}`，均誠實標記為 `UNKNOWN`）。",
    ]
    conditional_inferences = [
        f"[{rc.get('code')}] {rc.get('title')}：{'；'.join(rc.get('supporting_evidence') or [])}"
        for rc in root_causes
        if rc.get("evidence_tier") == TIER_CONDITIONAL_INFERENCE
    ]
    unverified_hypotheses = [
        f"[{rc.get('code')}] {rc.get('title')}（尚待實測證據驗證，不視為既定事實）"
        for rc in root_causes
        if rc.get("evidence_tier") == TIER_UNVERIFIED_HYPOTHESIS
    ]

    lines.extend(
        [
            "",
            "---",
            "",
            "## 7. 三層證據嚴格分級彙整",
            "",
            "### 7.1 已確認事實（Confirmed Facts）",
        ]
    )
    for cf in confirmed_facts:
        lines.append(f"- {mask_sensitive_text(cf)}")

    lines.extend(["", "### 7.2 有條件支持的推論（Conditionally Supported Inferences）"])
    if conditional_inferences:
        for ci in conditional_inferences:
            lines.append(f"- {mask_sensitive_text(ci)}")
    else:
        lines.append("- 目前尚無達到「有條件支持推論」門檻之環境歸因項目（需待開啟交易軟體監控與熱點對照補齊）。")

    lines.extend(["", "### 7.3 尚未驗證假設（Unverified Hypotheses）"])
    for uh in unverified_hypotheses:
        lines.append(f"- {mask_sensitive_text(uh)}")
    lines.append("")

    return "\n".join(lines)


def generate_html_report(bundle: Dict[str, Any]) -> str:
    """產生無外部資源依賴、離線安全之視覺化 HTML 診斷報告 (v0.2)."""
    esc = html.escape
    env = bundle.get("network_environment") or {}
    rest = bundle.get("restrictions") or {}
    kgi_probes = bundle.get("kgi_endpoint_probes") or []
    root_causes = bundle.get("root_causes") or []
    ab_comp = bundle.get("ab_comparison") or {}
    campus_mon = bundle.get("campus_monitor") or {}
    timeline = bundle.get("event_timeline") or campus_mon.get("event_timeline") or []
    qa_list = bundle.get("seven_questions") or answer_seven_diagnostic_questions(bundle)
    prim = env.get("primary_connection") or {}
    os_info = env.get("os_and_system") or {}

    qa_rows = []
    for qa in qa_list:
        qa_rows.append(
            f"<tr><td><strong>{esc(str(qa.get('question', '')))}</strong></td>"
            f"<td>{esc(mask_sensitive_text(str(qa.get('answer', ''))))}</td></tr>"
        )

    kgi_rows = []
    for kp in kgi_probes:
        tls_p = kp.get("tls_probe") or {}
        ok_cnt = int(kp.get("tcp_ok_count") or 0)
        tot_cnt = int(kp.get("tcp_probe_count") or 0)
        st_txt = "TCP可連通" if ok_cnt > 0 else "連線失敗"
        color = "#15803d" if ok_cnt > 0 else "#b91c1c"
        kgi_rows.append(
            f"<tr><td><code>{esc(str(kp.get('endpoint_source', 'static_ini_candidate')))}</code></td>"
            f"<td><code>{esc(str(kp.get('role', '')))}</code></td>"
            f"<td><code>{esc(str(kp.get('fqdn', '')))}:{esc(str(kp.get('port', '')))}</code></td>"
            f"<td>{ok_cnt}/{tot_cnt}</td>"
            f"<td>{esc(str(kp.get('tcp_avg_ms', '')))} ms</td>"
            f"<td><span class='badge' style='background:{color}'>{st_txt}</span></td>"
            f"<td><code>{esc(str(tls_p.get('tls_status', 'TLS_NOT_TESTED')))}</code> / <code>{esc(str(tls_p.get('application_protocol', 'UNKNOWN')))}</code></td>"
            f"<td>{esc(mask_sensitive_text(str(tls_p.get('detail', ''))))}</td></tr>"
        )

    web_rows = []
    for w in rest.get("websites") or []:
        cls_txt = str(w.get("classification", ""))
        color = _badge_color(cls_txt)
        web_rows.append(
            f"<tr><td>{esc(str(w.get('name', '')))}</td>"
            f"<td><code>{esc(str(w.get('url', '')))}</code></td>"
            f"<td>{'成功' if w.get('dns_ok') else '失敗'}</td>"
            f"<td>{esc(str(w.get('tcp_success_rate', '')))}</td>"
            f"<td><span class='badge' style='background:{color}'>{esc(cls_txt)}</span></td>"
            f"<td>{esc(mask_sensitive_text(str(w.get('evidence_summary', ''))))}</td></tr>"
        )

    tl_rows = []
    for ev in timeline[:100]:
        tier = str(ev.get("confidence_classification", ""))
        color = _badge_color(tier)
        tl_rows.append(
            f"<tr><td><code>{esc(str(ev.get('timestamp', '')))}</code></td>"
            f"<td><code>{esc(str(ev.get('run_id', '')))}</code></td>"
            f"<td>{esc(str(ev.get('network_profile', '')))}</td>"
            f"<td><code>{esc(mask_sensitive_text(str(ev.get('process_identity', ''))))}</code></td>"
            f"<td><strong>{esc(str(ev.get('event_type', '')))}</strong></td>"
            f"<td>{esc(mask_sensitive_text(str(ev.get('observed_state', ''))))}</td>"
            f"<td>{esc(mask_sensitive_text(str(ev.get('supporting_evidence', ''))))}</td>"
            f"<td>{esc(mask_sensitive_text(str(ev.get('alternative_explanations', ''))))}</td>"
            f"<td><span class='badge' style='background:{color}'>{esc(tier)}</span></td>"
            f"<td><code>{esc(str(ev.get('evidence_source', '')))}</code></td></tr>"
        )
    if not tl_rows:
        tl_rows.append("<tr><td colspan='10'>目前無觸發之異常或手動標記事件</td></tr>")

    rc_cards = []
    for rc in root_causes:
        tier = str(rc.get("evidence_tier", ""))
        color = _badge_color(tier)
        sup_li = "".join(f"<li>{esc(mask_sensitive_text(str(s)))}</li>" for s in (rc.get("supporting_evidence") or []))
        cnt_li = "".join(f"<li>{esc(mask_sensitive_text(str(c)))}</li>" for c in (rc.get("counter_evidence") or []))
        refs_str = ", ".join(rc.get("evidence_refs") or [])
        rc_cards.append(
            f"<div class='card'>"
            f"<h3>第 {rc.get('rank')} 順位：[{esc(str(rc.get('code')))}] {esc(str(rc.get('title')))} "
            f"<span class='badge' style='background:{color}'>{esc(tier)}</span></h3>"
            f"<p><small>追溯來源：<code>{esc(refs_str)}</code></small></p>"
            f"<div class='cols'><div><strong>支持觀測：</strong><ul>{sup_li}</ul></div>"
            f"<div><strong>反證與限制：</strong><ul>{cnt_li}</ul></div></div>"
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
<title>校園網路與凱基新超級大三元診斷報告 (v0.2)</title>
<style>
  body {{ font-family: "Microsoft JhengHei", system-ui, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 24px; line-height: 1.6; }}
  .container {{ max-width: 1280px; margin: 0 auto; }}
  header {{ background: #1e293b; color: #fff; padding: 20px 28px; border-radius: 10px; margin-bottom: 24px; }}
  header h1 {{ margin: 0 0 8px 0; font-size: 22px; }}
  header p {{ margin: 4px 0; color: #cbd5e1; font-size: 14px; }}
  section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px 24px; margin-bottom: 20px; box-shadow: 0 1px 2px rgba(0,0,0,0.03); overflow-x: auto; }}
  h2 {{ margin-top: 0; font-size: 18px; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; color: #1e3a8a; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 8px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: Consolas, monospace; font-size: 12px; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; display: inline-block; }}
  .card {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px 18px; margin-bottom: 12px; background: #fcfdff; }}
  .card h3 {{ margin: 0 0 6px 0; font-size: 16px; }}
  .cols {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; font-size: 13px; }}
  @media (max-width: 768px) {{ .cols {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>校園網路與凱基證券「新超級大三元」連線診斷報告 (v0.2)</h1>
    <p>Run ID：{esc(str(bundle.get('run_id', 'N/A')))} ｜ 狀態：{esc(str(bundle.get('overall_status', 'N/A')))} ｜ 產生時間：{esc(str(bundle.get('generated_at', '')))}</p>
    <p>作業系統：{esc(str(os_info.get('caption', '')))} ｜ 主要介面：{esc(str(prim.get('connection_type', '')))} ({esc(str(prim.get('interface_alias', '')))})</p>
  </header>

  <section>
    <h2>0. 七大核心診斷問題與實證回答</h2>
    <table>
      <thead><tr><th style="width:28%">核心問題</th><th>實證回答</th></tr></thead>
      <tbody>{''.join(qa_rows)}</tbody>
    </table>
  </section>

  <section>
    <h2>1. 事件時間線（Event Timeline）</h2>
    <table>
      <thead><tr><th>Timestamp</th><th>Run ID</th><th>Profile</th><th>Process</th><th>Event Type</th><th>Observed State</th><th>Supporting Evidence</th><th>Alternative Explanations</th><th>Confidence</th><th>Source</th></tr></thead>
      <tbody>{''.join(tl_rows)}</tbody>
    </table>
  </section>

  <section>
    <h2>2. 凱基端點檢測與協定狀態（不作未驗證專屬協定推論）</h2>
    <table>
      <thead><tr><th>來源分類</th><th>角色</th><th>FQDN:Port</th><th>TCP</th><th>平均延遲</th><th>連通狀態</th><th>TLS / 協定判定</th><th>觀測細節</th></tr></thead>
      <tbody>{''.join(kgi_rows)}</tbody>
    </table>
  </section>

  <section>
    <h2>3. 公開白名單網站限制對照檢查</h2>
    <table>
      <thead><tr><th>目標</th><th>URL</th><th>DNS</th><th>TCP</th><th>診斷分類</th><th>證據分析</th></tr></thead>
      <tbody>{''.join(web_rows)}</tbody>
    </table>
  </section>

  <section>
    <h2>4. 可能原因客觀評估（三層證據分級）</h2>
    {''.join(rc_cards)}
  </section>

  <section>
    <h2>5. 學校網路（測試 A）vs 手機熱點（測試 B）科學對照表</h2>
    <p><strong>狀態：</strong>{esc(str(ab_comp.get('status', '')))} — {esc(mask_sensitive_text(str(ab_comp.get('conclusion', ''))))}</p>
    <table>
      <thead><tr><th>比較指標</th><th>測試 A：學校網路</th><th>測試 B：個人手機熱點</th><th>差異 (A - B)</th></tr></thead>
      <tbody>{''.join(ab_rows)}</tbody>
    </table>
  </section>
</div>
</body>
</html>
"""
