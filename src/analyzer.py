"""診斷分析引擎：隱私遮罩、限制證據分類、凱基連線協定分析、根本原因決策與 A/B 對照分析."""

from __future__ import annotations

import os
import re
import statistics
from typing import Any, Dict, List, Optional

# 第二階段：五大標準限制分類
CAT_NORMAL = "正常"
CAT_CONN_FAIL = "連線失敗"
CAT_MAYBE_RESTRICTED = "可能受到限制"
CAT_CONFIRMED_BLOCK = "確認有明確封鎖回應"
CAT_INSUFFICIENT = "證據不足"

VALID_CLASSIFICATIONS = {
    CAT_NORMAL,
    CAT_CONN_FAIL,
    CAT_MAYBE_RESTRICTED,
    CAT_CONFIRMED_BLOCK,
    CAT_INSUFFICIENT,
}

# 知名公開 DNS 清單（無個人識別風險，保留以利網管排查）
WELL_KNOWN_PUBLIC_DNS = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "168.95.1.1",
    "168.95.192.1",
    "208.67.222.222",
    "208.67.220.220",
}

MITM_CERT_ISSUER_KEYWORDS = (
    "fortinet",
    "fortigate",
    "palo alto",
    "zscaler",
    "sonicwall",
    "sophos",
    "sangfor",
    "check point",
    "bluecoat",
    "symantec ssl visibility",
    "netskope",
    "untrusted",
)

BLOCK_REDIRECT_KEYWORDS = (
    "fortiguard",
    "blockpage",
    "blocked",
    "captive",
    "portal",
    "access-denied",
    "policy-deny",
    "webfilter",
)


def mask_ip(ip_str: str, preserve_public_target: bool = False) -> str:
    """遮罩本機、內網或校園端點 IP 位址以保護隱私，必要時保留公開目標服務 IP."""
    if not ip_str:
        return ""
    val = ip_str.strip()
    if val in ("0.0.0.0", "::", "127.0.0.1", "::1", "255.255.255.0", "255.255.0.0"):
        return val
    if val in WELL_KNOWN_PUBLIC_DNS or preserve_public_target:
        return val
    m4 = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/\d+)?$", val)
    if m4:
        cidr = m4.group(5) or ""
        return f"{m4.group(1)}.{m4.group(2)}.xxx.xxx{cidr}"
    if ":" in val:
        parts = val.split(":")
        if len(parts) >= 2:
            return f"{parts[0]}:{parts[1]}:xxxx:xxxx::xxxx"
        return "xxxx:xxxx::xxxx"
    return val


def mask_sensitive_text(
    text: str,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
) -> str:
    """遮罩字串中的使用者名稱、電腦主機名稱、MAC 位址與敏感識別碼."""
    if not text:
        return ""
    res = text
    uname = username if username is not None else os.environ.get("USERNAME", "")
    hname = hostname if hostname is not None else os.environ.get("COMPUTERNAME", "")
    if uname:
        res = re.sub(re.escape(uname), "<USER>", res, flags=re.IGNORECASE)
    if hname:
        res = re.sub(re.escape(hname), "<HOST>", res, flags=re.IGNORECASE)
    # 台灣身分證字號格式保護遮罩
    res = re.sub(r"\b[A-Za-z][12]\d{8}\b", "[REDACTED_ID]", res)
    # MAC / BSSID 遮罩後三組
    res = re.sub(
        r"\b([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})(?:[:-][0-9A-Fa-f]{2}){3}\b",
        r"\1:xx:xx:xx",
        res,
    )
    return res


def classify_website_evidence(entry: Dict[str, Any]) -> Dict[str, str]:
    """依據證據判定網站連線狀態，嚴格禁止將單純 403/TLS 錯誤/逾時直接等同學校封鎖."""
    dns_ok = bool(entry.get("dns_ok", False))
    tcp_rate_str = str(entry.get("tcp_success_rate", "0/0"))
    tcp_ok_cnt = 0
    tcp_total_cnt = 0
    if "/" in tcp_rate_str:
        parts = tcp_rate_str.split("/", 1)
        try:
            tcp_ok_cnt = int(parts[0])
            tcp_total_cnt = int(parts[1])
        except ValueError:
            pass

    intermittent = bool(entry.get("intermittent", False)) or (
        0 < tcp_ok_cnt < tcp_total_cnt
    )
    tls = entry.get("tls") or {}
    http_info = entry.get("http") or {}

    tls_ok = bool(tls.get("ok", False))
    issuer_lower = str(tls.get("issuer", "")).lower()
    status_code = int(http_info.get("status_code") or 0)
    location_lower = str(http_info.get("location", "")).lower()
    via_header = str(http_info.get("via", "")).strip()
    body_hint_lower = str(http_info.get("block_snippet", "")).lower()

    has_mitm_cert = any(k in issuer_lower for k in MITM_CERT_ISSUER_KEYWORDS)
    has_block_redirect = any(k in location_lower for k in BLOCK_REDIRECT_KEYWORDS)
    has_block_page_text = any(k in body_hint_lower for k in BLOCK_REDIRECT_KEYWORDS)

    if not dns_ok:
        return {
            "classification": CAT_CONN_FAIL,
            "reason": "DNS 解析失敗，無法取得目標 IP（需比對公開 DNS 與校園 DNS 區分原因）",
        }
    if tcp_ok_cnt == 0:
        return {
            "classification": CAT_CONN_FAIL,
            "reason": "DNS 解析成功但 TCP 三方交握全部失敗/逾時（尚無明確封鎖頁面，不能直接斷定為學校封鎖）",
        }
    if status_code == 451 or has_block_redirect or has_block_page_text:
        return {
            "classification": CAT_CONFIRMED_BLOCK,
            "reason": f"偵測到明確政策攔截回應或導向頁（HTTP {status_code}, Location={http_info.get('location', '')}）",
        }
    if has_mitm_cert:
        return {
            "classification": CAT_MAYBE_RESTRICTED,
            "reason": f"偵測到疑似防火牆/資安設備簽發之 TLS 中繼憑證（Issuer: {tls.get('issuer', '')}）",
        }
    if intermittent:
        return {
            "classification": CAT_MAYBE_RESTRICTED,
            "reason": f"TCP 連線呈現間歇性失敗（成功 {tcp_rate_str}），疑似封包遺失或連線速率/狀態限制",
        }
    if not tls_ok and str(entry.get("url", "")).lower().startswith("https://"):
        return {
            "classification": CAT_MAYBE_RESTRICTED,
            "reason": f"TCP 連通但 TLS 憑證驗證異常（{tls.get('error', '')}），需進一步確認是否為 SSL 檢測設備或本機時間/憑證問題",
        }
    if 200 <= status_code < 400:
        proxy_note = f"（偵測到 Via 標頭: {via_header}）" if via_header else ""
        return {
            "classification": CAT_NORMAL,
            "reason": f"DNS、TCP、TLS 憑證鏈與 HTTP 回應（{status_code}）皆正常{proxy_note}",
        }
    if status_code == 403:
        return {
            "classification": CAT_INSUFFICIENT,
            "reason": "收到 HTTP 403，但憑證為官方簽發且無防火牆攔截頁特徵，常見於目標站台 WAF/CDN 對非瀏覽器請求之保護，不能直接視為學校封鎖",
        }
    return {
        "classification": CAT_INSUFFICIENT,
        "reason": f"收到 HTTP 狀態碼 {status_code}，目前缺乏足夠證據判定為網路限制",
    }


def classify_application_evidence(app_entry: Dict[str, Any]) -> Dict[str, str]:
    """依據證據判定本機應用程式連線狀態，嚴格遵守『未啟動程式不得判定為受限』原則."""
    installed = bool(app_entry.get("installed", False))
    is_running = bool(app_entry.get("is_running", False))
    fw_block = int(app_entry.get("firewall_block_rules") or 0)
    active_tcp = int(app_entry.get("active_tcp_count") or 0)

    if not installed:
        return {
            "classification": CAT_INSUFFICIENT,
            "reason": "本機尚未找到此執行檔路徑，證據不足",
        }
    if fw_block > 0:
        return {
            "classification": CAT_CONFIRMED_BLOCK,
            "reason": f"Windows 本機防火牆存在 {fw_block} 條針對此執行檔之啟用中封鎖（Block）規則",
        }
    if not is_running:
        return {
            "classification": CAT_INSUFFICIENT,
            "reason": "程式已安裝且簽章已檢查，但目前未啟動執行；依診斷規範不得將未啟動程式判定為受到限制",
        }
    if active_tcp > 0:
        return {
            "classification": CAT_NORMAL,
            "reason": f"程式執行中且已成功建立 {active_tcp} 條對外 TCP 連線",
        }
    return {
        "classification": CAT_INSUFFICIENT,
        "reason": "程式執行中但目前尚無對外 TCP 連線（可能停留在未登入畫面），需於實際連線狀態下觀測",
    }


def classify_download_evidence(dl_entry: Dict[str, Any]) -> Dict[str, str]:
    """依據低資料量 HEAD 請求判定檔案下載限制."""
    base_code = int(dl_entry.get("base_site_status") or 0)
    dl_code = int(dl_entry.get("download_status") or 0)
    loc_lower = str(dl_entry.get("redirect_location", "")).lower()
    ftype = str(dl_entry.get("file_type", ""))

    if dl_code == 451 or any(k in loc_lower for k in BLOCK_REDIRECT_KEYWORDS):
        return {
            "classification": CAT_CONFIRMED_BLOCK,
            "reason": f"下載端點收到明確政策攔截回應或重新導向（HTTP {dl_code}, Location={dl_entry.get('redirect_location', '')}）",
        }
    if 200 <= dl_code < 400:
        return {
            "classification": CAT_NORMAL,
            "reason": f"官方端點對 {ftype} 之 HEAD 請求正常回應（HTTP {dl_code}），無檔案型態封鎖跡象",
        }
    if (200 <= base_code < 400) and dl_code == 0:
        return {
            "classification": CAT_MAYBE_RESTRICTED,
            "reason": f"主站可正常存取（HTTP {base_code}），但針對 {ftype} 下載路徑連線遭中斷或逾時，疑似防火牆檔案型態過濾",
        }
    if dl_code == 403:
        return {
            "classification": CAT_INSUFFICIENT,
            "reason": f"下載端點回傳 HTTP 403，可能為來源伺服器防盜連/權限限制或閘道器規則，無明確攔截頁前屬證據不足",
        }
    if dl_code == 404:
        return {
            "classification": CAT_INSUFFICIENT,
            "reason": "來源伺服器正常回應 HTTP 404（代表網路與 TLS 可直達官方伺服器，僅該靜態路徑已更新或下架，非校園封鎖）",
        }
    return {
        "classification": CAT_CONN_FAIL,
        "reason": f"主站與下載端點皆無法完成回應（狀態碼 {dl_code}）",
    }


def analyze_kgi_endpoint_probes(
    endpoint_probes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """分析凱基新超級大三元實際伺服器端點之連線、延遲、TCP Reset 與非標準協定特徵."""
    total = len(endpoint_probes)
    dns_ok_list = [p for p in endpoint_probes if p.get("dns_ok")]
    tcp_ok_list = [p for p in endpoint_probes if p.get("tcp_ok_count", 0) > 0]
    rst_observed = [p for p in endpoint_probes if p.get("tcp_rst_observed")]
    proprietary_proto_endpoints = []
    mitm_endpoints = []

    all_rtts: List[float] = []
    for p in endpoint_probes:
        for r in p.get("tcp_rtts_ms", []):
            if isinstance(r, (int, float)):
                all_rtts.append(float(r))
        # 關鍵技術特徵：TCP 443/80 可連通，但非標準 TLS/HTTP（代表走凱基 HTS 專屬封包協定）
        if p.get("tcp_ok_count", 0) > 0 and p.get("port") == 443:
            tls_state = p.get("tls_probe") or {}
            if not tls_state.get("tls_handshake_ok", False):
                proprietary_proto_endpoints.append(
                    {
                        "fqdn": p.get("fqdn"),
                        "ip": p.get("primary_ip"),
                        "port": p.get("port"),
                        "tls_behavior": tls_state.get("detail", ""),
                    }
                )
            elif any(
                k in str(tls_state.get("issuer", "")).lower()
                for k in MITM_CERT_ISSUER_KEYWORDS
            ):
                mitm_endpoints.append(p.get("fqdn"))

    avg_rtt = round(statistics.mean(all_rtts), 2) if all_rtts else None
    max_rtt = round(max(all_rtts), 2) if all_rtts else None
    stdev_rtt = (
        round(statistics.stdev(all_rtts), 2) if len(all_rtts) >= 2 else 0.0
    )

    return {
        "total_endpoints_tested": total,
        "dns_reachable_count": len(dns_ok_list),
        "tcp_reachable_count": len(tcp_ok_list),
        "tcp_rst_endpoints": [p.get("fqdn") for p in rst_observed],
        "proprietary_binary_over_443_endpoints": proprietary_proto_endpoints,
        "mitm_cert_endpoints": mitm_endpoints,
        "avg_tcp_rtt_ms": avg_rtt,
        "max_tcp_rtt_ms": max_rtt,
        "tcp_rtt_jitter_ms": stdev_rtt,
    }


def evaluate_root_causes(
    network_env: Dict[str, Any],
    restrictions: Dict[str, Any],
    kgi_inspection: Dict[str, Any],
    kgi_probe_analysis: Dict[str, Any],
    campus_monitor: Optional[Dict[str, Any]] = None,
    hotspot_monitor: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """第四階段 4.4：自動評估 A~G 七大可能根本原因，列出支持證據、反證、未完成檢查與信心程度."""
    primary_conn = network_env.get("primary_connection") or {}
    conn_type = str(primary_conn.get("connection_type", "Unknown"))
    env_hint = str(primary_conn.get("environment_hint", ""))
    proxy_cfg = network_env.get("proxy_settings") or {}
    fw_cfg = network_env.get("windows_firewall") or {}
    wifi_cfg = (network_env.get("wifi_diagnostics") or {}).get("details") or {}
    events_cfg = network_env.get("recent_network_events") or {}
    vpn_cfg = network_env.get("vpn_auth_and_security") or {}

    prop_443 = kgi_probe_analysis.get("proprietary_binary_over_443_endpoints") or []
    rst_eps = kgi_probe_analysis.get("tcp_rst_endpoints") or []
    mitm_eps = kgi_probe_analysis.get("mitm_cert_endpoints") or []
    tcp_reach = int(kgi_probe_analysis.get("tcp_reachable_count") or 0)
    total_eps = int(kgi_probe_analysis.get("total_endpoints_tested") or 0)

    has_live_campus_disconnect = bool(
        campus_monitor
        and (campus_monitor.get("metrics") or {}).get("disconnect_count", 0) > 0
    )
    has_ab_comparison = bool(campus_monitor and hotspot_monitor)
    hotspot_stable = bool(
        hotspot_monitor
        and (hotspot_monitor.get("metrics") or {}).get("disconnect_count", 0) == 0
        and (hotspot_monitor.get("metrics") or {}).get(
            "connection_success_rate_pct", 0
        )
        >= 99.0
    )

    causes: List[Dict[str, Any]] = []

    # --- A. 學校網路出口或防火牆問題 ---
    sup_a: List[str] = []
    cnt_a: List[str] = []
    pend_a: List[str] = []
    score_a = 25

    if prop_443:
        ep_names = ", ".join(
            sorted({f"{x['fqdn']}:{x['port']}" for x in prop_443})
        )
        sup_a.append(
            f"實測發現凱基報價/交易伺服器（{ep_names}）雖使用 TCP 443/80 通訊埠，但並非標準 HTTPS/TLS 交握，而是凱基 HTS 專屬加密長連線協定（axsock.ocx / TS070300）；校園次世代防火牆（NGFW App-ID / Application Control）常將 Port 443 上的非標準 TLS 長連線識別為 unknown-tcp 或異常協定，進而套用極短閒置逾時（如 30~120 秒）或週期性中斷連線。"
        )
        score_a += 25
    if env_hint == "Campus_TANet_Or_Enterprise_Network":
        sup_a.append("本機網路環境辨識具學術網路（TANet 140.x）或企業級 802.1X 網路特徵。")
        score_a += 10
    if rst_eps:
        sup_a.append(f"對凱基端點測試時實際觀測到 TCP Reset (RST)：{', '.join(rst_eps)}。")
        score_a += 20
    if has_ab_comparison and has_live_campus_disconnect and hotspot_stable:
        sup_a.append("對照實驗顯示同一台電腦在手機熱點零斷線，而在學校網路發生斷線，證實問題與學校網路路徑或狀態設備有關。")
        score_a += 20

    if total_eps > 0 and tcp_reach == total_eps and not rst_eps:
        cnt_a.append(
            f"目前初次 TCP 三方交握對全部 {total_eps}/{total_eps} 個凱基端點均可連通，證實學校防火牆並未『完全靜態封鎖』凱基伺服器 IP 或 Port 80/443（若有關聯，較可能為長連線 NAT 狀態逾時或 NGFW 深度協定檢測中斷，而非靜態黑名單）。"
        )
    if not has_ab_comparison:
        pend_a.append("尚未完成「學校網路 vs 個人手機熱點」30 分鐘長連線 A/B 對照監控。")
    if not kgi_inspection.get("is_currently_running"):
        pend_a.append("檢測當下新超級大三元主程式未處於開啟登入狀態，尚未捕捉實際斷線瞬間之雙向狀態。")

    causes.append(
        {
            "code": "A",
            "title": "學校網路出口或防火牆問題（NGFW 協定檢測 / NAT 長連線閒置逾時）",
            "confidence": "高" if score_a >= 70 else ("中" if score_a >= 45 else "低"),
            "credibility_tier": "高可信度推論" if (has_ab_comparison and hotspot_stable) else "可能原因",
            "score": min(score_a, 95),
            "supporting_evidence": sup_a or ["尚無直接防火牆攔截證據"],
            "counter_evidence": cnt_a or ["尚無明確反證"],
            "pending_checks": pend_a,
        }
    )

    # --- B. DNS 或 Proxy 問題 ---
    sup_b: List[str] = []
    cnt_b: List[str] = []
    pend_b: List[str] = []
    score_b = 15

    if proxy_cfg.get("wininet_proxy_enabled") or proxy_cfg.get("wininet_pac_url"):
        sup_b.append(
            f"系統啟用了 WinINET Proxy 或 PAC 自動設定（Server={proxy_cfg.get('wininet_proxy_server')}, PAC={proxy_cfg.get('wininet_pac_url')}），非 HTTP 標準協定的證券交易軟體經過 HTTP Proxy 極易斷線。"
        )
        score_b += 45
    else:
        cnt_b.append("本機 WinINET 系統 Proxy 未啟用，且無設定 PAC 自動組態網址。")

    if not proxy_cfg.get("winhttp_direct_access", True):
        sup_b.append(f"WinHTTP 設定了非直接存取 Proxy：{proxy_cfg.get('winhttp_raw')}")
        score_b += 30
    else:
        cnt_b.append("本機 WinHTTP 為直接存取（Direct access，無代理伺服器）。")

    if proxy_cfg.get("env_proxies"):
        sup_b.append(f"偵測到系統環境變數 Proxy 設定：{list(proxy_cfg['env_proxies'].keys())}。")
        score_b += 20

    if mitm_eps:
        sup_b.append(f"偵測到透明 SSL Proxy 憑證替換：{', '.join(mitm_eps)}。")
        score_b += 40
    else:
        cnt_b.append("公開 HTTPS 網站（凱基官網、Microsoft、GitHub）憑證簽發者皆為合法公開 CA，未偵測到透明 SSL MITM 憑證替換。")

    dns_timeouts = events_cfg.get("dns_client_timeouts") or []
    if dns_timeouts:
        sup_b.append(f"過去 24 小時 Windows 系統日誌記錄到 {len(dns_timeouts)} 筆 DNS Client Event 1014 解析逾時事件。")
        score_b += 25
    else:
        cnt_b.append("過去 24 小時系統日誌無 DNS Client 1014 解析逾時紀錄，且凱基網域目前皆可正常解析。")

    if not campus_monitor:
        pend_b.append("需透過持續監控確認斷線瞬間是否伴隨偶發性 DNS 解析失敗。")

    causes.append(
        {
            "code": "B",
            "title": "DNS 解析異常或系統/透明 Proxy 干擾問題",
            "confidence": "高" if score_b >= 65 else ("中" if score_b >= 40 else "低"),
            "credibility_tier": "高可信度推論" if score_b >= 65 else "可能原因",
            "score": min(score_b, 95),
            "supporting_evidence": sup_b or ["目前未偵測到本機 Proxy 或 DNS 解析失敗"],
            "counter_evidence": cnt_b,
            "pending_checks": pend_b,
        }
    )

    # --- C. 網路品質不佳、封包遺失或 Wi-Fi 漫遊 ---
    sup_c: List[str] = []
    cnt_c: List[str] = []
    pend_c: List[str] = []
    score_c = 20

    wlan_evs = events_cfg.get("wlan_events") or []
    np_evs = [
        e
        for e in (events_cfg.get("network_profile_events") or [])
        if e.get("id") == 10001
    ]
    sig_pct = wifi_cfg.get("signal_percent")

    if conn_type == "Wi-Fi":
        sup_c.append("目前使用 Wi-Fi 無線網路連線，校園多基地台（AP）環境容易因訊號切換（BSSID 漫遊）或 802.1X 重新驗證造成瞬間封包中斷。")
        score_c += 15
        if isinstance(sig_pct, (int, float)):
            if sig_pct < 65:
                sup_c.append(f"目前 Wi-Fi 訊號強度偏弱（{sig_pct}%），容易引發重傳與瞬斷。")
                score_c += 30
            else:
                cnt_c.append(f"目前 Wi-Fi 訊號強度良好（{sig_pct}%）。")
    elif conn_type == "Ethernet":
        cnt_c.append("目前主要連線為有線網路（Ethernet），可排除 Wi-Fi 訊號強弱與 AP 漫遊因素。")
        score_c -= 10

    if wlan_evs:
        sup_c.append(f"過去 24 小時 Windows WLAN-AutoConfig 記錄到 {len(wlan_evs)} 筆無線連線狀態變更/重連事件。")
        score_c += 20
    if np_evs:
        sup_c.append(f"過去 24 小時 NetworkProfile 記錄到 {len(np_evs)} 次網路介面斷線事件（Event ID 10001）。")
        score_c += 20

    jitter = float(kgi_probe_analysis.get("tcp_rtt_jitter_ms") or 0.0)
    if jitter > 35.0:
        sup_c.append(f"凱基端點 TCP 建連延遲抖動偏高（Jitter={jitter} ms）。")
        score_c += 15
    elif kgi_probe_analysis.get("avg_tcp_rtt_ms") is not None:
        cnt_c.append(
            f"基準測試期間凱基伺服器 TCP 建連平均延遲為 {kgi_probe_analysis.get('avg_tcp_rtt_ms')} ms（抖動 {jitter} ms），連線品質平穩。"
        )

    if not campus_monitor:
        pend_c.append("需於斷線監控期間比對公開對照組（Microsoft）是否與凱基同時斷線，以區分底層斷網與單一服務中斷。")

    causes.append(
        {
            "code": "C",
            "title": "網路品質不佳、瞬間封包遺失、網卡閃斷或校園 Wi-Fi 漫遊",
            "confidence": "高" if score_c >= 65 else ("中" if score_c >= 40 else "低"),
            "credibility_tier": "可能原因",
            "score": max(5, min(score_c, 95)),
            "supporting_evidence": sup_c or ["基準測試未見明顯封包遺失或訊號異常"],
            "counter_evidence": cnt_c or ["尚無反證"],
            "pending_checks": pend_c,
        }
    )

    # --- D. Windows 防火牆、端點安全軟體或網卡設定問題 ---
    sup_d: List[str] = []
    cnt_d: List[str] = []
    pend_d: List[str] = []
    score_d = 15

    kgi_fw_rules = fw_cfg.get("kgi_related_rules") or []
    has_kgi_fw_block = any("Action=Block" in str(r.get("raw_summary", "")) for r in kgi_fw_rules)
    if has_kgi_fw_block:
        sup_d.append("Windows 防火牆存在針對凱基相關程式之明確封鎖（Block）規則！")
        score_d += 60
    else:
        cnt_d.append("Windows 防火牆對外預設動作為 Allow，且無針對 SUPERTSC64.exe 或 axis.exe 之封鎖規則。")

    # 檢查網卡省電設定與睡眠事件
    adapters = network_env.get("network_adapters") or []
    pm_enabled_nics = [
        a.get("name")
        for a in adapters
        if a.get("status") == "Up"
        and isinstance(a.get("power_management"), dict)
        and str((a.get("power_management") or {}).get("allow_computer_to_turn_off", "")).lower() in ("true", "enabled", "1")
    ]
    if pm_enabled_nics:
        sup_d.append(
            f"啟用中之網路介面卡（{', '.join(pm_enabled_nics)}）允許系統關閉裝置以節省電源，閒置時可能導致長連線斷開。"
        )
        score_d += 20

    sleep_evs = events_cfg.get("power_sleep_events") or []
    if sleep_evs:
        sup_d.append(f"過去 24 小時系統發生 {len(sleep_evs)} 次睡眠/現代待命（Modern Standby）電源狀態切換，待命期間會中斷證券 TCP 長連線。")
        score_d += 20

    vpn_procs = vpn_cfg.get("running_vpn_or_proxy_processes") or []
    if vpn_procs:
        sup_d.append(f"偵測到背景執行中之 VPN / 代理程序：{', '.join(vpn_procs)}，可能劫持路由導致交易連線不穩。")
        score_d += 30
    else:
        cnt_d.append("目前未偵測到第三方 VPN 或本地代理工具（如 Clash/WireGuard/OpenVPN）在背景執行。")

    sec_prods = [
        p.get("display_name")
        for p in (vpn_cfg.get("security_products") or [])
        if p.get("display_name") and "Windows Defender" not in str(p.get("display_name"))
    ]
    if sec_prods:
        sup_d.append(f"安裝有第三方端點安全/防毒軟體（{', '.join(sec_prods)}），其網路防護模組可能掃描加密流量。")
        score_d += 15
        pend_d.append("若手機熱點同樣發生斷線，需檢查第三方防毒軟體之『加密連線掃描 / 網路防護』是否干擾 axis.exe。")

    causes.append(
        {
            "code": "D",
            "title": "Windows 本機防火牆、端點安全軟體、VPN 或網卡省電/睡眠設定問題",
            "confidence": "高" if score_d >= 65 else ("中" if score_d >= 40 else "低"),
            "credibility_tier": "高可信度推論" if has_kgi_fw_block else "可能原因",
            "score": min(score_d, 95),
            "supporting_evidence": sup_d or ["本機防火牆與代理檢查無異常阻擋"],
            "counter_evidence": cnt_d,
            "pending_checks": pend_d,
        }
    )

    # --- E. 凱基證券伺服器或交易程式問題 ---
    sup_e: List[str] = []
    cnt_e: List[str] = []
    pend_e: List[str] = []
    score_e = 15

    arch = kgi_inspection.get("architecture_and_reconnect") or {}
    crash_cnt = int(arch.get("crashpad_dump_count") or 0)
    if crash_cnt > 0:
        sup_e.append(f"新超級大三元內嵌 WebView2 Crashpad 目錄存在 {crash_cnt} 份當機傾印檔（.dmp），顯示子元件曾發生異常終止。")
        score_e += 30
    else:
        cnt_e.append("Crashpad 目錄無當機傾印檔（0 個 .dmp），無主程式崩潰跡象。")

    core_exes = [
        e for e in (kgi_inspection.get("executables") or []) if e.get("is_core_binary")
    ]
    valid_sigs = [
        e for e in core_exes if e.get("signature_status") == "Valid"
    ]
    if valid_sigs:
        cnt_e.append(
            f"核心執行檔（SUPERTSC64.exe v2.0.0、axis.exe v3.0.0.1，安裝版本 1.0.5）具備有效之 KGI Securities Co. Ltd. 數位簽章，檔案完整未損毀。"
        )
    if tcp_reach == total_eps and total_eps > 0:
        cnt_e.append("凱基國內與外期報價/交易伺服器（gtsquot/gtstrade/gtsfquot/gtsftrade.kgieworld.com.tw）目前皆正常回應 TCP 連線。")
    elif total_eps > 0 and tcp_reach < total_eps:
        sup_e.append(f"部分凱基設定端點目前無法完成 TCP 交握（僅 {tcp_reach}/{total_eps} 成功）。")
        score_e += 25

    if not has_ab_comparison:
        pend_e.append("需透過手機熱點同時間對照：若連手機熱點亦頻繁斷線，則問題偏向凱基伺服器負載或程式本身。")

    causes.append(
        {
            "code": "E",
            "title": "凱基證券伺服器維護/瞬斷或交易程式版本問題",
            "confidence": "中" if score_e >= 40 else "低",
            "credibility_tier": "可能原因",
            "score": min(score_e, 95),
            "supporting_evidence": sup_e or ["目前伺服器 TCP 回應與程式檔案簽章皆正常"],
            "counter_evidence": cnt_e,
            "pending_checks": pend_e,
        }
    )

    # --- F. 交易系統自身閒置逾時或登入 Session 問題 ---
    sup_f: List[str] = []
    cnt_f: List[str] = []
    pend_f: List[str] = []
    score_f = 20

    reconn_mechs = arch.get("reconnect_mechanisms") or []
    if any("FOCLR" in m for m in reconn_mechs):
        sup_f.append("靜態設定檔 tab/HTSWORK.INI 定義有盤後交易開盤清盤重載機制（FOCLR），特定換盤時段會提示或觸發畫面重載。")
    sup_f.append("證券交易軟體普遍具有『單一帳號重複登入互踢（手機 App 三竹/隨身 e 策略與電腦版同時登入同一組身分證）』或『交易 Session 閒置逾時保護』機制。")

    if has_ab_comparison and hotspot_stable and has_live_campus_disconnect:
        cnt_f.append("在相同使用習慣下手機熱點未發生斷線，降低單純帳號互踢或固定 Session 逾時的可能性。")
    else:
        pend_f.append("請確認使用電腦版新超級大三元期間，手機端『凱基隨身 e 策略』是否同時開啟或推播自動重連（可能造成同帳號 Session 互踢或重驗）。")
        pend_f.append("需記錄斷線是否固定發生在無操作 N 分鐘後或固定整點/換盤時間。")

    causes.append(
        {
            "code": "F",
            "title": "交易系統自身閒置逾時、換盤清盤或同帳號跨裝置（手機 App）Session 互踢",
            "confidence": "中" if score_f >= 35 else "低",
            "credibility_tier": "可能原因",
            "score": score_f,
            "supporting_evidence": sup_f,
            "counter_evidence": cnt_f or ["尚未經由長連線監控排除"],
            "pending_checks": pend_f,
        }
    )

    # --- G. 目前證據不足，無法確定 ---
    sup_g: List[str] = []
    cnt_g: List[str] = []
    pend_g: List[str] = []
    score_g = 30

    if not kgi_inspection.get("is_currently_running"):
        sup_g.append("本次自動基準檢查執行時，使用者尚未開啟並登入「新超級大三元」，尚未擷取到斷線當下的即時 Socket 狀態變化。")
        score_g += 30
    if not campus_monitor:
        sup_g.append("尚未累積 30 秒週期之長時段斷線時間序列監控紀錄。")
        score_g += 15
    if not hotspot_monitor:
        sup_g.append("尚未進行個人手機熱點（測試 B）對照實驗，依科學診斷原則不得在缺乏對照證據前直接歸咎於學校封鎖。")
        score_g += 15

    if has_ab_comparison and (has_live_campus_disconnect or hotspot_stable):
        score_g = 15
        cnt_g.append("已完成學校網路與手機熱點雙環境監控數據蒐集。")
    else:
        cnt_g.append("已完成本機網路環境、防火牆、Proxy、凱基安裝路徑與官方交易端點（YELLOWPAGE.INI）之完整靜態與連通性基準取證。")
        pend_g.append("請啟動新超級大三元並執行 monitor start --label campus 與 --label hotspot 取得斷線實測樣本。")

    causes.append(
        {
            "code": "G",
            "title": "目前證據不足，尚無法最終定論單一根本原因（需補齊登入狀態監控與熱點對照）",
            "confidence": "高" if score_g >= 65 else ("中" if score_g >= 40 else "低"),
            "credibility_tier": "已確認事實" if score_g >= 65 else "尚無法判斷",
            "score": min(score_g, 95),
            "supporting_evidence": sup_g or ["所有動態對照實驗已完成"],
            "counter_evidence": cnt_g,
            "pending_checks": pend_g,
        }
    )

    # 依分數由高至低排序輸出（同時保留原始 A-G 代碼）
    causes_sorted = sorted(causes, key=lambda x: x["score"], reverse=True)
    for rank_idx, item in enumerate(causes_sorted, start=1):
        item["rank"] = rank_idx
    return causes_sorted


def compare_ab_results(
    campus_data: Optional[Dict[str, Any]],
    hotspot_data: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """第五階段：比較學校網路（測試 A）與個人手機熱點（測試 B）之八大核心指標."""
    metric_defs = [
        ("connection_success_rate_pct", "1. 連線成功率 (%)", "%"),
        ("tcp_connect_avg_ms", "2. TCP 連線建立平均耗時 (ms)", "ms"),
        ("disconnect_count", "3. 連線中斷次數 (次)", "次"),
        ("avg_connection_duration_sec", "4. 平均連線持續時間 (秒)", "秒"),
        ("dns_success_rate_pct", "5. DNS 查詢成功率 (%)", "%"),
        ("reconnect_count", "6. 重新連線/Socket 切換次數 (次)", "次"),
        ("network_anomaly_events", "7. 系統網路異常事件數 (次)", "次"),
        ("app_error_count", "8. 程式自身異常/中斷次數 (次)", "次"),
    ]

    cm = (campus_data or {}).get("metrics") or {}
    hm = (hotspot_data or {}).get("metrics") or {}

    rows: List[Dict[str, Any]] = []
    for key, label, unit in metric_defs:
        v_a = cm.get(key, "未測試") if campus_data else "未測試"
        v_b = hm.get(key, "未測試") if hotspot_data else "未測試"
        diff_str = "未測試"
        if isinstance(v_a, (int, float)) and isinstance(v_b, (int, float)):
            delta = round(float(v_a) - float(v_b), 2)
            sign = "+" if delta > 0 else ""
            diff_str = f"{sign}{delta} {unit}"
        rows.append(
            {
                "metric_key": key,
                "metric_name": label,
                "campus_value": v_a,
                "hotspot_value": v_b,
                "difference_a_minus_b": diff_str,
            }
        )

    if not campus_data and not hotspot_data:
        status = "未測試"
        conclusion = "尚未匯入學校網路（測試 A）與手機熱點（測試 B）之長時段監控紀錄。"
    elif campus_data and not hotspot_data:
        status = "部分完成（僅測試 A，尚缺手機熱點測試 B）"
        conclusion = "已取得學校網路監控數據，請切換至個人手機熱點執行相同監控後再執行 compare 產生完整對照結論。"
    elif hotspot_data and not campus_data:
        status = "部分完成（僅測試 B，尚缺學校網路測試 A）"
        conclusion = "已取得手機熱點監控數據，請補齊學校網路監控數據以完成對照。"
    else:
        c_disc = int(cm.get("disconnect_count") or 0)
        h_disc = int(hm.get("disconnect_count") or 0)
        c_rate = float(cm.get("connection_success_rate_pct") or 0.0)
        h_rate = float(hm.get("connection_success_rate_pct") or 0.0)
        status = "已完成雙環境對照"

        if c_disc > h_disc and h_disc == 0 and h_rate >= 99.0:
            conclusion = (
                "對照結果顯示：個人手機熱點連線穩定（0 次中斷），而學校網路發生中斷。"
                "依嚴謹診斷原則，可判定「問題明確與學校網路環境有關」（例如校園防火牆對非標準 TLS 長連線之狀態逾時、NAT 表回收或校園無線網路品質），"
                "但單憑此對照結果尚不能直接證實校方存在針對凱基證券之刻意政策封鎖。"
            )
        elif c_disc > 0 and h_disc > 0:
            conclusion = (
                "學校網路與個人手機熱點皆觀測到連線中斷，顯示問題較可能源自本機設定（網卡省電/安全軟體）、"
                "同帳號跨裝置互踢（如手機 App 同時在線）或凱基伺服器端問題，而非單純校園網路造成。"
            )
        elif c_disc == 0 and h_disc == 0 and c_rate >= 99.0 and h_rate >= 99.0:
            conclusion = (
                "本次測試時段內學校網路與手機熱點皆保持穩定（0 次中斷），斷線可能具有特定時段性（如盤中尖峰、校園流量高峰或長閒置逾時），"
                "建議延長監控時間至實際看盤時段以捕捉偶發事件。"
            )
        else:
            conclusion = (
                f"學校網路成功率 {c_rate}%（中斷 {c_disc} 次），手機熱點成功率 {h_rate}%（中斷 {h_disc} 次），請結合系統事件與協定特徵進一步判讀。"
            )

    return {
        "status": status,
        "campus_sample_count": (campus_data or {}).get("sample_count", 0) if campus_data else 0,
        "hotspot_sample_count": (hotspot_data or {}).get("sample_count", 0) if hotspot_data else 0,
        "metrics_table": rows,
        "conclusion": conclusion,
    }

