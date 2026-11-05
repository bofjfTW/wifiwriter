"""診斷分析引擎 (v0.2)：事件分類、TLS 細分、真實 Socket 統計、科學 A/B 驗證與證據分級."""

from __future__ import annotations

import statistics
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from src.privacy import mask_ip_strict, sanitize_text

# 執行與測試狀態標準常數 (Section 八)
STATUS_NOT_TESTED = "NOT_TESTED"
STATUS_FAILED = "FAILED"
STATUS_PARTIAL = "PARTIAL"
STATUS_SUCCESS = "SUCCESS"

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

# 第三階段 P0：八大標準監控事件分類 (Section 三)
EV_NETWORK_INTERFACE_DOWN = "NETWORK_INTERFACE_DOWN"
EV_CONTROL_ENDPOINT_FAILURE = "CONTROL_ENDPOINT_FAILURE"
EV_KGI_PROBE_FAILURE = "KGI_PROBE_FAILURE"
EV_KGI_SOCKET_DISCONNECTED = "KGI_SOCKET_DISCONNECTED"
EV_KGI_PROCESS_EXITED = "KGI_PROCESS_EXITED"
EV_KGI_APP_DISCONNECT_REPORTED = "KGI_APPLICATION_DISCONNECT_REPORTED"
EV_KGI_RECONNECTED = "KGI_RECONNECTED"
EV_UNKNOWN_EVENT = "UNKNOWN_EVENT"

ALL_EVENT_TYPES = {
    EV_NETWORK_INTERFACE_DOWN,
    EV_CONTROL_ENDPOINT_FAILURE,
    EV_KGI_PROBE_FAILURE,
    EV_KGI_SOCKET_DISCONNECTED,
    EV_KGI_PROCESS_EXITED,
    EV_KGI_APP_DISCONNECT_REPORTED,
    EV_KGI_RECONNECTED,
    EV_UNKNOWN_EVENT,
}

# 第四階段 P0：TLS 交握細分狀態與協定類型 (Section 四)
TLS_OK = "TLS_OK"
TLS_NOT_TESTED = "TLS_NOT_TESTED"
TLS_HANDSHAKE_TIMEOUT = "TLS_HANDSHAKE_TIMEOUT"
TLS_HANDSHAKE_RESET = "TLS_HANDSHAKE_RESET"
TLS_HANDSHAKE_EOF = "TLS_HANDSHAKE_EOF"
TLS_CERT_VERIFY_FAILED = "TLS_CERT_VERIFY_FAILED"
TLS_PROTOCOL_ERROR = "TLS_PROTOCOL_ERROR"

PROTO_STANDARD_TLS = "STANDARD_TLS"
PROTO_UNKNOWN = "UNKNOWN"

# 證據可信度三級標準 (Section 四 & 十)
TIER_CONFIRMED_FACT = "已確認事實"
TIER_CONDITIONAL_INFERENCE = "有條件支持的推論"
TIER_UNVERIFIED_HYPOTHESIS = "尚未驗證假設"

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
    """遮罩本機、內網或校園端點 IP 位址，保留與舊版介面相容並強化遮罩."""
    if not ip_str:
        return ""
    val = ip_str.strip()
    if val in WELL_KNOWN_PUBLIC_DNS:
        return val
    return mask_ip_strict(val, preserve_public_target=preserve_public_target)


def mask_sensitive_text(
    text: str,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
) -> str:
    """遮罩字串中之使用者帳號、主機名稱、密碼/Token/Cookie、身分證、MAC 與內網 IP."""
    return sanitize_text(text, username=username, hostname=hostname, mask_all_private_ips=True)


def _parse_iso_ts(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        cleaned = ts_str.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        return datetime.fromisoformat(cleaned)
    except Exception:
        return None


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

    intermittent = bool(entry.get("intermittent", False)) or (0 < tcp_ok_cnt < tcp_total_cnt)
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
            "reason": f"TCP 連通但 TLS 憑證驗證異常（{tls.get('error', '')}），需確認是否為中間設備憑證替換或本機時間/憑證問題",
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
            "reason": "收到 HTTP 403，但憑證為官方簽發且無攔截頁特徵，常見於目標站台 WAF/CDN 對非瀏覽器請求之保護，不能直接視為學校封鎖",
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
            "reason": f"主站可正常存取（HTTP {base_code}），但針對 {ftype} 下載路徑連線遭中斷或逾時，疑似檔案型態過濾或端點連線中斷",
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
    """分析凱基伺服器端點探測結果 (v0.2)：細分 TLS 狀態，嚴禁將 TLS 失敗直接推論為專屬二進位協定."""
    total = len(endpoint_probes)
    dns_ok_list = [p for p in endpoint_probes if p.get("dns_ok")]
    tcp_ok_list = [p for p in endpoint_probes if p.get("tcp_ok_count", 0) > 0]
    rst_observed = [p for p in endpoint_probes if p.get("tcp_rst_observed")]

    tls_status_counts: Dict[str, int] = {
        TLS_OK: 0,
        TLS_HANDSHAKE_TIMEOUT: 0,
        TLS_HANDSHAKE_RESET: 0,
        TLS_HANDSHAKE_EOF: 0,
        TLS_CERT_VERIFY_FAILED: 0,
        TLS_PROTOCOL_ERROR: 0,
        TLS_NOT_TESTED: 0,
    }
    unknown_proto_endpoints: List[Dict[str, Any]] = []
    mitm_endpoints: List[str] = []
    source_counts: Dict[str, int] = {
        "observed_active": 0,
        "static_ini_candidate": 0,
        "unverified_remote": 0,
    }

    all_rtts: List[float] = []
    for p in endpoint_probes:
        ep_source = str(p.get("endpoint_source") or "static_ini_candidate")
        if ep_source in source_counts:
            source_counts[ep_source] += 1
        else:
            source_counts["unverified_remote"] += 1

        for r in p.get("tcp_rtts_ms", []):
            if isinstance(r, (int, float)):
                all_rtts.append(float(r))

        tls_state = p.get("tls_probe") or {}
        tls_status = str(tls_state.get("tls_status") or "")
        if not tls_status:
            if not tls_state.get("tested", False):
                tls_status = TLS_NOT_TESTED
            elif tls_state.get("tls_handshake_ok", False):
                tls_status = TLS_OK
            else:
                tls_status = TLS_PROTOCOL_ERROR

        tls_status_counts[tls_status] = tls_status_counts.get(tls_status, 0) + 1

        app_proto = str(tls_state.get("application_protocol") or (PROTO_STANDARD_TLS if tls_status == TLS_OK else PROTO_UNKNOWN))
        if p.get("tcp_ok_count", 0) > 0 and app_proto == PROTO_UNKNOWN:
            unknown_proto_endpoints.append(
                {
                    "fqdn": p.get("fqdn"),
                    "ip": p.get("primary_ip"),
                    "port": p.get("port"),
                    "endpoint_source": ep_source,
                    "tls_status": tls_status,
                    "application_protocol": PROTO_UNKNOWN,
                    "observed_detail": tls_state.get("detail", ""),
                }
            )
        if tls_status in (TLS_OK, TLS_CERT_VERIFY_FAILED) and any(
            k in str(tls_state.get("issuer", "")).lower() for k in MITM_CERT_ISSUER_KEYWORDS
        ):
            mitm_endpoints.append(str(p.get("fqdn") or ""))

    avg_rtt = round(statistics.mean(all_rtts), 2) if all_rtts else None
    max_rtt = round(max(all_rtts), 2) if all_rtts else None
    stdev_rtt = round(statistics.stdev(all_rtts), 2) if len(all_rtts) >= 2 else 0.0

    return {
        "total_endpoints_tested": total,
        "dns_reachable_count": len(dns_ok_list),
        "tcp_reachable_count": len(tcp_ok_list),
        "endpoint_source_counts": source_counts,
        "tcp_rst_endpoints": [p.get("fqdn") for p in rst_observed],
        "tls_status_counts": tls_status_counts,
        "unknown_protocol_endpoints": unknown_proto_endpoints,
        "mitm_cert_endpoints": mitm_endpoints,
        "avg_tcp_rtt_ms": avg_rtt,
        "max_tcp_rtt_ms": max_rtt,
        "tcp_rtt_jitter_ms": stdev_rtt,
    }


def analyze_monitor_dataset(
    samples: List[Dict[str, Any]],
    manual_marks: Optional[List[Dict[str, Any]]] = None,
    run_id: str = "run_unknown",
    label: str = "campus",
    network_profile: str = "",
    passive_interval_sec: int = 5,
    active_probe_interval_sec: int = 30,
    run_status: str = STATUS_SUCCESS,
    completion_reason: str = "completed",
) -> Dict[str, Any]:
    """
    核心監控序列分析器 (Section 三 & 五)：
    嚴格分離 8 大事件類型、被動 Socket 生死週期、主動探測結果與手動斷線標記關聯。
    """
    marks = sorted(manual_marks or [], key=lambda m: str(m.get("timestamp", "")))
    timeline: List[Dict[str, Any]] = []

    event_counts: Dict[str, int] = {ev: 0 for ev in ALL_EVENT_TYPES}

    observed_socket_open_count = 0
    observed_socket_close_count = 0
    socket_birth_ts: Dict[str, datetime] = {}
    identifiable_durations: List[float] = []

    prev_sockets: set[str] = set()
    prev_kgi_running = False
    prev_net_up = True
    kgi_running_samples = 0
    max_established_sockets = 0

    kgi_dns_total = 0
    kgi_dns_ok = 0
    kgi_tcp_total = 0
    kgi_tcp_ok = 0
    kgi_tcp_rtts: List[float] = []
    ctrl_tcp_total = 0
    ctrl_tcp_ok = 0

    net_anomaly_events = 0
    has_active_app_disconnect = False

    def _emit_event(
        ts: str,
        proc_id_str: str,
        ev_type: str,
        obs_state: str,
        sup_ev: str,
        alt_exp: str,
        conf_tier: str,
        ev_source: str,
    ) -> None:
        if ev_type not in event_counts:
            ev_type = EV_UNKNOWN_EVENT
        event_counts[ev_type] += 1
        timeline.append(
            {
                "timestamp": ts,
                "run_id": run_id,
                "network_profile": network_profile or label,
                "process_identity": proc_id_str,
                "event_type": ev_type,
                "observed_state": obs_state,
                "supporting_evidence": sup_ev,
                "alternative_explanations": alt_exp,
                "confidence_classification": conf_tier,
                "evidence_source": ev_source,
            }
        )

    for idx, sm in enumerate(samples):
        ts_str = str(sm.get("timestamp") or "")
        ts_dt = _parse_iso_ts(ts_str)
        net_up = bool(sm.get("net_up", True))
        kgi_running = bool(sm.get("kgi_running", False))
        verified_proc_summary = str(
            sm.get("process_identity_summary")
            or ("verified_kgi_process" if kgi_running else "not_running")
        )
        est_count = int(sm.get("kgi_established_sockets") or 0)
        raw_sock_list = sm.get("kgi_socket_keys")
        if isinstance(raw_sock_list, list):
            cur_sockets = {str(s) for s in raw_sock_list if s}
            est_count = max(est_count, len(cur_sockets))
        else:
            cur_sockets = set()

        if kgi_running:
            kgi_running_samples += 1
        if est_count > max_established_sockets:
            max_established_sockets = est_count

        if sm.get("bssid_roamed"):
            net_anomaly_events += 1
        win_ev_cnt = int(sm.get("system_events_count") or 0)
        net_anomaly_events += win_ev_cnt

        # 1. 本機網路介面狀態變化 (NETWORK_INTERFACE_DOWN)
        if not net_up and (idx == 0 or prev_net_up):
            _emit_event(
                ts=ts_str,
                proc_id_str=verified_proc_summary,
                ev_type=EV_NETWORK_INTERFACE_DOWN,
                obs_state="本機主要網路介面中斷或失去預設閘道",
                sup_ev=f"sample_index={sm.get('sample_index', idx + 1)}, net_up=False, interface={sm.get('primary_interface', '')}",
                alt_exp="實體網路線鬆脫、交換器重啟、Wi-Fi AP 斷開或網卡驅動程式重置",
                conf_tier=TIER_CONFIRMED_FACT,
                ev_source="passive_sample:Get-NetIPConfiguration",
            )

        # 2. 凱基程序退出 (KGI_PROCESS_EXITED) — 與 Socket 中斷嚴格分開！
        process_exited_this_tick = prev_kgi_running and (not kgi_running)
        if process_exited_this_tick:
            # 程序退出導致消失的 Socket 不計入獨立網路斷線，並結算已知連線時間
            for sk in prev_sockets:
                socket_birth_ts.pop(sk, None)
            _emit_event(
                ts=ts_str,
                proc_id_str="exited_previous_kgi_process",
                ev_type=EV_KGI_PROCESS_EXITED,
                obs_state="凱基交易軟體程序已退出（非網路層既有程序連線中斷）",
                sup_ev=f"sample_index={sm.get('sample_index', idx + 1)}: kgi_running 由 True 轉為 False",
                alt_exp="使用者手動關閉程式、自動更新重啟或程式異常崩潰",
                conf_tier=TIER_CONFIRMED_FACT,
                ev_source="passive_sample:ProcessIdentityMonitor",
            )
            prev_sockets = set()
        else:
            # 3. 追蹤既有程序之 TCP Socket 開啟與關閉
            if idx == 0:
                # 監控啟動時已存在的連線無法得知真實建立時間，不納入誕生計數與精確時長
                prev_sockets = set(cur_sockets)
            else:
                opened = cur_sockets - prev_sockets
                closed = prev_sockets - cur_sockets
                if opened:
                    observed_socket_open_count += len(opened)
                    if ts_dt:
                        for sk in opened:
                            socket_birth_ts[sk] = ts_dt
                    if has_active_app_disconnect and kgi_running and len(cur_sockets) > 0:
                        has_active_app_disconnect = False
                        _emit_event(
                            ts=ts_str,
                            proc_id_str=verified_proc_summary,
                            ev_type=EV_KGI_RECONNECTED,
                            obs_state="於交易斷線回報後觀測到凱基程序重新建立 Established TCP Socket",
                            sup_ev=f"新增 {len(opened)} 條 Established Socket，目前總數={len(cur_sockets)}",
                            alt_exp="程式內建 DISPROXY/背景重連完成或使用者手動觸發重新連線",
                            conf_tier=TIER_CONDITIONAL_INFERENCE,
                            ev_source="passive_sample:Get-NetTCPConnection",
                        )

                if closed and kgi_running:
                    observed_socket_close_count += len(closed)
                    for sk in closed:
                        b_dt = socket_birth_ts.pop(sk, None)
                        if b_dt and ts_dt and (ts_dt >= b_dt):
                            identifiable_durations.append(round((ts_dt - b_dt).total_seconds(), 2))

                    remaining_cnt = len(cur_sockets)
                    app_rep_flag = bool(sm.get("app_disconnect_reported", False))
                    if app_rep_flag:
                        has_active_app_disconnect = True
                        _emit_event(
                            ts=ts_str,
                            proc_id_str=verified_proc_summary,
                            ev_type=EV_KGI_APP_DISCONNECT_REPORTED,
                            obs_state="應用程式狀態確認交易連線中斷，且同步觀測到既有 TCP Socket 關閉",
                            sup_ev=f"關閉 {len(closed)} 條 Socket，剩餘 Established={remaining_cnt}",
                            alt_exp="遠端伺服器關閉、校園防火牆/NAT 狀態回收或本機網路瞬斷",
                            conf_tier=TIER_CONFIRMED_FACT,
                            ev_source="app_state+Get-NetTCPConnection",
                        )
                    else:
                        state_desc = (
                            "觀察到凱基程序既有 TCP Socket 結束（尚無應用層斷線回報；可能為短查詢連線正常輪替，不直接計入已確認交易斷線）"
                            if remaining_cnt > 0
                            else "觀察到凱基程序全部既有 TCP Socket 結束歸零（尚待使用者標記或應用層狀態確認是否發生交易 Session 斷線）"
                        )
                        _emit_event(
                            ts=ts_str,
                            proc_id_str=verified_proc_summary,
                            ev_type=EV_KGI_SOCKET_DISCONNECTED,
                            obs_state=state_desc,
                            sup_ev=f"關閉 {len(closed)} 條既有 Socket，剩餘 Established={remaining_cnt}",
                            alt_exp="HTS 行情/回報子通道正常連線更新、伺服器分流切換，或網路中途連線被切斷",
                            conf_tier=TIER_CONFIRMED_FACT,
                            ev_source="passive_sample:Get-NetTCPConnection",
                        )

                prev_sockets = set(cur_sockets)

        # 4. 主動探測事件評估（僅在主動探測週期 active_probe_executed == True 時執行）
        active_ran = bool(sm.get("active_probe_executed", ("kgi_quote_probe" in sm or "kgi_trade_probe" in sm)))
        if active_ran:
            q_probe = sm.get("kgi_quote_probe")
            t_probe = sm.get("kgi_trade_probe")
            c_probe = sm.get("control_probe")

            kgi_probe_failures: List[str] = []
            for p_name, p_obj in (("Quote", q_probe), ("Trade", t_probe)):
                if isinstance(p_obj, dict) and p_obj:
                    kgi_dns_total += 1
                    kgi_tcp_total += 1
                    if p_obj.get("dns_ok"):
                        kgi_dns_ok += 1
                    if p_obj.get("tcp_ok"):
                        kgi_tcp_ok += 1
                        if isinstance(p_obj.get("tcp_ms"), (int, float)):
                            kgi_tcp_rtts.append(float(p_obj["tcp_ms"]))
                    else:
                        kgi_probe_failures.append(f"{p_name}:{p_obj.get('error', 'FAIL')}")

            ctrl_failed = False
            ctrl_err = ""
            if isinstance(c_probe, dict) and c_probe:
                ctrl_tcp_total += 1
                if c_probe.get("tcp_ok"):
                    ctrl_tcp_ok += 1
                else:
                    ctrl_failed = True
                    ctrl_err = str(c_probe.get("error", "FAIL"))

            if kgi_probe_failures:
                obs_msg = (
                    "探測失敗，尚無交易程式斷線證據（凱基程式目前未啟動，單獨探測異常不得計為交易軟體斷線）"
                    if not kgi_running
                    else "對凱基端點的獨立主動 TCP/DNS 探測失敗（若無應用層或手動斷線證據，僅列為探測異常，不直接宣稱交易 Session 斷線）"
                )
                _emit_event(
                    ts=ts_str,
                    proc_id_str=verified_proc_summary,
                    ev_type=EV_KGI_PROBE_FAILURE,
                    obs_state=obs_msg,
                    sup_ev=f"主動探測異常: {'; '.join(kgi_probe_failures)} (kgi_running={kgi_running}, est_sockets={est_count})",
                    alt_exp="目標探測埠連線速率限制、暫時性封包遺失、DNS 逾時或防火牆攔截新連線",
                    conf_tier=TIER_CONFIRMED_FACT,
                    ev_source="active_probe:LowLoadTcpDnsProbe",
                )

            if ctrl_failed:
                _emit_event(
                    ts=ts_str,
                    proc_id_str=verified_proc_summary,
                    ev_type=EV_CONTROL_ENDPOINT_FAILURE,
                    obs_state="公開對照端點連線失敗（凱基狀態已獨立評估，不混入凱基斷線計數）",
                    sup_ev=f"對照組主動探測失敗 ({ctrl_err}), kgi_running={kgi_running}, kgi_est_sockets={est_count}",
                    alt_exp="對外一般網際網路瞬斷、校園出口壅塞或對照網站 CDN 節點異常",
                    conf_tier=TIER_CONFIRMED_FACT,
                    ev_source="active_probe:ControlEndpointProbe",
                )

        if sm.get("unclassified_anomaly"):
            _emit_event(
                ts=ts_str,
                proc_id_str=verified_proc_summary,
                ev_type=EV_UNKNOWN_EVENT,
                obs_state="觀測到無法單一歸類之狀態異常，目前證據不足",
                sup_ev=str(sm.get("unclassified_anomaly")),
                alt_exp="取樣邊界狀態轉換或系統短暫延遲",
                conf_tier=TIER_UNVERIFIED_HYPOTHESIS,
                ev_source="monitor:anomaly_detector",
            )

        prev_kgi_running = kgi_running
        prev_net_up = net_up

    # 5. 整合使用者手動斷線/重連標記 (Section 5.3 & 驗收情境二)
    user_reported_disconnects = 0
    user_reported_reconnects = 0
    mark_correlations: List[Dict[str, Any]] = []

    for mk in marks:
        mk_ts_str = str(mk.get("timestamp") or "")
        mk_dt = _parse_iso_ts(mk_ts_str)
        mk_ev = str(mk.get("event") or "").lower()
        mk_note = mask_sensitive_text(str(mk.get("note") or ""))

        # 尋找標記前後 ±60 秒內之被動/主動樣本建立可追溯關聯
        nearby_samples: List[Tuple[float, Dict[str, Any]]] = []
        if mk_dt:
            for sm in samples:
                s_dt = _parse_iso_ts(str(sm.get("timestamp") or ""))
                if s_dt:
                    try:
                        diff_s = abs((s_dt - mk_dt).total_seconds())
                        if diff_s <= 60.0:
                            nearby_samples.append((diff_s, sm))
                    except TypeError:
                        pass
        nearby_samples.sort(key=lambda x: x[0])

        nearest = nearby_samples[0][1] if nearby_samples else (mk.get("instant_snapshot") or {})
        near_proc = str(
            nearest.get("process_identity_summary")
            or ("verified_kgi_process" if nearest.get("kgi_running") else "no_verified_kgi_process")
        )
        near_net_up = nearest.get("net_up")
        near_est = nearest.get("kgi_established_sockets")
        near_q = nearest.get("kgi_quote_probe") or {}
        near_t = nearest.get("kgi_trade_probe") or {}
        near_c = nearest.get("control_probe") or {}
        near_sys_evs = nearest.get("system_event_types") or []

        corr_summary = (
            f"鄰近樣本數={len(nearby_samples)} | kgi_running={nearest.get('kgi_running')} | "
            f"established_sockets={near_est} | net_up={near_net_up} | "
            f"quote_probe(dns={near_q.get('dns_ok')},tcp={near_q.get('tcp_ok')}) | "
            f"trade_probe(dns={near_t.get('dns_ok')},tcp={near_t.get('tcp_ok')}) | "
            f"control_tcp={near_c.get('tcp_ok')} | win_events={near_sys_evs}"
        )
        if mk_note:
            corr_summary += f" | note={mk_note}"

        mark_correlations.append(
            {
                "mark_timestamp": mk_ts_str,
                "mark_event": mk_ev,
                "matched_window_sample_count": len(nearby_samples),
                "nearest_sample_timestamp": nearest.get("timestamp", ""),
                "kgi_running_at_mark": nearest.get("kgi_running"),
                "established_sockets_at_mark": near_est,
                "net_up_at_mark": near_net_up,
                "quote_probe_at_mark": near_q,
                "trade_probe_at_mark": near_t,
                "control_probe_at_mark": near_c,
                "windows_events_at_mark": near_sys_evs,
                "correlation_summary": corr_summary,
            }
        )

        if mk_ev in ("kgi-disconnected", "disconnected"):
            user_reported_disconnects += 1
            _emit_event(
                ts=mk_ts_str,
                proc_id_str=near_proc,
                ev_type=EV_KGI_APP_DISCONNECT_REPORTED,
                obs_state="使用者手動標記觀察到新超級大三元顯示斷線（已關聯前後程序、Socket、DNS/TCP 與系統網路狀態）",
                sup_ev=corr_summary,
                alt_exp="若 net_up=True 且 control_tcp=True，偏向單一服務長連線中斷或帳號 Session 重置；若 net_up=False 則為本機底層斷網",
                conf_tier=TIER_CONFIRMED_FACT,
                ev_source="user_cli_mark:diagnostics.py mark --event kgi-disconnected",
            )
        elif mk_ev in ("kgi-reconnected", "reconnected"):
            user_reported_reconnects += 1
            _emit_event(
                ts=mk_ts_str,
                proc_id_str=near_proc,
                ev_type=EV_KGI_RECONNECTED,
                obs_state="使用者手動標記新超級大三元已恢復交易/行情連線",
                sup_ev=corr_summary,
                alt_exp="軟體自動重連成功或使用者手動重新連線成功",
                conf_tier=TIER_CONFIRMED_FACT,
                ev_source="user_cli_mark:diagnostics.py mark --event kgi-reconnected",
            )
        else:
            _emit_event(
                ts=mk_ts_str,
                proc_id_str=near_proc,
                ev_type=EV_UNKNOWN_EVENT,
                obs_state=f"未識別之標記事件 ({mk_ev})",
                sup_ev=corr_summary,
                alt_exp="自訂備註標記",
                conf_tier=TIER_UNVERIFIED_HYPOTHESIS,
                ev_source="user_cli_mark",
            )

    timeline.sort(key=lambda e: str(e.get("timestamp", "")))

    # 計算總監控時長（秒）
    total_duration_sec = 0.0
    if len(samples) >= 2:
        t_first = _parse_iso_ts(str(samples[0].get("timestamp", "")))
        t_last = _parse_iso_ts(str(samples[-1].get("timestamp", "")))
        if t_first and t_last and t_last >= t_first:
            total_duration_sec = round((t_last - t_first).total_seconds(), 1)
    if total_duration_sec <= 0.0 and samples:
        total_duration_sec = float(len(samples) * passive_interval_sec)

    hours_factor = (total_duration_sec / 3600.0) if total_duration_sec > 0 else 0.0

    # Section 5.4: 嚴禁使用 total_duration / (disconnect_count + 1)！
    avg_identifiable_sock_dur: Optional[float] = (
        round(statistics.mean(identifiable_durations), 2) if identifiable_durations else None
    )
    sock_dur_display = (
        f"{avg_identifiable_sock_dur} 秒（基於 {len(identifiable_durations)} 條完整觀測生滅之 Socket）"
        if avg_identifiable_sock_dur is not None
        else "無法精確估計"
    )

    indep_probe_rate = (
        round(kgi_tcp_ok * 100.0 / kgi_tcp_total, 2) if kgi_tcp_total > 0 else None
    )
    indep_dns_rate = (
        round(kgi_dns_ok * 100.0 / kgi_dns_total, 2) if kgi_dns_total > 0 else None
    )
    ctrl_probe_rate = (
        round(ctrl_tcp_ok * 100.0 / ctrl_tcp_total, 2) if ctrl_tcp_total > 0 else None
    )
    avg_tcp_ms = round(statistics.mean(kgi_tcp_rtts), 2) if kgi_tcp_rtts else None
    max_tcp_ms = round(max(kgi_tcp_rtts), 2) if kgi_tcp_rtts else None

    # 唯有具備可信應用層/使用者確認證據之 KGI_APPLICATION_DISCONNECT_REPORTED 才列入「已確認交易斷線」
    confirmed_disconnect_cnt = event_counts[EV_KGI_APP_DISCONNECT_REPORTED]

    def _per_hour(cnt: int) -> Optional[float]:
        if hours_factor <= 0:
            return None
        return round(cnt / hours_factor, 2)

    metrics = {
        # 新版 v0.2 精確統計指標
        "confirmed_trading_disconnect_count": confirmed_disconnect_cnt,
        "confirmed_disconnects_per_hour": _per_hour(confirmed_disconnect_cnt),
        "user_reported_disconnect_count": user_reported_disconnects,
        "user_reported_reconnect_count": user_reported_reconnects,
        "observed_socket_open_count": observed_socket_open_count,
        "observed_socket_close_count": observed_socket_close_count,
        "socket_closes_per_hour": _per_hour(observed_socket_close_count),
        "identifiable_socket_count": len(identifiable_durations),
        "avg_identifiable_socket_duration_sec": avg_identifiable_sock_dur,
        "identifiable_connection_duration_display": sock_dur_display,
        "independent_kgi_probe_success_rate_pct": indep_probe_rate,
        "independent_dns_success_rate_pct": indep_dns_rate,
        "independent_control_probe_success_rate_pct": ctrl_probe_rate,
        "kgi_probe_failures_per_hour": _per_hour(event_counts[EV_KGI_PROBE_FAILURE]),
        "tcp_connect_avg_ms": avg_tcp_ms,
        "tcp_connect_max_ms": max_tcp_ms,
        "kgi_running_sample_count": kgi_running_samples,
        "max_established_sockets": max_established_sockets,
        "network_anomaly_events": net_anomaly_events,
        "event_counts": event_counts,
        "unknown_event_count": event_counts[EV_UNKNOWN_EVENT],
        # 相容欄位（但語意已修正為真實確認斷線與真實可辨識時長，不再膨脹誤判）
        "connection_success_rate_pct": indep_probe_rate,
        "dns_success_rate_pct": indep_dns_rate,
        "control_success_rate_pct": ctrl_probe_rate,
        "disconnect_count": confirmed_disconnect_cnt,
        "avg_connection_duration_sec": avg_identifiable_sock_dur if avg_identifiable_sock_dur is not None else "無法精確估計",
        "reconnect_count": event_counts[EV_KGI_RECONNECTED],
        "app_error_count": event_counts[EV_KGI_PROCESS_EXITED],
    }

    data_completeness = (
        "COMPLETE"
        if (run_status == STATUS_SUCCESS and len(samples) > 0 and completion_reason in ("completed", "duration_reached", "manual_stop"))
        else ("EMPTY" if len(samples) == 0 else "INCOMPLETE")
    )

    return {
        "schema_version": "2.0",
        "run_id": run_id,
        "run_status": run_status,
        "completion_reason": completion_reason,
        "data_completeness": data_completeness,
        "label": label,
        "network_profile": network_profile or label,
        "passive_interval_seconds": passive_interval_sec,
        "active_probe_interval_seconds": active_probe_interval_sec,
        "total_duration_sec": total_duration_sec,
        "sample_count": len(samples),
        "metrics": metrics,
        "event_timeline": timeline,
        "mark_correlations": mark_correlations,
    }


def evaluate_root_causes(
    network_env: Dict[str, Any],
    restrictions: Dict[str, Any],
    kgi_inspection: Dict[str, Any],
    kgi_probe_analysis: Dict[str, Any],
    campus_monitor: Optional[Dict[str, Any]] = None,
    hotspot_monitor: Optional[Dict[str, Any]] = None,
    ab_comparison: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    第四階段 4.4 根本原因客觀分類評估 (v0.2 修正版)：
    - 移除任意 0~100 數值信心評分與無根據之「高可信度 / 已證實」標籤
    - 嚴禁因 TCP 443 標準 TLS 交握失敗而推論專屬協定或校園防火牆 App-ID/NAT 回收
    - 每項推論皆附上可追溯之原始觀測欄位來源 (evidence_refs)
    """
    primary_conn = network_env.get("primary_connection") or {}
    conn_type = str(primary_conn.get("connection_type", "Unknown"))
    env_hint = str(primary_conn.get("environment_hint", ""))
    proxy_cfg = network_env.get("proxy_settings") or {}
    fw_cfg = network_env.get("windows_firewall") or {}
    wifi_cfg = (network_env.get("wifi_diagnostics") or {}).get("details") or {}
    events_cfg = network_env.get("recent_network_events") or {}
    vpn_cfg = network_env.get("vpn_auth_and_security") or {}

    rst_eps = kgi_probe_analysis.get("tcp_rst_endpoints") or []
    mitm_eps = kgi_probe_analysis.get("mitm_cert_endpoints") or []
    unknown_proto_eps = kgi_probe_analysis.get("unknown_protocol_endpoints") or []
    tcp_reach = int(kgi_probe_analysis.get("tcp_reachable_count") or 0)
    total_eps = int(kgi_probe_analysis.get("total_endpoints_tested") or 0)

    cm_metrics = (campus_monitor or {}).get("metrics") or {}
    hm_metrics = (hotspot_monitor or {}).get("metrics") or {}
    campus_confirmed_disc = int(
        cm_metrics.get("confirmed_trading_disconnect_count", cm_metrics.get("disconnect_count", 0)) or 0
    )
    hotspot_confirmed_disc = int(
        hm_metrics.get("confirmed_trading_disconnect_count", hm_metrics.get("disconnect_count", 0)) or 0
    )
    ab_valid = bool((ab_comparison or {}).get("is_scientifically_comparable", False))

    causes: List[Dict[str, Any]] = []

    # --- A. 學校網路出口或防火牆問題 ---
    sup_a: List[str] = []
    cnt_a: List[str] = []
    pend_a: List[str] = []
    refs_a: List[str] = ["network_environment.primary_connection", "kgi_probe_analysis"]

    if env_hint == "Campus_TANet_Or_Enterprise_Network":
        sup_a.append("本機網路位址區段具台灣學術網路（TANet）或企業/校園網路環境特徵（來源：primary_connection.environment_hint）。")
    if rst_eps:
        sup_a.append(
            f"對凱基端點進行低負載 TCP 探測時觀測到 TCP Reset：{', '.join(str(x) for x in rst_eps)}（來源：kgi_probe_analysis.tcp_rst_endpoints；惟單憑本機 Socket 錯誤尚無法單獨區分重置封包來自遠端伺服器或中間網路設備）。"
        )
    if ab_valid and campus_confirmed_disc > 0 and hotspot_confirmed_disc == 0:
        sup_a.append(
            f"經有效 A/B 同條件對照實驗，校園網路觀測到 {campus_confirmed_disc} 次已確認交易斷線，而個人手機熱點觀測期間為 0 次（來源：ab_comparison）。"
        )
        refs_a.append("ab_comparison")

    if unknown_proto_eps:
        cnt_a.append(
            f"雖然 {len(unknown_proto_eps)} 個凱基端點在 TCP 443 連通後未完成標準 TLS 交握，但缺乏官方協定規格或封包證據前，應用層協定僅能標記為 UNKNOWN，不得據此聲稱校園防火牆執行應用程式識別（App-ID）或 NAT 閒置回收。"
        )
    if total_eps > 0 and tcp_reach == total_eps and not rst_eps:
        cnt_a.append(
            f"本次探測之全部 {total_eps}/{total_eps} 個凱基端點均完成初次 TCP 三方交握且無 RST，顯示目前不存在針對該組 IP/Port 之靜態完全阻斷。"
        )

    if not ab_valid:
        pend_a.append("尚未完成符合科學驗證條件之「校園網路 vs 手機熱點」長時段登入監控對照。")
    if not kgi_inspection.get("is_currently_running") and not campus_monitor:
        pend_a.append("尚未在交易軟體實際執行並建立連線的狀態下記錄斷線時間線。")

    tier_a = (
        TIER_CONDITIONAL_INFERENCE
        if (ab_valid and campus_confirmed_disc > 0 and hotspot_confirmed_disc == 0)
        else TIER_UNVERIFIED_HYPOTHESIS
    )
    causes.append(
        {
            "code": "A",
            "title": "學校網路出口路徑、NAT 狀態設備或防火牆策略影響",
            "evidence_tier": tier_a,
            "supporting_evidence": sup_a or ["目前無直接證據顯示學校防火牆中斷凱基連線"],
            "counter_evidence": cnt_a or ["尚無反證"],
            "pending_checks": pend_a,
            "evidence_refs": refs_a,
        }
    )

    # --- B. DNS 或 Proxy 問題 ---
    sup_b: List[str] = []
    cnt_b: List[str] = []
    pend_b: List[str] = []
    refs_b: List[str] = ["network_environment.proxy_settings", "network_environment.recent_network_events"]

    has_local_proxy = bool(
        proxy_cfg.get("wininet_proxy_enabled")
        or proxy_cfg.get("wininet_pac_url")
        or (not proxy_cfg.get("winhttp_direct_access", True))
        or proxy_cfg.get("env_proxies")
    )
    if proxy_cfg.get("wininet_proxy_enabled") or proxy_cfg.get("wininet_pac_url"):
        sup_b.append(
            f"本機設定了 WinINET Proxy 或 PAC（Server={proxy_cfg.get('wininet_proxy_server')}, PAC={proxy_cfg.get('wininet_pac_url')}）。"
        )
    else:
        cnt_b.append("本機 WinINET 系統 Proxy 未啟用且未設定 PAC 自動組態網址。")

    if not proxy_cfg.get("winhttp_direct_access", True):
        sup_b.append(f"本機 WinHTTP 非直接存取：{proxy_cfg.get('winhttp_raw')}。")
    else:
        cnt_b.append("本機 WinHTTP 為直接存取（Direct access）。")

    if mitm_eps:
        sup_b.append(f"偵測到第三方資安/代理設備簽發之 TLS 憑證：{', '.join(mitm_eps)}。")
    else:
        cnt_b.append("公開 HTTPS 測試端點之伺服器憑證鏈皆由標準公開 CA 簽發，未觀測到透明 TLS 憑證替換。")

    dns_timeouts = events_cfg.get("dns_client_timeouts") or []
    if dns_timeouts:
        sup_b.append(f"Windows 系統事件日誌於回溯期間記錄到 {len(dns_timeouts)} 筆 DNS Client Event 1014 逾時事件。")
    else:
        cnt_b.append("回溯期間內 Windows 系統日誌無 DNS Client 1014 解析逾時紀錄。")

    if not campus_monitor:
        pend_b.append("需於斷線發生當下比對主動探測之 DNS 解析是否同步失敗。")

    tier_b = TIER_CONDITIONAL_INFERENCE if (has_local_proxy or mitm_eps or dns_timeouts) else TIER_UNVERIFIED_HYPOTHESIS
    causes.append(
        {
            "code": "B",
            "title": "DNS 解析逾時或系統 / 透明 Proxy 介入問題",
            "evidence_tier": tier_b,
            "supporting_evidence": sup_b or ["目前未觀測到 Proxy 設定或 DNS 解析失敗證據"],
            "counter_evidence": cnt_b,
            "pending_checks": pend_b,
            "evidence_refs": refs_b,
        }
    )

    # --- C. 網路品質不佳、封包遺失或 Wi-Fi 漫遊 ---
    sup_c: List[str] = []
    cnt_c: List[str] = []
    pend_c: List[str] = []
    refs_c: List[str] = ["network_environment.primary_connection", "network_environment.recent_network_events"]

    wlan_evs = events_cfg.get("wlan_events") or []
    np_evs = [e for e in (events_cfg.get("network_profile_events") or []) if e.get("id") == 10001]
    sig_pct = wifi_cfg.get("signal_percent")
    nic_down_cnt = int(((cm_metrics.get("event_counts") or {}).get(EV_NETWORK_INTERFACE_DOWN, 0)) or 0)

    if conn_type == "Wi-Fi":
        sup_c.append("目前使用 Wi-Fi 連線，無線環境可能受訊號衰減或基地台（BSSID）漫遊影響。")
        if isinstance(sig_pct, (int, float)) and sig_pct < 65:
            sup_c.append(f"目前 Wi-Fi 訊號強度偏低（{sig_pct}%）。")
        elif isinstance(sig_pct, (int, float)):
            cnt_c.append(f"檢查當下 Wi-Fi 訊號強度為 {sig_pct}%。")
    elif conn_type == "Ethernet":
        cnt_c.append("目前主要連線為有線網路（Ethernet），本次連線可排除 Wi-Fi 訊號與無線漫遊因素。")

    if nic_down_cnt > 0:
        sup_c.append(f"監控期間實際觀測到 {nic_down_cnt} 次本機網路介面中斷事件（NETWORK_INTERFACE_DOWN）。")
        refs_c.append("campus_monitor.event_timeline")
    if wlan_evs:
        sup_c.append(f"回溯期間內 WLAN-AutoConfig 記錄到 {len(wlan_evs)} 筆無線狀態變更事件。")
    if np_evs:
        sup_c.append(f"回溯期間內 NetworkProfile 記錄到 {len(np_evs)} 次網路中斷事件（Event ID 10001）。")

    jitter = float(kgi_probe_analysis.get("tcp_rtt_jitter_ms") or 0.0)
    if jitter > 35.0:
        sup_c.append(f"端點 TCP 建連延遲標準差偏高（{jitter} ms）。")
    elif kgi_probe_analysis.get("avg_tcp_rtt_ms") is not None:
        cnt_c.append(
            f"基準探測期間凱基端點平均 TCP RTT 為 {kgi_probe_analysis.get('avg_tcp_rtt_ms')} ms（標準差 {jitter} ms）。"
        )

    if not campus_monitor:
        pend_c.append("需於監控期間觀察公開對照端點（CONTROL_ENDPOINT_FAILURE）與本機介面（NETWORK_INTERFACE_DOWN）是否與斷線同步發生。")

    tier_c = TIER_CONDITIONAL_INFERENCE if (nic_down_cnt > 0 or np_evs or (conn_type == "Wi-Fi" and wlan_evs)) else TIER_UNVERIFIED_HYPOTHESIS
    causes.append(
        {
            "code": "C",
            "title": "底層網路品質波動、網卡瞬斷或校園 Wi-Fi 漫遊",
            "evidence_tier": tier_c,
            "supporting_evidence": sup_c or ["基準檢查期間未觀測到明顯底層斷網或延遲抖動"],
            "counter_evidence": cnt_c or ["尚無反證"],
            "pending_checks": pend_c,
            "evidence_refs": refs_c,
        }
    )

    # --- D. Windows 本機防火牆、端點安全軟體或網卡省電/睡眠設定 ---
    sup_d: List[str] = []
    cnt_d: List[str] = []
    pend_d: List[str] = []
    refs_d: List[str] = ["network_environment.windows_firewall", "network_environment.network_adapters"]

    kgi_fw_rules = fw_cfg.get("kgi_related_rules") or []
    has_kgi_fw_block = any("Action=Block" in str(r.get("raw_summary", "")) for r in kgi_fw_rules)
    if has_kgi_fw_block:
        sup_d.append("Windows 本機防火牆存在針對凱基相關執行檔之啟用中封鎖（Action=Block）規則。")
    else:
        cnt_d.append("Windows 本機防火牆對外預設為 Allow，且未檢出針對凱基執行檔之封鎖規則。")

    adapters = network_env.get("network_adapters") or []
    pm_enabled_nics = [
        str(a.get("name") or "")
        for a in adapters
        if a.get("status") == "Up"
        and isinstance(a.get("power_management"), dict)
        and str((a.get("power_management") or {}).get("allow_computer_to_turn_off", "")).lower() in ("true", "enabled", "1")
    ]
    if pm_enabled_nics:
        sup_d.append(f"啟用中之網路介面卡（{', '.join(pm_enabled_nics)}）開啟了允許系統關閉裝置省電之設定。")

    sleep_evs = events_cfg.get("power_sleep_events") or []
    if sleep_evs:
        sup_d.append(f"回溯期間內系統記錄到 {len(sleep_evs)} 次睡眠/待命電源狀態切換事件。")

    vpn_procs = vpn_cfg.get("running_vpn_or_proxy_processes") or []
    if vpn_procs:
        sup_d.append(f"偵測到背景執行中之 VPN / 代理程序：{', '.join(vpn_procs)}。")
    else:
        cnt_d.append("未偵測到背景執行中之第三方 VPN 或本地代理程序。")

    tier_d = (
        TIER_CONFIRMED_FACT
        if has_kgi_fw_block
        else (TIER_CONDITIONAL_INFERENCE if (vpn_procs or sleep_evs or pm_enabled_nics) else TIER_UNVERIFIED_HYPOTHESIS)
    )
    causes.append(
        {
            "code": "D",
            "title": "Windows 本機防火牆、端點安全軟體、VPN 或網卡省電/睡眠設定",
            "evidence_tier": tier_d,
            "supporting_evidence": sup_d or ["目前未觀測到本機防火牆封鎖或代理程式干擾"],
            "counter_evidence": cnt_d,
            "pending_checks": pend_d,
            "evidence_refs": refs_d,
        }
    )

    # --- E. 凱基證券伺服器或交易程式本身問題 ---
    sup_e: List[str] = []
    cnt_e: List[str] = []
    pend_e: List[str] = []
    refs_e: List[str] = ["kgi_inspection.executables", "kgi_inspection.architecture_and_reconnect"]

    arch = kgi_inspection.get("architecture_and_reconnect") or {}
    crash_cnt = int(arch.get("crashpad_dump_count") or 0)
    proc_exit_cnt = int(((cm_metrics.get("event_counts") or {}).get(EV_KGI_PROCESS_EXITED, 0)) or 0)

    if crash_cnt > 0:
        sup_e.append(f"Crashpad 目錄存在 {crash_cnt} 份歷史 `.dmp` 當機傾印檔。")
    else:
        cnt_e.append("Crashpad 目錄目前為 0 個 `.dmp` 當機傾印檔。")

    if proc_exit_cnt > 0:
        sup_e.append(f"監控期間觀測到 {proc_exit_cnt} 次凱基程序退出事件（KGI_PROCESS_EXITED）。")

    core_exes = [e for e in (kgi_inspection.get("executables") or []) if e.get("is_core_binary")]
    valid_sigs = [e for e in core_exes if e.get("signature_status") == "Valid"]
    if valid_sigs:
        cnt_e.append("核心執行檔（SUPERTSC64.exe / axis.exe）具備有效之 KGI Securities Co. Ltd. 數位簽章。")
    if total_eps > 0 and tcp_reach < total_eps:
        sup_e.append(f"部分凱基設定端點於檢查時無法建立 TCP 連線（成功 {tcp_reach}/{total_eps}）。")
    elif total_eps > 0:
        cnt_e.append(f"全部 {total_eps} 組測試之凱基設定端點於基準測試時皆可完成 TCP 三方交握。")

    if not ab_valid:
        pend_e.append("需透過個人手機熱點對照實驗確認非校園網路環境下是否同樣出現斷線。")

    tier_e = TIER_CONDITIONAL_INFERENCE if (crash_cnt > 0 or (total_eps > 0 and tcp_reach < total_eps)) else TIER_UNVERIFIED_HYPOTHESIS
    causes.append(
        {
            "code": "E",
            "title": "凱基證券伺服器端瞬斷、維護或交易軟體元件異常",
            "evidence_tier": tier_e,
            "supporting_evidence": sup_e or ["目前無程式崩潰傾印或伺服器全面失聯證據"],
            "counter_evidence": cnt_e,
            "pending_checks": pend_e,
            "evidence_refs": refs_e,
        }
    )

    # --- F. 交易系統自身閒置逾時、清盤重載或跨裝置同帳號 Session 互踢 ---
    sup_f: List[str] = []
    cnt_f: List[str] = []
    pend_f: List[str] = []
    refs_f: List[str] = ["kgi_inspection.architecture_and_reconnect"]

    reconn_mechs = arch.get("reconnect_mechanisms") or []
    if any("FOCLR" in str(m) for m in reconn_mechs):
        sup_f.append("本機靜態設定檔 `tab/HTSWORK.INI` 定義有換盤清盤提示/重載參數（FOCLR）。")
    if ab_valid and campus_confirmed_disc > 0 and hotspot_confirmed_disc > 0:
        sup_f.append("校園網路與手機熱點對照實驗均發生已確認交易斷線，支持與網路無關之帳號 Session 互踢或伺服器/軟體機制。")
    elif ab_valid and campus_confirmed_disc > 0 and hotspot_confirmed_disc == 0:
        cnt_f.append("對照實驗中手機熱點觀測期間未發生斷線，降低固定閒置逾時或同時間跨裝置互踢的可能性。")

    pend_f.append("測試期間請確認手機端看盤 App（如凱基隨身 e 策略）未同時以同一身分證帳號登入或背景自動重連。")
    pend_f.append("請搭配 `diagnostics.py mark --event kgi-disconnected` 記錄斷線是否集中在固定閒置分鐘數或特定換盤時刻。")

    tier_f = (
        TIER_CONDITIONAL_INFERENCE
        if (ab_valid and campus_confirmed_disc > 0 and hotspot_confirmed_disc > 0)
        else TIER_UNVERIFIED_HYPOTHESIS
    )
    causes.append(
        {
            "code": "F",
            "title": "交易系統自身閒置逾時、換盤重載或同帳號跨裝置 Session 互踢",
            "evidence_tier": tier_f,
            "supporting_evidence": sup_f or ["屬證券交易平台常見機制，需依實際發生時點與熱點對照排除"],
            "counter_evidence": cnt_f or ["尚未透過對照實驗排除"],
            "pending_checks": pend_f,
            "evidence_refs": refs_f,
        }
    )

    # --- G. 目前證據不足，無法單一定論 ---
    sup_g: List[str] = []
    cnt_g: List[str] = []
    pend_g: List[str] = []
    refs_g: List[str] = ["kgi_inspection.is_currently_running", "campus_monitor", "hotspot_monitor"]

    kgi_ran_in_campus = bool(campus_monitor and int(cm_metrics.get("kgi_running_sample_count") or 0) > 0)
    if not kgi_inspection.get("is_currently_running") and not kgi_ran_in_campus:
        sup_g.append("檢查與監控紀錄中尚未包含「新超級大三元」實際開啟並建立交易連線期間之觀測樣本。")
    if not campus_monitor:
        sup_g.append("尚未取得校園網路長時段被動 Socket + 主動探測監控資料。")
    elif campus_confirmed_disc == 0:
        sup_g.append("目前已執行的校園監控樣本中，尚未捕捉到使用者或應用層確認之交易斷線事件。")
    if not ab_valid:
        sup_g.append("尚未完成通過科學有效性檢核之「校園網路 vs 個人手機熱點」A/B 對照實驗。")

    cnt_g.append("已完成本機網路組態、防火牆、Proxy 與靜態安裝環境之基礎取證。")
    if sup_g:
        pend_g.append("請於開啟並登入新超級大三元後執行校園與手機熱點各 30 分鐘監控，並於斷線發生時執行 `mark --event kgi-disconnected`。")

    tier_g = TIER_CONFIRMED_FACT if sup_g else TIER_UNVERIFIED_HYPOTHESIS
    causes.append(
        {
            "code": "G",
            "title": "目前證據不足，尚無法單一定論根本原因",
            "evidence_tier": tier_g,
            "supporting_evidence": sup_g or ["已具備登入狀態斷線關聯與有效 A/B 對照資料"],
            "counter_evidence": cnt_g,
            "pending_checks": pend_g,
            "evidence_refs": refs_g,
        }
    )

    # 依客觀證據等級排序（不產生虛假百分比信心分數）：
    # 若 G（證據不足）為已確認事實且尚無其他已確認事實，G 排第 1 順位以防止過度推論
    tier_priority = {
        TIER_CONFIRMED_FACT: 0,
        TIER_CONDITIONAL_INFERENCE: 1,
        TIER_UNVERIFIED_HYPOTHESIS: 2,
    }
    causes_sorted = sorted(
        causes,
        key=lambda item: (
            tier_priority.get(item["evidence_tier"], 3),
            0 if item["code"] == "G" and item["evidence_tier"] == TIER_CONFIRMED_FACT else 1,
            item["code"],
        ),
    )
    for idx, item in enumerate(causes_sorted, start=1):
        item["rank"] = idx
        # 相容舊版報表讀取欄位，但不再輸出任意分數
        item["credibility_tier"] = item["evidence_tier"]
        item["confidence"] = item["evidence_tier"]
        item["score"] = None
    return causes_sorted


def _infer_profile_mismatch(expected_role: str, monitor_data: Dict[str, Any]) -> Optional[str]:
    """檢查測試標籤 (campus/hotspot) 是否與實際監控記錄到之網路環境明顯不符."""
    actual_label = str(monitor_data.get("label") or "").lower()
    net_prof = str(monitor_data.get("network_profile") or "").lower()
    env_hint = str(monitor_data.get("environment_hint") or "").lower()

    if expected_role == "campus":
        if "hotspot" in actual_label or "hotspot" in net_prof or "tether" in net_prof or "hotspot" in env_hint:
            return f"測試 A 預期為校園網路 (campus)，但資料標記顯示為熱點環境 (label={actual_label}, profile={net_prof or env_hint})"
    elif expected_role == "hotspot":
        if actual_label == "campus" or "tanet" in net_prof or "campus_tanet" in env_hint:
            return f"測試 B 預期為個人手機熱點 (hotspot)，但資料標記顯示為校園/學術網路環境 (label={actual_label}, profile={net_prof or env_hint})"
    return None


def compare_ab_results(
    campus_data: Optional[Dict[str, Any]],
    hotspot_data: Optional[Dict[str, Any]],
    min_comparable_duration_sec: float = 60.0,
) -> Dict[str, Any]:
    """
    第七節 P1：具備嚴格科學有效性驗證與每小時標準化率之 A/B 對照分析器.
    驗證項目：
      1. 雙邊資料存在且樣本數 > 0
      2. Label 與實際網路環境相符
      3. 測試皆正常結束且資料完整 (run_status == SUCCESS)
      4. 監控取樣頻率設定一致
      5. 測試期間凱基交易程式實際執行
      6. 實際觀察到凱基 Established TCP Socket
      7. 測試持續時間具可比性（時長比介於 0.5x ~ 2.0x 且達最低觀測門檻）
    """
    metric_defs = [
        ("confirmed_trading_disconnect_count", "1. 已確認交易斷線次數 (次)", "次"),
        ("confirmed_disconnects_per_hour", "2. 已確認交易斷線率 (次/小時)", "次/hr"),
        ("observed_socket_close_count", "3. 觀察到既有 Socket 結束次數 (次)", "次"),
        ("socket_closes_per_hour", "4. 既有 Socket 結束率 (次/小時)", "次/hr"),
        ("identifiable_connection_duration_display", "5. 可辨識 Socket 平均持續時間", ""),
        ("independent_kgi_probe_success_rate_pct", "6. 獨立主動探測成功率 (%)", "%"),
        ("independent_dns_success_rate_pct", "7. 獨立 DNS 查詢成功率 (%)", "%"),
        ("tcp_connect_avg_ms", "8. 主動探測 TCP 平均耗時 (ms)", "ms"),
        ("independent_control_probe_success_rate_pct", "9. 公開對照組成功率 (%)", "%"),
        ("network_anomaly_events", "10. 系統網路異常事件數 (次)", "次"),
    ]

    cm = (campus_data or {}).get("metrics") or {}
    hm = (hotspot_data or {}).get("metrics") or {}

    def _get_metric(m_dict: Dict[str, Any], key: str, present: bool) -> Any:
        if not present:
            return STATUS_NOT_TESTED
        if key in m_dict and m_dict[key] is not None:
            return m_dict[key]
        # 舊版 v0.1 結構向下相容映射
        fallback_map = {
            "confirmed_trading_disconnect_count": "disconnect_count",
            "independent_kgi_probe_success_rate_pct": "connection_success_rate_pct",
            "independent_dns_success_rate_pct": "dns_success_rate_pct",
            "independent_control_probe_success_rate_pct": "control_success_rate_pct",
        }
        fb = fallback_map.get(key)
        if fb and fb in m_dict and m_dict[fb] is not None:
            return m_dict[fb]
        if key == "identifiable_connection_duration_display":
            return "無法精確估計"
        return STATUS_NOT_TESTED

    rows: List[Dict[str, Any]] = []
    for key, label, unit in metric_defs:
        v_a = _get_metric(cm, key, campus_data is not None)
        v_b = _get_metric(hm, key, hotspot_data is not None)
        diff_str = STATUS_NOT_TESTED
        if isinstance(v_a, (int, float)) and isinstance(v_b, (int, float)):
            delta = round(float(v_a) - float(v_b), 2)
            sign = "+" if delta > 0 else ""
            diff_str = f"{sign}{delta} {unit}".strip()
        elif campus_data is not None and hotspot_data is not None:
            diff_str = "不適用 / 無法直接相減"
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
        return {
            "status": STATUS_NOT_TESTED,
            "is_scientifically_comparable": False,
            "validation_checks": [],
            "validation_warnings": ["尚未提供校園網路（測試 A）與手機熱點（測試 B）監控資料。"],
            "campus_sample_count": 0,
            "hotspot_sample_count": 0,
            "metrics_table": rows,
            "conclusion": "未測試：尚未執行學校網路（測試 A，建議 30 分鐘）與個人手機熱點（測試 B，建議 30 分鐘）對照實驗。",
        }

    if (campus_data and not hotspot_data) or (hotspot_data and not campus_data):
        missing_side = "個人手機熱點（測試 B）" if campus_data else "學校網路（測試 A）"
        return {
            "status": STATUS_PARTIAL,
            "is_scientifically_comparable": False,
            "validation_checks": [],
            "validation_warnings": [f"僅具備單邊監控資料，缺少{missing_side}。"],
            "campus_sample_count": int((campus_data or {}).get("sample_count") or 0),
            "hotspot_sample_count": int((hotspot_data or {}).get("sample_count") or 0),
            "metrics_table": rows,
            "conclusion": f"部分完成（PARTIAL）：尚缺{missing_side}同條件監控資料，無法進行科學 A/B 比較。",
        }

    assert campus_data is not None and hotspot_data is not None
    checks: List[Dict[str, Any]] = []
    warnings: List[str] = []

    def _add_check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})
        if not passed:
            warnings.append(f"[{name}] {detail}")

    # Check 1: 樣本數 > 0
    c_samples = int(campus_data.get("sample_count") or 0)
    h_samples = int(hotspot_data.get("sample_count") or 0)
    _add_check(
        "sample_count_nonzero",
        c_samples > 0 and h_samples > 0,
        f"Campus 樣本數={c_samples}, Hotspot 樣本數={h_samples}（雙邊皆須 > 0）",
    )

    # Check 2: Label 與實際網路環境一致
    mismatch_a = _infer_profile_mismatch("campus", campus_data)
    mismatch_b = _infer_profile_mismatch("hotspot", hotspot_data)
    label_ok = (mismatch_a is None) and (mismatch_b is None)
    _add_check(
        "label_matches_network_profile",
        label_ok,
        mismatch_a or mismatch_b or "測試標籤與網路環境描述一致",
    )

    # Check 3: 測試正常結束與資料完整性
    c_status = str(campus_data.get("run_status") or STATUS_SUCCESS)
    h_status = str(hotspot_data.get("run_status") or STATUS_SUCCESS)
    c_comp = str(campus_data.get("data_completeness") or ("COMPLETE" if c_samples > 0 else "EMPTY"))
    h_comp = str(hotspot_data.get("data_completeness") or ("COMPLETE" if h_samples > 0 else "EMPTY"))
    completion_ok = (
        c_status == STATUS_SUCCESS
        and h_status == STATUS_SUCCESS
        and c_comp == "COMPLETE"
        and h_comp == "COMPLETE"
    )
    _add_check(
        "normal_completion_and_completeness",
        completion_ok,
        f"Campus=({c_status}/{c_comp}), Hotspot=({h_status}/{h_comp})",
    )

    # Check 4: 監控取樣頻率一致
    c_pass_int = int(campus_data.get("passive_interval_seconds") or campus_data.get("interval_seconds") or 30)
    h_pass_int = int(hotspot_data.get("passive_interval_seconds") or hotspot_data.get("interval_seconds") or 30)
    c_act_int = int(campus_data.get("active_probe_interval_seconds") or campus_data.get("interval_seconds") or 30)
    h_act_int = int(hotspot_data.get("active_probe_interval_seconds") or hotspot_data.get("interval_seconds") or 30)
    settings_match = (c_pass_int == h_pass_int) and (c_act_int == h_act_int)
    _add_check(
        "matching_monitor_intervals",
        settings_match,
        f"Campus=(passive {c_pass_int}s / active {c_act_int}s), Hotspot=(passive {h_pass_int}s / active {h_act_int}s)",
    )

    # Check 5: 凱基交易軟體在雙邊測試期間皆實際執行
    c_kgi_ran = int(cm.get("kgi_running_sample_count") or 0)
    h_kgi_ran = int(hm.get("kgi_running_sample_count") or 0)
    kgi_ran_both = (c_kgi_ran > 0) and (h_kgi_ran > 0)
    _add_check(
        "kgi_process_running_during_test",
        kgi_ran_both,
        f"凱基執行中樣本數：Campus={c_kgi_ran}, Hotspot={h_kgi_ran}（雙邊皆須實際開啟交易程式）",
    )

    # Check 6: 雙邊皆觀察到實際 Established TCP Socket
    c_max_sock = int(cm.get("max_established_sockets") or 0)
    h_max_sock = int(hm.get("max_established_sockets") or 0)
    sockets_observed = (c_max_sock > 0) and (h_max_sock > 0)
    _add_check(
        "sufficient_actual_sockets_observed",
        sockets_observed,
        f"最大活躍交易 Socket 數：Campus={c_max_sock}, Hotspot={h_max_sock}（須實際登入建立連線）",
    )

    # Check 7: 持續時間具可比性
    c_dur = float(campus_data.get("total_duration_sec") or 0.0)
    h_dur = float(hotspot_data.get("total_duration_sec") or 0.0)
    ratio = (max(c_dur, h_dur) / min(c_dur, h_dur)) if min(c_dur, h_dur) > 0 else 999.0
    duration_comparable = (
        c_dur >= min_comparable_duration_sec
        and h_dur >= min_comparable_duration_sec
        and ratio <= 2.0
    )
    _add_check(
        "comparable_test_duration",
        duration_comparable,
        f"測試時長：Campus={c_dur}s, Hotspot={h_dur}s, 時長比={round(ratio, 2)}x（建議各 1800s，比例須 <= 2.0x 且 >= {min_comparable_duration_sec}s）",
    )

    is_valid = all(ch["passed"] for ch in checks)
    if not is_valid:
        return {
            "status": f"{STATUS_PARTIAL}（A/B 資料未通過科學可比性檢核）",
            "is_scientifically_comparable": False,
            "validation_checks": checks,
            "validation_warnings": warnings,
            "campus_sample_count": c_samples,
            "hotspot_sample_count": h_samples,
            "metrics_table": rows,
            "conclusion": (
                "目前兩份監控資料未通過科學可比性前置檢核（原因："
                + "；".join(warnings)
                + "），系統拒絕基於無效或不對等樣本做出環境歸因結論。請於雙環境開啟並登入新超級大三元，以相同取樣設定各執行約 30 分鐘後再行比較。"
            ),
        }

    c_disc = int(cm.get("confirmed_trading_disconnect_count", cm.get("disconnect_count", 0)) or 0)
    h_disc = int(hm.get("confirmed_trading_disconnect_count", hm.get("disconnect_count", 0)) or 0)
    c_rate_hr = cm.get("confirmed_disconnects_per_hour")
    h_rate_hr = hm.get("confirmed_disconnects_per_hour")

    if c_disc > h_disc and h_disc == 0:
        conclusion = (
            f"有效對照結果顯示：本次觀測期間內，個人手機熱點未發生已確認交易斷線（0 次，0 次/小時），"
            f"而校園網路發生 {c_disc} 次已確認交易斷線（約 {c_rate_hr} 次/小時）。"
            "此結果有條件支持「斷線現象與校園網路環境存在關聯」（例如長連線狀態逾時、路由品質或無線漫遊），"
            "但即使 A/B 對照具顯著差異，仍不能直接證明學校防火牆設有針對凱基證券之刻意封鎖政策；且手機熱點本次觀測期間未發生斷線，亦不代表未來所有時段保證穩定。"
        )
    elif c_disc > 0 and h_disc > 0:
        conclusion = (
            f"校園網路（{c_disc} 次，{c_rate_hr} 次/小時）與個人手機熱點（{h_disc} 次，{h_rate_hr} 次/小時）於本次觀測期間皆發生已確認交易斷線，"
            "顯示問題較可能與跨網路共通因素有關（例如同帳號跨裝置 Session 互踢、本機電源/安全軟體設定，或凱基伺服器端瞬斷），而非單純校園網路所致。"
        )
    elif c_disc == 0 and h_disc == 0:
        conclusion = (
            "本次觀測期間內，校園網路與個人手機熱點均未發生已確認交易斷線（皆為 0 次）。"
            "依保守科學原則，僅能表示「本次觀測期間未發生」，不能保證後續或盤中尖峰時段絕對穩定；建議於實際經常發生斷線之交易時段重複多組 30 分鐘 A/B 實驗。"
        )
    else:
        conclusion = (
            f"本次觀測期間校園網路已確認斷線 {c_disc} 次（{c_rate_hr} 次/小時），手機熱點 {h_disc} 次（{h_rate_hr} 次/小時）；"
            "請結合事件時間線中之本機網路狀態與對照組探測結果綜合研判。"
        )

    return {
        "status": STATUS_SUCCESS,
        "is_scientifically_comparable": True,
        "validation_checks": checks,
        "validation_warnings": [],
        "campus_sample_count": c_samples,
        "hotspot_sample_count": h_samples,
        "metrics_table": rows,
        "conclusion": conclusion,
    }


def validate_artifact_freshness(
    artifact: Optional[Dict[str, Any]],
    expected_run_id: Optional[str] = None,
    timestamp_keys: Tuple[str, ...] = ("collected_at", "checked_at", "inspected_at", "started_at", "generated_at"),
    reference_date_str: Optional[str] = None,
) -> Dict[str, Any]:
    """
    第八節 P1：驗證診斷產物是否屬於本次 Run ID 或同一日期，防止舊報告偽裝成最新結果或跨日混用.
    """
    if not artifact or not isinstance(artifact, dict):
        return {
            "status": STATUS_NOT_TESTED,
            "is_fresh": False,
            "artifact_run_id": None,
            "artifact_date": None,
            "reason": "無資料檔案",
        }

    art_status = str(artifact.get("run_status") or artifact.get("status") or STATUS_SUCCESS).upper()
    if art_status == STATUS_FAILED:
        return {
            "status": STATUS_FAILED,
            "is_fresh": False,
            "artifact_run_id": artifact.get("run_id"),
            "artifact_date": None,
            "reason": str(artifact.get("error_message") or "該步驟執行失敗 (FAILED)"),
        }

    art_run_id = artifact.get("run_id")
    ts_val = ""
    for k in timestamp_keys:
        if artifact.get(k):
            ts_val = str(artifact[k])
            break
    art_dt = _parse_iso_ts(ts_val)
    art_date = art_dt.strftime("%Y-%m-%d") if art_dt else (ts_val[:10] if len(ts_val) >= 10 else None)

    if expected_run_id and art_run_id != expected_run_id:
        return {
            "status": STATUS_PARTIAL,
            "is_fresh": False,
            "artifact_run_id": art_run_id,
            "artifact_date": art_date,
            "reason": f"資料 Run ID ({art_run_id or 'legacy_v0.1'}) 與本次執行 ({expected_run_id}) 不一致，屬歷史遺留資料",
        }

    if reference_date_str and art_date and art_date != reference_date_str:
        return {
            "status": STATUS_PARTIAL,
            "is_fresh": False,
            "artifact_run_id": art_run_id,
            "artifact_date": art_date,
            "reason": f"資料日期 ({art_date}) 與基準日期 ({reference_date_str}) 不同，不得混充為同一輪即時測試",
        }

    return {
        "status": STATUS_SUCCESS,
        "is_fresh": True,
        "artifact_run_id": art_run_id,
        "artifact_date": art_date,
        "reason": "通過本次執行與時效一致性驗證",
    }


def answer_seven_diagnostic_questions(bundle: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    第十節 P2：明確且誠實回答七大核心診斷問題.
    """
    kgi_info = bundle.get("kgi_inspection") or {}
    campus_mon = bundle.get("campus_monitor") or {}
    cm_metrics = campus_mon.get("metrics") or {}
    timeline = bundle.get("event_timeline") or campus_mon.get("event_timeline") or []
    ab_comp = bundle.get("ab_comparison") or {}
    kgi_analysis = bundle.get("kgi_probe_analysis") or {}

    insp_running = bool(kgi_info.get("is_currently_running", False))
    mon_running_samples = int(cm_metrics.get("kgi_running_sample_count") or 0)
    active_conns = kgi_info.get("active_tcp_connections") or []
    max_mon_socks = int(cm_metrics.get("max_established_sockets") or 0)

    # Q1: 交易程式當時是否正在執行？
    if insp_running or mon_running_samples > 0:
        a1 = (
            f"是。即時檢查執行中={insp_running}；監控期間共有 {mon_running_samples} 個取樣點驗證到凱基程序執行中。"
        )
    else:
        a1 = "否。執行檢查與目前載入之紀錄期間，凱基「新超級大三元」均未啟動執行。"

    # Q2: 是否觀察到實際的交易相關 Socket？
    if len(active_conns) > 0 or max_mon_socks > 0:
        a2 = (
            f"是。即時檢查捕捉到 {len(active_conns)} 條對外 TCP 連線；監控期間觀測到最多 {max_mon_socks} 條 Established TCP Socket。"
        )
    else:
        a2 = "否。尚未觀察到屬於凱基程序之活躍交易 TCP Socket（僅完成靜態設定候選端點之獨立探測）。"

    # Q3: 斷線是使用者回報、應用程式回報，還是系統推測？
    user_disc = int(cm_metrics.get("user_reported_disconnect_count") or 0)
    confirmed_disc = int(cm_metrics.get("confirmed_trading_disconnect_count") or 0)
    sock_disc = int(((cm_metrics.get("event_counts") or {}).get(EV_KGI_SOCKET_DISCONNECTED, 0)) or 0)
    probe_fail = int(((cm_metrics.get("event_counts") or {}).get(EV_KGI_PROBE_FAILURE, 0)) or 0)
    if confirmed_disc > 0:
        src_desc = "使用者手動標記 (`mark --event kgi-disconnected`)" if user_disc > 0 else "應用程式狀態回報"
        a3 = f"本次記錄到 {confirmed_disc} 次已確認交易斷線，來源為：{src_desc}（另有 {sock_disc} 次被動 Socket 關閉事件、{probe_fail} 次獨立探測異常）。"
    elif sock_disc > 0 or probe_fail > 0:
        a3 = (
            f"目前無已確認之交易功能斷線（0 次使用者/應用層回報）；僅觀測到 {sock_disc} 次被動 Socket 結束與 {probe_fail} 次獨立主動探測失敗，系統依規範不將其推測為交易 Session 斷線。"
        )
    else:
        a3 = "目前尚未記錄到任何已確認斷線或探測失敗事件。"

    # Q4: 斷線前後本機網路是否正常？
    nic_downs = [e for e in timeline if e.get("event_type") == EV_NETWORK_INTERFACE_DOWN]
    marks_corr = campus_mon.get("mark_correlations") or []
    if marks_corr:
        net_states = [f"{m.get('mark_timestamp')}: net_up={m.get('net_up_at_mark')}" for m in marks_corr]
        a4 = f"依據斷線標記前後 ±60 秒關聯紀錄：{'; '.join(net_states)}；全期本機介面中斷事件數={len(nic_downs)}。"
    elif campus_mon:
        a4 = f"監控期間本機網路介面中斷事件（NETWORK_INTERFACE_DOWN）共 {len(nic_downs)} 次（尚無手動斷線標記可供前後比對）。"
    else:
        a4 = "未測試（尚未執行監控或記錄斷線事件）。"

    # Q5: 凱基端點與公開對照服務是否同時失敗？
    ctrl_fails = [e for e in timeline if e.get("event_type") == EV_CONTROL_ENDPOINT_FAILURE]
    kgi_fails = [e for e in timeline if e.get("event_type") == EV_KGI_PROBE_FAILURE]
    ctrl_ts = {e.get("timestamp") for e in ctrl_fails}
    co_fail_ts = [e.get("timestamp") for e in kgi_fails if e.get("timestamp") in ctrl_ts]
    if co_fail_ts:
        a5 = f"是，於 {len(co_fail_ts)} 個取樣時間點觀測到凱基主動探測與公開對照組同時失敗（代表對外整體網路異常）。"
    elif kgi_fails or ctrl_fails:
        a5 = f"否，未同時失敗（凱基探測失敗 {len(kgi_fails)} 次、公開對照失敗 {len(ctrl_fails)} 次，發生時間未重疊）。"
    elif campus_mon:
        a5 = "監控期間凱基主動探測與公開對照服務皆未發生失敗。"
    else:
        a5 = "未測試（基準單次檢查中公開網站與凱基端點 TCP 皆通過，尚未進行長時段同步監控）。"

    # Q6: 是否有直接證據支持學校防火牆造成中斷？
    rst_cnt = len(kgi_analysis.get("tcp_rst_endpoints") or [])
    mitm_cnt = len(kgi_analysis.get("mitm_cert_endpoints") or [])
    if mitm_cnt > 0:
        a6 = f"有條件線索：偵測到 {mitm_cnt} 個端點出現防火牆/資安設備憑證替換特徵，但仍需比對實際交易連線影響。"
    else:
        a6 = (
            f"否，目前沒有直接證據證明學校防火牆阻斷凱基連線（未偵測到明確攔截頁面或防火牆憑證替換，初次 TCP 探測 RST 端點數={rst_cnt}；即使 TCP 443 非標準 TLS 亦不能直接推論防火牆攔截）。"
        )

    # Q7: 還缺少哪些證據？
    missing: List[str] = []
    if not (insp_running or mon_running_samples > 0):
        missing.append("開啟並登入「新超級大三元」實際運作期間之程序與 Established Socket 樣本")
    if confirmed_disc == 0:
        missing.append("實際發生斷線當下由使用者執行 `diagnostics.py mark --event kgi-disconnected` 之時間關聯紀錄")
    if not ab_comp.get("is_scientifically_comparable"):
        missing.append("通過科學有效性檢核之「校園網路 30 分鐘 vs 個人手機熱點 30 分鐘」同條件 A/B 對照實驗資料")
    a7 = "；".join(missing) if missing else "已完成現階段非侵入式端點層級所需之主要觀測證據蒐集。"

    return [
        {"question": "1. 交易程式當時是否正在執行？", "answer": a1},
        {"question": "2. 是否觀察到實際的交易相關 Socket？", "answer": a2},
        {"question": "3. 斷線是使用者回報、應用程式回報，還是系統推測？", "answer": a3},
        {"question": "4. 斷線前後本機網路是否正常？", "answer": a4},
        {"question": "5. 凱基端點與公開對照服務是否同時失敗？", "answer": a5},
        {"question": "6. 是否有直接證據支持學校防火牆造成中斷？", "answer": a6},
        {"question": "7. 還缺少哪些證據？", "answer": a7},
    ]
