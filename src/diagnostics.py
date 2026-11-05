"""校園網路與凱基證券「新超級大三元」連線診斷系統主程式與 CLI 介面."""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analyzer import (  # noqa: E402
    analyze_kgi_endpoint_probes,
    classify_application_evidence,
    classify_download_evidence,
    classify_website_evidence,
    compare_ab_results,
    evaluate_root_causes,
    mask_sensitive_text,
)
from src.report_generator import (  # noqa: E402
    generate_html_report,
    generate_network_environment_markdown,
    generate_research_report_markdown,
    write_csv_summary,
)

REPORTS_DIR = PROJECT_ROOT / "reports"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
CONFIG_DIR = PROJECT_ROOT / "config"


def setup_logger() -> logging.Logger:
    """建立具備隱私遮罩之操作日誌系統."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("campus_diag")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = logging.FileHandler(REPORTS_DIR / "operations.log", encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


def is_admin() -> bool:
    """唯讀檢查目前程序是否具備 Windows 管理員權限（不觸發 UAC 提權視窗）."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def load_json_safe(path: Path) -> Optional[Dict[str, Any]]:
    """安全讀取 UTF-8 JSON 檔案."""
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8-sig")
        return json.loads(raw)
    except Exception:
        return None


def save_json_safe(path: Path, data: Any) -> None:
    """安全寫入 UTF-8 JSON 檔案."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def run_powershell_script(
    script_name: str,
    args: Optional[List[str]] = None,
    timeout_sec: int = 60,
    logger: Optional[logging.Logger] = None,
) -> subprocess.CompletedProcess[str]:
    """安全執行專案內建之唯讀 PowerShell 腳本，附帶 Timeout 與編碼保護."""
    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        raise FileNotFoundError(f"找不到 PowerShell 腳本: {script_path}")

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
    ]
    if args:
        cmd.extend(args)

    if logger:
        logger.info(
            "執行腳本: %s %s",
            script_name,
            mask_sensitive_text(" ".join(args or [])),
        )

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_sec,
        check=False,
    )
    if proc.returncode != 0 and logger:
        logger.warning(
            "腳本 %s 回傳碼 %s: %s",
            script_name,
            proc.returncode,
            mask_sensitive_text(proc.stderr.strip()),
        )
    return proc


def probe_kgi_endpoint(
    fqdn: str,
    port: int,
    role: str,
    probe_count: int = 3,
    timeout_sec: float = 4.0,
) -> Dict[str, Any]:
    """低負載檢測單一凱基伺服器端點：DNS 解析、TCP 延遲/RST、以及 Port 443 協定辨識."""
    t0 = time.perf_counter()
    ips: List[str] = []
    dns_err = ""
    try:
        infos = socket.getaddrinfo(fqdn, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        for info in infos:
            ip_addr = info[4][0]
            if ip_addr not in ips:
                ips.append(ip_addr)
        dns_ok = len(ips) > 0
    except Exception as exc:
        dns_ok = False
        dns_err = str(exc)
    dns_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    primary_ip = ips[0] if ips else ""
    rtts: List[float] = []
    errors: List[str] = []
    rst_seen = False

    if dns_ok and primary_ip:
        for idx in range(probe_count):
            s0 = time.perf_counter()
            try:
                with socket.create_connection((primary_ip, port), timeout=timeout_sec):
                    rtts.append(round((time.perf_counter() - s0) * 1000.0, 2))
            except ConnectionResetError as exc:
                rst_seen = True
                errors.append(f"TCP_RST: {exc}")
            except socket.timeout:
                errors.append("TCP_TIMEOUT")
            except OSError as exc:
                if getattr(exc, "winerror", None) == 10054:
                    rst_seen = True
                errors.append(f"OS_ERR({getattr(exc, 'winerror', '')}): {exc}")
            if idx < probe_count - 1:
                time.sleep(0.35)

    tls_probe: Dict[str, Any] = {
        "tested": False,
        "tls_handshake_ok": False,
        "issuer": "",
        "protocol_summary": "TCP 連線檢測",
        "detail": "非 443 埠或 TCP 未連通，略過 TLS 探測",
    }

    if port == 443 and len(rtts) > 0:
        tls_probe["tested"] = True
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((primary_ip, port), timeout=timeout_sec) as raw_sock:
                raw_sock.settimeout(3.5)
                with ctx.wrap_socket(raw_sock, server_hostname=fqdn) as ssl_sock:
                    cert = ssl_sock.getpeercert()
                    issuer_str = str(cert.get("issuer", ""))
                    tls_ver = ssl_sock.version() or "TLS"
                    tls_probe.update(
                        {
                            "tls_handshake_ok": True,
                            "issuer": issuer_str,
                            "protocol_summary": f"標準 {tls_ver} 加密連線",
                            "detail": "通過標準 X.509 憑證驗證",
                        }
                    )
        except (socket.timeout, TimeoutError):
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "protocol_summary": "非標準 TLS（HTS 專屬封包協定 over TCP 443）",
                    "detail": "TCP 443 三方交握迅速成功，但伺服器不回應標準 TLS ClientHello（等待專屬 HTS 封包）",
                }
            )
        except ConnectionResetError:
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "protocol_summary": "非標準 TLS 或連線遭重置（TCP RST on ClientHello）",
                    "detail": "發送標準 TLS ClientHello 後收到 TCP Reset，顯示該埠為專屬協定或遭中間設備重置",
                }
            )
        except ssl.SSLError as exc:
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "protocol_summary": "非標準 TLS 回應（HTS 專屬封包協定 over TCP 443）",
                    "detail": f"伺服器回應非標準 TLS 紀錄格式 ({exc.__class__.__name__}: {str(exc)[:80]})",
                }
            )
        except EOFError:
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "protocol_summary": "非標準 TLS（伺服器主動關閉非 HTS 交握）",
                    "detail": "標準 TLS 交握收到 EOF，確認非一般 HTTPS 網頁服務",
                }
            )
        except OSError as exc:
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "protocol_summary": "非標準 TLS / Socket 關閉",
                    "detail": f"TLS 探測結束 ({exc})",
                }
            )
    elif port == 80 and len(rtts) > 0:
        tls_probe.update(
            {
                "tested": False,
                "tls_handshake_ok": False,
                "protocol_summary": "HTS 備援通訊埠 (TCP 80 長連線)",
                "detail": "TCP 80 三方交握成功（供新超級大三元專屬封包通訊使用）",
            }
        )

    return {
        "role": role,
        "fqdn": fqdn,
        "port": port,
        "dns_ok": dns_ok,
        "dns_latency_ms": dns_ms,
        "resolved_ips": ips,
        "primary_ip": primary_ip,
        "dns_error": dns_err,
        "tcp_probe_count": probe_count,
        "tcp_ok_count": len(rtts),
        "tcp_rtts_ms": rtts,
        "tcp_avg_ms": round(statistics.mean(rtts), 2) if rtts else None,
        "tcp_rst_observed": rst_seen,
        "tcp_errors": errors,
        "tls_probe": tls_probe,
    }


def cmd_env(args: argparse.Namespace, logger: logging.Logger) -> Dict[str, Any]:
    """第一階段：自動辨識本機網路環境並輸出 network_environment.json 與 .md."""
    out_json = REPORTS_DIR / "network_environment.json"
    out_md = REPORTS_DIR / "network_environment.md"
    run_powershell_script(
        "collect_network.ps1",
        ["-OutputPath", str(out_json), "-EventLookbackHours", str(args.lookback_hours)],
        timeout_sec=60,
        logger=logger,
    )
    env_data = load_json_safe(out_json) or {}
    md_text = generate_network_environment_markdown(env_data)
    out_md.write_text(md_text, encoding="utf-8")

    # 同步輸出至專案根目錄以符合第二階段檔名規格
    shutil.copyfile(out_json, PROJECT_ROOT / "network_environment.json")
    shutil.copyfile(out_md, PROJECT_ROOT / "network_environment.md")
    logger.info("已完成網路環境辨識：%s 與 %s", out_json.name, out_md.name)
    return env_data


def cmd_check(args: argparse.Namespace, logger: logging.Logger) -> Dict[str, Any]:
    """第二階段：網站、應用程式與檔案下載限制檢查."""
    targets_file = Path(args.targets) if args.targets else (
        (CONFIG_DIR / "targets.json")
        if (CONFIG_DIR / "targets.json").exists()
        else (CONFIG_DIR / "targets.example.json")
    )
    raw_ps_out = REPORTS_DIR / "restrictions_check_ps.json"
    run_powershell_script(
        "check_restrictions.ps1",
        ["-TargetsPath", str(targets_file), "-OutputPath", str(raw_ps_out)],
        timeout_sec=90,
        logger=logger,
    )
    data = load_json_safe(raw_ps_out) or {"websites": [], "applications": [], "downloads": []}
    if "targets_source" in data:
        data["targets_source"] = mask_sensitive_text(str(data["targets_source"]))

    # 套用 Python 嚴謹證據分類器覆核每一筆結果
    for w in data.get("websites") or []:
        verdict = classify_website_evidence(w)
        w["classification"] = verdict["classification"]
        w["evidence_summary"] = verdict["reason"]

    for a in data.get("applications") or []:
        verdict = classify_application_evidence(a)
        a["classification"] = verdict["classification"]
        a["evidence_summary"] = verdict["reason"]

    for d in data.get("downloads") or []:
        verdict = classify_download_evidence(d)
        d["classification"] = verdict["classification"]
        d["evidence_summary"] = verdict["reason"]

    final_path = REPORTS_DIR / "restrictions_check.json"
    save_json_safe(final_path, data)
    logger.info("已完成網站、程式與下載限制檢查：%s", final_path.name)
    return data


def cmd_kgi(args: argparse.Namespace, logger: logging.Logger) -> Dict[str, Any]:
    """第三階段：自動辨識凱基「新超級大三元」並針對實際端點進行深度協定診斷."""
    insp_path = REPORTS_DIR / "kgi_inspection.json"
    run_powershell_script(
        "inspect_kgi.ps1",
        ["-OutputPath", str(insp_path)],
        timeout_sec=60,
        logger=logger,
    )
    insp_data = load_json_safe(insp_path) or {}

    # 整理需實測的端點（優先根據活動連線與 YELLOWPAGE.INI 官方靜態設定，絕不憑空假設）
    probe_targets: List[Dict[str, Any]] = []
    seen_pairs = set()

    for ep in insp_data.get("configured_endpoints") or []:
        fqdn = ep.get("fqdn")
        role = ep.get("role", "KGI_Server")
        ports = ep.get("ports") or [443, 80]
        for pt in ports:
            key = (fqdn, int(pt))
            if fqdn and key not in seen_pairs:
                seen_pairs.add(key)
                probe_targets.append({"fqdn": fqdn, "port": int(pt), "role": role})

    for ac in insp_data.get("active_tcp_connections") or []:
        rem_ip = ac.get("remote_address")
        rem_port = int(ac.get("remote_port") or 0)
        fqdn = ac.get("verified_fqdn") or rem_ip
        key = (fqdn, rem_port)
        if fqdn and rem_port > 0 and key not in seen_pairs:
            seen_pairs.add(key)
            probe_targets.append(
                {"fqdn": fqdn, "port": rem_port, "role": "Active_Process_TCP"}
            )

    logger.info("開始低負載檢測 %d 組凱基已驗證連線端點...", len(probe_targets))
    probes: List[Dict[str, Any]] = []
    for item in probe_targets:
        res = probe_kgi_endpoint(
            fqdn=item["fqdn"],
            port=item["port"],
            role=item["role"],
            probe_count=3,
            timeout_sec=4.0,
        )
        probes.append(res)
        time.sleep(0.25)

    probe_analysis = analyze_kgi_endpoint_probes(probes)
    deep_result = {
        "inspected_at": datetime.now().isoformat(),
        "inspection": insp_data,
        "endpoint_probes": probes,
        "probe_analysis": probe_analysis,
    }
    save_json_safe(REPORTS_DIR / "kgi_deep_diagnostics.json", deep_result)
    logger.info("已完成凱基新超級大三元深度診斷：kgi_deep_diagnostics.json")
    return deep_result


def cmd_monitor(args: argparse.Namespace, logger: logging.Logger) -> None:
    """第三階段 4.3：啟動、停止或查詢每 30 秒低負載斷線監控."""
    sub = args.monitor_action
    if sub == "stop":
        proc = run_powershell_script(
            "monitor_connections.ps1",
            ["-Action", "Stop", "-OutputDir", str(REPORTS_DIR)],
            timeout_sec=15,
            logger=logger,
        )
        print(proc.stdout.strip())
        return

    if sub == "status":
        proc = run_powershell_script(
            "monitor_connections.ps1",
            ["-Action", "Status", "-OutputDir", str(REPORTS_DIR)],
            timeout_sec=15,
            logger=logger,
        )
        print(proc.stdout.strip())
        return

    ps_action = "RunForeground" if args.foreground else "Start"
    timeout_val = (args.duration + 60) if (args.foreground and args.duration > 0) else 20
    ps_args = [
        "-Action",
        ps_action,
        "-IntervalSeconds",
        str(max(10, args.interval)),
        "-DurationSeconds",
        str(args.duration),
        "-Label",
        args.label,
        "-OutputDir",
        str(REPORTS_DIR),
    ]
    proc = run_powershell_script(
        "monitor_connections.ps1",
        ps_args,
        timeout_sec=timeout_val,
        logger=logger,
    )
    print(proc.stdout.strip())


def cmd_compare(args: argparse.Namespace, logger: logging.Logger) -> Dict[str, Any]:
    """第四階段：匯入學校網路與手機熱點測試結果並產生對照報告."""
    campus_path = Path(args.campus) if args.campus else (REPORTS_DIR / "monitor_campus_latest.json")
    hotspot_path = Path(args.hotspot) if args.hotspot else (REPORTS_DIR / "monitor_hotspot_latest.json")

    campus_data = load_json_safe(campus_path)
    hotspot_data = load_json_safe(hotspot_path)

    comp = compare_ab_results(campus_data, hotspot_data)
    save_json_safe(REPORTS_DIR / "ab_comparison.json", comp)
    logger.info("已產生學校網路與手機熱點對照結果：ab_comparison.json (%s)", comp["status"])

    # 同步更新總報告
    cmd_report(args, logger)
    return comp


def cmd_report(args: argparse.Namespace, logger: logging.Logger) -> Dict[str, Any]:
    """第七階段：整合現有全部實測證據產生 Markdown、JSON、CSV 與 HTML 完整研究報告."""
    env_data = load_json_safe(REPORTS_DIR / "network_environment.json") or {}
    rest_data = load_json_safe(REPORTS_DIR / "restrictions_check.json") or {}
    kgi_deep = load_json_safe(REPORTS_DIR / "kgi_deep_diagnostics.json") or {}
    kgi_insp = kgi_deep.get("inspection") or load_json_safe(REPORTS_DIR / "kgi_inspection.json") or {}
    kgi_probes = kgi_deep.get("endpoint_probes") or []
    kgi_analysis = kgi_deep.get("probe_analysis") or analyze_kgi_endpoint_probes(kgi_probes)

    campus_mon = load_json_safe(REPORTS_DIR / "monitor_campus_latest.json")
    hotspot_mon = load_json_safe(REPORTS_DIR / "monitor_hotspot_latest.json")

    ab_comp = compare_ab_results(campus_mon, hotspot_mon)
    root_causes = evaluate_root_causes(
        network_env=env_data,
        restrictions=rest_data,
        kgi_inspection=kgi_insp,
        kgi_probe_analysis=kgi_analysis,
        campus_monitor=campus_mon,
        hotspot_monitor=hotspot_mon,
    )

    bundle = {
        "schema_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "is_elevated": is_admin(),
        "network_environment": env_data,
        "restrictions": rest_data,
        "kgi_inspection": kgi_insp,
        "kgi_endpoint_probes": kgi_probes,
        "kgi_probe_analysis": kgi_analysis,
        "campus_monitor": campus_mon,
        "hotspot_monitor": hotspot_mon,
        "ab_comparison": ab_comp,
        "root_causes": root_causes,
    }

    report_json_path = REPORTS_DIR / "diagnostic_report.json"
    report_md_path = REPORTS_DIR / "diagnostic_report.md"
    report_html_path = REPORTS_DIR / "diagnostic_report.html"

    save_json_safe(report_json_path, bundle)
    csv_paths = write_csv_summary(rest_data, kgi_probes, ab_comp, REPORTS_DIR)
    report_md_path.write_text(generate_research_report_markdown(bundle), encoding="utf-8")
    report_html_path.write_text(generate_html_report(bundle), encoding="utf-8")

    logger.info(
        "完整診斷報告已輸出：%s, %s, %s, %s",
        report_md_path.name,
        report_json_path.name,
        Path(csv_paths["diagnostic_summary_csv"]).name,
        report_html_path.name,
    )
    return bundle


def cmd_all(args: argparse.Namespace, logger: logging.Logger) -> Dict[str, Any]:
    """一鍵執行全部安全、唯讀、不需管理員權限之基準診斷並輸出第一份完整報告."""
    logger.info("=== 開始執行全方位安全唯讀基準診斷 (Admin=%s) ===", is_admin())
    cmd_env(args, logger)
    cmd_check(args, logger)
    cmd_kgi(args, logger)
    bundle = cmd_report(args, logger)
    logger.info("=== 全方位基準診斷完成 ===")
    return bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="diagnostics.py",
        description="壓力測試（Campus Network Diagnostic）— 校園網路與凱基證券「新超級大三元」低負載連線診斷工具",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # 1. env
    p_env = sub.add_parser("env", help="1. 一鍵蒐集本機網路環境並輸出 network_environment.json/.md")
    p_env.add_argument("--lookback-hours", type=int, default=24, help="回溯系統網路與電源事件時數（預設 24）")

    # 2. check
    p_chk = sub.add_parser("check", help="2. 檢查白名單網站、指定應用程式及官方端點下載限制")
    p_chk.add_argument("--targets", type=str, default="", help="自訂測試目標 JSON 檔案路徑")

    # 3. kgi
    sub.add_parser("kgi", help="3a. 自動辨識凱基「新超級大三元」並檢測實際連線端點與協定特徵")

    # 4. monitor
    p_mon = sub.add_parser("monitor", help="3b. 開始、停止或查詢凱基每 30 秒低負載斷線監控")
    p_mon.add_argument("monitor_action", choices=["start", "stop", "status"], help="監控控制指令")
    p_mon.add_argument("--interval", type=int, default=30, help="監控取樣間隔秒數（預設 30 秒，最低 10 秒）")
    p_mon.add_argument("--duration", type=int, default=1800, help="監控總秒數（預設 1800 秒=30分鐘，設 0 為持續至手動 stop）")
    p_mon.add_argument("--label", type=str, default="campus", help="實驗標籤：campus（學校網路）或 hotspot（手機熱點）")
    p_mon.add_argument("--foreground", action="store_true", help="於前景執行監控（預設啟動背景程序）")

    # 5. compare
    p_cmp = sub.add_parser("compare", help="4. 匯入學校網路與手機熱點測試結果並產生對照分析")
    p_cmp.add_argument("--campus", type=str, default="", help="測試 A（學校網路）監控 JSON 路徑")
    p_cmp.add_argument("--hotspot", type=str, default="", help="測試 B（手機熱點）監控 JSON 路徑")

    # 6. report
    sub.add_parser("report", help="5. 根據現有診斷資料重新產生 Markdown / JSON / CSV / HTML 研究報告")

    # 7. all
    p_all = sub.add_parser("all", help="一鍵執行完整安全唯讀診斷流程（env + check + kgi + report）")
    p_all.add_argument("--lookback-hours", type=int, default=24, help="回溯系統網路事件時數")
    p_all.add_argument("--targets", type=str, default="", help="自訂測試目標 JSON 檔案路徑")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = setup_logger()

    try:
        if args.command == "env":
            cmd_env(args, logger)
        elif args.command == "check":
            cmd_check(args, logger)
        elif args.command == "kgi":
            cmd_kgi(args, logger)
        elif args.command == "monitor":
            cmd_monitor(args, logger)
        elif args.command == "compare":
            cmd_compare(args, logger)
        elif args.command == "report":
            cmd_report(args, logger)
        elif args.command == "all":
            cmd_all(args, logger)
        return 0
    except subprocess.TimeoutExpired as exc:
        logger.error("執行外部診斷程序逾時 (%s 秒): %s", exc.timeout, exc.cmd)
        return 2
    except Exception as exc:
        logger.exception("診斷執行過程發生未預期錯誤: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

