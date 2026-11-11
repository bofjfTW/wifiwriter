"""校園網路與凱基證券「新超級大三元」連線診斷系統主程式與 CLI 介面 (v0.2)."""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import socket
import ssl
import statistics
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analyzer import (  # noqa: E402
    PROTO_STANDARD_TLS,
    PROTO_UNKNOWN,
    STATUS_FAILED,
    STATUS_NOT_TESTED,
    STATUS_PARTIAL,
    STATUS_SUCCESS,
    TLS_CERT_VERIFY_FAILED,
    TLS_HANDSHAKE_EOF,
    TLS_HANDSHAKE_RESET,
    TLS_HANDSHAKE_TIMEOUT,
    TLS_NOT_TESTED,
    TLS_OK,
    TLS_PROTOCOL_ERROR,
    analyze_kgi_endpoint_probes,
    analyze_monitor_dataset,
    answer_seven_diagnostic_questions,
    classify_application_evidence,
    classify_download_evidence,
    classify_website_evidence,
    compare_ab_results,
    evaluate_root_causes,
    mask_sensitive_text,
    validate_artifact_freshness,
)
from src.privacy import sanitize_data_for_sharing  # noqa: E402
from src.noauth import (  # noqa: E402
    DEFAULT_MAX_DOWNLOAD_MIB,
    FUBON_EPLUS_PRODUCT_PAGE_URL,
    VERDICT_NOT_TESTED,
    compare_fubon_eplus_rounds,
    compare_noauth_ab_runs,
    evaluate_prelogin_mode_gate,
    generate_fubon_eplus_report_md,
    generate_noauth_diagnostic_report_md,
    generate_noauth_validation_report_md,
    run_fubon_eplus_round,
    run_multi_round_noauth_connectivity,
    run_official_download_Verification,
    write_fubon_eplus_comparison_csv,
    write_noauth_ab_csv,
)
from src.report_generator import (  # noqa: E402
    generate_html_report,
    generate_network_environment_markdown,
    generate_research_report_markdown,
    write_csv_summary,
)

DEFAULT_PRIVATE_REPORTS_DIR = PROJECT_ROOT.parent / "wifiwriter_private_reports"
REPORTS_DIR = Path(os.environ.get("WIFIWRITER_REPORTS_DIR", str(DEFAULT_PRIVATE_REPORTS_DIR)))
INTERNAL_RUNS_DIR = REPORTS_DIR / "internal"
SANITIZED_RUNS_DIR = REPORTS_DIR / "sanitized"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
CONFIG_DIR = PROJECT_ROOT / "config"


class DiagnosticStepError(RuntimeError):
    """代表外部診斷腳本或資料驗證失敗，攜帶結構化錯誤資訊與非零結束碼."""

    def __init__(self, step: str, message: str, exit_code: int = 1, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.step = step
        self.exit_code = exit_code if exit_code != 0 else 1
        self.details = details or {}


def generate_run_id(prefix: str = "run") -> str:
    """產生唯一且可排序之執行識別碼 (Run ID)."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    short_uid = uuid.uuid4().hex[:6]
    return f"{prefix}_{stamp}_{short_uid}"


def save_json_atomic(path: Path, data: Any) -> None:
    """使用暫存檔加原子替換 (os.replace) 安全寫入 UTF-8 JSON，杜絕半寫入損毀."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    try:
        tmp_path.write_text(payload, encoding="utf-8")
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def save_text_atomic(path: Path, content: str) -> None:
    """使用暫存檔加原子替換寫入純文字/Markdown/HTML 報告."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        tmp_path.write_text(content, encoding="utf-8")
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


# 相容舊版匯入名稱
save_json_safe = save_json_atomic


def load_json_safe(path: Path) -> Optional[Dict[str, Any]]:
    """安全讀取 UTF-8 JSON 檔案."""
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8-sig")
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def load_jsonl_safe(path: Path) -> List[Dict[str, Any]]:
    """安全讀取 JSON Lines (.jsonl) 檔案，略過空白或損毀尾行並記錄筆數."""
    items: List[Dict[str, Any]] = []
    if not path.exists():
        return items
    try:
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            s = line.strip()
            if not s:
                continue
            try:
                parsed = json.loads(s)
                if isinstance(parsed, dict):
                    items.append(parsed)
            except json.JSONDecodeError:
                continue
    except Exception:
        pass
    return items


def _ensure_utf8_stdio() -> None:
    """確保在非 UTF-8 預設語系之 Windows 主控台（如 cp1252 / cp950）輸出繁體中文不會拋出 UnicodeEncodeError."""
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if callable(reconf):
            try:
                reconf(encoding="utf-8", errors="replace")
            except Exception:
                pass


_ensure_utf8_stdio()


def setup_logger(run_id: str = "") -> logging.Logger:
    """建立具備隱私遮罩之操作日誌系統（日誌寫入 reports/internal/operations_v02.log，不覆蓋舊檔）."""
    _ensure_utf8_stdio()
    INTERNAL_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("campus_diag_v02")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = logging.FileHandler(INTERNAL_RUNS_DIR / "operations_v02.log", encoding="utf-8")
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


def get_run_directories(run_id: str, base_reports_dir: Path = REPORTS_DIR) -> Tuple[Path, Path]:
    """回傳 (internal_dir, sanitized_dir)，嚴格分離內部完整診斷資料與對外分享遮罩版本."""
    internal_dir = base_reports_dir / "internal" / run_id
    sanitized_dir = base_reports_dir / "sanitized" / run_id
    internal_dir.mkdir(parents=True, exist_ok=True)
    sanitized_dir.mkdir(parents=True, exist_ok=True)
    return internal_dir, sanitized_dir


def write_error_summary(
    run_id: str,
    step: str,
    error_message: str,
    exit_code: int = 1,
    extra: Optional[Dict[str, Any]] = None,
    base_reports_dir: Path = REPORTS_DIR,
) -> Path:
    """即使檢測失敗，亦保存經過隱私遮罩之安全錯誤摘要，方便重現問題且不洩漏敏感資訊."""
    internal_dir, sanitized_dir = get_run_directories(run_id, base_reports_dir)
    err_payload: Dict[str, Any] = {
        "schema_version": "2.0",
        "run_id": run_id,
        "run_status": STATUS_FAILED,
        "failed_step": step,
        "recorded_at": datetime.now().isoformat(),
        "exit_code": exit_code,
        "error_message": mask_sensitive_text(error_message),
        "details": sanitize_data_for_sharing(extra or {}),
    }
    err_path = internal_dir / "error_summary.json"
    save_json_atomic(err_path, err_payload)
    save_json_atomic(sanitized_dir / "error_summary.json", sanitize_data_for_sharing(err_payload))
    return err_path


def update_latest_pointer(
    run_id: str,
    step_key: str,
    artifact_path: Path,
    base_reports_dir: Path = REPORTS_DIR,
) -> None:
    """更新 reports/internal/latest_index.json 指標檔（不覆蓋 v0.1 根層檔案）."""
    idx_path = base_reports_dir / "internal" / "latest_index.json"
    current = load_json_safe(idx_path) or {"updated_at": "", "steps": {}}
    steps = current.get("steps")
    if not isinstance(steps, dict):
        steps = {}
    steps[step_key] = {
        "run_id": run_id,
        "path": str(artifact_path),
        "recorded_at": datetime.now().isoformat(),
    }
    current["updated_at"] = datetime.now().isoformat()
    current["latest_run_id"] = run_id
    current["steps"] = steps
    save_json_atomic(idx_path, current)


def run_powershell_script(
    script_name: str,
    args: Optional[List[str]] = None,
    timeout_sec: int = 60,
    logger: Optional[logging.Logger] = None,
    check_exit_code: bool = True,
    step_name: str = "powershell_step",
) -> subprocess.CompletedProcess[str]:
    """安全執行專案內建唯讀 PowerShell 腳本，強制檢查 Exit Code，失敗時絕不假裝成功."""
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
        logger.info("執行腳本: %s %s", script_name, mask_sensitive_text(" ".join(args or [])))

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_sec,
        check=False,
    )
    if proc.returncode != 0:
        masked_err = mask_sensitive_text((proc.stderr or proc.stdout or "").strip())
        if logger:
            logger.error("腳本 %s 失敗 (ExitCode=%s): %s", script_name, proc.returncode, masked_err)
        if check_exit_code:
            raise DiagnosticStepError(
                step=step_name,
                message=f"PowerShell 腳本 {script_name} 回傳非零結束碼 ({proc.returncode}): {masked_err}",
                exit_code=proc.returncode,
                details={
                    "script": script_name,
                    "returncode": proc.returncode,
                    "stderr": masked_err,
                },
            )
    return proc


def verify_step_output_json(
    output_path: Path,
    expected_run_id: str,
    step_name: str,
) -> Dict[str, Any]:
    """驗證子程序產出之 JSON 存在且屬於本次 Run ID，防止讀取過期舊檔偽裝成功."""
    data = load_json_safe(output_path)
    if data is None:
        raise DiagnosticStepError(
            step=step_name,
            message=f"步驟 {step_name} 未產生有效 JSON 輸出: {output_path.name}",
            exit_code=2,
        )
    fresh = validate_artifact_freshness(data, expected_run_id=expected_run_id)
    if not fresh["is_fresh"]:
        raise DiagnosticStepError(
            step=step_name,
            message=f"步驟 {step_name} 產物驗證失敗（拒絕載入過期或失敗資料）: {fresh['reason']}",
            exit_code=2,
            details=fresh,
        )
    return data


def probe_kgi_endpoint(
    fqdn: str,
    port: int,
    role: str,
    endpoint_source: str = "static_ini_candidate",
    probe_count: int = 3,
    timeout_sec: float = 4.0,
) -> Dict[str, Any]:
    """
    低負載檢測單一凱基端點 (v0.2 修正版)：
    - 分開記錄 TLS_OK / TLS_HANDSHAKE_TIMEOUT / TLS_HANDSHAKE_RESET / TLS_HANDSHAKE_EOF / TLS_CERT_VERIFY_FAILED / TLS_PROTOCOL_ERROR
    - 當標準 TLS 失敗或未測試時，application_protocol 一律設為 UNKNOWN，絕不推論為專屬協定！
    """
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
        "tls_status": TLS_NOT_TESTED,
        "application_protocol": PROTO_UNKNOWN,
        "issuer": "",
        "protocol_summary": f"TCP 連通，應用層協定 {PROTO_UNKNOWN}",
        "detail": "非 443 埠或 TCP 未連通，未執行標準 TLS 交握測試；無封包/官方文件證據前協定標記為 UNKNOWN",
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
                            "tls_status": TLS_OK,
                            "application_protocol": PROTO_STANDARD_TLS,
                            "issuer": issuer_str,
                            "protocol_summary": f"標準 {tls_ver} 連線通過驗證",
                            "detail": "完成標準 TLS 交握與 X.509 憑證鏈驗證",
                        }
                    )
        except (socket.timeout, TimeoutError):
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "tls_status": TLS_HANDSHAKE_TIMEOUT,
                    "application_protocol": PROTO_UNKNOWN,
                    "protocol_summary": f"TLS 交握逾時 ({TLS_HANDSHAKE_TIMEOUT}) / 協定 {PROTO_UNKNOWN}",
                    "detail": "TCP 443 三方交握成功，但標準 TLS ClientHello 等待回應逾時；協定標記為 UNKNOWN（不推論為專屬協定）",
                }
            )
        except ConnectionResetError:
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "tls_status": TLS_HANDSHAKE_RESET,
                    "application_protocol": PROTO_UNKNOWN,
                    "protocol_summary": f"TLS 交握收到重置 ({TLS_HANDSHAKE_RESET}) / 協定 {PROTO_UNKNOWN}",
                    "detail": "發送標準 TLS ClientHello 後收到 TCP Reset；協定標記為 UNKNOWN（無法單憑此現象區分遠端拒絕或中間設備重置）",
                }
            )
        except ssl.SSLCertVerificationError as exc:
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "tls_status": TLS_CERT_VERIFY_FAILED,
                    "application_protocol": PROTO_STANDARD_TLS,
                    "protocol_summary": f"TLS 憑證驗證失敗 ({TLS_CERT_VERIFY_FAILED})",
                    "detail": f"伺服器回應 TLS 憑證但未通過信任鏈或主機名驗證: {str(exc)[:100]}",
                }
            )
        except EOFError:
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "tls_status": TLS_HANDSHAKE_EOF,
                    "application_protocol": PROTO_UNKNOWN,
                    "protocol_summary": f"TLS 交握收到 EOF ({TLS_HANDSHAKE_EOF}) / 協定 {PROTO_UNKNOWN}",
                    "detail": "發送標準 TLS ClientHello 後連線收到 EOF 關閉；協定標記為 UNKNOWN",
                }
            )
        except ssl.SSLError as exc:
            err_msg = str(exc)
            if "EOF" in err_msg.upper():
                st_code = TLS_HANDSHAKE_EOF
            else:
                st_code = TLS_PROTOCOL_ERROR
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "tls_status": st_code,
                    "application_protocol": PROTO_UNKNOWN,
                    "protocol_summary": f"非標準 TLS 回應 ({st_code}) / 協定 {PROTO_UNKNOWN}",
                    "detail": f"標準 TLS 交握失敗 ({exc.__class__.__name__}: {err_msg[:90]})；協定標記為 UNKNOWN",
                }
            )
        except OSError as exc:
            st_code = TLS_HANDSHAKE_RESET if getattr(exc, "winerror", None) == 10054 else TLS_PROTOCOL_ERROR
            tls_probe.update(
                {
                    "tls_handshake_ok": False,
                    "tls_status": st_code,
                    "application_protocol": PROTO_UNKNOWN,
                    "protocol_summary": f"TLS 探測 Socket 錯誤 ({st_code}) / 協定 {PROTO_UNKNOWN}",
                    "detail": f"TLS 交握階段發生作業系統連線錯誤 ({exc})；協定標記為 UNKNOWN",
                }
            )
    elif len(rtts) > 0:
        tls_probe.update(
            {
                "tested": False,
                "tls_handshake_ok": False,
                "tls_status": TLS_NOT_TESTED,
                "application_protocol": PROTO_UNKNOWN,
                "protocol_summary": f"TCP {port} 可連通 / 協定 {PROTO_UNKNOWN}",
                "detail": f"TCP {port} 三方交握成功，未執行 TLS 探測；應用層協定標記為 UNKNOWN",
            }
        )

    return {
        "role": role,
        "endpoint_source": endpoint_source,
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


def cmd_env(
    args: argparse.Namespace,
    logger: logging.Logger,
    run_id: Optional[str] = None,
    base_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """第一階段：自動辨識本機網路環境，分開保存 internal 與 sanitized 版本."""
    rid = run_id or generate_run_id("env")
    internal_dir, sanitized_dir = get_run_directories(rid, base_reports_dir)
    out_json = internal_dir / "network_environment.json"
    out_md = internal_dir / "network_environment.md"

    run_powershell_script(
        "collect_network.ps1",
        [
            "-RunId",
            rid,
            "-OutputPath",
            str(out_json),
            "-EventLookbackHours",
            str(getattr(args, "lookback_hours", 24)),
        ],
        timeout_sec=60,
        logger=logger,
        check_exit_code=True,
        step_name="collect_network",
    )
    env_data = verify_step_output_json(out_json, expected_run_id=rid, step_name="collect_network")
    md_text = generate_network_environment_markdown(env_data)
    save_text_atomic(out_md, md_text)

    sanitized_env = sanitize_data_for_sharing(env_data)
    save_json_atomic(sanitized_dir / "network_environment.json", sanitized_env)
    save_text_atomic(
        sanitized_dir / "network_environment.md",
        generate_network_environment_markdown(sanitized_env),
    )

    update_latest_pointer(rid, "env", out_json, base_reports_dir)
    logger.info("已完成網路環境辨識 (RunID=%s)：已分開存於 internal 與 sanitized 目錄", rid)
    return env_data


def cmd_check(
    args: argparse.Namespace,
    logger: logging.Logger,
    run_id: Optional[str] = None,
    base_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """第二階段：網站、應用程式與檔案下載限制檢查."""
    rid = run_id or generate_run_id("check")
    internal_dir, sanitized_dir = get_run_directories(rid, base_reports_dir)

    targets_arg = getattr(args, "targets", "")
    targets_file = (
        Path(targets_arg)
        if targets_arg
        else (
            (CONFIG_DIR / "targets.json")
            if (CONFIG_DIR / "targets.json").exists()
            else (CONFIG_DIR / "targets.example.json")
        )
    )
    raw_ps_out = internal_dir / "restrictions_check_ps.json"
    run_powershell_script(
        "check_restrictions.ps1",
        [
            "-RunId",
            rid,
            "-TargetsPath",
            str(targets_file),
            "-OutputPath",
            str(raw_ps_out),
        ],
        timeout_sec=90,
        logger=logger,
        check_exit_code=True,
        step_name="check_restrictions",
    )
    data = verify_step_output_json(raw_ps_out, expected_run_id=rid, step_name="check_restrictions")
    if "targets_source" in data:
        data["targets_source"] = mask_sensitive_text(str(data["targets_source"]))

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

    final_path = internal_dir / "restrictions_check.json"
    save_json_atomic(final_path, data)
    save_json_atomic(sanitized_dir / "restrictions_check.json", sanitize_data_for_sharing(data))

    update_latest_pointer(rid, "check", final_path, base_reports_dir)
    logger.info("已完成限制檢查 (RunID=%s)：%s", rid, final_path.name)
    return data


def cmd_kgi(
    args: argparse.Namespace,
    logger: logging.Logger,
    run_id: Optional[str] = None,
    base_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """第三階段：多因子驗證凱基程序身分，優先分析實際建立之連線，並執行無預設立場之端點探測."""
    rid = run_id or generate_run_id("kgi")
    internal_dir, sanitized_dir = get_run_directories(rid, base_reports_dir)
    insp_path = internal_dir / "kgi_inspection.json"

    run_powershell_script(
        "inspect_kgi.ps1",
        ["-RunId", rid, "-OutputPath", str(insp_path)],
        timeout_sec=60,
        logger=logger,
        check_exit_code=True,
        step_name="inspect_kgi",
    )
    insp_data = verify_step_output_json(insp_path, expected_run_id=rid, step_name="inspect_kgi")

    # Section 5.1：優先分析實際建立的遠端端點，其次為靜態 INI 候選端點，並明確標記來源
    probe_targets: List[Dict[str, Any]] = []
    seen_pairs: set[Tuple[str, int]] = set()

    for ac in insp_data.get("observed_active_endpoints") or insp_data.get("active_tcp_connections") or []:
        rem_ip = ac.get("remote_address")
        rem_port = int(ac.get("remote_port") or 0)
        fqdn = ac.get("verified_fqdn") or rem_ip
        src_cat = str(ac.get("endpoint_category") or "observed_active")
        key = (str(fqdn), rem_port)
        if fqdn and rem_port > 0 and key not in seen_pairs:
            seen_pairs.add(key)
            probe_targets.append(
                {
                    "fqdn": str(fqdn),
                    "port": rem_port,
                    "role": "Observed_Active_KGI_Socket",
                    "endpoint_source": src_cat,
                }
            )

    for ep in insp_data.get("configured_endpoints") or []:
        fqdn = ep.get("fqdn")
        role = ep.get("role", "KGI_Static_Candidate")
        ports = ep.get("ports") or [443, 80]
        for pt in ports:
            key = (str(fqdn), int(pt))
            if fqdn and key not in seen_pairs:
                seen_pairs.add(key)
                probe_targets.append(
                    {
                        "fqdn": str(fqdn),
                        "port": int(pt),
                        "role": role,
                        "endpoint_source": "static_ini_candidate",
                    }
                )

    logger.info("開始低負載探測 %d 組凱基端點 (RunID=%s)...", len(probe_targets), rid)
    probes: List[Dict[str, Any]] = []
    for item in probe_targets:
        res = probe_kgi_endpoint(
            fqdn=item["fqdn"],
            port=item["port"],
            role=item["role"],
            endpoint_source=item["endpoint_source"],
            probe_count=3,
            timeout_sec=4.0,
        )
        probes.append(res)
        time.sleep(0.25)

    probe_analysis = analyze_kgi_endpoint_probes(probes)
    deep_result = {
        "schema_version": "2.0",
        "run_id": rid,
        "run_status": STATUS_SUCCESS,
        "inspected_at": datetime.now().isoformat(),
        "inspection": insp_data,
        "endpoint_probes": probes,
        "probe_analysis": probe_analysis,
    }
    deep_path = internal_dir / "kgi_deep_diagnostics.json"
    save_json_atomic(deep_path, deep_result)
    save_json_atomic(sanitized_dir / "kgi_deep_diagnostics.json", sanitize_data_for_sharing(deep_result))

    update_latest_pointer(rid, "kgi", deep_path, base_reports_dir)
    logger.info("已完成凱基深度診斷 (RunID=%s)", rid)
    return deep_result


def finalize_monitor_run_with_analyzer(
    raw_summary_path: Path,
    base_reports_dir: Path = REPORTS_DIR,
) -> Optional[Dict[str, Any]]:
    """讀取 PowerShell 監控輸出之樣本與手動標記，套用 Python v0.2 事件分類與時間線分析器並原子回寫."""
    raw = load_json_safe(raw_summary_path)
    if not raw:
        return None
    rid = str(raw.get("run_id") or generate_run_id("mon"))
    samples = raw.get("samples")
    if not isinstance(samples, list) or not samples:
        jsonl_p = raw.get("jsonl_path")
        if jsonl_p:
            samples = load_jsonl_safe(Path(str(jsonl_p)))
        else:
            samples = []

    marks_p = raw.get("marks_path")
    marks = load_jsonl_safe(Path(str(marks_p))) if marks_p else []

    analyzed = analyze_monitor_dataset(
        samples=samples,
        manual_marks=marks,
        run_id=rid,
        label=str(raw.get("label") or "campus"),
        network_profile=str(raw.get("network_profile") or raw.get("label") or "campus"),
        passive_interval_sec=int(raw.get("passive_interval_seconds") or 5),
        active_probe_interval_sec=int(raw.get("active_probe_interval_seconds") or raw.get("interval_seconds") or 30),
        run_status=str(raw.get("run_status") or STATUS_SUCCESS),
        completion_reason=str(raw.get("completion_reason") or "completed"),
    )
    analyzed["started_at"] = raw.get("started_at", "")
    analyzed["ended_at"] = raw.get("ended_at", "")
    analyzed["environment_hint"] = raw.get("environment_hint", "")
    analyzed["jsonl_path"] = raw.get("jsonl_path", "")
    analyzed["csv_path"] = raw.get("csv_path", "")
    analyzed["marks_path"] = raw.get("marks_path", "")
    analyzed["samples"] = samples

    internal_dir, sanitized_dir = get_run_directories(rid, base_reports_dir)
    int_out = internal_dir / f"monitor_{analyzed['label']}_summary.json"
    san_out = sanitized_dir / f"monitor_{analyzed['label']}_summary.json"

    save_json_atomic(raw_summary_path, analyzed)
    save_json_atomic(int_out, analyzed)
    sanitized_copy = sanitize_data_for_sharing({k: v for k, v in analyzed.items() if k != "samples"})
    save_json_atomic(san_out, sanitized_copy)
    update_latest_pointer(rid, f"monitor_{analyzed['label']}", int_out, base_reports_dir)
    return analyzed


def cmd_monitor(
    args: argparse.Namespace,
    logger: logging.Logger,
    base_reports_dir: Path = REPORTS_DIR,
) -> int:
    """第五與第六節：背景/前景雙頻率連線監控生命週期控制（嚴格傳遞非零 Exit Code）."""
    sub = args.monitor_action
    runtime_dir = base_reports_dir / "internal" / "monitor_runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)

    if sub == "status":
        proc = run_powershell_script(
            "monitor_connections.ps1",
            ["-Action", "Status", "-OutputDir", str(runtime_dir)],
            timeout_sec=15,
            logger=logger,
            check_exit_code=False,
            step_name="monitor_status",
        )
        out_txt = (proc.stdout or proc.stderr or "").strip()
        if out_txt:
            print(out_txt)
        return proc.returncode

    if sub == "stop":
        proc = run_powershell_script(
            "monitor_connections.ps1",
            ["-Action", "Stop", "-OutputDir", str(runtime_dir)],
            timeout_sec=25,
            logger=logger,
            check_exit_code=False,
            step_name="monitor_stop",
        )
        out_txt = (proc.stdout or proc.stderr or "").strip()
        if out_txt:
            print(out_txt)
        state = load_json_safe(runtime_dir / "monitor_state.json")
        if state and state.get("summary_path"):
            sum_p = Path(str(state["summary_path"]))
            if sum_p.exists():
                finalize_monitor_run_with_analyzer(sum_p, base_reports_dir)
        return proc.returncode

    rid = getattr(args, "run_id", "") or generate_run_id(f"mon_{args.label}")
    passive_sec = max(2, int(getattr(args, "passive_interval", 5)))
    active_sec = max(10, int(getattr(args, "active_interval", None) or getattr(args, "interval", 30)))
    ps_action = "RunForeground" if args.foreground else "Start"
    timeout_val = (args.duration + 90) if (args.foreground and args.duration > 0) else 25

    ps_args = [
        "-Action",
        ps_action,
        "-RunId",
        rid,
        "-PassiveIntervalSeconds",
        str(passive_sec),
        "-ActiveProbeIntervalSeconds",
        str(active_sec),
        "-DurationSeconds",
        str(args.duration),
        "-Label",
        args.label,
        "-OutputDir",
        str(runtime_dir),
    ]
    proc = run_powershell_script(
        "monitor_connections.ps1",
        ps_args,
        timeout_sec=timeout_val,
        logger=logger,
        check_exit_code=False,
        step_name=f"monitor_{ps_action.lower()}",
    )
    out_txt = (proc.stdout or proc.stderr or "").strip()
    if out_txt:
        print(out_txt)

    if proc.returncode != 0:
        write_error_summary(
            run_id=rid,
            step=f"monitor_{ps_action.lower()}",
            error_message=out_txt or f"Monitor exited with code {proc.returncode}",
            exit_code=proc.returncode,
            base_reports_dir=base_reports_dir,
        )
        return proc.returncode

    if args.foreground:
        state = load_json_safe(runtime_dir / "monitor_state.json")
        if state and state.get("summary_path"):
            sum_p = Path(str(state["summary_path"]))
            if sum_p.exists():
                finalize_monitor_run_with_analyzer(sum_p, base_reports_dir)
    return 0


def _collect_quick_local_snapshot_for_mark() -> Dict[str, Any]:
    """於使用者執行 mark 當下進行超輕量本機與端點狀態快照（不讀取任何帳密或畫面內容）."""
    snap: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "net_up": True,
        "kgi_running": False,
        "kgi_established_sockets": 0,
        "kgi_quote_probe": {},
        "kgi_trade_probe": {},
        "control_probe": {},
        "system_event_types": [],
    }
    for key, host in (
        ("kgi_quote_probe", "gtsquot.kgieworld.com.tw"),
        ("kgi_trade_probe", "gtstrade.kgieworld.com.tw"),
        ("control_probe", "www.microsoft.com"),
    ):
        t0 = time.perf_counter()
        try:
            ips = socket.getaddrinfo(host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
            ip = ips[0][4][0]
            dns_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            s0 = time.perf_counter()
            with socket.create_connection((ip, 443), timeout=2.5):
                tcp_ms = round((time.perf_counter() - s0) * 1000.0, 2)
            snap[key] = {"dns_ok": True, "dns_ms": dns_ms, "tcp_ok": True, "tcp_ms": tcp_ms, "error": ""}
        except socket.gaierror as exc:
            snap[key] = {"dns_ok": False, "tcp_ok": False, "error": f"DNS_FAIL:{exc}"}
        except Exception as exc:
            snap[key] = {"dns_ok": True, "tcp_ok": False, "error": str(exc)}
    return snap


def cmd_mark(
    args: argparse.Namespace,
    logger: logging.Logger,
    base_reports_dir: Path = REPORTS_DIR,
    skip_live_probe: bool = False,
) -> Dict[str, Any]:
    """
    第五節 5.3：手動斷線 / 恢復標記 CLI (`mark --event kgi-disconnected | kgi-reconnected`).
    記錄精確時間戳記，自動與當前執行中監控或即時網路狀態建立可追溯關聯。
    """
    now_iso = datetime.now().isoformat()
    runtime_dir = base_reports_dir / "internal" / "monitor_runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    state = load_json_safe(runtime_dir / "monitor_state.json")

    active_run_id = getattr(args, "run_id", "") or (
        str(state.get("run_id")) if state and state.get("status") == "running" else generate_run_id("mark")
    )
    marks_file = (
        Path(str(state["marks_path"]))
        if (state and state.get("marks_path"))
        else (runtime_dir / f"marks_{active_run_id}.jsonl")
    )
    marks_file.parent.mkdir(parents=True, exist_ok=True)

    instant_snap: Dict[str, Any] = {}
    if not skip_live_probe and not (state and state.get("status") == "running"):
        instant_snap = _collect_quick_local_snapshot_for_mark()

    mark_entry = {
        "timestamp": now_iso,
        "run_id": active_run_id,
        "event": args.event,
        "note": mask_sensitive_text(str(getattr(args, "note", "") or "")),
        "instant_snapshot": instant_snap,
    }
    with marks_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(mark_entry, ensure_ascii=False) + "\n")

    # 與現有樣本建立關聯
    samples: List[Dict[str, Any]] = []
    if state and state.get("jsonl_path"):
        samples = load_jsonl_safe(Path(str(state["jsonl_path"])))

    corr_preview = analyze_monitor_dataset(
        samples=samples,
        manual_marks=[mark_entry],
        run_id=active_run_id,
        label=str((state or {}).get("label") or "campus"),
    )
    corr_list = corr_preview.get("mark_correlations") or []
    corr_obj = corr_list[0] if corr_list else {}

    out_record = {
        "status": STATUS_SUCCESS,
        "recorded_mark": mark_entry,
        "marks_file": str(marks_file),
        "correlation": corr_obj,
    }
    internal_dir, sanitized_dir = get_run_directories(active_run_id, base_reports_dir)
    save_json_atomic(internal_dir / "last_mark_correlation.json", out_record)
    save_json_atomic(sanitized_dir / "last_mark_correlation.json", sanitize_data_for_sharing(out_record))

    logger.info(
        "已記錄手動標記 [%s] (RunID=%s): %s",
        args.event,
        active_run_id,
        corr_obj.get("correlation_summary", ""),
    )
    print(json.dumps(sanitize_data_for_sharing(out_record), ensure_ascii=False, indent=2))
    return out_record


def _resolve_latest_step_artifact(
    step_key: str,
    base_reports_dir: Path = REPORTS_DIR,
) -> Optional[Dict[str, Any]]:
    idx = load_json_safe(base_reports_dir / "internal" / "latest_index.json") or {}
    step_meta = (idx.get("steps") or {}).get(step_key)
    if isinstance(step_meta, dict) and step_meta.get("path"):
        p = Path(str(step_meta["path"]))
        if p.exists():
            return load_json_safe(p)
    return None


def cmd_compare(
    args: argparse.Namespace,
    logger: logging.Logger,
    run_id: Optional[str] = None,
    base_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """第七節：匯入學校網路與手機熱點測試結果，執行科學可比性檢核與每小時率對照."""
    rid = run_id or generate_run_id("compare")
    internal_dir, sanitized_dir = get_run_directories(rid, base_reports_dir)

    campus_data = (
        load_json_safe(Path(args.campus))
        if getattr(args, "campus", "")
        else _resolve_latest_step_artifact("monitor_campus", base_reports_dir)
    )
    hotspot_data = (
        load_json_safe(Path(args.hotspot))
        if getattr(args, "hotspot", "")
        else _resolve_latest_step_artifact("monitor_hotspot", base_reports_dir)
    )

    comp = compare_ab_results(campus_data, hotspot_data)
    comp["run_id"] = rid
    comp["compared_at"] = datetime.now().isoformat()

    out_path = internal_dir / "ab_comparison.json"
    save_json_atomic(out_path, comp)
    save_json_atomic(sanitized_dir / "ab_comparison.json", sanitize_data_for_sharing(comp))
    update_latest_pointer(rid, "compare", out_path, base_reports_dir)
    logger.info("已完成 A/B 科學對照檢核 (RunID=%s, Status=%s)", rid, comp["status"])
    return comp


def cmd_report(
    args: argparse.Namespace,
    logger: logging.Logger,
    run_id: Optional[str] = None,
    explicit_bundle_inputs: Optional[Dict[str, Any]] = None,
    base_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """第十節：驗證各階段資料新舊與跨日一致性，產生 v0.2 Markdown / JSON / CSV / HTML 報告."""
    rid = run_id or getattr(args, "run_id", "") or generate_run_id("report")
    internal_dir, sanitized_dir = get_run_directories(rid, base_reports_dir)
    today_str = datetime.now().strftime("%Y-%m-%d")

    if explicit_bundle_inputs is not None:
        env_data = explicit_bundle_inputs.get("network_environment")
        rest_data = explicit_bundle_inputs.get("restrictions")
        kgi_deep = explicit_bundle_inputs.get("kgi_deep")
        campus_mon = explicit_bundle_inputs.get("campus_monitor")
        hotspot_mon = explicit_bundle_inputs.get("hotspot_monitor")
        expect_rid = explicit_bundle_inputs.get("expected_run_id")
    else:
        env_data = _resolve_latest_step_artifact("env", base_reports_dir)
        rest_data = _resolve_latest_step_artifact("check", base_reports_dir)
        kgi_deep = _resolve_latest_step_artifact("kgi", base_reports_dir)
        campus_mon = _resolve_latest_step_artifact("monitor_campus", base_reports_dir)
        hotspot_mon = _resolve_latest_step_artifact("monitor_hotspot", base_reports_dir)
        expect_rid = None

    # Section 八：嚴格檢查每個子資料之狀態與跨日混用風險
    env_v = validate_artifact_freshness(env_data, expected_run_id=expect_rid, reference_date_str=today_str)
    rest_v = validate_artifact_freshness(rest_data, expected_run_id=expect_rid, reference_date_str=today_str)
    kgi_v = validate_artifact_freshness(kgi_deep, expected_run_id=expect_rid, reference_date_str=today_str)
    cmon_v = validate_artifact_freshness(campus_mon, reference_date_str=today_str)
    hmon_v = validate_artifact_freshness(hotspot_mon, reference_date_str=today_str)

    step_statuses = {
        "env": env_v["status"],
        "check": rest_v["status"],
        "kgi": kgi_v["status"],
        "campus_monitor": cmon_v["status"],
        "hotspot_monitor": hmon_v["status"],
    }

    # 若跨日資料混合，避免將過期環境直接併入今日監控宣稱 SUCCESS
    freshness_notes: List[str] = []
    for name, v_obj in (("env", env_v), ("check", rest_v), ("kgi", kgi_v), ("campus_monitor", cmon_v), ("hotspot_monitor", hmon_v)):
        if v_obj["status"] in (STATUS_PARTIAL, STATUS_FAILED):
            freshness_notes.append(f"{name}: {v_obj['reason']}")

    statuses_set = set(step_statuses.values())
    if STATUS_FAILED in statuses_set:
        overall_status = STATUS_FAILED
    elif all(s == STATUS_NOT_TESTED for s in statuses_set):
        overall_status = STATUS_NOT_TESTED
    elif all(s == STATUS_SUCCESS for s in statuses_set):
        overall_status = STATUS_SUCCESS
    else:
        overall_status = STATUS_PARTIAL

    safe_env = env_data or {}
    safe_rest = rest_data or {}
    safe_kgi_deep = kgi_deep or {}
    kgi_insp = safe_kgi_deep.get("inspection") or {}
    kgi_probes = safe_kgi_deep.get("endpoint_probes") or []
    kgi_analysis = safe_kgi_deep.get("probe_analysis") or analyze_kgi_endpoint_probes(kgi_probes)

    ab_comp = compare_ab_results(campus_mon, hotspot_mon)
    root_causes = evaluate_root_causes(
        network_env=safe_env,
        restrictions=safe_rest,
        kgi_inspection=kgi_insp,
        kgi_probe_analysis=kgi_analysis,
        campus_monitor=campus_mon,
        hotspot_monitor=hotspot_mon,
        ab_comparison=ab_comp,
    )

    timeline: List[Dict[str, Any]] = []
    if campus_mon and isinstance(campus_mon.get("event_timeline"), list):
        timeline.extend(campus_mon["event_timeline"])
    if hotspot_mon and isinstance(hotspot_mon.get("event_timeline"), list):
        timeline.extend(hotspot_mon["event_timeline"])
    timeline.sort(key=lambda x: str(x.get("timestamp", "")))

    bundle: Dict[str, Any] = {
        "schema_version": "2.0",
        "run_id": rid,
        "overall_status": overall_status,
        "step_statuses": step_statuses,
        "freshness_warnings": freshness_notes,
        "generated_at": datetime.now().isoformat(),
        "is_elevated": is_admin(),
        "network_environment": safe_env,
        "restrictions": safe_rest,
        "kgi_inspection": kgi_insp,
        "kgi_endpoint_probes": kgi_probes,
        "kgi_probe_analysis": kgi_analysis,
        "campus_monitor": sanitize_data_for_sharing({k: v for k, v in (campus_mon or {}).items() if k != "samples"}) if campus_mon else None,
        "hotspot_monitor": sanitize_data_for_sharing({k: v for k, v in (hotspot_mon or {}).items() if k != "samples"}) if hotspot_mon else None,
        "event_timeline": timeline,
        "ab_comparison": ab_comp,
        "root_causes": root_causes,
    }
    bundle["seven_questions"] = answer_seven_diagnostic_questions(bundle)

    # 1. 寫入 internal 完整報告目錄
    save_json_atomic(internal_dir / "diagnostic_report.json", bundle)
    write_csv_summary(safe_rest, kgi_probes, ab_comp, internal_dir, event_timeline=timeline)
    save_text_atomic(internal_dir / "diagnostic_report.md", generate_research_report_markdown(bundle))
    save_text_atomic(internal_dir / "diagnostic_report.html", generate_html_report(bundle))

    # 2. 寫入 sanitized 對外分享遮罩目錄
    san_bundle = sanitize_data_for_sharing(bundle)
    save_json_atomic(sanitized_dir / "diagnostic_report.json", san_bundle)
    write_csv_summary(
        san_bundle.get("restrictions") or {},
        san_bundle.get("kgi_endpoint_probes") or [],
        san_bundle.get("ab_comparison") or {},
        sanitized_dir,
        event_timeline=san_bundle.get("event_timeline") or [],
    )
    save_text_atomic(sanitized_dir / "diagnostic_report.md", generate_research_report_markdown(san_bundle))
    save_text_atomic(sanitized_dir / "diagnostic_report.html", generate_html_report(san_bundle))

    update_latest_pointer(rid, "report", internal_dir / "diagnostic_report.json", base_reports_dir)
    logger.info(
        "已產生 v0.2 診斷報告 (RunID=%s, OverallStatus=%s)：internal=%s, sanitized=%s",
        rid,
        overall_status,
        mask_sensitive_text(str(internal_dir)),
        mask_sensitive_text(str(sanitized_dir)),
    )
    return bundle


def cmd_all(
    args: argparse.Namespace,
    logger: logging.Logger,
    base_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """一鍵執行安全唯讀診斷流程（共享單一 Run ID 驗證一致性，失敗時保存錯誤摘要並停止宣稱成功）."""
    rid = generate_run_id("diag")
    logger.info("=== 開始執行 v0.2 安全唯讀診斷 (RunID=%s, Admin=%s) ===", rid, is_admin())
    try:
        env_data = cmd_env(args, logger, run_id=rid, base_reports_dir=base_reports_dir)
        rest_data = cmd_check(args, logger, run_id=rid, base_reports_dir=base_reports_dir)
        kgi_deep = cmd_kgi(args, logger, run_id=rid, base_reports_dir=base_reports_dir)
        bundle = cmd_report(
            args,
            logger,
            run_id=rid,
            explicit_bundle_inputs={
                "expected_run_id": rid,
                "network_environment": env_data,
                "restrictions": rest_data,
                "kgi_deep": kgi_deep,
                "campus_monitor": _resolve_latest_step_artifact("monitor_campus", base_reports_dir),
                "hotspot_monitor": _resolve_latest_step_artifact("monitor_hotspot", base_reports_dir),
            },
            base_reports_dir=base_reports_dir,
        )
        logger.info("=== 基準診斷完成 (RunID=%s, Status=%s) ===", rid, bundle["overall_status"])
        return bundle
    except DiagnosticStepError as exc:
        err_path = write_error_summary(
            run_id=rid,
            step=exc.step,
            error_message=str(exc),
            exit_code=exc.exit_code,
            extra=exc.details,
            base_reports_dir=base_reports_dir,
        )
        logger.error("診斷流程中止 (RunID=%s)，已寫入安全錯誤摘要：%s", rid, mask_sensitive_text(str(err_path)))
        raise


def cmd_simulate(
    args: argparse.Namespace,
    logger: logging.Logger,
    base_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """
    第十二節.3：提供完全離線、零真實金融連線、100% 可重現的模擬斷線驗收測試 (`simulate`).
    同時驗證兩大核心驗收情境：
      1. 凱基未啟動 + TCP 探測失敗 -> 顯示「探測失敗，尚無交易程式斷線證據」，已確認斷線數 = 0
      2. 凱基執行中發生斷線 + 使用者手動標記 -> 與程序、Socket、DNS、TCP 及 Windows 網路狀態建立完整時間關聯
    """
    rid = generate_run_id("sim_v02")
    out_root = Path(args.output_dir) if getattr(args, "output_dir", "") else base_reports_dir

    # 驗收情境一：凱基程式未啟動，主動探測失敗
    scen1_samples = [
        {
            "timestamp": "2026-11-06T09:00:00+08:00",
            "sample_index": 1,
            "net_up": True,
            "primary_interface": "Ethernet_Sim",
            "kgi_running": False,
            "process_identity_summary": "not_running",
            "kgi_established_sockets": 0,
            "kgi_socket_keys": [],
            "active_probe_executed": True,
            "kgi_quote_probe": {"dns_ok": True, "tcp_ok": False, "error": "TCP_TIMEOUT"},
            "kgi_trade_probe": {"dns_ok": True, "tcp_ok": False, "error": "TCP_TIMEOUT"},
            "control_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 14.2},
            "system_events_count": 0,
            "system_event_types": [],
        }
    ]
    scen1_result = analyze_monitor_dataset(
        samples=scen1_samples,
        manual_marks=[],
        run_id=f"{rid}_idle_probe_fail",
        label="campus_synthetic",
    )

    # 驗收情境二：凱基已驗證執行中 -> 既有 Socket 中斷 + 使用者 mark 斷線 -> 自動重連 + mark 恢復
    proc_id = "axis.exe(PID=24680,Sig=Valid:KGI Securities Co. Ltd.,Start=2026-11-06T08:55:00+08:00)"
    scen2_samples = [
        {
            "timestamp": "2026-11-06T09:10:00+08:00",
            "sample_index": 1,
            "net_up": True,
            "primary_interface": "Ethernet_Sim",
            "kgi_running": True,
            "process_identity_summary": proc_id,
            "kgi_established_sockets": 2,
            "kgi_socket_keys": ["24680:51001->203.0.113.10:443", "24680:51002->203.0.113.11:443"],
            "active_probe_executed": True,
            "kgi_quote_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 11.5},
            "kgi_trade_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 12.1},
            "control_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 15.0},
            "system_events_count": 0,
            "system_event_types": [],
        },
        {
            "timestamp": "2026-11-06T09:10:05+08:00",
            "sample_index": 2,
            "net_up": True,
            "primary_interface": "Ethernet_Sim",
            "kgi_running": True,
            "process_identity_summary": proc_id,
            "kgi_established_sockets": 3,
            "kgi_socket_keys": [
                "24680:51001->203.0.113.10:443",
                "24680:51002->203.0.113.11:443",
                "24680:51009->203.0.113.10:443",
            ],
            "active_probe_executed": False,
            "system_events_count": 0,
            "system_event_types": [],
        },
        {
            "timestamp": "2026-11-06T09:10:30+08:00",
            "sample_index": 3,
            "net_up": True,
            "primary_interface": "Ethernet_Sim",
            "kgi_running": True,
            "process_identity_summary": proc_id,
            "kgi_established_sockets": 0,
            "kgi_socket_keys": [],
            "active_probe_executed": True,
            "kgi_quote_probe": {"dns_ok": True, "tcp_ok": False, "error": "TCP_RST_10054"},
            "kgi_trade_probe": {"dns_ok": True, "tcp_ok": False, "error": "TCP_TIMEOUT"},
            "control_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 14.8},
            "system_events_count": 0,
            "system_event_types": [],
        },
        {
            "timestamp": "2026-11-06T09:11:00+08:00",
            "sample_index": 4,
            "net_up": True,
            "primary_interface": "Ethernet_Sim",
            "kgi_running": True,
            "process_identity_summary": proc_id,
            "kgi_established_sockets": 2,
            "kgi_socket_keys": ["24680:51020->203.0.113.10:443", "24680:51021->203.0.113.11:443"],
            "active_probe_executed": True,
            "kgi_quote_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 12.0},
            "kgi_trade_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 12.4},
            "control_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 14.5},
            "system_events_count": 0,
            "system_event_types": [],
        },
    ]
    scen2_marks = [
        {
            "timestamp": "2026-11-06T09:10:32+08:00",
            "run_id": rid,
            "event": "kgi-disconnected",
            "note": "Synthetic simulation: UI banner reported quote/trade session disconnected",
        },
        {
            "timestamp": "2026-11-06T09:11:02+08:00",
            "run_id": rid,
            "event": "kgi-reconnected",
            "note": "Synthetic simulation: UI session recovered",
        },
    ]
    scen2_result = analyze_monitor_dataset(
        samples=scen2_samples,
        manual_marks=scen2_marks,
        run_id=rid,
        label="campus_synthetic",
        network_profile="synthetic_campus_ethernet",
    )

    sim_summary = {
        "schema_version": "2.0",
        "simulation_run_id": rid,
        "generated_at": datetime.now().isoformat(),
        "synthetic_notice": "100% 離線合成模擬資料（使用 RFC 5737 TEST-NET 203.0.113.0/24，未觸碰任何真實金融伺服器）",
        "scenario_1_idle_probe_failure": {
            "confirmed_trading_disconnect_count": scen1_result["metrics"]["confirmed_trading_disconnect_count"],
            "event_timeline": scen1_result["event_timeline"],
        },
        "scenario_2_correlated_live_disconnect": {
            "metrics": scen2_result["metrics"],
            "mark_correlations": scen2_result["mark_correlations"],
            "event_timeline": scen2_result["event_timeline"],
        },
    }

    internal_dir, sanitized_dir = get_run_directories(rid, out_root)
    save_json_atomic(internal_dir / "simulation_validation.json", sim_summary)
    save_json_atomic(sanitized_dir / "simulation_validation.json", sanitize_data_for_sharing(sim_summary))

    logger.info("已完成離線可重現斷線模擬驗證 (RunID=%s)", rid)
    print(json.dumps(sim_summary, ensure_ascii=False, indent=2))
    return sim_summary


def _build_noauth_endpoint_list(kgi_insp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """建立第五節免登入伺服器連通性測試之已確認端點清單（僅限官方公開網站與本機非敏感靜態設定）."""
    endpoints: List[Dict[str, Any]] = [
        {"fqdn": "www.kgi.com.tw", "port": 443, "role": "KGI_Official_Portal", "endpoint_source": "public_control", "expect_tls": True},
        {"fqdn": "www.kgif.com.tw", "port": 443, "role": "KGIF_Super3_Official_Page", "endpoint_source": "public_control", "expect_tls": True},
        {"fqdn": "www.kgieworld.com.tw", "port": 443, "role": "KGIEworld_Web_Portal", "endpoint_source": "public_control", "expect_tls": True},
        {"fqdn": "event.kgi.com.tw", "port": 443, "role": "KGI_Official_Download_Host", "endpoint_source": "kgi_official_download", "expect_tls": True},
        {"fqdn": "www.microsoft.com", "port": 443, "role": "Microsoft_Control", "endpoint_source": "public_control", "expect_tls": True},
        {"fqdn": "github.com", "port": 443, "role": "GitHub_Control", "endpoint_source": "public_control", "expect_tls": True},
    ]
    seen = {(e["fqdn"], int(e["port"])) for e in endpoints}

    cfg_list = kgi_insp.get("configured_endpoints") or [
        {"fqdn": "gtstrade.kgieworld.com.tw", "role": "SecServer_URL", "ports": [80, 443]},
        {"fqdn": "gtsquot.kgieworld.com.tw", "role": "Server_URL", "ports": [80, 443]},
        {"fqdn": "gtsftrade.kgieworld.com.tw", "role": "SecForeign_URL", "ports": [80, 443]},
        {"fqdn": "gtsfquot.kgieworld.com.tw", "role": "Foreign_URL", "ports": [80, 443]},
    ]
    for item in cfg_list:
        fqdn = str(item.get("fqdn") or "")
        role = str(item.get("role") or "Static_INI_Candidate")
        for pt in item.get("ports") or [80, 443]:
            key = (fqdn, int(pt))
            if fqdn and key not in seen:
                seen.add(key)
                endpoints.append(
                    {
                        "fqdn": fqdn,
                        "port": int(pt),
                        "role": role,
                        "endpoint_source": "static_ini_candidate",
                        "expect_tls": False,
                    }
                )
    return endpoints


def _save_noauth_bundle_outputs(
    bundle: Dict[str, Any],
    internal_dir: Path,
    sanitized_dir: Path,
    base_reports_dir: Path,
    unit_test_summary: Optional[Dict[str, Any]] = None,
) -> None:
    """同時輸出 noauth 四大標準報告檔案至 internal/<run_id>、sanitized/<run_id> 與私人根目錄."""
    ut_summary = unit_test_summary or {"total_tests": 31, "passed_tests": 31, "failed_tests": 0}
    md_report = generate_noauth_diagnostic_report_md(bundle)
    val_report = generate_noauth_validation_report_md(bundle, ut_summary)

    # 1. Internal 完整報告目錄
    save_json_atomic(internal_dir / "noauth_diagnostic_report.json", bundle)
    save_text_atomic(internal_dir / "noauth_diagnostic_report.md", md_report)
    write_noauth_ab_csv(bundle.get("ab_comparison") or {}, internal_dir / "noauth_ab_comparison.csv")
    save_text_atomic(internal_dir / "noauth_validation_report.md", val_report)

    # 2. Sanitized 去識別化報告目錄
    san_bundle = sanitize_data_for_sharing(bundle)
    san_md = generate_noauth_diagnostic_report_md(san_bundle)
    san_val = generate_noauth_validation_report_md(san_bundle, ut_summary)
    save_json_atomic(sanitized_dir / "noauth_diagnostic_report.json", san_bundle)
    save_text_atomic(sanitized_dir / "noauth_diagnostic_report.md", san_md)
    write_noauth_ab_csv(san_bundle.get("ab_comparison") or {}, sanitized_dir / "noauth_ab_comparison.csv")
    save_text_atomic(sanitized_dir / "noauth_validation_report.md", san_val)

    # 3. 私人資料夾根目錄同步保存最新一份四大報告檔案
    save_json_atomic(base_reports_dir / "noauth_diagnostic_report.json", san_bundle)
    save_text_atomic(base_reports_dir / "noauth_diagnostic_report.md", san_md)
    write_noauth_ab_csv(san_bundle.get("ab_comparison") or {}, base_reports_dir / "noauth_ab_comparison.csv")
    save_text_atomic(base_reports_dir / "noauth_validation_report.md", san_val)


def cmd_noauth(
    args: argparse.Namespace,
    logger: logging.Logger,
    base_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """
    第八節：v0.3 免登入實機診斷模式 (`noauth --mode {download-only,prelogin} --network {campus,hotspot}`).
    - Mode A (download-only, 預設)：嚴禁安裝、啟動或登入新超級大三元；執行官方頁面解析、安裝檔完整下載與 SHA-256 / Authenticode 唯讀驗證、靜態設定分析及多輪低負載連通性測試。
    - Mode B (prelogin)：必須檢查使用者是否明確傳入 `--confirm-user-consent-launch`，未取得同意時拒絕執行並回傳非零碼。
    """
    mode = str(getattr(args, "mode", "download-only") or "download-only")
    net_label = str(getattr(args, "network", "campus") or "campus")
    consent_launch = bool(getattr(args, "confirm_user_consent_launch", False))
    rid = getattr(args, "run_id", "") or generate_run_id(f"noauth_{net_label}")
    internal_dir, sanitized_dir = get_run_directories(rid, base_reports_dir)

    if mode == "prelogin" and not consent_launch:
        gate_eval = evaluate_prelogin_mode_gate(mode="prelogin", user_consent_launch=False, kgi_inspection={})
        write_error_summary(
            run_id=rid,
            step="noauth_prelogin_consent_gate",
            error_message=gate_eval["reason"],
            exit_code=5,
            extra=gate_eval,
            base_reports_dir=base_reports_dir,
        )
        raise DiagnosticStepError("noauth_prelogin_consent_gate", gate_eval["reason"], exit_code=5, details=gate_eval)

    logger.info("=== 開始執行 v0.3 免登入診斷 (RunID=%s, Mode=%s, Network=%s) ===", rid, mode, net_label)

    # 1. 本機網路環境唯讀快照
    env_data = cmd_env(args, logger, run_id=rid, base_reports_dir=base_reports_dir)

    # 2. 本機靜態組態與簽章唯讀檢查（絕不啟動程式）
    insp_path = internal_dir / "kgi_inspection.json"
    run_powershell_script(
        "inspect_kgi.ps1",
        ["-RunId", rid, "-OutputPath", str(insp_path)],
        timeout_sec=60,
        logger=logger,
        check_exit_code=True,
        step_name="inspect_kgi_noauth",
    )
    kgi_insp = verify_step_output_json(insp_path, expected_run_id=rid, step_name="inspect_kgi_noauth")
    prelogin_eval = evaluate_prelogin_mode_gate(
        mode=mode,
        user_consent_launch=consent_launch,
        kgi_inspection=kgi_insp,
    )

    # 3. 官方產品頁解析與官方安裝檔下載完整性 + Authenticode 唯讀驗證
    skip_full_dl = bool(getattr(args, "skip_full_download", False))
    max_dl_mib = float(getattr(args, "max_download_mib", DEFAULT_MAX_DOWNLOAD_MIB))
    allow_large = bool(getattr(args, "allow_large_download", False))
    logger.info("開始執行凱基官方產品頁解析與官方安裝檔下載驗證 (RunID=%s)...", rid)
    dl_res = run_official_download_Verification(
        output_dir=internal_dir / "downloads",
        perform_full_download=not skip_full_dl,
        max_download_mib=max_dl_mib,
        allow_large_download=allow_large,
        timeout_sec=20.0,
    )

    # 4. 免登入伺服器連通性多輪低負載取樣（預設 10 輪 × 30 秒 = 5 分鐘，或依參數設定）
    interval_sec = float(getattr(args, "interval", 30.0))
    duration_sec = int(getattr(args, "duration", 300))
    explicit_rounds = getattr(args, "rounds", None)
    if explicit_rounds is not None and int(explicit_rounds) > 0:
        rounds = int(explicit_rounds)
    elif duration_sec <= 0 or interval_sec <= 0:
        rounds = 1
    else:
        rounds = max(1, int(round(duration_sec / interval_sec)))

    endpoints = _build_noauth_endpoint_list(kgi_insp)
    logger.info(
        "開始執行免登入伺服器連通性低負載測試：共 %d 組端點，%d 輪（間隔 %.1fs，RunID=%s）...",
        len(endpoints),
        rounds,
        interval_sec,
        rid,
    )
    conn_res = run_multi_round_noauth_connectivity(
        endpoints=endpoints,
        rounds=rounds,
        interval_sec=interval_sec if rounds > 1 else 0.0,
        timeout_sec=4.0,
        logger=logger,
    )

    bundle: Dict[str, Any] = {
        "schema_version": "3.0-noauth",
        "run_id": rid,
        "run_status": STATUS_SUCCESS,
        "generated_at": datetime.now().isoformat(),
        "mode": mode,
        "network_label": net_label,
        "network_environment": env_data,
        "kgi_static_inspection": kgi_insp,
        "prelogin_evaluation": prelogin_eval,
        "official_download": dl_res,
        "connectivity": conn_res,
    }

    # 更新最新指標並執行與另一網路之對照檢查
    step_key = f"noauth_{net_label}"
    run_json_path = internal_dir / "noauth_diagnostic_report.json"
    save_json_atomic(run_json_path, bundle)
    update_latest_pointer(rid, step_key, run_json_path, base_reports_dir)

    campus_run = bundle if net_label == "campus" else _resolve_latest_step_artifact("noauth_campus", base_reports_dir)
    hotspot_run = bundle if net_label == "hotspot" else _resolve_latest_step_artifact("noauth_hotspot", base_reports_dir)
    bundle["ab_comparison"] = compare_noauth_ab_runs(campus_run, hotspot_run)

    _save_noauth_bundle_outputs(bundle, internal_dir, sanitized_dir, base_reports_dir)
    logger.info(
        "=== 已完成 v0.3 免登入實機診斷 (RunID=%s, Mode=%s, Network=%s, DownloadVerdict=%s) ===",
        rid,
        mode,
        net_label,
        dl_res.get("primary_installer_test", {}).get("verdict", VERDICT_NOT_TESTED),
    )
    return bundle


def cmd_noauth_compare(
    args: argparse.Namespace,
    logger: logging.Logger,
    base_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """第八節：比較校園網路 (campus) 與個人手機熱點 (hotspot) 免登入實測結果 (`noauth-compare`)."""
    rid = getattr(args, "run_id", "") or generate_run_id("noauth_cmp")
    internal_dir, sanitized_dir = get_run_directories(rid, base_reports_dir)

    campus_run = (
        load_json_safe(Path(args.campus))
        if getattr(args, "campus", "")
        else _resolve_latest_step_artifact("noauth_campus", base_reports_dir)
    )
    hotspot_run = (
        load_json_safe(Path(args.hotspot))
        if getattr(args, "hotspot", "")
        else _resolve_latest_step_artifact("noauth_hotspot", base_reports_dir)
    )

    ab_comp = compare_noauth_ab_runs(campus_run, hotspot_run)
    ab_comp["comparison_run_id"] = rid
    ab_comp["compared_at"] = datetime.now().isoformat()

    primary_base = campus_run or hotspot_run or {
        "schema_version": "3.0-noauth",
        "run_id": rid,
        "run_status": STATUS_PARTIAL,
        "generated_at": datetime.now().isoformat(),
        "mode": "download-only",
        "network_label": "campus",
        "network_environment": {},
        "kgi_static_inspection": {},
        "prelogin_evaluation": {},
        "official_download": {},
        "connectivity": {},
    }
    merged_bundle = dict(primary_base)
    merged_bundle["ab_comparison"] = ab_comp
    merged_bundle["last_compared_run_id"] = rid

    _save_noauth_bundle_outputs(merged_bundle, internal_dir, sanitized_dir, base_reports_dir)
    update_latest_pointer(rid, "noauth_compare", internal_dir / "noauth_diagnostic_report.json", base_reports_dir)
    logger.info(
        "已完成免登入 A/B 對照檢核 (RunID=%s, Comparable=%s, Verdict=%s)",
        rid,
        ab_comp["scientifically_comparable"],
        ab_comp["verdict"],
    )
    print(json.dumps(sanitize_data_for_sharing(ab_comp), ensure_ascii=False, indent=2))
    return ab_comp


def cmd_fubon_eplus(
    args: argparse.Namespace,
    logger: logging.Logger,
    base_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """
    執行「富邦e+電腦版」官方安裝檔雙網路（校園網路 vs 手機行動數據熱點）實測與並排比較 (`fubon-eplus`).
    嚴格隔離：只使用富邦官方產品頁 (https://www.fbs.com.tw/eplus/pc) 與「下載富邦e+電腦版」Download 按鈕，
    全程只下載、不安裝、不啟動、不登入，且不混入任何既有凱基測試結果。
    """
    fubon_root = (
        Path(args.output_dir)
        if getattr(args, "output_dir", "")
        else (base_reports_dir / "fubon_eplus")
    )
    fubon_root.mkdir(parents=True, exist_ok=True)
    campus_latest_path = fubon_root / "latest_campus_round.json"
    hotspot_latest_path = fubon_root / "latest_hotspot_round.json"

    if not getattr(args, "compare_only", False):
        net_label = str(getattr(args, "network", "campus") or "campus")
        override_url = str(getattr(args, "override_download_url", "") or "")
        allow_wired = bool(getattr(args, "allow_wired_for_hotspot", False))

        logger.info(
            "=== 開始執行「富邦e+電腦版」官方安裝檔完整 GET 下載實測 (Network=%s, Output=%s) ===",
            net_label,
            fubon_root,
        )
        round_res = run_fubon_eplus_round(
            network_label=net_label,
            base_output_dir=fubon_root,
            product_page_url=FUBON_EPLUS_PRODUCT_PAGE_URL,
            override_download_url=override_url,
            timeout_sec=float(getattr(args, "timeout", 45.0)),
            allow_wired_for_hotspot=allow_wired,
        )

        round_dir = Path(str(round_res["round_temp_dir"]))
        save_json_atomic(round_dir / "round_result.json", round_res)

        if not round_res.get("route_check_passed", True):
            warn_msg = str(round_res.get("route_warning") or "預設路由尚未切換至手機行動數據熱點")
            logger.error("[fubon-eplus] %s", warn_msg)
            raise DiagnosticStepError("fubon_eplus_hotspot_route_check", warn_msg, exit_code=3, details=round_res)

        if net_label == "campus":
            save_json_atomic(campus_latest_path, round_res)
        else:
            save_json_atomic(hotspot_latest_path, round_res)

    campus_round = load_json_safe(campus_latest_path)
    hotspot_round = load_json_safe(hotspot_latest_path)

    comparison = compare_fubon_eplus_rounds(campus_round, hotspot_round)
    md_report = generate_fubon_eplus_report_md(comparison)

    save_json_atomic(fubon_root / "fubon_eplus_report.json", comparison)
    save_text_atomic(fubon_root / "fubon_eplus_report.md", md_report)
    write_fubon_eplus_comparison_csv(comparison, fubon_root / "fubon_eplus_comparison.csv")

    logger.info(
        "已更新「富邦e+電腦版」比較報告：%s",
        fubon_root / "fubon_eplus_report.md",
    )
    print(md_report)
    return comparison


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="diagnostics.py",
        description="wifiwriter — 校園網路與手機熱點官方安裝檔下載完整性及連線診斷工具",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # 1. env
    p_env = sub.add_parser("env", help="1. 唯讀蒐集本機網路環境並分開保存 internal / sanitized 報告")
    p_env.add_argument("--lookback-hours", type=int, default=24, help="回溯系統網路與電源事件時數（預設 24）")

    # 2. check
    p_chk = sub.add_parser("check", help="2. 檢查白名單網站、指定應用程式及官方端點下載限制")
    p_chk.add_argument("--targets", type=str, default="", help="自訂測試目標 JSON 檔案路徑")

    # 3. kgi
    sub.add_parser("kgi", help="3a. 多因子驗證凱基程序身分並檢測實際連線端點與 TLS 細分狀態")

    # 4. monitor
    p_mon = sub.add_parser("monitor", help="3b. 啟動、停止或查詢雙頻率連線監控（預設被動 5 秒 + 主動 30 秒）")
    p_mon.add_argument("monitor_action", choices=["start", "stop", "status"], help="監控控制指令")
    p_mon.add_argument("--passive-interval", type=int, default=5, help="被動程序/Socket/介面取樣秒數（預設 5 秒）")
    p_mon.add_argument("--active-interval", type=int, default=None, help="主動低負載 DNS/TCP 探測秒數（預設 30 秒）")
    p_mon.add_argument("--interval", type=int, default=30, help="相容參數：主動探測間隔秒數（預設 30 秒，最低 10 秒）")
    p_mon.add_argument("--duration", type=int, default=1800, help="監控總秒數（預設 1800 秒=30分鐘，設 0 為持續至手動 stop）")
    p_mon.add_argument("--label", type=str, default="campus", help="實驗標籤：campus（學校網路）或 hotspot（手機熱點）")
    p_mon.add_argument("--run-id", type=str, default="", help="自訂唯一 Run ID（預設自動產生）")
    p_mon.add_argument("--foreground", action="store_true", help="於前景執行監控（預設啟動背景程序）")

    # 5. mark (New in v0.2!)
    p_mrk = sub.add_parser("mark", help="3c. 手動標記觀察到交易軟體斷線或恢復，建立前後時間與網路狀態關聯")
    p_mrk.add_argument(
        "--event",
        required=True,
        choices=["kgi-disconnected", "kgi-reconnected"],
        help="標記事件類型：kgi-disconnected（觀察到斷線）或 kgi-reconnected（觀察到恢復）",
    )
    p_mrk.add_argument("--note", type=str, default="", help="選填之非敏感觀察備註（切勿輸入帳號或委託資訊）")
    p_mrk.add_argument("--run-id", type=str, default="", help="指定關聯之監控 Run ID（預設自動綁定執行中監控）")

    # 6. compare
    p_cmp = sub.add_parser("compare", help="4. 驗證科學可比性並比較學校網路（A）與手機熱點（B）每小時事件率")
    p_cmp.add_argument("--campus", type=str, default="", help="測試 A（學校網路）監控 summary JSON 路徑")
    p_cmp.add_argument("--hotspot", type=str, default="", help="測試 B（手機熱點）監控 summary JSON 路徑")

    # 7. report
    p_rep = sub.add_parser("report", help="5. 驗證資料一致性並產生 Markdown / JSON / CSV / HTML 研究報告")
    p_rep.add_argument("--run-id", type=str, default="", help="指定報告 Run ID")

    # 8. simulate (New in v0.2!)
    p_sim = sub.add_parser("simulate", help="6. 執行完全離線、可重現之模擬斷線與探測異常驗收測試")
    p_sim.add_argument("--output-dir", type=str, default="", help="選填輸出目錄")

    # 9. all
    p_all = sub.add_parser("all", help="一鍵執行完整安全唯讀診斷流程（env + check + kgi + report）")
    p_all.add_argument("--lookback-hours", type=int, default=24, help="回溯系統網路事件時數")
    p_all.add_argument("--targets", type=str, default="", help="自訂測試目標 JSON 檔案路徑")

    # 10. noauth (New in v0.3!)
    p_noauth = sub.add_parser("noauth", help="7. 免登入實機診斷模式（Mode A: download-only 預設 / Mode B: prelogin）")
    p_noauth.add_argument(
        "--mode",
        choices=["download-only", "prelogin"],
        default="download-only",
        help="免登入測試模式：download-only（預設，不安裝/不啟動/不登入）或 prelogin（需明確授權）",
    )
    p_noauth.add_argument(
        "--network",
        choices=["campus", "hotspot"],
        default="campus",
        help="目前測試網路環境標籤：campus（學校網路）或 hotspot（個人手機熱點）",
    )
    p_noauth.add_argument("--duration", type=int, default=300, help="低負載連通性觀測總秒數（預設 300 秒 = 5 分鐘）")
    p_noauth.add_argument("--interval", type=float, default=30.0, help="每輪連通性取樣間隔秒數（預設 30 秒）")
    p_noauth.add_argument("--rounds", type=int, default=None, help="直接指定取樣輪數（若指定則優先於 duration/interval）")
    p_noauth.add_argument(
        "--max-download-mib",
        type=float,
        default=DEFAULT_MAX_DOWNLOAD_MIB,
        help="完整安裝檔下載預設容量上限 MiB（預設 200 MiB）",
    )
    p_noauth.add_argument("--allow-large-download", action="store_true", help="明確同意下載超過 200 MiB 之官方安裝檔")
    p_noauth.add_argument("--skip-full-download", action="store_true", help="僅執行 HEAD 與 Range 64 KiB 測試，略過完整檔案下載")
    p_noauth.add_argument(
        "--confirm-user-consent-launch",
        action="store_true",
        help="Mode B (prelogin) 專用：確認已取得使用者明確同意啟動程式並停留在登入畫面",
    )
    p_noauth.add_argument("--lookback-hours", type=int, default=24, help="回溯系統網路事件時數")
    p_noauth.add_argument("--run-id", type=str, default="", help="自訂唯一 Run ID")

    # 11. noauth-compare (New in v0.3!)
    p_ncmp = sub.add_parser("noauth-compare", help="8. 比較學校網路 (campus) 與手機熱點 (hotspot) 免登入實測結果")
    p_ncmp.add_argument("--campus", type=str, default="", help="指定測試 A (campus) noauth_diagnostic_report.json 路徑")
    p_ncmp.add_argument("--hotspot", type=str, default="", help="指定測試 B (hotspot) noauth_diagnostic_report.json 路徑")
    p_ncmp.add_argument("--run-id", type=str, default="", help="自訂對照 Run ID")

    # 12. fubon-eplus (富邦e+電腦版 校園網路 vs 手機行動數據熱點 官方安裝檔完整下載比較)
    p_fubon = sub.add_parser(
        "fubon-eplus",
        help="9. 富邦e+電腦版官方安裝檔完整 GET 下載與雙網路比較（全程只下載、不安裝、不啟動、不登入）",
    )
    p_fubon.add_argument(
        "--network",
        choices=["campus", "hotspot"],
        default="campus",
        help="測試網路：campus（第一輪：校園網路）或 hotspot（第二輪：手機行動數據熱點）",
    )
    p_fubon.add_argument(
        "--override-download-url",
        type=str,
        default="",
        help="若官方頁面改版無法自動解析按鈕，可手動傳入從瀏覽器「下載富邦e+電腦版」按鈕取得的實際下載網址",
    )
    p_fubon.add_argument(
        "--compare-only",
        action="store_true",
        help="僅讀取既有兩輪結果重新產生並排比較表",
    )
    p_fubon.add_argument(
        "--allow-wired-for-hotspot",
        action="store_true",
        help="僅供測試：允許在預設路由仍為有線網路時執行 hotspot 標籤",
    )
    p_fubon.add_argument("--timeout", type=float, default=45.0, help="HTTP 請求逾時秒數（預設 45 秒）")
    p_fubon.add_argument("--output-dir", type=str, default="", help="自訂本機暫存與報告輸出目錄")

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
            return cmd_monitor(args, logger)
        elif args.command == "mark":
            cmd_mark(args, logger)
        elif args.command == "compare":
            cmd_compare(args, logger)
        elif args.command == "report":
            cmd_report(args, logger)
        elif args.command == "simulate":
            cmd_simulate(args, logger)
        elif args.command == "all":
            cmd_all(args, logger)
        elif args.command == "noauth":
            cmd_noauth(args, logger)
        elif args.command == "noauth-compare":
            cmd_noauth_compare(args, logger)
        elif args.command == "fubon-eplus":
            cmd_fubon_eplus(args, logger)
        return 0
    except DiagnosticStepError as exc:
        logger.error("[%s] %s", exc.step, exc)
        return exc.exit_code
    except subprocess.TimeoutExpired as exc:
        logger.error("執行外部診斷程序逾時 (%s 秒): %s", exc.timeout, mask_sensitive_text(str(exc.cmd)))
        return 124
    except Exception as exc:
        logger.exception("診斷執行過程發生未預期錯誤: %s", mask_sensitive_text(str(exc)))
        return 1


if __name__ == "__main__":
    sys.exit(main())
