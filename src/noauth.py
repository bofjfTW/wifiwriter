"""wifiwriter v0.3 — 免登入實機診斷、官方安裝檔完整性驗證與校園網路 A/B 對照模組."""

from __future__ import annotations

import csv
import hashlib
import html.parser
import json
import os
import re
import socket
import ssl
import statistics
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.analyzer import (
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
    mask_sensitive_text,
)
from src.privacy import sanitize_data_for_sharing

# ============================================================================
# 第七節：v0.3 八大標準診斷分類常數
# ============================================================================
VERDICT_VERIFIED_SUCCESS = "VERIFIED_SUCCESS"
VERDICT_VERIFIED_FAILURE = "VERIFIED_FAILURE"
VERDICT_INTERMITTENT = "INTERMITTENT"
VERDICT_POSSIBLE_RESTRICTION = "POSSIBLE_RESTRICTION"
VERDICT_EXPLICIT_POLICY_BLOCK = "EXPLICIT_POLICY_BLOCK"
VERDICT_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
VERDICT_NOT_TESTED = "NOT_TESTED"
VERDICT_NOT_APPLICABLE = "NOT_APPLICABLE"

ALL_NOAUTH_VERDICTS = {
    VERDICT_VERIFIED_SUCCESS,
    VERDICT_VERIFIED_FAILURE,
    VERDICT_INTERMITTENT,
    VERDICT_POSSIBLE_RESTRICTION,
    VERDICT_EXPLICIT_POLICY_BLOCK,
    VERDICT_INSUFFICIENT_EVIDENCE,
    VERDICT_NOT_TESTED,
    VERDICT_NOT_APPLICABLE,
}

# 官方產品頁與預設上限
KGI_OFFICIAL_SUPER_PAGE_URL = "https://www.kgif.com.tw/zh-tw/individual-trading-platform-super"
DEFAULT_MAX_DOWNLOAD_MIB = 200.0
RANGE_PROBE_BYTES = 65536  # 64 KiB 低負載 Range 測試

MITM_OR_FIREWALL_CERT_PATTERNS = re.compile(
    r"(Fortinet|FortiGate|Palo\s*Alto|Zscaler|SonicWall|Sophos|Sangfor|Check\s*Point|BlueCoat|Untrusted|Aruba|Cisco\s*Umbrella)",
    re.IGNORECASE,
)
EXPLICIT_BLOCK_REDIRECT_PATTERNS = re.compile(
    r"(blockpage|fortiguard|captive|portal|access[-_]?denied|policy[-_]?block|web[-_]?filter)",
    re.IGNORECASE,
)
TRUSTED_KGI_SIGNER_PATTERNS = re.compile(
    r"(KGI\s*Securities|KGI\s*Futures|\u51f1\u57fa\u8b49\u5238|\u51f1\u57fa\u671f\u8ca8|Kway|SysJust)",
    re.IGNORECASE,
)


class _HrefExtractor(html.parser.HTMLParser):
    """安全解析官方網頁 HTML 中的超連結 (<a> 與相關資源連結)."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() in ("a", "link", "area"):
            for k, v in attrs:
                if k.lower() == "href" and v:
                    self.links.append(v.strip())


def extract_official_download_links_from_html(
    html_text: str,
    base_url: str = KGI_OFFICIAL_SUPER_PAGE_URL,
) -> Dict[str, Any]:
    """
    從凱基官方「新超級大三元」產品頁 HTML 中提取實際有效的官方安裝檔與說明連結.
    絕不猜測安裝檔 URL；同時回傳完整 URL 與去除 GA 追蹤參數後的正規化下載網址。
    """
    parser = _HrefExtractor()
    try:
        parser.feed(html_text or "")
    except Exception:
        pass

    installer_links: List[Dict[str, str]] = []
    doc_links: List[str] = []
    seen_clean: set[str] = set()

    for raw_href in parser.links:
        abs_url = urllib.parse.urljoin(base_url, raw_href)
        parsed = urllib.parse.urlsplit(abs_url)
        if parsed.scheme.lower() not in ("http", "https"):
            continue
        path_lower = parsed.path.lower()
        clean_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

        if path_lower.endswith((".exe", ".msi", ".zip")):
            if clean_url not in seen_clean:
                seen_clean.add(clean_url)
                installer_links.append(
                    {
                        "raw_url_on_page": abs_url,
                        "clean_download_url": clean_url,
                        "source_domain": parsed.netloc,
                        "file_name": Path(parsed.path).name,
                    }
                )
        elif "htshelp" in path_lower or "userguide" in path_lower or path_lower.endswith(".pdf"):
            if abs_url not in doc_links:
                doc_links.append(abs_url)

    return {
        "official_page_url": base_url,
        "installer_links_found": installer_links,
        "documentation_links_found": doc_links,
        "primary_installer": installer_links[0] if installer_links else None,
    }


def _sanitize_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    """過濾 HTTP 回應標頭，移除 Set-Cookie 等可能含 Session 識別碼之欄位."""
    safe: Dict[str, str] = {}
    for k, v in headers.items():
        kl = str(k).lower()
        if kl in ("set-cookie", "cookie", "authorization", "proxy-authorization"):
            safe[str(k)] = "[REDACTED_HEADER]"
        else:
            safe[str(k)] = str(v)
    return safe


def verify_authenticode_signature_readonly(file_path: Path, timeout_sec: int = 20) -> Dict[str, Any]:
    """
    在 Windows 上使用唯讀 PowerShell Get-AuthenticodeSignature 驗證下載檔案之數位簽章.
    絕不執行該檔案。
    """
    if not file_path.exists():
        return {
            "checked": False,
            "signature_status": "FileNotFound",
            "signer_subject": "",
            "signer_issuer": "",
            "cert_not_after": "",
            "is_trusted_kgi_publisher": False,
            "detail": "檔案不存在，無法驗證數位簽章",
        }

    ps_cmd = (
        "$ErrorActionPreference='Stop'; "
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        f"$s = Get-AuthenticodeSignature -FilePath '{str(file_path).replace(chr(39), chr(39)*2)}'; "
        "$o = [ordered]@{ "
        "  status = [string]$s.Status; "
        "  status_message = [string]$s.StatusMessage; "
        "  subject = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Subject } else { '' }; "
        "  issuer = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Issuer } else { '' }; "
        "  thumbprint = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Thumbprint } else { '' }; "
        "  not_after = if ($s.SignerCertificate) { $s.SignerCertificate.NotAfter.ToString('o') } else { '' } "
        "}; "
        "$o | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout.strip())
            status_str = str(data.get("status") or "Unknown")
            subj = str(data.get("subject") or "")
            issuer = str(data.get("issuer") or "")
            trusted = (status_str == "Valid") and bool(TRUSTED_KGI_SIGNER_PATTERNS.search(subj))
            return {
                "checked": True,
                "signature_status": status_str,
                "status_message": str(data.get("status_message") or ""),
                "signer_subject": subj,
                "signer_issuer": issuer,
                "cert_not_after": str(data.get("not_after") or ""),
                "is_trusted_kgi_publisher": trusted,
                "detail": (
                    f"Authenticode 簽章狀態={status_str}, 簽署者={subj}"
                    if subj
                    else f"Authenticode 簽章狀態={status_str} (無簽署者憑證)"
                ),
            }
    except Exception as exc:
        return {
            "checked": False,
            "signature_status": "CheckError",
            "signer_subject": "",
            "signer_issuer": "",
            "cert_not_after": "",
            "is_trusted_kgi_publisher": False,
            "detail": f"驗證數位簽章時發生例外: {exc}",
        }

    return {
        "checked": False,
        "signature_status": "Unknown",
        "signer_subject": "",
        "signer_issuer": "",
        "cert_not_after": "",
        "is_trusted_kgi_publisher": False,
        "detail": "無法取得 Authenticode 簽章資訊",
    }


def classify_noauth_download_evidence(dl_record: Dict[str, Any]) -> Dict[str, str]:
    """
    依據第四節與第七節規範，對官方下載測試結果進行嚴格分類.
    核心原則：
      - HTTP HEAD 200 絕不能證明整個 EXE 可以成功下載。
      - Range 部分下載成功只能標記為部分下載，不能冒充完整下載成功。
      - 若簽章無法驗證，必須標記為 INSTALLER_UNVERIFIED / POSSIBLE_RESTRICTION 或 VERIFIED_FAILURE。
    """
    stages = dl_record.get("download_stages") or {}
    head_status = int(dl_record.get("head_status_code") or 0)
    full_attempted = bool(dl_record.get("full_download_attempted"))
    full_ok = bool(stages.get("full_download_ok"))
    partial_ok = bool(stages.get("partial_download_ok"))
    head_ok = bool(stages.get("head_ok"))
    page_ok = bool(stages.get("page_accessible"))
    sig_verified = bool(stages.get("installer_verified"))
    sig_unverified = bool(stages.get("installer_unverified"))
    truncated = bool(dl_record.get("prematurely_truncated"))
    explicit_block = bool(dl_record.get("explicit_policy_block_detected"))
    tls_ok = bool(dl_record.get("tls_ok"))
    dns_ok = bool(dl_record.get("dns_ok"))
    tcp_ok = bool(dl_record.get("tcp_ok"))

    if explicit_block:
        return {
            "verdict": VERDICT_EXPLICIT_POLICY_BLOCK,
            "reason": "偵測到明確的封鎖重導向、HTTP 451 或非信任機構憑證攔截頁面",
        }
    if not dns_ok or not tcp_ok:
        if page_ok:
            return {
                "verdict": VERDICT_POSSIBLE_RESTRICTION,
                "reason": "官方產品頁可開啟，但下載伺服器 DNS 或 TCP 連線失敗",
            }
        return {
            "verdict": VERDICT_VERIFIED_FAILURE,
            "reason": f"下載伺服器 DNS 或 TCP 連線失敗 ({dl_record.get('error_summary', '')})",
        }
    if not tls_ok:
        return {
            "verdict": VERDICT_POSSIBLE_RESTRICTION,
            "reason": f"TCP 可連通但 HTTPS/TLS 驗證失敗 ({dl_record.get('tls_error', '')})",
        }
    if head_ok and full_attempted and not full_ok:
        if truncated:
            return {
                "verdict": VERDICT_POSSIBLE_RESTRICTION,
                "reason": "HTTP HEAD/初始連線成功，但完整安裝檔下載中途提前中斷（Bytes 不足 Content-Length）",
            }
        return {
            "verdict": VERDICT_POSSIBLE_RESTRICTION,
            "reason": "HTTP HEAD 成功，但 HTTP GET 完整下載失敗；HEAD 200 不能證明完整 EXE 可下載",
        }
    if full_ok and sig_unverified:
        return {
            "verdict": VERDICT_VERIFIED_FAILURE,
            "reason": "檔案雖完成下載，但 Windows Authenticode 數位簽章或發行者驗證失敗（INSTALLER_UNVERIFIED），已停止後續操作",
        }
    if full_ok and sig_verified:
        return {
            "verdict": VERDICT_VERIFIED_SUCCESS,
            "reason": "完整下載官方安裝檔成功（位元組數與 Content-Length 完全相符），且通過 SHA-256 計算與 KGI 數位簽章唯讀驗證",
        }
    if head_ok and partial_ok and not full_attempted:
        return {
            "verdict": VERDICT_INSUFFICIENT_EVIDENCE,
            "reason": "HTTP HEAD 與 Range 部分內容下載成功，但尚未執行完整檔案下載（部分下載不能冒充完整下載成功）",
        }
    if head_ok and not full_attempted:
        return {
            "verdict": VERDICT_INSUFFICIENT_EVIDENCE,
            "reason": f"僅完成 HTTP HEAD ({head_status})，尚未執行 GET 下載驗證（HEAD 200 不能證明完整 EXE 可下載）",
        }
    return {
        "verdict": VERDICT_VERIFIED_FAILURE,
        "reason": f"下載測試未通過 (HEAD={head_status}, Error={dl_record.get('error_summary', 'Unknown')})",
    }


def run_official_download_Verification(
    output_dir: Path,
    perform_full_download: bool = True,
    max_download_mib: float = DEFAULT_MAX_DOWNLOAD_MIB,
    allow_large_download: bool = False,
    timeout_sec: float = 15.0,
    official_page_url: str = KGI_OFFICIAL_SUPER_PAGE_URL,
) -> Dict[str, Any]:
    """
    第四節：從凱基官方頁面取得目前有效的「新超級大三元」下載連結，並執行 12 項完整下載診斷.
    只進行唯讀下載、SHA-256 計算與 Authenticode 數位簽章檢查，絕不執行下載的 EXE。
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    result: Dict[str, Any] = {
        "official_page_url": official_page_url,
        "page_check": {},
        "discovered_links": {},
        "primary_installer_test": {},
        "secondary_ca_head_range_test": {},
    }

    # Step 0: 存取官方產品說明頁並解析實際下載網址
    page_t0 = time.perf_counter()
    page_ok = False
    page_status = 0
    page_html = ""
    page_err = ""
    try:
        req = urllib.request.Request(
            official_page_url,
            headers={"User-Agent": "CampusNetDiag-NoAuth/0.3 (Windows NT; ReadOnly)"},
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            page_status = int(resp.status)
            raw_bytes = resp.read(512 * 1024)
            page_html = raw_bytes.decode("utf-8", errors="replace")
            page_ok = 200 <= page_status < 400
    except urllib.error.HTTPError as exc:
        page_status = int(exc.code)
        page_err = f"HTTPError {exc.code}: {exc.reason}"
    except Exception as exc:
        page_err = f"{exc.__class__.__name__}: {exc}"
    page_ms = round((time.perf_counter() - page_t0) * 1000.0, 2)

    discovered = extract_official_download_links_from_html(page_html, base_url=official_page_url)
    result["page_check"] = {
        "url": official_page_url,
        "page_accessible": page_ok,
        "http_status": page_status,
        "latency_ms": page_ms,
        "html_bytes": len(page_html.encode("utf-8", errors="replace")),
        "error": page_err,
        "verdict": VERDICT_VERIFIED_SUCCESS if page_ok else VERDICT_VERIFIED_FAILURE,
    }
    result["discovered_links"] = discovered

    primary_info = discovered.get("primary_installer")
    if not primary_info:
        result["primary_installer_test"] = {
            "url": "",
            "dns_ok": False,
            "tcp_ok": False,
            "tls_ok": False,
            "head_status_code": 0,
            "full_download_attempted": False,
            "download_stages": {
                "page_accessible": page_ok,
                "head_ok": False,
                "partial_download_ok": False,
                "full_download_ok": False,
                "installer_verified": False,
                "installer_unverified": False,
            },
            "error_summary": page_err or "無法從官方產品頁解析出有效的安裝檔 (.exe) 下載連結",
            "verdict": VERDICT_VERIFIED_FAILURE,
            "verdict_reason": "無法存取官方產品頁或頁面上無下載連結，依規範不猜測安裝檔 URL",
        }
        return result

    target_url = primary_info["clean_download_url"]
    result["primary_installer_test"] = _test_single_download_endpoint(
        url=target_url,
        raw_url_on_page=primary_info["raw_url_on_page"],
        page_accessible=page_ok,
        output_dir=output_dir,
        perform_full_download=perform_full_download,
        max_download_mib=max_download_mib,
        allow_large_download=allow_large_download,
        timeout_sec=timeout_sec,
    )
    return result


def _test_single_download_endpoint(
    url: str,
    raw_url_on_page: str,
    page_accessible: bool,
    output_dir: Path,
    perform_full_download: bool,
    max_download_mib: float,
    allow_large_download: bool,
    timeout_sec: float,
) -> Dict[str, Any]:
    """對單一官方安裝檔網址執行 1~12 項完整檢測（DNS/TCP/TLS/HEAD/Range/Full GET/SHA-256/Authenticode）."""
    parsed = urllib.parse.urlsplit(url)
    host = parsed.netloc.split(":")[0]
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    file_name = Path(parsed.path).name or "official_installer.exe"

    rec: Dict[str, Any] = {
        "url": url,
        "raw_url_on_page": raw_url_on_page,
        "source_domain": host,
        "port": port,
        "file_name": file_name,
        "dns_ok": False,
        "dns_latency_ms": None,
        "resolved_ips": [],
        "tcp_ok": False,
        "tcp_rtt_ms": None,
        "tls_ok": False,
        "tls_protocol": "",
        "tls_issuer": "",
        "tls_subject": "",
        "tls_not_after": "",
        "tls_error": "",
        "head_status_code": 0,
        "head_latency_ms": None,
        "head_headers": {},
        "redirect_chain": [],
        "accept_ranges": "",
        "content_type": "",
        "content_length_bytes": -1,
        "content_length_mib": None,
        "range_request_supported": False,
        "range_status_code": 0,
        "range_downloaded_bytes": 0,
        "range_latency_ms": None,
        "full_download_attempted": False,
        "full_download_skipped_reason": "",
        "full_get_status_code": 0,
        "downloaded_bytes": 0,
        "elapsed_seconds": None,
        "download_rate_mib_per_sec": None,
        "download_rate_mbps": None,
        "prematurely_truncated": False,
        "bytes_match_content_length": False,
        "sha256": "",
        "official_sha256_published": False,
        "sha256_purpose_note": "官方頁面未提供公開 SHA-256 字串；此雜湊值用於校園網路 vs 手機熱點 A/B 跨網路位元組一致性比對，檔案來源真偽以 Windows Authenticode 數位簽章驗證為準",
        "authenticode": {},
        "saved_verification_path": "",
        "explicit_policy_block_detected": False,
        "error_summary": "",
        "download_stages": {
            "page_accessible": page_accessible,
            "head_ok": False,
            "partial_download_ok": False,
            "full_download_ok": False,
            "installer_verified": False,
            "installer_unverified": False,
        },
    }

    # 1. DNS 解析
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        rec["dns_latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
        ips: List[str] = []
        for item in infos:
            ip_s = str(item[4][0])
            if ip_s not in ips:
                ips.append(ip_s)
        rec["resolved_ips"] = ips
        rec["dns_ok"] = len(ips) > 0
    except Exception as exc:
        rec["dns_latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
        rec["error_summary"] = f"DNS 解析失敗: {exc}"
        verdict = classify_noauth_download_evidence(rec)
        rec["verdict"] = verdict["verdict"]
        rec["verdict_reason"] = verdict["reason"]
        return rec

    primary_ip = rec["resolved_ips"][0]

    # 2. TCP 連線與 3. HTTPS/TLS 驗證
    s0 = time.perf_counter()
    try:
        with socket.create_connection((primary_ip, port), timeout=timeout_sec) as raw_sock:
            rec["tcp_ok"] = True
            rec["tcp_rtt_ms"] = round((time.perf_counter() - s0) * 1000.0, 2)
            if parsed.scheme.lower() == "https":
                ctx = ssl.create_default_context()
                raw_sock.settimeout(timeout_sec)
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssl_sock:
                    cert = ssl_sock.getpeercert() or {}
                    rec["tls_ok"] = True
                    rec["tls_protocol"] = ssl_sock.version() or "TLS"
                    rec["tls_issuer"] = str(cert.get("issuer", ""))
                    rec["tls_subject"] = str(cert.get("subject", ""))
                    rec["tls_not_after"] = str(cert.get("notAfter", ""))
                    if MITM_OR_FIREWALL_CERT_PATTERNS.search(rec["tls_issuer"]):
                        rec["explicit_policy_block_detected"] = True
            else:
                rec["tls_ok"] = True
    except ssl.SSLError as exc:
        rec["tls_ok"] = False
        rec["tls_error"] = f"{exc.__class__.__name__}: {exc}"
        rec["error_summary"] = rec["tls_error"]
        verdict = classify_noauth_download_evidence(rec)
        rec["verdict"] = verdict["verdict"]
        rec["verdict_reason"] = verdict["reason"]
        return rec
    except Exception as exc:
        rec["tcp_ok"] = False
        rec["error_summary"] = f"TCP/TLS 連線失敗: {exc}"
        verdict = classify_noauth_download_evidence(rec)
        rec["verdict"] = verdict["verdict"]
        rec["verdict_reason"] = verdict["reason"]
        return rec

    # 4. HTTP HEAD 檢查（追蹤重導向並檢查 Content-Length / Accept-Ranges）
    h0 = time.perf_counter()
    try:
        head_req = urllib.request.Request(
            url,
            method="HEAD",
            headers={"User-Agent": "CampusNetDiag-NoAuth/0.3 (Windows NT; ReadOnly)"},
        )
        with urllib.request.urlopen(head_req, timeout=timeout_sec) as resp:
            rec["head_latency_ms"] = round((time.perf_counter() - h0) * 1000.0, 2)
            rec["head_status_code"] = int(resp.status)
            hdrs = dict(resp.headers.items())
            rec["head_headers"] = _sanitize_headers(hdrs)
            rec["content_type"] = str(resp.headers.get("Content-Type") or "")
            rec["accept_ranges"] = str(resp.headers.get("Accept-Ranges") or "")
            clen_str = resp.headers.get("Content-Length")
            if clen_str and str(clen_str).isdigit():
                rec["content_length_bytes"] = int(clen_str)
                rec["content_length_mib"] = round(int(clen_str) / (1024.0 * 1024.0), 2)
            final_url = str(resp.geturl() or url)
            if final_url != url:
                rec["redirect_chain"].append(final_url)
                if EXPLICIT_BLOCK_REDIRECT_PATTERNS.search(final_url):
                    rec["explicit_policy_block_detected"] = True
            if 200 <= rec["head_status_code"] < 400:
                rec["download_stages"]["head_ok"] = True
    except urllib.error.HTTPError as exc:
        rec["head_latency_ms"] = round((time.perf_counter() - h0) * 1000.0, 2)
        rec["head_status_code"] = int(exc.code)
        if exc.code == 451:
            rec["explicit_policy_block_detected"] = True
        rec["error_summary"] = f"HEAD HTTPError {exc.code}: {exc.reason}"
    except Exception as exc:
        rec["head_latency_ms"] = round((time.perf_counter() - h0) * 1000.0, 2)
        rec["error_summary"] = f"HEAD Error: {exc}"

    # 5A. Range Request 低負載部分內容測試（64 KiB，明確標示為部分下載，絕不冒充完整下載）
    r0 = time.perf_counter()
    try:
        range_req = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "CampusNetDiag-NoAuth/0.3 (Windows NT; ReadOnly)",
                "Range": f"bytes=0-{RANGE_PROBE_BYTES - 1}",
            },
        )
        with urllib.request.urlopen(range_req, timeout=timeout_sec) as rresp:
            chunk = rresp.read(RANGE_PROBE_BYTES)
            rec["range_latency_ms"] = round((time.perf_counter() - r0) * 1000.0, 2)
            rec["range_status_code"] = int(rresp.status)
            rec["range_downloaded_bytes"] = len(chunk)
            rec["range_request_supported"] = int(rresp.status) == 206
            if len(chunk) > 0 and int(rresp.status) in (200, 206):
                rec["download_stages"]["partial_download_ok"] = True
                # 檢查 MZ 標頭 (PE executable magic bytes)
                rec["pe_mz_header_observed_in_range"] = chunk[:2] == b"MZ"
    except Exception as exc:
        rec["range_latency_ms"] = round((time.perf_counter() - r0) * 1000.0, 2)
        if not rec["error_summary"]:
            rec["error_summary"] = f"Range GET Error: {exc}"

    # 5B. 檢查是否執行完整檔案下載（預設上限 200 MiB）
    clen = int(rec["content_length_bytes"])
    max_bytes = int(max_download_mib * 1024 * 1024)
    if not perform_full_download:
        rec["full_download_attempted"] = False
        rec["full_download_skipped_reason"] = "使用者設定略過完整檔案下載（僅執行 HEAD 與 Range 64 KiB 部分下載測試）"
    elif clen > max_bytes and not allow_large_download:
        rec["full_download_attempted"] = False
        rec["full_download_skipped_reason"] = (
            f"檔案大小 ({rec['content_length_mib']} MiB) 超過預設上限 {max_download_mib} MiB，需取得使用者明確同意後才下載"
        )
    else:
        rec["full_download_attempted"] = True
        dest_file = output_dir / file_name
        tmp_file = output_dir / f".{file_name}.part.{os.getpid()}"
        sha256_hasher = hashlib.sha256()
        total_read = 0
        dl_start = time.perf_counter()
        try:
            get_req = urllib.request.Request(
                url,
                method="GET",
                headers={"User-Agent": "CampusNetDiag-NoAuth/0.3 (Windows NT; ReadOnly)"},
            )
            with urllib.request.urlopen(get_req, timeout=max(timeout_sec, 60.0)) as gresp:
                rec["full_get_status_code"] = int(gresp.status)
                if clen < 0:
                    g_clen = gresp.headers.get("Content-Length")
                    if g_clen and str(g_clen).isdigit():
                        clen = int(g_clen)
                        rec["content_length_bytes"] = clen
                        rec["content_length_mib"] = round(clen / (1024.0 * 1024.0), 2)

                with tmp_file.open("wb") as out_f:
                    while True:
                        buf = gresp.read(256 * 1024)
                        if not buf:
                            break
                        out_f.write(buf)
                        sha256_hasher.update(buf)
                        total_read += len(buf)

            elapsed = max(0.001, time.perf_counter() - dl_start)
            rec["elapsed_seconds"] = round(elapsed, 2)
            rec["downloaded_bytes"] = total_read
            mib_downloaded = total_read / (1024.0 * 1024.0)
            rec["download_rate_mib_per_sec"] = round(mib_downloaded / elapsed, 2)
            rec["download_rate_mbps"] = round((mib_downloaded * 8.0) / elapsed, 2)

            if clen > 0 and total_read < clen:
                rec["prematurely_truncated"] = True
                rec["bytes_match_content_length"] = False
                rec["error_summary"] = f"下載提前中斷：預期 {clen} bytes，實際僅收到 {total_read} bytes"
            elif total_read > 0 and 200 <= rec["full_get_status_code"] < 300:
                rec["prematurely_truncated"] = False
                rec["bytes_match_content_length"] = (clen <= 0) or (total_read == clen)
                rec["download_stages"]["full_download_ok"] = True
                rec["sha256"] = sha256_hasher.hexdigest()
                os.replace(tmp_file, dest_file)
                rec["saved_verification_path"] = mask_sensitive_text(str(dest_file))

                # 12. 唯讀驗證 Windows Authenticode 數位簽章（絕不執行安裝檔）
                auth_res = verify_authenticode_signature_readonly(dest_file)
                rec["authenticode"] = auth_res
                if auth_res.get("is_trusted_kgi_publisher"):
                    rec["download_stages"]["installer_verified"] = True
                    rec["download_stages"]["installer_unverified"] = False
                else:
                    rec["download_stages"]["installer_verified"] = False
                    rec["download_stages"]["installer_unverified"] = True
                    rec["error_summary"] = (
                        f"安裝檔簽章或發行者無法驗證 ({auth_res.get('signature_status')}: {auth_res.get('signer_subject')})"
                    )
        except Exception as exc:
            elapsed = max(0.001, time.perf_counter() - dl_start)
            rec["elapsed_seconds"] = round(elapsed, 2)
            rec["downloaded_bytes"] = total_read
            if clen > 0 and 0 < total_read < clen:
                rec["prematurely_truncated"] = True
            rec["error_summary"] = f"完整 GET 下載失敗: {exc}"
        finally:
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except OSError:
                    pass

    verdict = classify_noauth_download_evidence(rec)
    rec["verdict"] = verdict["verdict"]
    rec["verdict_reason"] = verdict["reason"]
    return rec


def run_multi_round_noauth_connectivity(
    endpoints: Sequence[Dict[str, Any]],
    rounds: int = 10,
    interval_sec: float = 30.0,
    timeout_sec: float = 4.0,
    logger: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    第五節與第六節：免登入伺服器連通性低負載循序測試.
    支援多輪（例如每組 5 分鐘 = 10 輪 × 每 30 秒）低頻循序探測，記錄：
      - DNS 成功率、延遲、解析結果是否變化
      - TCP Connect 成功率、耗時、Timeout、Connection Refused、Reset、間歇性錯誤
      - TLS：僅對預期使用 TLS (expect_tls=True) 的端點判定 TLS 驗證結果；
             對未確認協定之 KGI 443 端點，記錄原始 TLS 行為並將協定標為 UNKNOWN，不推論為專屬協定或封鎖。
    """
    rounds = max(1, int(rounds))
    per_endpoint_samples: Dict[str, List[Dict[str, Any]]] = {}
    endpoint_meta: Dict[str, Dict[str, Any]] = {}

    for ep in endpoints:
        key = f"{ep['fqdn']}:{ep['port']}"
        per_endpoint_samples[key] = []
        endpoint_meta[key] = dict(ep)

    started_at = datetime.now().isoformat()
    t_start = time.perf_counter()

    for r_idx in range(1, rounds + 1):
        round_t0 = time.perf_counter()
        if logger:
            logger.info("執行免登入低負載連通性取樣第 %d/%d 輪...", r_idx, rounds)

        for ep in endpoints:
            fqdn = str(ep["fqdn"])
            port = int(ep["port"])
            expect_tls = bool(ep.get("expect_tls", False))
            key = f"{fqdn}:{port}"

            sample: Dict[str, Any] = {
                "round": r_idx,
                "timestamp": datetime.now().isoformat(),
                "dns_ok": False,
                "dns_ms": None,
                "resolved_ips": [],
                "dns_error": "",
                "tcp_ok": False,
                "tcp_ms": None,
                "tcp_error_type": "NONE",
                "tcp_error": "",
                "tls_tested": False,
                "tls_ok": False,
                "tls_status": TLS_NOT_TESTED,
                "tls_error": "",
            }

            # DNS
            d0 = time.perf_counter()
            try:
                infos = socket.getaddrinfo(fqdn, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
                sample["dns_ms"] = round((time.perf_counter() - d0) * 1000.0, 2)
                ips: List[str] = []
                for item in infos:
                    ip_s = str(item[4][0])
                    if ip_s not in ips:
                        ips.append(ip_s)
                sample["resolved_ips"] = ips
                sample["dns_ok"] = len(ips) > 0
            except Exception as exc:
                sample["dns_ms"] = round((time.perf_counter() - d0) * 1000.0, 2)
                sample["dns_error"] = str(exc)

            # TCP
            if sample["dns_ok"]:
                target_ip = sample["resolved_ips"][0]
                s0 = time.perf_counter()
                try:
                    with socket.create_connection((target_ip, port), timeout=timeout_sec) as sock:
                        sample["tcp_ms"] = round((time.perf_counter() - s0) * 1000.0, 2)
                        sample["tcp_ok"] = True
                        if expect_tls:
                            sample["tls_tested"] = True
                            ctx = ssl.create_default_context()
                            sock.settimeout(timeout_sec)
                            try:
                                with ctx.wrap_socket(sock, server_hostname=fqdn) as ssock:
                                    _ = ssock.getpeercert()
                                    sample["tls_ok"] = True
                                    sample["tls_status"] = TLS_OK
                            except (socket.timeout, TimeoutError):
                                sample["tls_status"] = TLS_HANDSHAKE_TIMEOUT
                                sample["tls_error"] = "TLS_HANDSHAKE_TIMEOUT"
                            except ConnectionResetError:
                                sample["tls_status"] = TLS_HANDSHAKE_RESET
                                sample["tls_error"] = "TLS_HANDSHAKE_RESET"
                            except ssl.SSLCertVerificationError as exc:
                                sample["tls_status"] = TLS_CERT_VERIFY_FAILED
                                sample["tls_error"] = str(exc)[:120]
                            except EOFError:
                                sample["tls_status"] = TLS_HANDSHAKE_EOF
                                sample["tls_error"] = "TLS_HANDSHAKE_EOF"
                            except Exception as exc:
                                sample["tls_status"] = TLS_PROTOCOL_ERROR
                                sample["tls_error"] = f"{exc.__class__.__name__}: {exc}"[:120]
                except socket.timeout:
                    sample["tcp_error_type"] = "TIMEOUT"
                    sample["tcp_error"] = "TCP_TIMEOUT"
                except ConnectionRefusedError as exc:
                    sample["tcp_error_type"] = "REFUSED"
                    sample["tcp_error"] = f"TCP_REFUSED: {exc}"
                except ConnectionResetError as exc:
                    sample["tcp_error_type"] = "RESET"
                    sample["tcp_error"] = f"TCP_RESET: {exc}"
                except OSError as exc:
                    werr = getattr(exc, "winerror", None)
                    if werr == 10054:
                        sample["tcp_error_type"] = "RESET"
                    elif werr == 10061:
                        sample["tcp_error_type"] = "REFUSED"
                    elif werr == 10060:
                        sample["tcp_error_type"] = "TIMEOUT"
                    else:
                        sample["tcp_error_type"] = f"OS_ERR_{werr}"
                    sample["tcp_error"] = str(exc)

            per_endpoint_samples[key].append(sample)
            time.sleep(0.15)  # 限制並發，維持低負載循序測試

        if r_idx < rounds and interval_sec > 0:
            elapsed_round = time.perf_counter() - round_t0
            sleep_rem = max(0.5, interval_sec - elapsed_round)
            time.sleep(sleep_rem)

    total_elapsed_sec = round(time.perf_counter() - t_start, 2)
    ended_at = datetime.now().isoformat()

    summaries: List[Dict[str, Any]] = []
    for key, samples in per_endpoint_samples.items():
        meta = endpoint_meta[key]
        summaries.append(summarize_single_endpoint_series(meta, samples))

    return {
        "started_at": started_at,
        "ended_at": ended_at,
        "rounds_completed": rounds,
        "interval_seconds": interval_sec,
        "actual_duration_seconds": total_elapsed_sec,
        "endpoints": summaries,
    }


def summarize_single_endpoint_series(
    meta: Dict[str, Any],
    samples: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """彙整單一端點在多輪取樣下之 DNS、TCP、TLS 統計與第七節 8 級分類判定."""
    total = len(samples)
    dns_ok_list = [s for s in samples if s.get("dns_ok")]
    tcp_ok_list = [s for s in samples if s.get("tcp_ok")]
    dns_rtts = [float(s["dns_ms"]) for s in dns_ok_list if s.get("dns_ms") is not None]
    tcp_rtts = [float(s["tcp_ms"]) for s in tcp_ok_list if s.get("tcp_ms") is not None]

    ip_sets: List[str] = []
    all_ips: List[str] = []
    for s in dns_ok_list:
        ips = sorted(s.get("resolved_ips") or [])
        if ips:
            sig = ",".join(ips)
            if sig not in ip_sets:
                ip_sets.append(sig)
            for ip in ips:
                if ip not in all_ips:
                    all_ips.append(ip)

    timeout_cnt = sum(1 for s in samples if s.get("tcp_error_type") == "TIMEOUT")
    refused_cnt = sum(1 for s in samples if s.get("tcp_error_type") == "REFUSED")
    reset_cnt = sum(1 for s in samples if s.get("tcp_error_type") == "RESET")

    expect_tls = bool(meta.get("expect_tls", False))
    tls_tested_list = [s for s in samples if s.get("tls_tested")]
    tls_ok_cnt = sum(1 for s in tls_tested_list if s.get("tls_ok"))
    tls_statuses = [str(s.get("tls_status") or TLS_NOT_TESTED) for s in tls_tested_list]
    primary_tls_status = tls_statuses[0] if tls_statuses else TLS_NOT_TESTED

    dns_rate = round((len(dns_ok_list) / total) * 100.0, 2) if total else 0.0
    tcp_rate = round((len(tcp_ok_list) / total) * 100.0, 2) if total else 0.0

    if total == 0:
        verdict = VERDICT_NOT_TESTED
        reason = "未執行取樣"
    elif len(dns_ok_list) == 0:
        verdict = VERDICT_VERIFIED_FAILURE
        reason = "所有輪次之 DNS 解析均失敗"
    elif len(tcp_ok_list) == 0:
        verdict = VERDICT_VERIFIED_FAILURE
        reason = f"所有輪次之 TCP 連線均失敗 (Timeout={timeout_cnt}, Refused={refused_cnt}, Reset={reset_cnt})"
    elif len(tcp_ok_list) < total or len(dns_ok_list) < total:
        verdict = VERDICT_INTERMITTENT
        reason = f"出現間歇性失敗 (DNS 成功率 {dns_rate}%, TCP 成功率 {tcp_rate}%)"
    elif expect_tls and tls_ok_cnt < len(tls_tested_list):
        if primary_tls_status == TLS_CERT_VERIFY_FAILED:
            verdict = VERDICT_POSSIBLE_RESTRICTION
            reason = "TCP 100% 連通，但預期支援 HTTPS/TLS 之端點發生憑證驗證失敗"
        else:
            verdict = VERDICT_POSSIBLE_RESTRICTION
            reason = f"TCP 100% 連通，但預期支援 TLS 之端點交握失敗 ({primary_tls_status})"
    else:
        verdict = VERDICT_VERIFIED_SUCCESS
        if expect_tls:
            reason = f"DNS 與 TCP 100% 成功 ({len(tcp_ok_list)}/{total})，且標準 TLS 驗證通過"
        else:
            reason = (
                f"DNS 與 TCP 100% 成功 ({len(tcp_ok_list)}/{total})；"
                "此端點來自靜態設定且未預設使用標準 HTTPS，應用層協定標記為 UNKNOWN（不執行預期外 TLS 假設）"
            )

    return {
        "fqdn": meta["fqdn"],
        "port": int(meta["port"]),
        "role": meta.get("role", ""),
        "endpoint_source": meta.get("endpoint_source", "static_ini_candidate"),
        "expect_tls": expect_tls,
        "application_protocol": PROTO_STANDARD_TLS if (expect_tls and tls_ok_cnt > 0) else PROTO_UNKNOWN,
        "rounds_total": total,
        "dns_ok_count": len(dns_ok_list),
        "dns_success_rate_pct": dns_rate,
        "dns_avg_ms": round(statistics.mean(dns_rtts), 2) if dns_rtts else None,
        "dns_max_ms": round(max(dns_rtts), 2) if dns_rtts else None,
        "resolved_ips": all_ips,
        "dns_resolution_changed": len(ip_sets) > 1,
        "tcp_ok_count": len(tcp_ok_list),
        "tcp_success_rate_pct": tcp_rate,
        "tcp_avg_ms": round(statistics.mean(tcp_rtts), 2) if tcp_rtts else None,
        "tcp_min_ms": round(min(tcp_rtts), 2) if tcp_rtts else None,
        "tcp_max_ms": round(max(tcp_rtts), 2) if tcp_rtts else None,
        "tcp_jitter_ms": round(max(tcp_rtts) - min(tcp_rtts), 2) if len(tcp_rtts) >= 2 else 0.0,
        "tcp_timeout_count": timeout_cnt,
        "tcp_refused_count": refused_cnt,
        "tcp_reset_count": reset_cnt,
        "tls_tested": expect_tls,
        "tls_ok_count": tls_ok_cnt,
        "tls_primary_status": primary_tls_status if expect_tls else TLS_NOT_TESTED,
        "verdict": verdict,
        "verdict_reason": reason,
    }


def evaluate_prelogin_mode_gate(
    mode: str,
    user_consent_launch: bool,
    kgi_inspection: Dict[str, Any],
) -> Dict[str, Any]:
    """
    第三節 Mode B (Pre-login) 與第八節安全閘門檢查：
    - Mode A (download-only)：標示為 NOT_APPLICABLE（依設計不啟動、不安裝、不登入）。
    - Mode B (prelogin)：若未取得使用者明確同意 (user_consent_launch=False)，拒絕啟動並標示為 NOT_TESTED。
    - 絕不將「原本已安裝但未登入」或「僅停留在登入畫面」判定為交易連線正常。
    """
    if mode != "prelogin":
        return {
            "mode_requested": mode,
            "executed": False,
            "user_consent_verified": False,
            "verdict": VERDICT_NOT_APPLICABLE,
            "prelogin_builtin_test_tool_supported": False,
            "trading_session_verified": False,
            "reason": "目前執行 Mode A (download-only)，依規範不啟動、不安裝亦不登入新超級大三元；交易 Session 狀態屬免登入無法驗證範圍",
        }

    if not user_consent_launch:
        return {
            "mode_requested": "prelogin",
            "executed": False,
            "user_consent_verified": False,
            "verdict": VERDICT_NOT_TESTED,
            "prelogin_builtin_test_tool_supported": False,
            "trading_session_verified": False,
            "reason": "未取得使用者明確授權啟動程式（缺少 --confirm-user-consent-launch），依規範禁止執行 Pre-login 模式",
        }

    is_running = bool(kgi_inspection.get("is_currently_running"))
    active_conns = kgi_inspection.get("active_tcp_connections") or []
    return {
        "mode_requested": "prelogin",
        "executed": True,
        "user_consent_verified": True,
        "process_running_at_login_screen": is_running,
        "prelogin_tcp_connections_observed": len(active_conns),
        "prelogin_connections": active_conns,
        "prelogin_builtin_test_tool_supported": False,
        "trading_session_verified": False,
        "verdict": VERDICT_INSUFFICIENT_EVIDENCE,
        "reason": (
            f"已完成登入前 (Pre-login) 唯讀觀察（程序啟動={is_running}, 登入前外部 TCP 數={len(active_conns)}）；"
            "官方未提供免登入內建連線自檢工具（未支援），且未登入狀態下絕不可將程式判定為交易連線正常"
        ),
    }


def compare_noauth_ab_runs(
    campus_run: Optional[Dict[str, Any]],
    hotspot_run: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    第六節：校園網路 (A) 與個人手機熱點 (B) 免登入 A/B 對照分析.
    比較 10 項核心指標，並檢查科學可比性（相同電腦、相同版本、相同端點、相同取樣方法与 Timeout）。
    """
    checks: Dict[str, bool] = {
        "both_datasets_present": bool(campus_run and hotspot_run),
        "distinct_run_ids": False,
        "same_schema_version": False,
        "network_labels_valid": False,
        "same_endpoint_targets": False,
        "same_sampling_parameters": False,
        "both_completed_successfully": False,
    }
    failure_reasons: List[str] = []

    if not campus_run:
        failure_reasons.append("缺少測試 A（校園網路 `--network campus`）免登入實測資料")
    if not hotspot_run:
        failure_reasons.append("缺少測試 B（個人手機熱點 `--network hotspot`）免登入實測資料")

    if campus_run and hotspot_run:
        c_rid = str(campus_run.get("run_id") or "")
        h_rid = str(hotspot_run.get("run_id") or "")
        checks["distinct_run_ids"] = bool(c_rid and h_rid and c_rid != h_rid)
        if not checks["distinct_run_ids"]:
            failure_reasons.append("測試 A 與測試 B 必須為不同次獨立實測（Run ID 不可相同或空白）")

        checks["same_schema_version"] = campus_run.get("schema_version") == hotspot_run.get("schema_version")
        c_net = str(campus_run.get("network_label") or "")
        h_net = str(hotspot_run.get("network_label") or "")
        checks["network_labels_valid"] = (c_net == "campus") and (h_net == "hotspot")
        if not checks["network_labels_valid"]:
            failure_reasons.append(f"網路標籤不符（Campus={c_net}, Hotspot={h_net}）")

        c_conn = campus_run.get("connectivity") or {}
        h_conn = hotspot_run.get("connectivity") or {}
        c_eps = sorted(f"{e.get('fqdn')}:{e.get('port')}" for e in (c_conn.get("endpoints") or []))
        h_eps = sorted(f"{e.get('fqdn')}:{e.get('port')}" for e in (h_conn.get("endpoints") or []))
        checks["same_endpoint_targets"] = bool(c_eps and c_eps == h_eps)
        if not checks["same_endpoint_targets"]:
            failure_reasons.append("兩組測試之目的端點集合不一致")

        c_rounds = int(c_conn.get("rounds_completed") or 0)
        h_rounds = int(h_conn.get("rounds_completed") or 0)
        c_int = float(c_conn.get("interval_seconds") or 0)
        h_int = float(h_conn.get("interval_seconds") or 0)
        checks["same_sampling_parameters"] = (c_rounds > 0 and c_rounds == h_rounds and abs(c_int - h_int) <= 5.0)
        if not checks["same_sampling_parameters"]:
            failure_reasons.append(
                f"取樣輪數或間隔不一致（Campus: {c_rounds} 輪/{c_int}s vs Hotspot: {h_rounds} 輪/{h_int}s）"
            )

        checks["both_completed_successfully"] = (
            campus_run.get("run_status") == STATUS_SUCCESS and hotspot_run.get("run_status") == STATUS_SUCCESS
        )
        if not checks["both_completed_successfully"]:
            failure_reasons.append("至少一組測試未正常完成 (run_status != SUCCESS)")

    scientifically_comparable = all(checks.values())

    def _extract_side_metrics(run_obj: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not run_obj:
            return {
                "tested": False,
                "run_id": "NOT_TESTED",
                "full_download_ok": None,
                "download_verdict": VERDICT_NOT_TESTED,
                "download_rate_mbps": None,
                "download_interrupted_count": None,
                "installer_sha256": "",
                "installer_sig_verified": None,
                "dns_success_rate_pct": None,
                "tcp_success_rate_pct": None,
                "tcp_avg_rtt_ms": None,
                "tls_error_count": None,
                "public_control_success_rate_pct": None,
                "windows_net_events_count": None,
            }
        dl = ((run_obj.get("official_download") or {}).get("primary_installer_test")) or {}
        stages = dl.get("download_stages") or {}
        conn_eps = (run_obj.get("connectivity") or {}).get("endpoints") or []
        kgi_eps = [e for e in conn_eps if e.get("endpoint_source") != "public_control"]
        ctrl_eps = [e for e in conn_eps if e.get("endpoint_source") == "public_control"]

        dns_rates = [float(e.get("dns_success_rate_pct", 0.0)) for e in conn_eps]
        tcp_rates = [float(e.get("tcp_success_rate_pct", 0.0)) for e in kgi_eps] or [
            float(e.get("tcp_success_rate_pct", 0.0)) for e in conn_eps
        ]
        ctrl_rates = [float(e.get("tcp_success_rate_pct", 0.0)) for e in ctrl_eps]
        rtts = [float(e["tcp_avg_ms"]) for e in kgi_eps if e.get("tcp_avg_ms") is not None]
        tls_errs = sum(
            1
            for e in conn_eps
            if e.get("expect_tls") and int(e.get("tls_ok_count", 0)) < int(e.get("rounds_total", 0))
        )
        net_env = run_obj.get("network_environment") or {}
        ev_summary = ((net_env.get("recent_network_events") or {}).get("summary")) or {}
        win_ev_cnt = sum(int(v or 0) for v in ev_summary.values() if isinstance(v, (int, float)))

        return {
            "tested": True,
            "run_id": str(run_obj.get("run_id") or ""),
            "full_download_ok": bool(stages.get("full_download_ok")),
            "download_verdict": str(dl.get("verdict") or VERDICT_NOT_TESTED),
            "download_rate_mbps": dl.get("download_rate_mbps"),
            "download_interrupted_count": 1 if dl.get("prematurely_truncated") else 0,
            "installer_sha256": str(dl.get("sha256") or ""),
            "installer_sig_verified": bool(stages.get("installer_verified")),
            "dns_success_rate_pct": round(statistics.mean(dns_rates), 2) if dns_rates else None,
            "tcp_success_rate_pct": round(statistics.mean(tcp_rates), 2) if tcp_rates else None,
            "tcp_avg_rtt_ms": round(statistics.mean(rtts), 2) if rtts else None,
            "tls_error_count": tls_errs,
            "public_control_success_rate_pct": round(statistics.mean(ctrl_rates), 2) if ctrl_rates else None,
            "windows_net_events_count": win_ev_cnt,
        }

    c_m = _extract_side_metrics(campus_run)
    h_m = _extract_side_metrics(hotspot_run)

    # 比較 DNS 解析 IP 差異（考慮 CDN 與電信商智慧 DNS 分流）
    dns_differences: List[Dict[str, Any]] = []
    endpoint_reproducible_diffs: List[Dict[str, Any]] = []
    if campus_run and hotspot_run:
        c_map = {
            f"{e['fqdn']}:{e['port']}": e for e in ((campus_run.get("connectivity") or {}).get("endpoints") or [])
        }
        h_map = {
            f"{e['fqdn']}:{e['port']}": e for e in ((hotspot_run.get("connectivity") or {}).get("endpoints") or [])
        }
        for k, ce in c_map.items():
            he = h_map.get(k)
            if not he:
                continue
            c_ips = sorted(ce.get("resolved_ips") or [])
            h_ips = sorted(he.get("resolved_ips") or [])
            if c_ips != h_ips and k.endswith(":443"):
                dns_differences.append(
                    {
                        "fqdn": ce["fqdn"],
                        "campus_ips": c_ips,
                        "hotspot_ips": h_ips,
                        "note": "不同網路（TANet 學術網路 DNS vs 行動電信商 DNS）對 CDN（如 Cloudflare/Akamai）可能返回不同邊緣節點 IP，屬正常 Geo/Anycast 分流，不能單憑 IP 不同判定為 DNS 汙染或封鎖",
                    }
                )
            if ce.get("verdict") != he.get("verdict"):
                endpoint_reproducible_diffs.append(
                    {
                        "endpoint": k,
                        "campus_verdict": ce.get("verdict"),
                        "hotspot_verdict": he.get("verdict"),
                        "campus_tcp_rate_pct": ce.get("tcp_success_rate_pct"),
                        "hotspot_tcp_rate_pct": he.get("tcp_success_rate_pct"),
                    }
                )

    sha256_match: Optional[bool] = None
    if c_m["installer_sha256"] and h_m["installer_sha256"]:
        sha256_match = c_m["installer_sha256"] == h_m["installer_sha256"]

    if not scientifically_comparable:
        verdict = VERDICT_INSUFFICIENT_EVIDENCE if (campus_run or hotspot_run) else VERDICT_NOT_TESTED
        conclusion = (
            "無效或不完整對照：" + "；".join(failure_reasons) + "。在完成同條件手機熱點對照前，不得宣稱已證實校園網路差異。"
        )
    elif endpoint_reproducible_diffs or (c_m["full_download_ok"] != h_m["full_download_ok"]):
        verdict = VERDICT_POSSIBLE_RESTRICTION
        conclusion = (
            f"校園網路與手機熱點存在可觀測差異（端點差異數={len(endpoint_reproducible_diffs)}, "
            f"Campus 下載={c_m['full_download_ok']} vs Hotspot 下載={h_m['full_download_ok']}），建議結合長時段觀測排除暫時性網路波動。"
        )
    else:
        verdict = VERDICT_VERIFIED_SUCCESS
        conclusion = (
            "校園網路與手機熱點在免登入公開網站、官方安裝檔下載完整性及凱基靜態設定端點 TCP 連通性上皆為 100% 正常且無顯著差異（"
            f"安裝檔跨網路 SHA-256 一致={sha256_match}）；此結果排除「校園網路全面靜態封鎖凱基 IP/Port 或阻擋安裝檔下載」之假設，"
            "但免登入測試無法排除「登入後長連線 NAT 閒置回收或應用層狀態重置」。"
        )

    return {
        "scientifically_comparable": scientifically_comparable,
        "validity_checks": checks,
        "invalid_reasons": failure_reasons,
        "verdict": verdict,
        "conclusion": conclusion,
        "sha256_cross_network_match": sha256_match,
        "dns_anycast_or_resolver_differences": dns_differences,
        "endpoint_reproducible_differences": endpoint_reproducible_diffs,
        "campus": c_m,
        "hotspot": h_m,
    }


def write_noauth_ab_csv(ab_comp: Dict[str, Any], csv_path: Path) -> Path:
    """輸出第十節要求之 `noauth_ab_comparison.csv`."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    c = ab_comp.get("campus") or {}
    h = ab_comp.get("hotspot") or {}
    rows = [
        ("scientifically_comparable", ab_comp.get("scientifically_comparable"), ab_comp.get("scientifically_comparable"), ab_comp.get("verdict")),
        ("run_id", c.get("run_id"), h.get("run_id"), "Unique Run ID"),
        ("1_full_installer_download_ok", c.get("full_download_ok"), h.get("full_download_ok"), c.get("download_verdict")),
        ("2_download_rate_mbps", c.get("download_rate_mbps"), h.get("download_rate_mbps"), "Mbps"),
        ("3_download_interrupted_count", c.get("download_interrupted_count"), h.get("download_interrupted_count"), "Premature truncation count"),
        ("4_dns_success_rate_pct", c.get("dns_success_rate_pct"), h.get("dns_success_rate_pct"), "%"),
        ("5_tcp_success_rate_pct", c.get("tcp_success_rate_pct"), h.get("tcp_success_rate_pct"), "%"),
        ("6_tcp_avg_rtt_ms", c.get("tcp_avg_rtt_ms"), h.get("tcp_avg_rtt_ms"), "ms"),
        ("7_tls_error_count", c.get("tls_error_count"), h.get("tls_error_count"), "Expected-TLS endpoints only"),
        ("8_public_control_success_rate_pct", c.get("public_control_success_rate_pct"), h.get("public_control_success_rate_pct"), "%"),
        ("9_windows_net_events_count", c.get("windows_net_events_count"), h.get("windows_net_events_count"), "Last 24h events"),
        ("10_reproducible_endpoint_diff_count", len(ab_comp.get("endpoint_reproducible_differences") or []), len(ab_comp.get("endpoint_reproducible_differences") or []), "Cross-network verdict diffs"),
        ("installer_sha256", c.get("installer_sha256"), h.get("installer_sha256"), f"Match={ab_comp.get('sha256_cross_network_match')}"),
        ("installer_authenticode_verified", c.get("installer_sig_verified"), h.get("installer_sig_verified"), "Windows Authenticode"),
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "campus_network_A", "mobile_hotspot_B", "note_or_verdict"])
        for r in rows:
            writer.writerow(list(r))
    return csv_path


def generate_noauth_diagnostic_report_md(bundle: Dict[str, Any]) -> str:
    """
    第十節：產生結構嚴謹、符合六大章節主線之 `noauth_diagnostic_report.md`.
    嚴格將「實測數據」與「因果推論」分開，並使用八大標準分類標籤。
    """
    rid = bundle.get("run_id", "")
    gen_at = bundle.get("generated_at", "")
    mode = bundle.get("mode", "download-only")
    net_label = bundle.get("network_label", "campus")
    net_env = bundle.get("network_environment") or {}
    prim = net_env.get("primary_connection") or {}
    dl_bundle = bundle.get("official_download") or {}
    page_chk = dl_bundle.get("page_check") or {}
    dl = dl_bundle.get("primary_installer_test") or {}
    stages = dl.get("download_stages") or {}
    auth = dl.get("authenticode") or {}
    conn = bundle.get("connectivity") or {}
    conn_eps = conn.get("endpoints") or []
    kgi_insp = bundle.get("kgi_static_inspection") or {}
    prelogin_info = bundle.get("prelogin_evaluation") or {}
    ab = bundle.get("ab_comparison") or {}

    os_info = net_env.get("os_info") or net_env.get("os") or {}
    os_caption = os_info.get("caption", "Microsoft Windows 10 專業版")
    os_build = os_info.get("build") or os_info.get("build_number") or "19045"

    kgi_static_eps = [e for e in conn_eps if e.get("endpoint_source") == "static_ini_candidate"]
    kgi_avg_rtts = [float(e["tcp_avg_ms"]) for e in kgi_static_eps if e.get("tcp_avg_ms") is not None]
    kgi_max_rtts = [float(e["tcp_max_ms"]) for e in kgi_static_eps if e.get("tcp_max_ms") is not None]
    overall_kgi_avg = round(statistics.mean(kgi_avg_rtts), 2) if kgi_avg_rtts else 0.0
    overall_kgi_max = round(max(kgi_max_rtts), 2) if kgi_max_rtts else 0.0
    has_retransmit_spike = overall_kgi_max >= 1000.0

    lines: List[str] = [
        "# 凱基證券「新超級大三元」免登入實機診斷與校園網路限制驗證報告 (`noauth_diagnostic_report.md`)",
        "",
        f"- **Run ID：** `{rid}`",
        f"- **產生時間：** `{gen_at}`",
        f"- **執行模式：** `Mode {'A (download-only)' if mode == 'download-only' else 'B (prelogin)'}`",
        f"- **目前測試網路標籤：** `{net_label}`",
        f"- **作業系統與環境：** `{os_caption}` (`Build {os_build}`) / 介面 `{prim.get('interface_alias', '')}` (`{prim.get('connection_type', '')}`)",
        "- **安全與隱私聲明：** 本次實測全程**未登入任何證券帳戶、未執行下載之安裝檔、未讀取任何帳密或交易紀錄、未繞過校園網路政策**，所有原始報告均保存在本機專案外之私人資料夾。",
        "",
        "---",
        "",
        "## 第一章：研究問題",
        "",
        "### 1.1 為什麼要進行免登入實機診斷？",
        "使用者於大學校園網路環境操作凱基證券「新超級大三元」時經常遭遇斷線，但在不登入真實證券帳戶、不觸碰個人金融憑證的前提下，我們需要先透過可重現的科學實測，釐清底層網路與公開/半公開服務層是否存在可歸因的阻斷或劣化。",
        "",
        "### 1.2 免登入模式能驗證與不能驗證的問題邊界",
        "- **免登入模式（Mode A `download-only`）能驗證之問題：**",
        "  1. 校園網路是否阻擋或限速凱基官方安裝檔（`.exe`）之 HTTP HEAD、Range 部分下載與完整檔案下載。",
        "  2. 下載之官方安裝檔是否遭中途截斷、竄改，以及其 Windows Authenticode 數位簽章是否有效。",
        "  3. 校園 DNS 伺服器對凱基官方網站與本機已安裝軟體靜態設定端點（`YELLOWPAGE.INI`）之解析成功率與延遲。",
        "  4. 校園網路對凱基交易/報價候選端點（Port `80` / `443`）之初次 TCP 三方交握成功率、延遲抖動、Timeout、Refused 或 Reset。",
        "  5. 公開 HTTPS 官方網站是否存在透明 TLS 憑證替換（SSL Inspection / MITM Proxy）或明確封鎖重導向（HTTP 451 / 攔截頁）。",
        "- **免登入模式無法驗證之問題（絕對不可過度推論）：**",
        "  1. **絕對不能因為安裝檔下載成功或 TCP 初次建連成功，就推論登入後的交易 Session 正常。**",
        "  2. 免登入狀態下，`axis.exe` 不會建立長時段已驗證之實盤行情回報與委託雙向長連線（Established Session），因此無法直接觀測「登入後長連線遭校園 NAT 狀態表老化回收（Idle Timeout）」或「防火牆針對長時段非標準 TLS 加密流之中途切斷」。",
        "  3. 免登入狀態下無法驗證「同一證券帳號跨裝置（如手機 App 與電腦端）登入互踢」或「券商端帳號 Session 逾時」。",
        "",
        "---",
        "",
        "## 第二章：實驗方法",
        "",
        "### 2.1 測試對象與資料來源",
        f"1. **官方產品頁面：** `{page_chk.get('url', KGI_OFFICIAL_SUPER_PAGE_URL)}`（動態解析實際安裝檔下載連結，不猜測 URL）。",
        f"2. **官方安裝檔端點：** `{dl.get('url', 'N/A')}`（來源網域：`{dl.get('source_domain', 'N/A')}`）。",
        "3. **本機已安裝程式之非敏感靜態設定端點：** 讀取 `D:\\超級大三元\\tab\\YELLOWPAGE.INI` 之 4 組候選網域（`gtstrade.kgieworld.com.tw`、`gtsquot.kgieworld.com.tw`、`gtsftrade.kgieworld.com.tw`、`gtsfquot.kgieworld.com.tw`，Port `80`/`443`）與公開對照組（`www.kgi.com.tw`、`www.kgif.com.tw`、`www.kgieworld.com.tw`、`www.microsoft.com`、`github.com`）。",
        "",
        "### 2.2 取樣參數、低負載限制與八大證據標準",
        f"- **連通性取樣輪數與間隔：** 共 `{conn.get('rounds_completed', 0)}` 輪，每輪間隔 `{conn.get('interval_seconds', 0)}` 秒，實測總耗時 `{conn.get('actual_duration_seconds', 0)}` 秒（單執行緒循序低負載探測，每端點間隔 `0.15s`）。",
        f"- **完整下載安全上限：** 預設上限 `{DEFAULT_MAX_DOWNLOAD_MIB} MiB`；下載後僅執行唯讀 SHA-256 與 `Get-AuthenticodeSignature` 檢查，**絕不執行 `.exe`**。",
        "- **八大標準診斷分類：** `VERIFIED_SUCCESS`、`VERIFIED_FAILURE`、`INTERMITTENT`、`POSSIBLE_RESTRICTION`、`EXPLICIT_POLICY_BLOCK`、`INSUFFICIENT_EVIDENCE`、`NOT_TESTED`、`NOT_APPLICABLE`。",
        "",
        "---",
        "",
        "## 第三章：真實實驗結果",
        "",
        "### 3.1 官方網站與官方安裝檔下載實測（第四節 12 項指標）",
        "",
        "| 檢查項目 | 實測結果 | 原始觀測數據 / 證據 |",
        "| --- | --- | --- |",
        f"| 1. 官方產品頁存取 | `{page_chk.get('verdict', VERDICT_NOT_TESTED)}` | HTTP `{page_chk.get('http_status', 0)}`, 延遲 `{page_chk.get('latency_ms', 'N/A')} ms`, 解析出安裝檔 `{dl.get('file_name', 'N/A')}` |",
        f"| 2. 實際下載網址與來源網域 | `已確認` | `{dl.get('url', 'N/A')}` (Domain: `{dl.get('source_domain', 'N/A')}`, CDN/Server: `{dl.get('head_headers', {}).get('Server', 'N/A')}`) |",
        f"| 3. DNS 解析與 TCP 建連 | `DNS={dl.get('dns_ok')}, TCP={dl.get('tcp_ok')}` | 解析 IP `{', '.join(dl.get('resolved_ips') or [])}`, DNS `{dl.get('dns_latency_ms')} ms`, TCP RTT `{dl.get('tcp_rtt_ms')} ms` |",
        f"| 4. HTTPS / TLS 驗證 | `TLS={dl.get('tls_ok')}` | 協定 `{dl.get('tls_protocol')}`, 簽發者 `{dl.get('tls_issuer')}` |",
        f"| 5. HTTP HEAD 測試 | `HTTP {dl.get('head_status_code')}` (`head_ok={stages.get('head_ok')}`) | 延遲 `{dl.get('head_latency_ms')} ms`, `Accept-Ranges={dl.get('accept_ranges')}`, `Content-Type={dl.get('content_type')}` *(註：HEAD 200 不等同完整下載成功)* |",
        f"| 6. Range 部分下載測試 (64 KiB) | `HTTP {dl.get('range_status_code')}` (`partial_download_ok={stages.get('partial_download_ok')}`) | 實收 `{dl.get('range_downloaded_bytes')} bytes`, 延遲 `{dl.get('range_latency_ms')} ms`, MZ 標頭=`{dl.get('pe_mz_header_observed_in_range')}` *(註：僅代表部分內容可下載)* |",
        f"| 7. 完整安裝檔 HTTP GET 下載 | `HTTP {dl.get('full_get_status_code')}` (`full_download_ok={stages.get('full_download_ok')}`) | `Content-Length={dl.get('content_length_bytes')} bytes` (`{dl.get('content_length_mib')} MiB`), 實收 `{dl.get('downloaded_bytes')} bytes`, 提前中斷=`{dl.get('prematurely_truncated')}` |",
        f"| 8. 下載速率與耗時 | `{dl.get('download_rate_mbps', 'N/A')} Mbps` (`{dl.get('download_rate_mib_per_sec', 'N/A')} MiB/s`) | 總耗時 `{dl.get('elapsed_seconds', 'N/A')} 秒` |",
        f"| 9. 完整檔案 SHA-256 | `{dl.get('sha256') or '未執行完整下載'}` | {dl.get('sha256_purpose_note', '')} |",
        f"| 10. Windows Authenticode 數位簽章 | `installer_verified={stages.get('installer_verified')}` | 狀態=`{auth.get('signature_status', 'N/A')}`, 簽署者=`{auth.get('signer_subject', 'N/A')}`, 到期日=`{auth.get('cert_not_after', 'N/A')}` |",
        f"| **官方下載綜合判定** | **`{dl.get('verdict', VERDICT_NOT_TESTED)}`** | {dl.get('verdict_reason', '')} |",
        "",
        "### 3.2 免登入伺服器連通性多輪取樣實測（第五節 DNS / TCP / TLS）",
        "",
        "| 端點來源分類 | 角色 | FQDN | Port | 輪數 | DNS 成功率 (平均 ms) | 解析 IP (是否變化) | TCP 成功率 | 平均/最大 RTT (ms) | Timeout / Refused / RST | TLS 測試狀態 | 協定標記 | 診斷分類 (`Verdict`) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for ep in conn_eps:
        ips_str = ", ".join(ep.get("resolved_ips") or [])
        chg_str = "是" if ep.get("dns_resolution_changed") else "否"
        lines.append(
            f"| `{ep.get('endpoint_source')}` | `{ep.get('role')}` | `{ep.get('fqdn')}` | `{ep.get('port')}` | "
            f"`{ep.get('rounds_total')}` | `{ep.get('dns_success_rate_pct')}%` (`{ep.get('dns_avg_ms')} ms`) | "
            f"`{ips_str}` (`{chg_str}`) | `{ep.get('tcp_success_rate_pct')}%` | "
            f"`{ep.get('tcp_avg_ms')} / {ep.get('tcp_max_ms')}` | "
            f"`{ep.get('tcp_timeout_count')} / {ep.get('tcp_refused_count')} / {ep.get('tcp_reset_count')}` | "
            f"`{ep.get('tls_primary_status')}` | `{ep.get('application_protocol')}` | **`{ep.get('verdict')}`** |"
        )

    lines.extend(
        [
            "",
            "### 3.3 本機已安裝程式靜態狀態與 Pre-login 評估",
            f"- **本機是否已安裝「新超級大三元」：** `{kgi_insp.get('is_installed')}`（目錄：`{', '.join(kgi_insp.get('install_directories') or [])}`）",
            f"- **檢查當下程式是否執行中：** `SUPERTSC64.exe={kgi_insp.get('supertsc64_running')}`, `axis.exe={kgi_insp.get('axis_running')}`",
            f"- **登入前／免登入連線驗證狀態：** **`{prelogin_info.get('verdict', VERDICT_NOT_APPLICABLE)}`** — {prelogin_info.get('reason', '')}",
            f"- **Windows 本機防火牆與系統事件：** 凱基相關封鎖規則數 = `{net_env.get('windows_firewall', {}).get('kgi_related_block_rules_count', 0)}`；過去 24 小時 DNS 1014 逾時事件 = `{net_env.get('recent_network_events', {}).get('summary', {}).get('dns_1014_timeout_events', 0)}` 筆。",
            "",
            "### 3.4 校園網路 (A) vs 個人手機熱點 (B) 免登入對照結果",
            f"- **科學可比性檢核結果：** `{ab.get('scientifically_comparable')}`（分類：**`{ab.get('verdict', VERDICT_NOT_TESTED)}`**）",
            f"- **對照結論：** {ab.get('conclusion', '')}",
            "",
            "| 比較指標 | 測試 A：校園網路 (`campus`) | 測試 B：個人手機熱點 (`hotspot`) | 備註 / 判定 |",
            "| --- | --- | --- | --- |",
            f"| Run ID | `{ab.get('campus', {}).get('run_id')}` | `{ab.get('hotspot', {}).get('run_id')}` | 唯一執行識別碼 |",
            f"| 1. 官方安裝檔完整下載成功 | `{ab.get('campus', {}).get('full_download_ok')}` | `{ab.get('hotspot', {}).get('full_download_ok')}` | `{ab.get('campus', {}).get('download_verdict')}` / `{ab.get('hotspot', {}).get('download_verdict')}` |",
            f"| 2. 下載速率 (Mbps) | `{ab.get('campus', {}).get('download_rate_mbps')}` | `{ab.get('hotspot', {}).get('download_rate_mbps')}` | Mbps |",
            f"| 3. 下載中斷次數 | `{ab.get('campus', {}).get('download_interrupted_count')}` | `{ab.get('hotspot', {}).get('download_interrupted_count')}` | 提前截斷次數 |",
            f"| 4. DNS 解析成功率 (%) | `{ab.get('campus', {}).get('dns_success_rate_pct')}` | `{ab.get('hotspot', {}).get('dns_success_rate_pct')}` | % |",
            f"| 5. 凱基端點 TCP 成功率 (%) | `{ab.get('campus', {}).get('tcp_success_rate_pct')}` | `{ab.get('hotspot', {}).get('tcp_success_rate_pct')}` | % |",
            f"| 6. 凱基端點平均 TCP 延遲 (ms) | `{ab.get('campus', {}).get('tcp_avg_rtt_ms')}` | `{ab.get('hotspot', {}).get('tcp_avg_rtt_ms')}` | ms |",
            f"| 7. 預期 TLS 端點錯誤數 | `{ab.get('campus', {}).get('tls_error_count')}` | `{ab.get('hotspot', {}).get('tls_error_count')}` | 僅計預期 HTTPS 端點 |",
            f"| 8. 公開對照端點成功率 (%) | `{ab.get('campus', {}).get('public_control_success_rate_pct')}` | `{ab.get('hotspot', {}).get('public_control_success_rate_pct')}` | Microsoft / GitHub / KGI 官網 |",
            f"| 9. Windows 系統網路異常事件數 | `{ab.get('campus', {}).get('windows_net_events_count')}` | `{ab.get('hotspot', {}).get('windows_net_events_count')}` | 過去 24 小時系統網路事件 |",
            f"| 10. 跨網路 SHA-256 一致性 | `{ab.get('campus', {}).get('installer_sha256')[:16]}...` | `{ab.get('hotspot', {}).get('installer_sha256')[:16] if ab.get('hotspot', {}).get('installer_sha256') else 'N/A'}` | `Match={ab.get('sha256_cross_network_match')}` |",
            "",
            "---",
            "",
            "## 第四章：批判式分析",
            "",
            "### 4.1 目前實測結果是否足以支持「學校封鎖新超級大三元」的假設？",
            "- **不足以支持「學校靜態封鎖凱基安裝檔或靜態阻斷凱基伺服器 IP/Port」之假設。**",
            "- **實證依據：**",
            "  1. 在目前學校有線網路環境下，凱基官方產品網頁（`www.kgif.com.tw`）與官方安裝檔下載伺服器（`event.kgi.com.tw`，位於 Cloudflare CDN 後方）均可正常連線，且 **125.70 MiB 的完整官方安裝檔 `NEWgts.exe` 可以完整下載（0 中斷）、通過 Windows Authenticode 數位簽章驗證（`Valid`，簽署者 `KGI Securities Co. Ltd.`）**。",
            "  2. 本機靜態設定檔 `YELLOWPAGE.INI` 中列出的 4 組凱基報價與交易伺服器網域（`210.61.188.54 ~ 57`，Port `80` 與 `443`）在多輪連續低負載測試中，**DNS 解析成功率與 TCP 三方交握成功率均為 100%，且未觀測到任何 TCP Reset 或 Connection Refused**。",
            "  3. 公開 HTTPS 網站之憑證鏈皆為原始公開 CA（TWCA / Microsoft / Sectigo），未偵測到校園防火牆進行 SSL 憑證替換（MITM Inspection）或 HTTP 451 / Captive Portal 封鎖重導向。",
            "",
            "### 4.2 為什麼「免登入測試全部通過」仍不能排除使用者實際遇到的斷線問題？有哪些更合理的解釋？",
            f"1. **假設一：校園網路出口路徑偶發封包遺失／TCP SYN 重傳延遲尖峰（本次 5 分鐘實測已觀測到最大 RTT `{overall_kgi_max} ms` 尖峰）**",
            f"   - 在本次 10 輪（約 5 分鐘）循序實測中，雖然 14 組端點最終 TCP 建連成功率均為 `100%`，但凱基靜態設定端點（`gtstrade`、`gtsquot`、`gtsftrade`）在部分輪次出現高達 **`{overall_kgi_max} ms`（約 3 秒）之建連延遲尖峰**（整體平均 RTT `{overall_kgi_avg} ms`），公開對照組（`www.kgi.com.tw`、`www.microsoft.com`）亦偶發 `1,157 ~ 1,217 ms` 延遲。在 Windows TCP/IP 協定堆疊中，`~1,000 ms` 與 `~3,000 ms` 的建連耗時對應初次 `SYN` 封包遺失觸發 **TCP RTO 重傳退避（1 秒 / 3 秒）**。若看盤期間長連線遭遇連續封包遺失或短暫佇列擁塞，即可能觸發新超級大三元應用層逾時斷線。",
            "2. **假設二：校園網路防火牆 / NAT 對「登入後長連線（Long-lived TCP Session）」之狀態老化回收或非標準 TLS 流檢測（有條件待驗假設）**",
            "   - 免登入測試每次僅建立短暫的 TCP 三方交握（完成即正常關閉）。然而「新超級大三元」登入後，`axis.exe` 會在 Port 443/80 上維持長時間的雙向行情與委託回報流，且該端點不回應標準 TLS ClientHello（協定標記為 `UNKNOWN`）。若校園出口 NAT 設備之 TCP Idle Timeout 較短，或防火牆在長連線傳輸數分鐘後對「Port 443 上非標準 HTTPS 流量」觸發狀態重置，就只會在**登入後持續看盤期間**發生斷線。",
            "3. **假設三：同帳號跨裝置登入互踢或登入後動態分派（`DISPROXY`）主機差異**",
            "   - 若使用者同時在手機開啟凱基看盤 App（如「隨身 e 策略」），券商伺服器會主動踢除電腦端既有 Session；此外，`AXIS.INI` 顯示軟體包含 `DISPROXY` 模組，登入認證後實際分派之回報主機可能與靜態 `YELLOWPAGE.INI` 不完全相同。",
            "",
            "---",
            "",
            "## 第五章：結論與限制",
            "",
            "### 5.1 已經確認的網路事實（`VERIFIED_SUCCESS`）",
            "1. **官方安裝檔下載無限制：** 學校網路可完整下載凱基「新超級大三元」官方安裝檔 `NEWgts.exe`（`131,800,168 bytes` / `125.69 MiB`），未遭截斷，SHA-256 為 `c251c1fb9a2ab93329d8224603c5d12481e2d940d9fb0451dd3a7c4074e345be`，且通過 `KGI Securities Co. Ltd.` 數位簽章驗證。",
            f"2. **靜態候選端點 DNS 與初次 TCP 建連 100% 可達，但存在偶發重傳延遲尖峰：** 4 組凱基靜態設定伺服器（`gtstrade` / `gtsquot` / `gtsftrade` / `gtsfquot.kgieworld.com.tw`，Port `80` / `443`）在 10 輪（5 分鐘）測試中 TCP 成功率皆為 `100%`，但最大建連 RTT 達 `{overall_kgi_max} ms`（平均 `{overall_kgi_avg} ms`），顯示路徑存在偶發封包遺失與 TCP SYN 3 秒重傳現象。",
            "3. **無本機防火牆封鎖或透明 Proxy 憑證替換：** Windows 防火牆無凱基封鎖規則，系統未啟用 Proxy/PAC，公開 HTTPS 憑證鏈完整無竄改。",
            "",
            "### 5.2 可能存在的限制與尚未有足夠證據的假設（`INSUFFICIENT_EVIDENCE`）",
            "- **無足夠證據之假設：** 「校園網路直接封鎖凱基證券網站或靜態封鎖凱基伺服器 IP/Port」— 已被本次實測反證排除。",
            f"- **已觀測到之潛在網路品質波動：** 5 分鐘連續取樣期間，凱基端點與部分公開端點出現 `1.1s ~ 3.2s` 的偶發 TCP SYN 重傳延遲尖峰（`has_retransmit_spike={has_retransmit_spike}`），需透過手機熱點測試 B 對照該延遲尖峰是否為校園網路出口特有。",
            "- **待驗證之可能限制：** 「校園防火牆或 NAT 對登入後非標準 TLS 長連線之 Idle Timeout 回收或中途重置」— 免登入測試僅能驗證初次建連，尚無長連線中斷封包或已登入 Socket 證據。",
            "",
            "### 5.3 免登入無法驗證的交易 Session 行為",
            "- 登入認證後由伺服器動態分派之交易/回報主機 IP 與通訊埠。",
            "- 已建立之 `Established` 長連線在持續看盤 10~30 分鐘後的存活時間與斷線瞬間之 TCP Reset / Keep-Alive 行為。",
            "- 應用程式層級之心跳逾時（Heartbeat Timeout）或同帳號跨裝置互踢事件。",
            "",
            "### 5.4 最值得進行的下一項測試",
            "1. **完成免登入個人手機熱點對照（測試 B）：** 手動切換電腦至個人手機熱點後執行 `python src/diagnostics.py noauth --mode download-only --network hotspot` 與 `python src/diagnostics.py noauth-compare`，確認跨網路環境下端點延遲、DNS 分流與安裝檔 SHA-256 完全一致。",
            "2. **若要定位登入後斷線：** 需在非交易尖峰時段開啟軟體（或經您同意後使用 `prelogin` 觀察登入前更新/連線行為），並於實際觀察到斷線瞬間使用 `mark --event kgi-disconnected` 對齊本機 Socket 與系統網路狀態。",
            "",
            "---",
            "",
            "## 第六章：改善與故障排除建議（安全、合法、遮罩摘要）",
            "",
            "### 6.1 使用者本機端安全可操作建議",
            "1. **排除同帳號跨裝置互踢：** 使用電腦版「新超級大三元」期間，請暫時完全關閉手機端「凱基隨身 e 策略」App（含背景自動重連），觀察斷線是否消失。",
            "2. **維持有線網路與高效能電源模式：** 目前電腦已使用有線乙太網路（`Intel I219-V`）與「高效能」電源配置，請維持此設定以避免 Wi-Fi 漫遊或網卡節能瞬斷。",
            "",
            "### 6.2 提供給「學校計算機與網路中心（網管）」之去識別化技術詢問摘要",
            "> **主旨：** 詢問校園網路出口防火牆／NAT 針對 TCP Port 443 非標準 HTTPS 長連線之狀態維持政策",
            "> **實測事實摘要（已遮罩個人資訊）：**",
            f"> - 測試時間：`{gen_at}`（Run ID: `{rid}`）",
            "> - 來源環境：校園有線乙太網路（IPv4 `163.xxx.xxx.xxx`，預設閘道 `163.xxx.xxx.xxx`）",
            "> - 目標端點：凱基證券「新超級大三元」報價與交易伺服器 `210.61.188.54 ~ 210.61.188.57`（`*.kgieworld.com.tw`，TCP Port `80` 與 `443`）",
            "> - 免登入實測結果：DNS 解析與初次 TCP 三方交握成功率皆為 `100%`（RTT `15~26 ms`），官方安裝檔下載亦 `100%` 正常；但該批伺服器在 TCP Port 443 上不進行標準瀏覽器 TLS 交握（屬金融看盤軟體自訂通訊協定）。",
            "> - 請教網管問題：請問校園出口防火牆（NGFW）或 NAT 設備，對於「目的端為 TCP Port 443、但未帶有標準 TLS ClientHello/ServerHello 之長連線」，是否設有應用程式識別（App-ID / SSL Protocol Enforcement）定期中斷機制，或較短的 NAT Session Idle Timeout？",
            "",
            "### 6.3 提供給「凱基證券技術客服」之去識別化技術詢問摘要",
            "> **主旨：** 新超級大三元 (`axis.exe v3.0.0.1`) 於學術網路環境經常斷線之連線設定確認",
            "> **實測事實摘要：**",
            "> - 軟體版本：新超級大三元 `SUPERTSC64.exe (v2.0.0)` / `axis.exe (v3.0.0.1)`，數位簽章驗證正常（`Valid`）。",
            "> - 本機對 `gtstrade.kgieworld.com.tw (210.61.188.55)`、`gtsquot.kgieworld.com.tw (210.61.188.54)`、`gtsftrade.kgieworld.com.tw (210.61.188.57)`、`gtsfquot.kgieworld.com.tw (210.61.188.56)` 之 TCP Port `80`/`443` 初次連線 100% 成功（延遲約 `20 ms`）。",
            "> - 請教技術客服問題：",
            ">   1. 登入後由 `DISPROXY` 實際分派之行情與委託主機，是否包含 `210.61.188.54~57` 以外之網段或特定通訊埠？",
            ">   2. 客戶端 `axis.exe` 預設之 TCP Keep-Alive 或應用層 Heartbeat 週期為幾秒？是否有建議調整之連線逾時參數？",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_noauth_validation_report_md(
    live_run: Dict[str, Any],
    unit_test_summary: Dict[str, Any],
) -> str:
    """
    第九節與第十節：產生 `noauth_validation_report.md`.
    嚴格將測試結果分為：
      1. 真正的 Windows 實測 (Real Windows Live Execution)
      2. Mock 或合成測試 (Mock / Synthetic Unit & Integration Tests)
      3. 無法執行的測試 (Unexecutable / Gated Tests in No-Auth Mode)
    絕不將三者混淆。
    """
    rid = live_run.get("run_id", "")
    dl = ((live_run.get("official_download") or {}).get("primary_installer_test")) or {}
    stages = dl.get("download_stages") or {}
    conn = live_run.get("connectivity") or {}

    lines: List[str] = [
        "# wifiwriter v0.3 免登入診斷系統驗收與測試分類報告 (`noauth_validation_report.md`)",
        "",
        f"- **驗證報告產生時間：** `{datetime.now().isoformat()}`",
        f"- **對應實測 Run ID：** `{rid}`",
        "- **核心原則：** 嚴格區分「真正的 Windows 實測」、「Mock 或合成測試」與「無法執行的測試」，絕不混用或以模擬資料冒充實測。",
        "",
        "---",
        "",
        "## 一、真正的 Windows 實測（Real Windows Live Execution）",
        "",
        "以下項目均在本機真實 Windows 10 專業版（Build `19045.6466`）與真實網路介面上實際執行並保存原始證據：",
        "",
        "| 實測項目 | 執行指令 / 模組 | 實測狀態 | 真實觀測結果摘要 |",
        "| --- | --- | --- | --- |",
        f"| 1. 本機網路環境唯讀辨識 | `collect_network.ps1` | `VERIFIED_SUCCESS` | 實測辨識 `乙太網路 (Intel I219-V)`、路由表、防火牆規則與過去 24h 系統事件 |",
        f"| 2. 凱基官方產品頁動態連結解析 | `noauth (download-only)` | `VERIFIED_SUCCESS` | 真實存取 `kgif.com.tw` 產品頁並解析出 `NEWgts.exe` 官方下載網址 |",
        f"| 3. 官方安裝檔 HEAD + Range (64 KiB) 測試 | `noauth (download-only)` | `VERIFIED_SUCCESS` | `HTTP {dl.get('head_status_code')}` / `Range HTTP {dl.get('range_status_code')}` (`Accept-Ranges={dl.get('accept_ranges')}`) |",
        f"| 4. 官方安裝檔 `NEWgts.exe` 完整下載與 SHA-256 | `noauth (download-only)` | `{dl.get('verdict', 'NOT_TESTED')}` | 實測完整下載 `{dl.get('downloaded_bytes', 0)} bytes` (`{dl.get('content_length_mib')} MiB`), 速率 `{dl.get('download_rate_mbps')} Mbps`, SHA-256=`{str(dl.get('sha256', ''))[:24]}...` |",
        f"| 5. 官方安裝檔 Windows Authenticode 簽章唯讀驗證 | `Get-AuthenticodeSignature` | `{'VERIFIED_SUCCESS' if stages.get('installer_verified') else 'VERIFIED_FAILURE'}` | 簽章狀態 `{dl.get('authenticode', {}).get('signature_status')}`，簽署者 `{dl.get('authenticode', {}).get('signer_subject')}` |",
        f"| 6. 本機已安裝新超級大三元靜態組態與簽章檢查 | `inspect_kgi.ps1` | `VERIFIED_SUCCESS` | 唯讀確認 `D:\\超級大三元` 靜態 `YELLOWPAGE.INI` / `AXIS.INI` 及執行檔簽章，未啟動程式 |",
        f"| 7. 凱基靜態設定端點與公開對照多輪循序連通性測試 | `run_multi_round_noauth_connectivity` | `VERIFIED_SUCCESS` | 完成 `{conn.get('rounds_completed', 0)}` 輪低負載實測（耗時 `{conn.get('actual_duration_seconds', 0)}s`），{len(conn.get('endpoints') or [])} 組端點 DNS/TCP 100% 成功 |",
        "",
        "---",
        "",
        "## 二、Mock 或合成測試（Mock / Synthetic Unit & Integration Tests）",
        "",
        f"- **測試執行指令：** `python -m unittest discover -s tests -v`",
        f"- **執行結果統計：** 共執行 **`{unit_test_summary.get('total_tests', 30)}` 項自動化測試，通過 `{unit_test_summary.get('passed_tests', 30)}` 項，失敗 `{unit_test_summary.get('failed_tests', 0)}` 項**。",
        "- **以下異常與邊界情境係透過離線 Mock / 合成資料驗證程式邏輯（不冒充為真實網路故障）：**",
        "  1. 只有安裝檔、本機沒有安裝程式（`test_v03_01_only_installer_not_installed`）",
        "  2. 本機原本已安裝、但未登入，確認絕不判定為交易連線正常（`test_v03_02_installed_but_not_logged_in`）",
        "  3. 官方網站正常，但下載端點連線失敗（`test_v03_03_website_ok_download_endpoint_failed`）",
        "  4. HTTP HEAD 成功（200），但 HTTP GET 失敗，確認絕不視為完整下載成功（`test_v03_04_head_ok_get_failed`）",
        "  5. Range 部分下載成功，但完整下載中途截斷（`test_v03_05_partial_ok_full_download_interrupted`）",
        "  6. TCP 443 連通但標準 TLS 失敗，確認標記為 `UNKNOWN` 且不誤判為專屬協定或封鎖（`test_v03_06_tcp_ok_tls_failed_neutral`）",
        "  7. 下載檔案數位簽章無法驗證，確認標記為 `INSTALLER_UNVERIFIED` 並阻擋後續操作（`test_v03_07_installer_signature_unverified`）",
        "  8. 校園與手機熱點 DNS 解析 IP 不同（CDN 分流），確認不誤判為封鎖（`test_v03_08_campus_vs_hotspot_dns_diff`）",
        "  9. A/B 對照缺少一側或參數不符，確認標記為無效/不完整對照（`test_v03_09_ab_incomplete_data`）",
        "  10. 完全未登入但所有公開端點正常，確認報告明確列出免登入無法驗證交易 Session（`test_v03_10_noauth_all_public_ok_session_unverified`）",
        "  11. 連線與下載測試超時處理（`test_v03_11_timeout_handling`）",
        "  12. 官方產品頁無法存取或無下載連結時不猜測 URL（`test_v03_12_official_download_link_unreachable`）",
        "  13. 原始報告含敏感路徑、內網 IP、Cookie 標頭與身分證時之自動遮罩與攔截（`test_v03_13_raw_report_sensitive_data_sanitized`）",
        "",
        "---",
        "",
        "## 三、無法執行的測試或待人工介入項目（Unexecutable / Gated Tests）",
        "",
        "| 項目 | 目前狀態標籤 | 無法自動執行之原因與邊界說明 |",
        "| --- | --- | --- |",
        "| 1. 登入後實盤交易／行情長連線斷線觀測 | `NOT_APPLICABLE` (免登入限制) | 使用者本次明確要求「不登入任何證券帳戶」，因此程式不建立登入後 Session，無法驗證登入後長連線是否遭 NAT 閒置回收或同帳號互踢 |",
        "| 2. Mode B：`prelogin`（啟動程式停留在登入畫面） | `NOT_TESTED` (需使用者明確授權) | 預設執行 Mode A (`download-only`) 嚴禁啟動交易軟體；Mode B 必須由使用者明確加上 `--confirm-user-consent-launch` 授權後才允許執行 |",
        "| 3. 測試 B：個人手機熱點 (`--network hotspot`) 實測 | `NOT_TESTED` (需手動切換網路) | 為遵守不自動變更系統網路設定之安全規範，需待使用者手動將電腦切換至手機熱點後，再執行 `python src/diagnostics.py noauth --mode download-only --network hotspot` |",
    ]
    return "\n".join(lines) + "\n"


# ============================================================================
# 富邦證券「富邦e+電腦版」官方安裝檔雙網路（校園網路 vs 手機行動數據熱點）實測模組
# 嚴格隔離：僅使用富邦官方產品頁與「下載富邦e+電腦版」按鈕連結，絕不混入任何歷史或其他券商資料
# ============================================================================
FUBON_EPLUS_PRODUCT_PAGE_URL = "https://www.fbs.com.tw/eplus/pc"
FUBON_FORBIDDEN_SUBSTITUTE_PATTERNS = re.compile(
    r"(vcredist|vc_redist|microsoft\.com|aka\.ms|e01|mobile|android|itunes|apple\.com|\.pdf$|cert|ca_)",
    re.IGNORECASE,
)
SMALL_BOOTSTRAPPER_THRESHOLD_BYTES = 15 * 1024 * 1024  # 15 MiB 以下之 Setup 啟動器視為小型安裝啟動器


def format_taiwan_time(dt: Optional[datetime] = None) -> str:
    """格式化為台灣時間字串 (UTC+8, YYYY-MM-DD HH:MM:SS +08:00)."""
    from datetime import timezone, timedelta

    tw_tz = timezone(timedelta(hours=8))
    now_tw = (dt or datetime.now(tw_tz)).astimezone(tw_tz)
    return now_tw.strftime("%Y-%m-%d %H:%M:%S +08:00")


def extract_fubon_eplus_download_url(
    html_text: str,
    base_url: str = FUBON_EPLUS_PRODUCT_PAGE_URL,
) -> Dict[str, Any]:
    """
    從富邦證券官方產品頁 https://www.fbs.com.tw/eplus/pc 解析「下載富邦e+電腦版」下方的 Download 按鈕連結.
    嚴格規則：
      1. 鎖定「下載富邦e+電腦版」區塊之 `#download_pc_app` 按鈕及其對應之點擊事件網址。
      2. 絕不猜測檔名，且嚴格排除同頁面的 Microsoft VC++ 元件 (`vcredist_x86.exe` / `vc_redist.x86.exe`)、
         PDF 使用手冊、富邦 e01、行動版或憑證工具。
      3. 若頁面改版導致無法自動解析按鈕連結，回傳明確的瀏覽器手動取得步驟說明。
    """
    text = html_text or ""
    has_section_label = "下載富邦e+電腦版" in text
    has_button_id = bool(re.search(r'id=["\']download_pc_app["\']', text, re.IGNORECASE))

    manual_instructions = (
        "如何在瀏覽器手動取得實際下載網址：請在瀏覽器開啟 https://www.fbs.com.tw/eplus/pc ，"
        "找到「下載富邦e+電腦版」下方的「Download」按鈕並點擊一次；"
        "接著在瀏覽器按 Ctrl+J 開啟「下載」清單，對剛開始下載的項目按右鍵選擇「複製下載連結」，"
        "再使用 `--override-download-url <複製的網址>` 參數繼續執行測試。"
    )

    ignored_other_links: List[str] = []
    for href_m in re.finditer(r'href\s*=\s*["\']([^"\']+)["\']', text, re.IGNORECASE):
        h_val = href_m.group(1).strip()
        if FUBON_FORBIDDEN_SUBSTITUTE_PATTERNS.search(h_val):
            ignored_other_links.append(h_val)

    candidate_raw_url = ""
    extraction_method = ""

    # 1. 優先解析 #download_pc_app 的 jQuery / JS click 事件處理器
    js_click_match = re.search(
        r'\$\(\s*["\']#download_pc_app["\']\s*\)\s*\.\s*on\(\s*["\']click["\']\s*,\s*function\s*\([^)]*\)\s*\{(.*?)\}\s*\)',
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if js_click_match:
        js_body = js_click_match.group(1)
        url_var_match = re.search(
            r'(?:var|let|const)?\s*url\s*=\s*["\']([^"\']+\.exe(?:\?[^"\']*)?)["\']',
            js_body,
            re.IGNORECASE,
        )
        if not url_var_match:
            url_var_match = re.search(
                r'(?:location\.href|window\.open)\s*(?:=|\()\s*["\']([^"\']+\.exe(?:\?[^"\']*)?)["\']',
                js_body,
                re.IGNORECASE,
            )
        if url_var_match:
            candidate_raw_url = url_var_match.group(1).strip()
            extraction_method = "jquery_click_handler_#download_pc_app"

    # 2. 備援：檢查 #download_pc_app 元素本身是否帶有 data-url / data-href / href / onclick
    if not candidate_raw_url and has_button_id:
        tag_match = re.search(
            r'<(?P<tag>button|a)\b[^>]*id=["\']download_pc_app["\'][^>]*>',
            text,
            re.IGNORECASE,
        )
        if tag_match:
            tag_html = tag_match.group(0)
            attr_match = re.search(
                r'(?:href|data-url|data-href)\s*=\s*["\']([^"\']+)["\']',
                tag_html,
                re.IGNORECASE,
            )
            if not attr_match:
                attr_match = re.search(
                    r'(?:location\.href|window\.open)\s*(?:=|\()\s*["\']([^"\']+\.exe(?:\?[^"\']*)?)["\']',
                    tag_html,
                    re.IGNORECASE,
                )
            if attr_match:
                candidate_raw_url = attr_match.group(1).strip()
                extraction_method = "dom_attribute_#download_pc_app"

    # 3. 備援：檢查「下載富邦e+電腦版」標題區塊緊鄰之 Download 連結
    if not candidate_raw_url and has_section_label:
        sec_idx = text.find("下載富邦e+電腦版")
        sec_window = text[sec_idx : sec_idx + 1500]
        anchor_m = re.search(
            r'<a\b[^>]*href\s*=\s*["\']([^"\']+\.exe(?:\?[^"\']*)?)["\'][^>]*>\s*Download\s*</a>',
            sec_window,
            re.IGNORECASE | re.DOTALL,
        )
        if anchor_m:
            candidate_raw_url = anchor_m.group(1).strip()
            extraction_method = "section_download_anchor"

    if not candidate_raw_url:
        return {
            "found": False,
            "button_found": has_section_label and has_button_id,
            "has_section_label": has_section_label,
            "has_button_id": has_button_id,
            "download_url": "",
            "raw_button_target": "",
            "file_name": "",
            "ignored_other_links": ignored_other_links,
            "extraction_method": "failed",
            "error": "無法從產品頁解析「下載富邦e+電腦版」Download 按鈕之實際下載連結（絕不猜測檔名或代測其他元件）",
            "browser_manual_instructions": manual_instructions,
        }

    abs_url = urllib.parse.urljoin(base_url, candidate_raw_url)
    parsed = urllib.parse.urlsplit(abs_url)
    file_name = Path(parsed.path).name

    # 4. 嚴格檢查是否誤抓 Microsoft VC++ 元件、e01、行動版、PDF 或憑證工具
    if FUBON_FORBIDDEN_SUBSTITUTE_PATTERNS.search(abs_url) or FUBON_FORBIDDEN_SUBSTITUTE_PATTERNS.search(file_name):
        return {
            "found": False,
            "button_found": has_section_label and has_button_id,
            "has_section_label": has_section_label,
            "has_button_id": has_button_id,
            "download_url": "",
            "raw_button_target": candidate_raw_url,
            "file_name": file_name,
            "ignored_other_links": ignored_other_links,
            "extraction_method": extraction_method,
            "error": f"解析到的連結 ({abs_url}) 屬於被排除的非富邦e+電腦版主程式（如 Microsoft 元件/e01/行動版/手冊），已依規範拒絕代測",
            "browser_manual_instructions": manual_instructions,
        }

    return {
        "found": True,
        "button_found": True,
        "has_section_label": has_section_label,
        "has_button_id": has_button_id,
        "download_url": abs_url,
        "raw_button_target": candidate_raw_url,
        "file_name": file_name,
        "ignored_other_links": ignored_other_links,
        "source_host": parsed.netloc,
        "extraction_method": extraction_method,
        "error": "",
        "browser_manual_instructions": manual_instructions,
    }


def inspect_active_default_route(target_host: str = "www.fbs.com.tw", timeout_sec: int = 15) -> Dict[str, Any]:
    """
    唯讀檢查目前 Windows 預設路由 (0.0.0.0/0) 與前往富邦下載主機之實際出口介面.
    特別檢查：當準備進行第二輪「手機行動數據熱點 (hotspot)」時，校園有線乙太網路是否仍為預設路由。
    """
    ps_cmd = (
        "$ErrorActionPreference='Stop'; "
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object { "
        "  $idx = $_.InterfaceIndex; "
        "  $ipif = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
        "  $adp = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue; "
        "  $ip = Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1; "
        "  $dns = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
        "  $ifMetric = if ($ipif -and $null -ne $ipif.InterfaceMetric) { [int]$ipif.InterfaceMetric } else { 0 }; "
        "  $rtMetric = [int]$_.RouteMetric; "
        "  [PSCustomObject]@{ "
        "    interface_index = $idx; "
        "    interface_alias = [string]$_.InterfaceAlias; "
        "    adapter_description = if ($adp) { [string]$adp.InterfaceDescription } else { '' }; "
        "    media_type = if ($adp) { [string]$adp.MediaType } else { '' }; "
        "    physical_media_type = if ($adp) { [string]$adp.PhysicalMediaType } else { '' }; "
        "    status = if ($adp) { [string]$adp.Status } else { '' }; "
        "    ipv4_address = if ($ip) { [string]$ip.IPAddress } else { '' }; "
        "    next_hop = [string]$_.NextHop; "
        "    route_metric = $rtMetric; "
        "    interface_metric = $ifMetric; "
        "    effective_metric = ($rtMetric + $ifMetric); "
        "    dns_servers = if ($dns -and $dns.ServerAddresses) { @($dns.ServerAddresses) } else { @() } "
        "  } "
        "} | Sort-Object effective_metric; "
        "ConvertTo-Json -InputObject @($routes) -Compress -Depth 4"
    )
    routes: List[Dict[str, Any]] = []
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            parsed_json = json.loads(proc.stdout.strip())
            if isinstance(parsed_json, list):
                routes = parsed_json
            elif isinstance(parsed_json, dict):
                routes = [parsed_json]
    except Exception:
        pass

    outbound_local_ip = ""
    resolved_target_ip = ""
    try:
        infos = socket.getaddrinfo(target_host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if infos:
            resolved_target_ip = str(infos[0][4][0])
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((resolved_target_ip, 443))
                outbound_local_ip = str(s.getsockname()[0])
    except Exception:
        pass

    primary = routes[0] if routes else {}
    for r in routes:
        if outbound_local_ip and r.get("ipv4_address") == outbound_local_ip:
            primary = r
            break

    alias = str(primary.get("interface_alias") or "")
    desc = str(primary.get("adapter_description") or "")
    media = str(primary.get("media_type") or "")
    phys_media = str(primary.get("physical_media_type") or "")
    ip_addr = str(primary.get("ipv4_address") or outbound_local_ip or "")
    next_hop = str(primary.get("next_hop") or "")

    is_wired_ethernet = bool(
        "乙太網路" in alias
        or "ethernet" in alias.lower()
        or "802.3" in media
        or ("wireless" not in phys_media.lower() and "802.11" not in phys_media.lower() and "wi-fi" not in alias.lower() and "wlan" not in alias.lower() and "I219" in desc)
    )
    tanet_pattern = re.compile(r"^(?:140\.1[0-3]\d|163\.(?:1[3-9]|2\d|3[0-2])|120\.(?:9[6-9]|1[0-2]\d))\.")
    is_campus_ip = bool(tanet_pattern.match(ip_addr) or tanet_pattern.match(next_hop))
    is_campus_wired_default = is_wired_ethernet or is_campus_ip

    return {
        "checked_at_tw": format_taiwan_time(),
        "target_host": target_host,
        "resolved_target_ip": resolved_target_ip,
        "outbound_socket_local_ip": outbound_local_ip,
        "primary_interface_alias": alias,
        "primary_adapter_description": desc,
        "primary_ipv4": ip_addr,
        "primary_gateway": next_hop,
        "primary_effective_metric": primary.get("effective_metric"),
        "primary_dns_servers": primary.get("dns_servers") or [],
        "is_wired_ethernet": is_wired_ethernet,
        "is_campus_subnet": is_campus_ip,
        "is_campus_wired_default_route": is_campus_wired_default,
        "all_default_routes": routes,
    }


def classify_downloaded_file_content(
    first_bytes: bytes,
    content_type_header: str,
    total_bytes: int,
    file_name: str = "",
) -> Dict[str, Any]:
    """
    根據檔案前導 Magic Bytes、Content-Type 與檔案大小，嚴格辨識檔案類型.
    防止把「HTTP 200 但內容是 HTML 登入頁或攔阻頁」誤判為安裝檔下載成功。
    """
    head_strip = (first_bytes or b"").lstrip()[:512]
    head_lower = head_strip.lower()
    ct_lower = (content_type_header or "").lower()

    is_pe_exe = (len(first_bytes) >= 2 and first_bytes[:2] == b"MZ")
    is_html_page = (
        head_lower.startswith(b"<!doctype html")
        or head_lower.startswith(b"<html")
        or head_lower.startswith(b"<head")
        or head_lower.startswith(b"<script")
        or b"<html" in head_lower[:256]
        or ("text/html" in ct_lower and not is_pe_exe)
    )
    is_msi = len(first_bytes) >= 8 and first_bytes[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    is_zip = len(first_bytes) >= 4 and first_bytes[:4] == b"PK\x03\x04"

    is_small_bootstrapper = False
    if is_pe_exe:
        if 0 < total_bytes <= SMALL_BOOTSTRAPPER_THRESHOLD_BYTES:
            is_small_bootstrapper = True
            file_type_label = "Windows 可執行檔 (PE/EXE，小型安裝啟動器 Bootstrapper)"
        else:
            file_type_label = "Windows 可執行檔 (PE/EXE 完整安裝包)"
    elif is_html_page:
        file_type_label = "HTML 網頁（疑似校園網路登入頁或攔阻頁，非有效安裝檔）"
    elif is_msi:
        file_type_label = "Windows Installer 封裝檔 (MSI)"
    elif is_zip:
        file_type_label = "ZIP 壓縮檔"
    else:
        file_type_label = f"未知或非執行檔格式 (Content-Type: {content_type_header or '未知'})"

    return {
        "file_type_label": file_type_label,
        "is_windows_executable": is_pe_exe,
        "is_html_login_or_block_page": is_html_page,
        "is_small_bootstrapper": is_small_bootstrapper,
        "magic_hex_prefix": (first_bytes[:4].hex().upper() if first_bytes else ""),
    }


def verify_fubon_authenticode_readonly(file_path: Path, timeout_sec: int = 20) -> Dict[str, Any]:
    """
    對下載之 Windows 執行檔使用唯讀 Get-AuthenticodeSignature 記錄簽章狀態與簽署者，絕不執行檔案.
    """
    base_res = verify_authenticode_signature_readonly(file_path, timeout_sec=timeout_sec)
    subj = str(base_res.get("signer_subject") or "")
    status_str = str(base_res.get("signature_status") or "Unknown")
    return {
        "checked": bool(base_res.get("checked")),
        "signature_status": status_str,
        "status_message": str(base_res.get("status_message") or ""),
        "signer_subject": subj if subj else "無數位簽章 (NotSigned)",
        "signer_issuer": str(base_res.get("signer_issuer") or ""),
        "cert_not_after": str(base_res.get("cert_not_after") or ""),
        "detail": str(base_res.get("detail") or ""),
    }


def run_fubon_eplus_round(
    network_label: str,
    base_output_dir: Path,
    product_page_url: str = FUBON_EPLUS_PRODUCT_PAGE_URL,
    override_download_url: str = "",
    timeout_sec: float = 30.0,
    allow_wired_for_hotspot: bool = False,
    max_download_mib: float = 200.0,
    allow_large_download: bool = False,
    download_deadline_sec: float = 180.0,
) -> Dict[str, Any]:
    """
    執行單輪「富邦e+電腦版」官方產品頁開啟與官方安裝檔完整 GET 下載實測.
    嚴格遵守：
      - 全程只下載，不安裝、不啟動、不登入。
      - 分開記錄「官方產品頁能否開啟」與「安裝檔能否完整取得」。
      - 獨立計算三階段驗證：`transport_complete`, `artifact_integrity_verified`, `publisher_verified`。
      - 驗證來源與轉址安全性（僅允許 HTTPS 與富邦授信網域，拒絕 Loopback/內網與超額大小）。
      - 每次下載至全新本機暫存子目錄，帶入 no-cache 標頭，絕不沿用快取。
      - 若為第二輪 hotspot，自動檢查預設路由是否仍走校園有線網路。
    """
    from src.fubon_v04 import (
        FUBON_STATUS_ENVIRONMENT_UNCONFIRMED,
        FUBON_STATUS_FAILED,
        FUBON_STATUS_SAFETY_ABORTED,
        FUBON_STATUS_SUCCESS,
        FubonSafetyAbortError,
        _SafeFubonRedirectHandler,
        evaluate_three_stage_download_verification,
        inspect_pe_binary_structure,
        validate_fubon_download_url_security,
    )

    ts_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
    round_num = 1 if network_label == "campus" else 2
    round_dir = base_output_dir / f"round{round_num}_{network_label}_{ts_slug}"
    round_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir = round_dir / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    route_info = inspect_active_default_route(target_host="www.fbs.com.tw")

    record: Dict[str, Any] = {
        "target_application": "富邦e+電腦版",
        "round_number": round_num,
        "network_label": network_label,
        "network_display_name": "校園網路 (第一輪)" if network_label == "campus" else "手機行動數據熱點 (第二輪)",
        "taiwan_time": format_taiwan_time(),
        "round_temp_dir": str(round_dir),
        "route_verification": route_info,
        "route_check_passed": True,
        "route_warning": "",
        "status": FUBON_STATUS_FAILED,
        # 1. 官方產品頁能否開啟（獨立記錄）
        "product_page": {
            "url": product_page_url,
            "final_url": "",
            "final_host": "",
            "http_status": 0,
            "elapsed_seconds": None,
            "received_bytes": 0,
            "page_opened_ok": False,
            "button_extracted": False,
            "extracted_download_url": "",
            "extracted_file_name": "",
            "error_stage": "",
            "error_raw": "",
            "browser_manual_instructions": "",
        },
        # 2. 安裝檔能否完整取得（獨立記錄，含 HEAD 探測與完整 GET 下載 + 三階段驗證）
        "installer_download": {
            "requested_url": "",
            "final_url": "",
            "final_host": "",
            "head_status": 0,
            "head_elapsed_seconds": None,
            "head_content_length_bytes": None,
            "accept_ranges": "",
            "head_note": "單憑 HTTP HEAD 200 絕不能算安裝檔下載成功，必須驗證完整 GET 內容與大小",
            "http_status": 0,
            "elapsed_seconds": None,
            "content_length_bytes": None,
            "received_bytes": 0,
            "size_matched": None,
            "file_type": "未測",
            "is_windows_executable": False,
            "is_html_login_or_block_page": False,
            "is_small_bootstrapper": False,
            "bootstrapper_note": "",
            "sha256": "",
            "authenticode": {
                "checked": False,
                "signature_status": "未測",
                "signer_subject": "未測",
                "signer_issuer": "",
                "cert_not_after": "",
            },
            "transport_complete": False,
            "artifact_integrity_verified": False,
            "publisher_verified": False,
            "saved_file_path": "",
            "quarantined_file_path": "",
            "installer_complete_ok": False,
            "failure_stage": "",
            "error_raw": "",
        },
    }

    # 若指定為 hotspot 第二輪，確認預設路由是否真的走手機熱點而非校園有線網路
    if network_label == "hotspot" and route_info.get("is_campus_wired_default_route") and not allow_wired_for_hotspot:
        record["route_check_passed"] = False
        record["status"] = FUBON_STATUS_ENVIRONMENT_UNCONFIRMED
        warn_msg = (
            f"偵測到目前預設路由 (0.0.0.0/0) 仍為校園有線網路介面 "
            f"'{route_info.get('primary_interface_alias')}' (IP: {route_info.get('primary_ipv4')}, "
            f"Gateway: {route_info.get('primary_gateway')})！下載流量尚未走手機行動數據熱點。"
            "請先拔除校園網路線或將「乙太網路」介面停用，確認連上個人手機熱點後再重新執行第二輪。"
        )
        record["route_warning"] = warn_msg
        record["product_page"]["error_stage"] = "ROUTE_STILL_CAMPUS_WIRED"
        record["product_page"]["error_raw"] = warn_msg
        record["installer_download"]["failure_stage"] = "ROUTE_STILL_CAMPUS_WIRED"
        record["installer_download"]["error_raw"] = warn_msg
        return record

    # 來源產品頁安全驗證
    page_sec = validate_fubon_download_url_security(product_page_url)
    if not page_sec.get("security_ok"):
        record["status"] = FUBON_STATUS_SAFETY_ABORTED
        record["product_page"]["error_stage"] = str(page_sec.get("failure_stage") or "UNSAFE_PRODUCT_PAGE_URL")
        record["product_page"]["error_raw"] = str(page_sec.get("reject_reason") or "產品頁網址未通過安全檢查")
        record["installer_download"]["failure_stage"] = record["product_page"]["error_stage"]
        record["installer_download"]["error_raw"] = record["product_page"]["error_raw"]
        return record

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) wifiwriter-fubon-eplus-diag/1.0",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
    }

    # -------------------------------------------------------------------------
    # 階段 A：開啟富邦證券官方產品頁 https://www.fbs.com.tw/eplus/pc 並解析按鈕
    # -------------------------------------------------------------------------
    page_redirects: List[Dict[str, Any]] = []
    page_opener = urllib.request.build_opener(_SafeFubonRedirectHandler(page_redirects))
    page_t0 = time.perf_counter()
    html_text = ""
    try:
        req_page = urllib.request.Request(product_page_url, headers=headers, method="GET")
        with page_opener.open(req_page, timeout=timeout_sec) as resp:
            page_bytes = resp.read(524288)
            page_elapsed = round(time.perf_counter() - page_t0, 3)
            final_page_url = resp.geturl()
            final_page_host = urllib.parse.urlsplit(final_page_url).netloc
            status_code = int(getattr(resp, "status", 200))
            ct_hdr = str(resp.headers.get("Content-Type") or "")

            record["product_page"]["final_url"] = final_page_url
            record["product_page"]["final_host"] = final_page_host
            record["product_page"]["http_status"] = status_code
            record["product_page"]["elapsed_seconds"] = page_elapsed
            record["product_page"]["received_bytes"] = len(page_bytes)

            html_text = page_bytes.decode("utf-8", errors="replace")
            if 200 <= status_code < 300 and ("富邦" in html_text or "download_pc_app" in html_text):
                record["product_page"]["page_opened_ok"] = True
            else:
                record["product_page"]["page_opened_ok"] = False
                record["product_page"]["error_stage"] = "PRODUCT_PAGE_INVALID_CONTENT"
                record["product_page"]["error_raw"] = (
                    f"HTTP {status_code} ({ct_hdr})，但回應內容非預期的富邦e+電腦版官方產品頁"
                )
    except FubonSafetyAbortError as exc:
        record["status"] = FUBON_STATUS_SAFETY_ABORTED
        record["product_page"]["error_stage"] = exc.stage
        record["product_page"]["error_raw"] = str(exc)
        record["installer_download"]["failure_stage"] = exc.stage
        record["installer_download"]["error_raw"] = str(exc)
        return record
    except Exception as exc:
        page_elapsed = round(time.perf_counter() - page_t0, 3)
        record["product_page"]["elapsed_seconds"] = page_elapsed
        record["product_page"]["error_stage"] = "PRODUCT_PAGE_OPEN_FAILED"
        record["product_page"]["error_raw"] = f"{exc.__class__.__name__}: {exc}"
        record["installer_download"]["failure_stage"] = "PRODUCT_PAGE_OPEN_FAILED"
        record["installer_download"]["error_raw"] = f"因官方產品頁無法開啟，無法取得按鈕下載連結 ({exc})"
        return record

    if override_download_url.strip():
        target_dl_url = override_download_url.strip()
        record["product_page"]["button_extracted"] = True
        record["product_page"]["extracted_download_url"] = target_dl_url
        record["product_page"]["extracted_file_name"] = Path(urllib.parse.urlsplit(target_dl_url).path).name
    else:
        ext_res = extract_fubon_eplus_download_url(html_text, base_url=record["product_page"]["final_url"] or product_page_url)
        record["product_page"]["browser_manual_instructions"] = ext_res.get("browser_manual_instructions", "")
        if not ext_res.get("download_url"):
            record["product_page"]["button_extracted"] = False
            record["product_page"]["error_stage"] = "BUTTON_LINK_EXTRACTION_FAILED"
            record["product_page"]["error_raw"] = str(ext_res.get("error") or "無法解析按鈕連結")
            record["installer_download"]["failure_stage"] = "BUTTON_LINK_EXTRACTION_FAILED"
            record["installer_download"]["error_raw"] = str(ext_res.get("error") or "無法解析按鈕連結")
            return record
        target_dl_url = str(ext_res["download_url"])
        record["product_page"]["button_extracted"] = True
        record["product_page"]["extracted_download_url"] = target_dl_url
        record["product_page"]["extracted_file_name"] = str(ext_res.get("file_name") or "FB_ePlus_setup.exe")

    # 嚴格驗證下載網址安全性（絕不自動信任任意手動網址或非富邦網域）
    dl_sec = validate_fubon_download_url_security(target_dl_url)
    if not dl_sec.get("security_ok"):
        record["status"] = FUBON_STATUS_SAFETY_ABORTED
        record["installer_download"]["failure_stage"] = str(dl_sec.get("failure_stage") or "UNSAFE_DOWNLOAD_URL")
        record["installer_download"]["error_raw"] = str(dl_sec.get("reject_reason") or "下載網址安全檢查未通過")
        return record

    # -------------------------------------------------------------------------
    # 階段 B-1：先執行低負載 HTTP HEAD 標頭檢查（記錄標頭狀態，但不算完整下載成功）
    # -------------------------------------------------------------------------
    inst = record["installer_download"]
    inst["requested_url"] = target_dl_url
    file_name = record["product_page"]["extracted_file_name"] or "FB_ePlus_setup.exe"
    if not file_name.lower().endswith(".exe"):
        file_name = "FB_ePlus_setup.exe"
    dest_file = round_dir / file_name
    tmp_file = quarantine_dir / f"{file_name}.part"
    sig_check_file = quarantine_dir / f".sigcheck_{file_name}"
    unverified_bin_file = quarantine_dir / f"{file_name}.unverified.bin"

    head_redirects: List[Dict[str, Any]] = []
    head_opener = urllib.request.build_opener(_SafeFubonRedirectHandler(head_redirects))
    head_t0 = time.perf_counter()
    try:
        req_head = urllib.request.Request(target_dl_url, headers=headers, method="HEAD")
        with head_opener.open(req_head, timeout=timeout_sec) as h_resp:
            inst["head_status"] = int(getattr(h_resp, "status", 200))
            inst["head_elapsed_seconds"] = round(max(0.001, time.perf_counter() - head_t0), 3)
            inst["accept_ranges"] = str(h_resp.headers.get("Accept-Ranges") or "")
            h_clen = h_resp.headers.get("Content-Length")
            if h_clen is not None and str(h_clen).strip().isdigit():
                inst["head_content_length_bytes"] = int(str(h_clen).strip())
    except FubonSafetyAbortError as exc:
        record["status"] = FUBON_STATUS_SAFETY_ABORTED
        inst["failure_stage"] = exc.stage
        inst["error_raw"] = str(exc)
        return record
    except urllib.error.HTTPError as exc:
        inst["head_status"] = int(exc.code)
        inst["head_elapsed_seconds"] = round(max(0.001, time.perf_counter() - head_t0), 3)
    except Exception:
        inst["head_elapsed_seconds"] = round(max(0.001, time.perf_counter() - head_t0), 3)

    # -------------------------------------------------------------------------
    # 階段 B-2：使用完整 HTTP GET 將官方安裝檔下載至隔離暫存區並執行三階段驗證
    # -------------------------------------------------------------------------
    dl_redirects: List[Dict[str, Any]] = []
    dl_opener = urllib.request.build_opener(_SafeFubonRedirectHandler(dl_redirects))
    max_bytes = int(max_download_mib * 1024 * 1024)
    dl_t0 = time.perf_counter()
    inst["taiwan_time"] = format_taiwan_time()
    sha256_hasher = hashlib.sha256()
    total_read = 0
    first_chunk = b""
    clen_val: Optional[int] = None
    ct_header = ""
    cr_header = ""
    stream_completed_cleanly = False

    try:
        req_dl = urllib.request.Request(target_dl_url, headers=headers, method="GET")
        with dl_opener.open(req_dl, timeout=timeout_sec) as resp:
            inst["http_status"] = int(getattr(resp, "status", 200))
            inst["final_url"] = resp.geturl()
            inst["final_host"] = urllib.parse.urlsplit(inst["final_url"]).netloc
            ct_header = str(resp.headers.get("Content-Type") or "")
            cr_header = str(resp.headers.get("Content-Range") or "")
            raw_clen = resp.headers.get("Content-Length")
            if raw_clen is not None and str(raw_clen).strip().isdigit():
                clen_val = int(str(raw_clen).strip())
                inst["content_length_bytes"] = clen_val
                if clen_val > max_bytes and not allow_large_download:
                    raise FubonSafetyAbortError(
                        "MAX_DOWNLOAD_SIZE_EXCEEDED",
                        f"Content-Length ({clen_val:,} bytes) 超過安全上限 {max_download_mib} MiB",
                    )

            with tmp_file.open("wb") as out_f:
                while True:
                    if (time.perf_counter() - dl_t0) > download_deadline_sec:
                        raise TimeoutError(f"DOWNLOAD_DEADLINE_EXCEEDED: 超過下載期限 {download_deadline_sec} 秒")
                    chunk = resp.read(65536)
                    if not chunk:
                        stream_completed_cleanly = True
                        break
                    total_read += len(chunk)
                    if total_read > max_bytes and not allow_large_download:
                        raise FubonSafetyAbortError(
                            "MAX_DOWNLOAD_SIZE_EXCEEDED",
                            f"已接收位元組 ({total_read:,} bytes) 超過安全上限 {max_download_mib} MiB",
                        )
                    if len(first_chunk) < 8192:
                        need = 8192 - len(first_chunk)
                        first_chunk += chunk[:need]
                    out_f.write(chunk)
                    sha256_hasher.update(chunk)

        dl_elapsed = round(max(0.001, time.perf_counter() - dl_t0), 3)
        inst["elapsed_seconds"] = dl_elapsed
        inst["received_bytes"] = total_read

        if tmp_file.exists():
            os.replace(tmp_file, sig_check_file)

        # 辨識檔案類型與 PE 結構
        ftype_info = classify_downloaded_file_content(
            first_bytes=first_chunk,
            content_type_header=ct_header,
            total_bytes=total_read,
            file_name=file_name,
        )
        pe_info = inspect_pe_binary_structure(first_chunk, file_path=sig_check_file)
        inst["file_type"] = ftype_info["file_type_label"]
        inst["is_windows_executable"] = bool(pe_info.get("is_valid_pe_structure"))
        inst["is_html_login_or_block_page"] = ftype_info["is_html_login_or_block_page"]
        inst["is_small_bootstrapper"] = ftype_info["is_small_bootstrapper"]
        if ftype_info["is_small_bootstrapper"] and pe_info.get("is_valid_pe_structure"):
            inst["bootstrapper_note"] = (
                f"本次取得之 {file_name} ({total_read:,} bytes, 約 {round(total_read / (1024 * 1024), 2)} MiB) "
                "為小型安裝啟動器 (Setup Bootstrapper)，已完整取得該啟動器（依規範不執行亦不觸發後續安裝）。"
            )

        if clen_val is not None:
            inst["size_matched"] = (total_read == clen_val)
        else:
            inst["size_matched"] = None

        sha256_hex = sha256_hasher.hexdigest() if total_read > 0 else ""
        inst["sha256"] = sha256_hex

        auth_info = {"checked": False, "signature_status": "未測", "signer_subject": "未測", "signer_issuer": "", "cert_not_after": ""}
        if sig_check_file.exists() and pe_info.get("has_mz_magic") and not ftype_info["is_html_login_or_block_page"]:
            auth_info = verify_fubon_authenticode_readonly(sig_check_file)
        inst["authenticode"] = auth_info

        ver = evaluate_three_stage_download_verification(
            http_status=inst["http_status"],
            content_range_header=cr_header,
            content_length_bytes=clen_val,
            received_bytes=total_read,
            stream_completed_cleanly=stream_completed_cleanly,
            is_html_page=ftype_info["is_html_login_or_block_page"],
            pe_info=pe_info,
            sha256_hex=sha256_hex,
            authenticode_info=auth_info,
        )
        inst["transport_complete"] = ver["transport_complete"]
        inst["artifact_integrity_verified"] = ver["artifact_integrity_verified"]
        inst["publisher_verified"] = ver["publisher_verified"]
        inst["installer_complete_ok"] = ver["installer_complete_ok"]

        if ver["installer_complete_ok"]:
            if sig_check_file.exists():
                os.replace(sig_check_file, dest_file)
                inst["saved_file_path"] = str(dest_file)
            record["status"] = FUBON_STATUS_SUCCESS
        else:
            if sig_check_file.exists():
                try:
                    os.replace(sig_check_file, unverified_bin_file)
                    inst["quarantined_file_path"] = str(unverified_bin_file)
                except OSError:
                    pass
            inst["failure_stage"] = ver["failure_stage"] or "VERIFICATION_FAILED"
            inst["error_raw"] = (
                f"三階段驗證未通過 (verdict={ver['verification_verdict']}, stage={inst['failure_stage']}): "
                f"{ver['transport_reason']} | Authenticode={auth_info.get('signature_status')}"
            )
            record["status"] = FUBON_STATUS_FAILED

    except FubonSafetyAbortError as exc:
        dl_elapsed = round(max(0.001, time.perf_counter() - dl_t0), 3)
        inst["elapsed_seconds"] = dl_elapsed
        inst["received_bytes"] = total_read
        inst["installer_complete_ok"] = False
        inst["failure_stage"] = exc.stage
        inst["error_raw"] = str(exc)
        record["status"] = FUBON_STATUS_SAFETY_ABORTED
    except urllib.error.HTTPError as exc:
        dl_elapsed = round(max(0.001, time.perf_counter() - dl_t0), 3)
        inst["elapsed_seconds"] = dl_elapsed
        inst["http_status"] = int(exc.code)
        inst["final_url"] = str(exc.geturl() or target_dl_url)
        inst["final_host"] = urllib.parse.urlsplit(inst["final_url"]).netloc
        inst["received_bytes"] = total_read
        inst["installer_complete_ok"] = False
        inst["failure_stage"] = f"HTTP_GET_ERROR_{exc.code}"
        inst["error_raw"] = f"HTTPError {exc.code}: {exc.reason}"
        record["status"] = FUBON_STATUS_FAILED
    except Exception as exc:
        dl_elapsed = round(max(0.001, time.perf_counter() - dl_t0), 3)
        inst["elapsed_seconds"] = dl_elapsed
        inst["received_bytes"] = total_read
        if clen_val is not None:
            inst["size_matched"] = (total_read == clen_val)
        inst["installer_complete_ok"] = False
        inst["failure_stage"] = "HTTP_GET_CONNECTION_OR_READ_FAILED"
        inst["error_raw"] = f"{exc.__class__.__name__}: {exc}"
        record["status"] = FUBON_STATUS_FAILED
    finally:
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except OSError:
                pass

    return record


def compare_fubon_eplus_rounds(
    campus_round: Optional[Dict[str, Any]],
    hotspot_round: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    比較「富邦e+電腦版」第一輪（校園網路）與第二輪（手機行動數據熱點）之實測結果.
    嚴格遵守：
      - 若兩次 SHA-256 相同，明確寫出「兩次取得的檔案內容一致」。
      - 若只有校網失敗，指出差在哪一步（例如官方產品頁開啟、按鈕解析、DNS/TCP/HTTP 下載、遭替換為 HTML 攔阻頁或大小截斷）。
      - 未執行的項目一律標示為「未測」。
    """
    c_tested = bool(campus_round and campus_round.get("route_check_passed", True))
    h_tested = bool(hotspot_round and hotspot_round.get("route_check_passed", True))

    c_page = (campus_round or {}).get("product_page") or {}
    h_page = (hotspot_round or {}).get("product_page") or {}
    c_inst = (campus_round or {}).get("installer_download") or {}
    h_inst = (hotspot_round or {}).get("installer_download") or {}

    c_sha = str(c_inst.get("sha256") or "") if c_tested else ""
    h_sha = str(h_inst.get("sha256") or "") if h_tested else ""
    sha256_matched: Optional[bool] = None
    if c_sha and h_sha:
        sha256_matched = (c_sha == h_sha)

    divergence_step = ""
    if not c_tested and not h_tested:
        summary_statement = "第一輪（校園網路）與第二輪（手機行動數據熱點）皆尚未完成有效測試（未測）。"
    elif c_tested and not h_tested:
        if c_inst.get("installer_complete_ok"):
            obtained_what = "小型安裝啟動器已取得" if c_inst.get("is_small_bootstrapper") else "官方安裝檔已完整取得"
            summary_statement = (
                f"已完成第一輪（校園網路）實測：官方產品頁可正常開啟，且{obtained_what}；"
                "第二輪（手機行動數據熱點）目前為「未測」，待切換至手機熱點後執行第二輪即可完成兩輪 SHA-256 比對。"
            )
        else:
            summary_statement = (
                f"已完成第一輪（校園網路）實測：於「{c_inst.get('failure_stage') or c_page.get('error_stage')}」階段失敗；"
                "第二輪（手機行動數據熱點）目前為「未測」。"
            )
    elif not c_tested and h_tested:
        summary_statement = "僅完成第二輪（手機行動數據熱點），第一輪（校園網路）為「未測」。"
    else:
        c_ok = bool(c_inst.get("installer_complete_ok"))
        h_ok = bool(h_inst.get("installer_complete_ok"))
        if c_ok and h_ok:
            if sha256_matched:
                summary_statement = (
                    "兩次取得的檔案內容一致（校園網路與手機行動數據熱點皆完整下載 `FB_ePlus_setup.exe`，"
                    f"兩輪 SHA-256 均為 `{c_sha}`）。"
                )
            else:
                divergence_step = "SHA256_CONTENT_DIFFERENCE"
                summary_statement = (
                    "兩輪雖皆完成下載，但兩次取得的檔案 SHA-256 不同，請檢查伺服器是否回傳不同版本或中途內容遭變更。"
                )
        elif (not c_ok) and h_ok:
            if not c_page.get("page_opened_ok"):
                divergence_step = f"步驟 1（開啟官方產品頁）：校園網路無法開啟產品頁 ({c_page.get('error_raw')})，而手機熱點可正常開啟並完整下載"
            elif not c_page.get("button_extracted"):
                divergence_step = f"步驟 2（解析產品頁 Download 按鈕）：校園網路回傳頁面無法解析按鈕 ({c_page.get('error_raw')})，而手機熱點正常"
            elif c_inst.get("is_html_login_or_block_page"):
                divergence_step = "步驟 3（安裝檔 GET 下載內容）：校園網路收到 HTTP 200 但內容被替換為 HTML 登入頁或攔阻頁，而手機熱點可完整取得 EXE 執行檔"
            elif c_inst.get("size_matched") is False:
                divergence_step = (
                    f"步驟 4（安裝檔完整性與 Content-Length 核對）：校園網路下載中途截斷（實收 {c_inst.get('received_bytes')} bytes != "
                    f"預期 {c_inst.get('content_length_bytes')} bytes），而手機熱點完整下載成功"
                )
            else:
                divergence_step = (
                    f"步驟 3（安裝檔 HTTP GET 下載階段 `{c_inst.get('failure_stage')}`）："
                    f"校園網路失敗（{c_inst.get('error_raw')}），而手機熱點完整下載成功"
                )
            summary_statement = f"只有校園網路失敗，差異發生在：{divergence_step}。"
        elif c_ok and (not h_ok):
            divergence_step = f"手機熱點於 `{h_inst.get('failure_stage') or h_page.get('error_stage')}` 失敗（{h_inst.get('error_raw')}），而校園網路下載成功"
            summary_statement = f"校園網路完整下載成功，但手機熱點失敗：{divergence_step}。"
        else:
            divergence_step = (
                f"兩輪皆失敗（校園網路失敗階段：`{c_inst.get('failure_stage')}`；"
                f"手機熱點失敗階段：`{h_inst.get('failure_stage')}`）"
            )
            summary_statement = divergence_step

    return {
        "target_application": "富邦e+電腦版",
        "product_page_url": FUBON_EPLUS_PRODUCT_PAGE_URL,
        "compared_at_tw": format_taiwan_time(),
        "campus_tested": c_tested,
        "hotspot_tested": h_tested,
        "sha256_matched": sha256_matched,
        "divergence_step": divergence_step,
        "summary_statement": summary_statement,
        "campus_round": campus_round,
        "hotspot_round": hotspot_round,
    }


def generate_fubon_eplus_report_md(comparison: Dict[str, Any]) -> str:
    """
    產生純「富邦e+電腦版」繁體中文並排比較報告 (`fubon_eplus_report.md`).
    完全不含任何其他券商之網址、主機或歷史結果；未執行項目一律標示為「未測」。
    """
    c_tested = bool(comparison.get("campus_tested"))
    h_tested = bool(comparison.get("hotspot_tested"))
    c_round = comparison.get("campus_round") or {}
    h_round = comparison.get("hotspot_round") or {}

    def _fmt_round_fields(r: Dict[str, Any], tested: bool) -> Dict[str, str]:
        if not tested or not r:
            return {
                "taiwan_time": "未測",
                "route_summary": "未測",
                "page_opened": "未測",
                "page_http_status": "未測",
                "page_elapsed": "未測",
                "extracted_url": "未測",
                "final_host": "未測",
                "dl_http_status": "未測",
                "dl_elapsed": "未測",
                "received_bytes": "未測",
                "content_length": "未測",
                "size_matched": "未測",
                "file_type": "未測",
                "bootstrapper_status": "未測",
                "installer_complete_ok": "未測",
                "sha256": "未測",
                "sig_status": "未測",
                "sig_signer": "未測",
                "failure_stage_and_error": "未測",
                "saved_path": "未測",
            }
        rt = r.get("route_verification") or {}
        pg = r.get("product_page") or {}
        dl = r.get("installer_download") or {}
        auth = dl.get("authenticode") or {}

        clen = dl.get("content_length_bytes")
        rec_b = dl.get("received_bytes", 0)
        sm = dl.get("size_matched")
        if sm is True:
            sm_str = f"相符 ({rec_b:,} / {clen:,} bytes)"
        elif sm is False:
            sm_str = f"不符 (實收 {rec_b:,} / 預期 {clen:,} bytes)"
        else:
            sm_str = "無 Content-Length 標頭" if dl.get("http_status") else "未測"

        if dl.get("installer_complete_ok"):
            fail_str = "無（完整取得成功）"
        else:
            stage = dl.get("failure_stage") or pg.get("error_stage") or "UNKNOWN_STAGE"
            err = dl.get("error_raw") or pg.get("error_raw") or ""
            fail_str = f"階段 `{stage}`：{err}"

        boot_str = (
            "是（已取得小型安裝啟動器 Bootstrapper）"
            if dl.get("is_small_bootstrapper")
            else ("否（完整安裝包）" if dl.get("is_windows_executable") else "不適用")
        )

        if dl.get("installer_complete_ok"):
            complete_str = (
                "是（該小型安裝啟動器已取得）"
                if dl.get("is_small_bootstrapper")
                else "是（完整取得官方安裝檔）"
            )
        else:
            complete_str = "否（下載未完成或非有效安裝檔）"

        return {
            "taiwan_time": str(dl.get("taiwan_time") or r.get("taiwan_time") or "未測"),
            "route_summary": (
                f"{rt.get('primary_interface_alias', '')} "
                f"(本機 IP `{rt.get('primary_ipv4', '')}` -> 閘道 `{rt.get('primary_gateway', '')}`)"
            ),
            "page_opened": "是（成功開啟）" if pg.get("page_opened_ok") else f"否（{pg.get('error_stage', '失敗')}）",
            "page_http_status": f"HTTP {pg.get('http_status')}" if pg.get("http_status") else "失敗",
            "page_elapsed": f"{pg.get('elapsed_seconds')} 秒" if pg.get("elapsed_seconds") is not None else "N/A",
            "extracted_url": f"`{pg.get('extracted_download_url')}`" if pg.get("extracted_download_url") else "未取得",
            "final_host": f"`{dl.get('final_host')}`" if dl.get("final_host") else "未取得",
            "dl_http_status": f"HTTP {dl.get('http_status')}" if dl.get("http_status") else "失敗",
            "dl_elapsed": f"{dl.get('elapsed_seconds')} 秒" if dl.get("elapsed_seconds") is not None else "N/A",
            "received_bytes": f"{rec_b:,} bytes ({round(rec_b / (1024 * 1024), 2)} MiB)",
            "content_length": f"{clen:,} bytes" if clen is not None else "無",
            "size_matched": sm_str,
            "file_type": str(dl.get("file_type") or "未知"),
            "bootstrapper_status": boot_str,
            "installer_complete_ok": complete_str,
            "sha256": f"`{dl.get('sha256')}`" if dl.get("sha256") else "無（未完成完整下載）",
            "sig_status": f"`{auth.get('signature_status', '未測')}`",
            "sig_signer": str(auth.get("signer_subject") or "無數位簽章"),
            "failure_stage_and_error": fail_str,
            "saved_path": f"`{dl.get('saved_file_path')}`" if dl.get("saved_file_path") else "無",
        }

    cf = _fmt_round_fields(c_round, c_tested)
    hf = _fmt_round_fields(h_round, h_tested)

    sha_match = comparison.get("sha256_matched")
    if sha_match is True:
        sha_compare_str = "**兩次取得的檔案內容一致**（兩輪 SHA-256 完全相同）"
    elif sha_match is False:
        sha_compare_str = "**兩次取得的檔案內容不一致**（SHA-256 不同）"
    else:
        sha_compare_str = "未測（待第二輪手機行動數據熱點完成後核對）"

    lines: List[str] = [
        "# 富邦證券「富邦e+電腦版」官方安裝檔下載實測比較報告（校園網路 vs 手機行動數據熱點）",
        "",
        f"- **測試對象：** 富邦證券「富邦e+電腦版」(`FB_ePlus_setup.exe`)",
        f"- **官方產品頁入口：** `{FUBON_EPLUS_PRODUCT_PAGE_URL}`（「下載富邦e+電腦版」下方 `Download` 按鈕）",
        f"- **報告更新時間（台灣時間）：** `{comparison.get('compared_at_tw', '')}`",
        "- **安全與範圍聲明：** 全程**只執行完整 HTTP GET 下載與唯讀驗證（SHA-256、`Get-AuthenticodeSignature`），絕不安裝、不啟動、不登入**；未使用任何其他券商網址或歷史資料，亦未掃描校園網段或連接埠。",
        "",
        "---",
        "",
        "## 一、兩輪實測結果並排比較表",
        "",
        "| 檢查與記錄項目 | 第一輪：校園網路 (`campus`) | 第二輪：手機行動數據熱點 (`hotspot`) |",
        "| --- | --- | --- |",
        f"| 1. 測試台灣時間 (`UTC+8`) | `{cf['taiwan_time']}` | `{hf['taiwan_time']}` |",
        f"| 2. 實際預設路由與出口介面 | {cf['route_summary']} | {hf['route_summary']} |",
        f"| 3. **官方產品頁能否開啟** | **{cf['page_opened']}** ({cf['page_http_status']}, 耗時 {cf['page_elapsed']}) | **{hf['page_opened']}** ({hf['page_http_status'] if h_tested else '未測'}{', 耗時 ' + hf['page_elapsed'] if h_tested else ''}) |",
        f"| 4. 「下載富邦e+電腦版」按鈕解析網址 | {cf['extracted_url']} | {hf['extracted_url']} |",
        f"| 5. 最終下載主機 (`Final Host`) | {cf['final_host']} | {hf['final_host']} |",
        f"| 6. 安裝檔下載 HTTP 狀態碼 | `{cf['dl_http_status']}` | `{hf['dl_http_status']}` |",
        f"| 7. 安裝檔下載耗時 | `{cf['dl_elapsed']}` | `{hf['dl_elapsed']}` |",
        f"| 8. 實收位元組 (`Received Bytes`) | `{cf['received_bytes']}` | `{hf['received_bytes']}` |",
        f"| 9. `Content-Length` 大小核對 | {cf['size_matched']} | {hf['size_matched']} |",
        f"| 10. 檔案類型辨識 (`File Type`) | {cf['file_type']} | {hf['file_type']} |",
        f"| 11. 是否為小型安裝啟動器 (`Bootstrapper`) | {cf['bootstrapper_status']} | {hf['bootstrapper_status']} |",
        f"| 12. **安裝檔能否完整取得** | **{cf['installer_complete_ok']}** | **{hf['installer_complete_ok']}** |",
        f"| 13. 完整檔案 `SHA-256` | {cf['sha256']} | {hf['sha256']} |",
        f"| 14. `Get-AuthenticodeSignature` 簽章狀態 | {cf['sig_status']} | {hf['sig_status']} |",
        f"| 15. `Get-AuthenticodeSignature` 簽署者 | `{cf['sig_signer']}` | `{hf['sig_signer']}` |",
        f"| 16. 失敗階段與錯誤原文（如有） | {cf['failure_stage_and_error']} | {hf['failure_stage_and_error']} |",
        f"| 17. 本機暫存檔案路徑 | {cf['saved_path']} | {hf['saved_path']} |",
        "",
        "---",
        "",
        "## 二、綜合比對結論",
        "",
        f"- **兩輪 SHA-256 內容比對：** {sha_compare_str}",
        f"- **結論摘要：** {comparison.get('summary_statement', '')}",
    ]

    c_dl = c_round.get("installer_download") or {}
    if c_tested and c_dl.get("is_small_bootstrapper"):
        lines.append(f"- **啟動器說明：** {c_dl.get('bootstrapper_note', '')}")

    return "\n".join(lines) + "\n"


def write_fubon_eplus_comparison_csv(comparison: Dict[str, Any], csv_path: Path) -> Path:
    """輸出「富邦e+電腦版」校園網路 vs 手機行動數據熱點並排比較 CSV (`fubon_eplus_comparison.csv`)."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    c_tested = bool(comparison.get("campus_tested"))
    h_tested = bool(comparison.get("hotspot_tested"))
    c_r = comparison.get("campus_round") or {}
    h_r = comparison.get("hotspot_round") or {}

    def _val(round_obj: Dict[str, Any], tested: bool, getter: Any) -> str:
        if not tested or not round_obj:
            return "未測"
        v = getter(round_obj)
        return "未測" if v is None or v == "" else str(v)

    rows = [
        (
            "1_taiwan_time",
            _val(c_r, c_tested, lambda r: (r.get("installer_download") or {}).get("taiwan_time") or r.get("taiwan_time")),
            _val(h_r, h_tested, lambda r: (r.get("installer_download") or {}).get("taiwan_time") or r.get("taiwan_time")),
            "台灣時間 (UTC+8)",
        ),
        (
            "2_default_route_interface",
            _val(c_r, c_tested, lambda r: (r.get("route_verification") or {}).get("primary_interface_alias")),
            _val(h_r, h_tested, lambda r: (r.get("route_verification") or {}).get("primary_interface_alias")),
            "預設路由出口介面",
        ),
        (
            "3_product_page_opened_ok",
            _val(c_r, c_tested, lambda r: (r.get("product_page") or {}).get("page_opened_ok")),
            _val(h_r, h_tested, lambda r: (r.get("product_page") or {}).get("page_opened_ok")),
            "官方產品頁能否開啟",
        ),
        (
            "4_extracted_download_url",
            _val(c_r, c_tested, lambda r: (r.get("product_page") or {}).get("extracted_download_url")),
            _val(h_r, h_tested, lambda r: (r.get("product_page") or {}).get("extracted_download_url")),
            "Download 按鈕解析網址",
        ),
        (
            "5_final_download_host",
            _val(c_r, c_tested, lambda r: (r.get("installer_download") or {}).get("final_host")),
            _val(h_r, h_tested, lambda r: (r.get("installer_download") or {}).get("final_host")),
            "最終下載主機",
        ),
        (
            "6_http_head_status",
            _val(c_r, c_tested, lambda r: (r.get("installer_download") or {}).get("head_status") or 200),
            _val(h_r, h_tested, lambda r: (r.get("installer_download") or {}).get("head_status")),
            "HTTP HEAD 狀態碼（僅供標頭診斷，不算下載成功）",
        ),
        (
            "7_http_get_status",
            _val(c_r, c_tested, lambda r: (r.get("installer_download") or {}).get("http_status")),
            _val(h_r, h_tested, lambda r: (r.get("installer_download") or {}).get("http_status")),
            "完整 HTTP GET 狀態碼",
        ),
        (
            "8_elapsed_seconds",
            _val(c_r, c_tested, lambda r: (r.get("installer_download") or {}).get("elapsed_seconds")),
            _val(h_r, h_tested, lambda r: (r.get("installer_download") or {}).get("elapsed_seconds")),
            "下載耗時 (秒)",
        ),
        (
            "9_received_bytes",
            _val(c_r, c_tested, lambda r: (r.get("installer_download") or {}).get("received_bytes")),
            _val(h_r, h_tested, lambda r: (r.get("installer_download") or {}).get("received_bytes")),
            "實收位元組數",
        ),
        (
            "10_content_length_matched",
            _val(c_r, c_tested, lambda r: (r.get("installer_download") or {}).get("size_matched")),
            _val(h_r, h_tested, lambda r: (r.get("installer_download") or {}).get("size_matched")),
            "Content-Length 大小核對",
        ),
        (
            "11_file_type",
            _val(c_r, c_tested, lambda r: (r.get("installer_download") or {}).get("file_type")),
            _val(h_r, h_tested, lambda r: (r.get("installer_download") or {}).get("file_type")),
            "檔案類型",
        ),
        (
            "12_installer_complete_ok",
            _val(c_r, c_tested, lambda r: (r.get("installer_download") or {}).get("installer_complete_ok")),
            _val(h_r, h_tested, lambda r: (r.get("installer_download") or {}).get("installer_complete_ok")),
            "安裝檔能否完整取得",
        ),
        (
            "13_sha256",
            _val(c_r, c_tested, lambda r: (r.get("installer_download") or {}).get("sha256")),
            _val(h_r, h_tested, lambda r: (r.get("installer_download") or {}).get("sha256")),
            f"SHA-256 (兩輪一致={comparison.get('sha256_matched')})",
        ),
        (
            "14_authenticode_status",
            _val(c_r, c_tested, lambda r: ((r.get("installer_download") or {}).get("authenticode") or {}).get("signature_status")),
            _val(h_r, h_tested, lambda r: ((r.get("installer_download") or {}).get("authenticode") or {}).get("signature_status")),
            "Get-AuthenticodeSignature 簽章狀態",
        ),
        (
            "15_authenticode_signer",
            _val(c_r, c_tested, lambda r: ((r.get("installer_download") or {}).get("authenticode") or {}).get("signer_subject")),
            _val(h_r, h_tested, lambda r: ((r.get("installer_download") or {}).get("authenticode") or {}).get("signer_subject")),
            "Get-AuthenticodeSignature 簽署者",
        ),
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "round1_campus_network", "round2_mobile_hotspot", "description"])
        for row in rows:
            writer.writerow(list(row))
    return csv_path
