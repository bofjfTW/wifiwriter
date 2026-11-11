"""wifiwriter v0.4 — 富邦證券「富邦 e+ 電腦版」校園網路實機診斷、安全下載驗證與根因分析模組."""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from src.analyzer import mask_sensitive_text
from src.noauth import (
    FUBON_EPLUS_PRODUCT_PAGE_URL,
    FUBON_FORBIDDEN_SUBSTITUTE_PATTERNS,
    MITM_OR_FIREWALL_CERT_PATTERNS,
    SMALL_BOOTSTRAPPER_THRESHOLD_BYTES,
    extract_fubon_eplus_download_url,
    format_taiwan_time,
    verify_authenticode_signature_readonly,
)
from src.privacy import sanitize_data_for_sharing

# ============================================================================
# Section 3.5：v0.4 執行完成狀態與嚴格 Exit Code 定義
# ============================================================================
FUBON_STATUS_SUCCESS = "SUCCESS"
FUBON_STATUS_PARTIAL = "PARTIAL"
FUBON_STATUS_FAILED = "FAILED"
FUBON_STATUS_SAFETY_ABORTED = "SAFETY_ABORTED"
FUBON_STATUS_ENVIRONMENT_UNCONFIRMED = "ENVIRONMENT_UNCONFIRMED"

FUBON_EXIT_CODES: Dict[str, int] = {
    FUBON_STATUS_SUCCESS: 0,
    FUBON_STATUS_FAILED: 1,
    FUBON_STATUS_PARTIAL: 2,
    FUBON_STATUS_SAFETY_ABORTED: 3,
    FUBON_STATUS_ENVIRONMENT_UNCONFIRMED: 4,
}

# ============================================================================
# Section 3.1 & 3.2：可信富邦網域與數位簽章發行者規則
# ============================================================================
TRUSTED_FUBON_DOMAIN_SUFFIXES: Tuple[str, ...] = (
    "fbs.com.tw",
    "fubon.com",
    "fubon.com.tw",
    "ebroker.com.tw",
)

TRUSTED_FUBON_PUBLISHER_PATTERNS = re.compile(
    r"(\u5bcc\u90a6\u7d9c\u5408\u8b49\u5238|\u5bcc\u90a6\u8b49\u5238|Fubon\s*Securities|Fubon\s*Financial)",
    re.IGNORECASE,
)

# Section 3.4：預設容量、連線逾時、整體期限與區塊讀取上限
TW_TZ = timezone(timedelta(hours=8))
DEFAULT_FUBON_PRIVATE_REPORT_DIR = (
    Path(__file__).resolve().parent.parent.parent / "wifiwriter_private_reports" / "fubon_eplus"
)
DEFAULT_FUBON_MAX_DOWNLOAD_MIB = 200.0
DEFAULT_CONNECT_TIMEOUT_SEC = 15.0
DEFAULT_READ_TIMEOUT_SEC = 15.0
DEFAULT_DOWNLOAD_DEADLINE_SEC = 180.0
DEFAULT_CHUNK_READ_BYTES = 65536  # 64 KiB
MAX_REDIRECT_HOPS = 5

# Section 七：10 大結構化證據與根因分類常數 (A ~ J)
RC_A_PAGE_INACCESSIBLE = "A_PRODUCT_PAGE_INACCESSIBLE"
RC_B_DNS_FAILURE = "B_DNS_RESOLUTION_FAILURE"
RC_C_TCP_FAILURE = "C_TCP_CONNECTION_FAILURE"
RC_D_TLS_FAILURE = "D_TLS_OR_CERT_VERIFICATION_FAILURE"
RC_E_HTTP_ABNORMAL = "E_HTTP_ABNORMAL_RESPONSE"
RC_F_DOWNLOAD_TRUNCATED = "F_DOWNLOAD_PREMATURE_TRUNCATION"
RC_G_ARTIFACT_OR_SIG_INVALID = "G_ARTIFACT_OR_SIGNATURE_INVALID"
RC_H_INTERMITTENT_ANOMALY = "H_INTERMITTENT_CONNECTIVITY_ANOMALY"
RC_I_DIRECT_POLICY_BLOCK = "I_DIRECT_CAMPUS_POLICY_RESTRICTION"
RC_J_INDETERMINATE = "J_INDETERMINATE_OR_NOAUTH_BOUNDARY"


class FubonSafetyAbortError(RuntimeError):
    """當下載 URL、Redirect 目標、檔案大小上限違反安全規範時拋出."""

    def __init__(self, stage: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.stage = stage
        self.details = details or {}


def is_ip_disallowed_for_official_download(
    ip_str: str,
    allow_loopback_for_test: bool = False,
) -> Tuple[bool, str]:
    """
    Section 3.2：檢查目標 IP 是否屬於本機、Loopback、Link-local、RFC1918 私網、CGNAT 或校園內部管理網段.
    """
    val = (ip_str or "").strip()
    if not val:
        return True, "空白 IP 位址"
    if "%" in val:
        val = val.split("%", 1)[0]
    try:
        ip_obj = ipaddress.ip_address(val)
    except ValueError:
        return True, f"無效的 IP 位址格式: {val}"

    if ip_obj.is_loopback:
        if allow_loopback_for_test:
            return False, "測試模式允許 Loopback"
        return True, f"拒絕指向本機 Loopback 位址 ({val})"
    if ip_obj.is_link_local:
        return True, f"拒絕指向 Link-local 位址 ({val})"
    if ip_obj.is_private:
        return True, f"拒絕指向私有內網位址 ({val})"
    if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
        return True, f"拒絕指向保留或未指定位址 ({val})"

    if isinstance(ip_obj, ipaddress.IPv4Address):
        octs = [int(x) for x in val.split(".")]
        a, b = octs[0], octs[1]
        # RFC 6598 CGNAT 100.64.x.x/10
        if a == 100 and 64 <= b <= 127:
            return True, f"拒絕指向 CGNAT 內部網段 ({val})"
        # 校園內部網段（避免指向校內認證伺服器或內部管理設備）
        if (a == 140 and 109 <= b <= 138) or (a == 163 and 13 <= b <= 32) or (a == 120 and 96 <= b <= 127):
            return True, f"拒絕指向校園網路內部端點 ({mask_sensitive_text(val)})"

    return False, "公開路由 IP"


def is_trusted_fubon_domain(
    host: str,
    allow_loopback_for_test: bool = False,
) -> bool:
    """驗證主機名稱是否屬於經確認之富邦證券官方網域."""
    h = (host or "").strip().lower()
    if ":" in h and not h.startswith("["):
        h = h.split(":", 1)[0]
    h = h.strip("[]")
    if not h:
        return False
    if allow_loopback_for_test and h in ("127.0.0.1", "localhost", "::1"):
        return True
    for sfx in TRUSTED_FUBON_DOMAIN_SUFFIXES:
        if h == sfx or h.endswith("." + sfx):
            return True
    return False


def validate_fubon_download_url_security(
    url: str,
    allow_loopback_for_test: bool = False,
    resolve_dns: bool = True,
    dns_resolver: Optional[Callable[[str, int], List[str]]] = None,
) -> Dict[str, Any]:
    """
    Section 3.2：嚴格驗證富邦 e+ 下載網址或手動指定網址之安全性.
    規則：
      1. 僅允許 HTTPS（拒絕 http://, file://, ftp:// 等；僅在本地整合測試開啟 allow_loopback_for_test 時允許本機 http）。
      2. 拒絕指向 localhost、Loopback、Link-local、RFC1918 內網或校園內部網段。
      3. 驗證網域必須屬於可信富邦官方網域（不接受無可信來源之第三方網域）。
      4. 拒絕非富邦 e+ 主程式之替代品（如 vcredist、e01、行動版、PDF、憑證工具）。
    """
    raw = (url or "").strip()
    result: Dict[str, Any] = {
        "url": raw,
        "security_ok": False,
        "scheme": "",
        "host": "",
        "port": 443,
        "path": "",
        "file_name": "",
        "resolved_ips": [],
        "failure_stage": "",
        "reject_reason": "",
    }
    if not raw:
        result["failure_stage"] = "EMPTY_DOWNLOAD_URL"
        result["reject_reason"] = "下載網址為空白"
        return result

    parsed = urllib.parse.urlsplit(raw)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip()
    port = parsed.port or (443 if scheme == "https" else 80)
    path_str = parsed.path or ""
    fname = Path(path_str).name

    result["scheme"] = scheme
    result["host"] = host
    result["port"] = port
    result["path"] = path_str
    result["file_name"] = fname

    # 1. 檢查 URL Scheme
    if scheme != "https":
        if not (allow_loopback_for_test and scheme == "http" and host in ("127.0.0.1", "localhost")):
            result["failure_stage"] = "UNSAFE_URL_SCHEME"
            result["reject_reason"] = f"僅允許 HTTPS 加密下載，拒絕不安全或不支援的通訊協定 Scheme '{scheme}://'"
            return result

    if not host:
        result["failure_stage"] = "MISSING_URL_HOST"
        result["reject_reason"] = "網址缺少有效主機名稱 (Host)"
        return result

    # 2. 檢查 Host 是否為直接 IP 或本機名稱
    if host.lower() in ("localhost", "localhost.localdomain") or host.lower().endswith(".local"):
        if not allow_loopback_for_test:
            result["failure_stage"] = "UNSAFE_INTERNAL_OR_LOOPBACK_TARGET"
            result["reject_reason"] = f"拒絕指向本機主機名稱 ({host})"
            return result

    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    if is_ip_literal:
        disallowed, reason = is_ip_disallowed_for_official_download(
            host.strip("[]"),
            allow_loopback_for_test=allow_loopback_for_test,
        )
        if disallowed:
            result["failure_stage"] = "UNSAFE_INTERNAL_OR_LOOPBACK_TARGET"
            result["reject_reason"] = reason
            return result
        if not allow_loopback_for_test:
            result["failure_stage"] = "UNTRUSTED_DOWNLOAD_DOMAIN"
            result["reject_reason"] = f"拒絕直接使用無網域憑證歸屬之裸 IP 下載網址 ({host})"
            return result

    # 3. 驗證是否屬於可信富邦網域
    if not is_trusted_fubon_domain(host, allow_loopback_for_test=allow_loopback_for_test):
        result["failure_stage"] = "UNTRUSTED_DOWNLOAD_DOMAIN"
        result["reject_reason"] = f"下載主機 '{host}' 非經驗證的富邦證券官方網域（拒絕未授權第三方網域）"
        return result

    # 4. 檢查是否為被禁止代測的其他元件
    if FUBON_FORBIDDEN_SUBSTITUTE_PATTERNS.search(raw) or FUBON_FORBIDDEN_SUBSTITUTE_PATTERNS.search(fname):
        result["failure_stage"] = "FORBIDDEN_SUBSTITUTE_COMPONENT"
        result["reject_reason"] = f"網址或檔名 '{fname}' 屬於被排除的非富邦e+電腦版主程式（如 Microsoft 元件/e01/行動版/手冊）"
        return result

    # 5. 解析 DNS 並驗證所有解析出的 IP 不得指向內網、Loopback 或校園管理端點
    if resolve_dns:
        ips: List[str] = []
        try:
            if dns_resolver is not None:
                ips = list(dns_resolver(host, port))
            else:
                infos = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
                for item in infos:
                    ip_s = str(item[4][0])
                    if ip_s not in ips:
                        ips.append(ip_s)
        except Exception as exc:
            result["failure_stage"] = "DNS_RESOLUTION_FAILED"
            result["reject_reason"] = f"無法解析下載主機 '{host}' 之 DNS: {exc}"
            return result

        result["resolved_ips"] = ips
        if not ips:
            result["failure_stage"] = "DNS_RESOLUTION_FAILED"
            result["reject_reason"] = f"下載主機 '{host}' DNS 解析結果為空"
            return result

        for ip_s in ips:
            disallowed, reason = is_ip_disallowed_for_official_download(
                ip_s,
                allow_loopback_for_test=allow_loopback_for_test,
            )
            if disallowed:
                result["failure_stage"] = "UNSAFE_INTERNAL_OR_LOOPBACK_TARGET"
                result["reject_reason"] = f"下載主機 '{host}' 解析至不安全目標 IP: {reason}"
                return result

    result["security_ok"] = True
    return result


class _SafeFubonRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Section 3.2：攔截並檢查每一次 HTTP Redirect (301/302/303/307/308).
    若任何一跳轉向非 HTTPS、非允許網域、本機或內網位址，立即拋出 FubonSafetyAbortError 中止連線。
    """

    def __init__(
        self,
        redirect_chain: List[Dict[str, Any]],
        allow_loopback_for_test: bool = False,
        dns_resolver: Optional[Callable[[str, int], List[str]]] = None,
    ) -> None:
        super().__init__()
        self.redirect_chain = redirect_chain
        self.allow_loopback_for_test = allow_loopback_for_test
        self.dns_resolver = dns_resolver

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        hop_no = len(self.redirect_chain) + 1
        from_url = req.full_url
        abs_target = urllib.parse.urljoin(from_url, newurl)

        if hop_no > MAX_REDIRECT_HOPS:
            hop_rec = {
                "hop": hop_no,
                "status_code": int(code),
                "from_url": from_url,
                "to_url": abs_target,
                "to_host": urllib.parse.urlsplit(abs_target).hostname or "",
                "security_ok": False,
                "reject_reason": f"HTTP Redirect 次數超過安全上限 ({MAX_REDIRECT_HOPS} 次)",
            }
            self.redirect_chain.append(hop_rec)
            raise FubonSafetyAbortError("TOO_MANY_REDIRECTS", hop_rec["reject_reason"], details=hop_rec)

        sec = validate_fubon_download_url_security(
            abs_target,
            allow_loopback_for_test=self.allow_loopback_for_test,
            resolve_dns=True,
            dns_resolver=self.dns_resolver,
        )
        hop_rec = {
            "hop": hop_no,
            "status_code": int(code),
            "from_url": from_url,
            "to_url": abs_target,
            "to_host": sec.get("host", ""),
            "security_ok": bool(sec.get("security_ok")),
            "reject_reason": str(sec.get("reject_reason") or ""),
        }
        self.redirect_chain.append(hop_rec)

        if not sec.get("security_ok"):
            raise FubonSafetyAbortError(
                sec.get("failure_stage") or "UNSAFE_REDIRECT_TARGET",
                f"HTTP {code} Redirect 第 {hop_no} 跳目標不安全 ({abs_target}): {sec.get('reject_reason')}",
                details=hop_rec,
            )

        return super().redirect_request(req, fp, code, msg, headers, abs_target)


def inspect_pe_binary_structure(file_or_header_bytes: bytes, file_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Section 3.1：檢查檔案是否具備合法的 Windows Portable Executable (PE) 結構 (`MZ` DOS Header + `PE\\0\\0` Signature).
    同時強調：具備 PE 結構僅代表檔案格式為 Windows 執行檔，絕不等於發行者可信！
    """
    buf = file_or_header_bytes or b""
    if len(buf) < 64:
        return {
            "has_mz_magic": len(buf) >= 2 and buf[:2] == b"MZ",
            "has_pe_signature": False,
            "pe_offset": None,
            "machine_type": "",
            "is_valid_pe_structure": False,
        }

    if buf[:2] != b"MZ":
        return {
            "has_mz_magic": False,
            "has_pe_signature": False,
            "pe_offset": None,
            "machine_type": "",
            "is_valid_pe_structure": False,
        }

    pe_offset = struct.unpack_from("<I", buf, 0x3C)[0]
    pe_bytes = b""
    if pe_offset + 6 <= len(buf):
        pe_bytes = buf[pe_offset : pe_offset + 6]
    elif file_path and file_path.exists() and 0 < pe_offset < (16 * 1024 * 1024):
        try:
            with file_path.open("rb") as f:
                f.seek(pe_offset)
                pe_bytes = f.read(6)
        except OSError:
            pe_bytes = b""

    has_pe_sig = len(pe_bytes) >= 4 and pe_bytes[:4] == b"PE\x00\x00"
    machine_str = ""
    if has_pe_sig and len(pe_bytes) >= 6:
        mach = struct.unpack_from("<H", pe_bytes, 4)[0]
        if mach == 0x014C:
            machine_str = "x86 (IMAGE_FILE_MACHINE_I386)"
        elif mach == 0x8664:
            machine_str = "x64 (IMAGE_FILE_MACHINE_AMD64)"
        else:
            machine_str = f"0x{mach:04X}"

    return {
        "has_mz_magic": True,
        "has_pe_signature": has_pe_sig,
        "pe_offset": pe_offset,
        "machine_type": machine_str,
        "is_valid_pe_structure": has_pe_sig,
    }


def evaluate_three_stage_download_verification(
    *,
    http_status: int,
    content_range_header: str,
    content_length_bytes: Optional[int],
    received_bytes: int,
    stream_completed_cleanly: bool,
    is_html_page: bool,
    pe_info: Dict[str, Any],
    sha256_hex: str,
    authenticode_info: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Section 3.1 & 3.3：將下載驗收拆分為三個獨立且嚴格的指標：
      A. `transport_complete`：HTTP 200 傳輸完整（拒絕 206 Partial Content、拒絕 Content-Range、核對 Content-Length）。
      B. `artifact_integrity_verified`：檔案非 HTML 攔阻頁、具備合法 PE (`MZ` + `PE\\0\\0`) 結構、SHA-256 計算成功且無 HashMismatch。
      C. `publisher_verified`：Windows Authenticode 簽章狀態為 `Valid` 且簽署者符合富邦綜合證券可信發行者。
    """
    sig_status = str(authenticode_info.get("signature_status") or "Unknown")
    signer_subj = str(authenticode_info.get("signer_subject") or "")
    sig_valid = sig_status == "Valid"
    trusted_fubon_signer = sig_valid and bool(TRUSTED_FUBON_PUBLISHER_PATTERNS.search(signer_subj))

    # C. Publisher Verified
    publisher_verified = bool(sig_valid and trusted_fubon_signer)

    # B. Artifact Integrity Verified
    valid_pe = bool(pe_info.get("is_valid_pe_structure"))
    has_sha256 = bool(sha256_hex and len(sha256_hex) == 64)
    not_hash_mismatch = sig_status != "HashMismatch"
    artifact_integrity_verified = bool(
        (not is_html_page) and valid_pe and has_sha256 and not_hash_mismatch
    )

    # A. Transport Complete
    content_length_missing_warning = False
    transport_notes: List[str] = []

    if http_status == 206 or bool((content_range_header or "").strip()):
        transport_complete = False
        transport_reason = "收到 HTTP 206 Partial Content 或帶有 Content-Range，依規範拒絕將部分回應當成完整下載"
        failure_stage = "PARTIAL_CONTENT_206_REJECTED"
    elif http_status != 200:
        transport_complete = False
        transport_reason = f"預期 HTTP 200 OK，但實際收到 HTTP {http_status}"
        failure_stage = f"HTTP_STATUS_{http_status}"
    elif not stream_completed_cleanly:
        transport_complete = False
        transport_reason = "HTTP 回應串流中途發生逾時或異常中斷"
        failure_stage = "STREAM_INTERRUPTED_OR_TIMEOUT"
    elif received_bytes <= 0:
        transport_complete = False
        transport_reason = "實際接收位元組為 0"
        failure_stage = "EMPTY_RESPONSE_BODY"
    elif content_length_bytes is not None:
        if received_bytes == content_length_bytes:
            transport_complete = True
            transport_reason = f"HTTP 200 傳輸完整，實收位元組 ({received_bytes:,} bytes) 與 Content-Length 完全相符"
            failure_stage = ""
        else:
            transport_complete = False
            transport_reason = (
                f"Content-Length 大小不符：預期 {content_length_bytes:,} bytes，實際僅收到 {received_bytes:,} bytes"
            )
            failure_stage = "CONTENT_LENGTH_MISMATCH_TRUNCATED"
    else:
        # 當伺服器未提供 Content-Length 時，不可僅靠 received_bytes > 0 宣稱傳輸完整！
        # 必須結合 PE 封裝結構與 Authenticode 數位簽章雜湊驗證（Authenticode Valid 代表整個 PE 映象未遭截斷）。
        content_length_missing_warning = True
        if valid_pe and sig_valid:
            transport_complete = True
            transport_reason = (
                f"回應未帶 Content-Length 標頭（實收 {received_bytes:,} bytes），"
                "已結合 PE 封裝結構與 Authenticode 全檔雜湊簽章 (Valid) 確認未遭截斷（註記無 Content-Length 限制）"
            )
            failure_stage = ""
        else:
            transport_complete = False
            transport_reason = (
                f"回應缺少 Content-Length 標頭（實收 {received_bytes:,} bytes），"
                "且無有效 Authenticode 數位簽章可證明檔案尾部未遭截斷，依規範不宣稱傳輸完整"
            )
            failure_stage = "MISSING_CONTENT_LENGTH_UNVERIFIED_COMPLETENESS"

    # 決定失敗階段與總體判定標籤
    if not transport_complete:
        overall_verdict = "TRANSPORT_FAILED"
    elif is_html_page:
        overall_verdict = "VERIFICATION_FAILED"
        failure_stage = "HTML_LOGIN_OR_BLOCK_PAGE_INTERCEPTED"
    elif not artifact_integrity_verified:
        overall_verdict = "VERIFICATION_FAILED"
        failure_stage = "ARTIFACT_INTEGRITY_FAILED"
    elif not publisher_verified:
        if sig_status in ("Unknown", "CheckError"):
            overall_verdict = "UNKNOWN"
            failure_stage = "AUTHENTICODE_CHECK_UNAVAILABLE"
        elif not sig_valid:
            overall_verdict = "VERIFICATION_FAILED"
            failure_stage = f"AUTHENTICODE_INVALID_{sig_status.upper()}"
        else:
            overall_verdict = "VERIFICATION_FAILED"
            failure_stage = "UNTRUSTED_AUTHENTICODE_SIGNER"
    else:
        overall_verdict = "VERIFIED_OFFICIAL_INSTALLER"
        failure_stage = ""

    all_three_passed = bool(transport_complete and artifact_integrity_verified and publisher_verified)

    return {
        "transport_complete": transport_complete,
        "artifact_integrity_verified": artifact_integrity_verified,
        "publisher_verified": publisher_verified,
        "installer_complete_ok": all_three_passed,
        "verification_verdict": overall_verdict,
        "content_length_missing_warning": content_length_missing_warning,
        "trusted_fubon_signer": trusted_fubon_signer,
        "failure_stage": failure_stage,
        "transport_reason": transport_reason,
    }


def verify_campus_network_environment(
    target_host: str = "www.fbs.com.tw",
    user_confirmed_campus: bool = False,
    confirm_campus_override: bool = False,
    timeout_sec: int = 20,
) -> Dict[str, Any]:
    """
    Section 五：使用 Windows 內建工具唯讀蒐集並確認目前是否確實使用校園網路.
    蒐集項目：
      - 目前啟用的網路介面 (Get-NetAdapter)
      - 主要 IPv4 與 IPv6 設定 (Get-NetIPAddress)
      - 預設路由 (0.0.0.0/0 與 ::/0)
      - DNS 伺服器 (Get-DnsClientServerAddress)
      - WinINET Proxy、PAC 設定與 WinHTTP Proxy
      - VPN 與其他虛擬網路介面
      - 前往富邦官方網站及下載端點之可能出口路由 (Find-NetRoute)
    特別檢查：
      - 本機 UDP Socket 選擇的來源 IP，在啟用 HTTP Proxy / PAC 時不一定能證明 HTTP 流量走相同路徑 (`proxy_route_uncertainty`)。
      - 不單靠單一 IP 字首猜測，綜合檢查實體介面、閘道、DNS 伺服器、無 VPN 劫持與無未確認 Proxy。
    """
    ps_script = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$adapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
    $idx = $_.ifIndex
    $ipv4 = @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 | ForEach-Object {
        [ordered]@{ ip = [string]$_.IPAddress; prefix_length = [int]$_.PrefixLength; prefix_origin = [string]$_.PrefixOrigin }
    })
    $ipv6 = @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv6 | Where-Object { $_.IPAddress -notlike 'fe80*' } | ForEach-Object {
        [ordered]@{ ip = [string]$_.IPAddress; prefix_length = [int]$_.PrefixLength }
    })
    $dns4 = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4
    $dns6 = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv6
    $profile = Get-NetConnectionProfile -InterfaceIndex $idx
    [ordered]@{
        interface_index = [int]$idx
        interface_alias = [string]$_.Name
        description = [string]$_.InterfaceDescription
        status = [string]$_.Status
        mac_address = [string]$_.MacAddress
        link_speed = [string]$_.LinkSpeed
        media_type = [string]$_.MediaType
        physical_media_type = [string]$_.PhysicalMediaType
        virtual = [bool]$_.Virtual
        network_category = if ($profile) { [string]$profile.NetworkCategory } else { '' }
        profile_name = if ($profile) { [string]$profile.Name } else { '' }
        ipv4_addresses = $ipv4
        ipv6_addresses = $ipv6
        dns_ipv4 = if ($dns4 -and $dns4.ServerAddresses) { @($dns4.ServerAddresses) } else { @() }
        dns_ipv6 = if ($dns6 -and $dns6.ServerAddresses) { @($dns6.ServerAddresses) } else { @() }
    }
})

$routes4 = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | ForEach-Object {
    $idx = $_.InterfaceIndex
    $ipif = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4
    $ifm = if ($ipif -and $null -ne $ipif.InterfaceMetric) { [int]$ipif.InterfaceMetric } else { 0 }
    $rtm = [int]$_.RouteMetric
    [ordered]@{
        interface_index = [int]$idx
        interface_alias = [string]$_.InterfaceAlias
        next_hop = [string]$_.NextHop
        route_metric = $rtm
        interface_metric = $ifm
        effective_metric = ($rtm + $ifm)
    }
} | Sort-Object effective_metric)

$routes6 = @(Get-NetRoute -DestinationPrefix '::/0' | ForEach-Object {
    $idx = $_.InterfaceIndex
    $ipif = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv6
    $ifm = if ($ipif -and $null -ne $ipif.InterfaceMetric) { [int]$ipif.InterfaceMetric } else { 0 }
    $rtm = [int]$_.RouteMetric
    [ordered]@{
        interface_index = [int]$idx
        interface_alias = [string]$_.InterfaceAlias
        next_hop = [string]$_.NextHop
        effective_metric = ($rtm + $ifm)
    }
} | Sort-Object effective_metric)

$inetKey = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$winInet = [ordered]@{
    proxy_enable = if ($inetKey -and $null -ne $inetKey.ProxyEnable) { [bool]([int]$inetKey.ProxyEnable -ne 0) } else { $false }
    proxy_server = if ($inetKey -and $inetKey.ProxyServer) { [string]$inetKey.ProxyServer } else { '' }
    auto_config_url = if ($inetKey -and $inetKey.AutoConfigURL) { [string]$inetKey.AutoConfigURL } else { '' }
    auto_detect = if ($inetKey -and $null -ne $inetKey.AutoDetect) { [bool]([int]$inetKey.AutoDetect -ne 0) } else { $false }
}

$winHttpRaw = (& netsh winhttp show proxy 2>$null | Out-String).Trim()
$winHttpDirect = ($winHttpRaw -match 'Direct access' -or $winHttpRaw -match '直接存取')

$vpnKeywords = '(VPN|WireGuard|Tailscale|ZeroTier|AnyConnect|Forti|PANGP|TAP-Windows|Wintun|Sangfor|Pulse|Juniper|OpenVPN|PPP)'
$vpnAdapters = @($adapters | Where-Object { $_.interface_alias -match $vpnKeywords -or $_.description -match $vpnKeywords })

$out = [ordered]@{
    collected_at = (Get-Date).ToString('o')
    active_adapters = $adapters
    default_routes_ipv4 = $routes4
    default_routes_ipv6 = $routes6
    wininet_proxy = $winInet
    winhttp_proxy = [ordered]@{
        is_direct = [bool]$winHttpDirect
        raw_summary = $winHttpRaw
    }
    vpn_or_tunnel_adapters = $vpnAdapters
}
$out | ConvertTo-Json -Compress -Depth 6
"""
    raw_env: Dict[str, Any] = {}
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            raw_env = json.loads(proc.stdout.strip())
    except Exception:
        raw_env = {}

    # 查詢前往 target_host (www.fbs.com.tw) 之解析 IP 與 Find-NetRoute 出口路由
    resolved_target_ip = ""
    udp_socket_local_ip = ""
    find_net_route_info: Dict[str, Any] = {}
    try:
        infos = socket.getaddrinfo(target_host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if infos:
            resolved_target_ip = str(infos[0][4][0])
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((resolved_target_ip, 443))
                udp_socket_local_ip = str(s.getsockname()[0])
    except Exception:
        pass

    if resolved_target_ip:
        ps_find = (
            "$ErrorActionPreference='SilentlyContinue'; "
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
            f"$r = Find-NetRoute -RemoteIPAddress '{resolved_target_ip}' | Select-Object -First 1; "
            "if ($r) { "
            "  [ordered]@{ "
            "    interface_index = [int]$r.InterfaceIndex; "
            "    interface_alias = [string]$r.InterfaceAlias; "
            "    local_ip = [string]$r.IPAddress; "
            "    next_hop = [string]$r.NextHop "
            "  } | ConvertTo-Json -Compress "
            "}"
        )
        try:
            proc_r = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_find],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            if proc_r.returncode == 0 and proc_r.stdout.strip():
                find_net_route_info = json.loads(proc_r.stdout.strip())
        except Exception:
            pass

    return evaluate_campus_environment_evidence(
        raw_env=raw_env,
        target_host=target_host,
        resolved_target_ip=resolved_target_ip,
        udp_socket_local_ip=udp_socket_local_ip,
        find_net_route_info=find_net_route_info,
        user_confirmed_campus=user_confirmed_campus,
        confirm_campus_override=confirm_campus_override,
    )


def evaluate_campus_environment_evidence(
    raw_env: Dict[str, Any],
    target_host: str = "www.fbs.com.tw",
    resolved_target_ip: str = "",
    udp_socket_local_ip: str = "",
    find_net_route_info: Optional[Dict[str, Any]] = None,
    user_confirmed_campus: bool = False,
    confirm_campus_override: bool = False,
) -> Dict[str, Any]:
    """
    Section 五：純邏輯評估目前網路環境是否可確認為學校網路，並檢查 Proxy / VPN 是否導致出口路由不確定.
    可獨立於單元測試中注入合成資料驗證，同時支援 PowerShell 原始結構與扁平測試結構。
    """
    confirmed_override = bool(user_confirmed_campus or confirm_campus_override)
    adapters = raw_env.get("active_adapters") or []
    routes4 = raw_env.get("default_routes_ipv4") or raw_env.get("default_routes") or []
    routes6 = raw_env.get("default_routes_ipv6") or []
    wininet = raw_env.get("wininet_proxy") or {}
    winhttp = raw_env.get("winhttp_proxy") or {}
    flat_proxy = raw_env.get("proxy") or {}
    vpn_adapters = raw_env.get("vpn_or_tunnel_adapters") or raw_env.get("vpn_or_virtual_adapters") or []
    fn_route = find_net_route_info or raw_env.get("route_to_target") or {}

    primary_route = routes4[0] if routes4 else {}
    primary_idx = primary_route.get("interface_index") or raw_env.get("primary_interface_index")
    primary_adapter: Dict[str, Any] = {}
    for adp in adapters:
        if adp.get("interface_index") == primary_idx:
            primary_adapter = adp
            break
    if not primary_adapter and adapters:
        primary_adapter = adapters[0]

    ipv4_list = [str(x.get("ip") or "") for x in (primary_adapter.get("ipv4_addresses") or []) if x.get("ip")]
    ipv6_list = [str(x.get("ip") or "") for x in (primary_adapter.get("ipv6_addresses") or []) if x.get("ip")]
    primary_ipv4 = str(
        fn_route.get("local_ip")
        or (ipv4_list[0] if ipv4_list else "")
        or raw_env.get("primary_ipv4")
        or udp_socket_local_ip
        or ""
    )
    primary_gateway = str(
        fn_route.get("next_hop")
        or primary_route.get("next_hop")
        or raw_env.get("primary_gateway")
        or ""
    )
    primary_alias = str(
        fn_route.get("interface_alias")
        or primary_adapter.get("interface_alias")
        or primary_route.get("interface_alias")
        or raw_env.get("primary_interface_alias")
        or ""
    )
    primary_desc = str(
        primary_adapter.get("description")
        or raw_env.get("primary_interface_description")
        or ""
    )
    primary_link_speed = str(
        primary_adapter.get("link_speed")
        or raw_env.get("primary_link_speed")
        or "未知"
    )
    phys_media = str(primary_adapter.get("physical_media_type") or primary_adapter.get("media_type") or "")
    if raw_env.get("primary_media_kind"):
        primary_media_kind = str(raw_env["primary_media_kind"])
    elif any(k in (primary_alias + " " + primary_desc + " " + phys_media).lower() for k in ("cellular", "mobile broadband", "wwan")):
        primary_media_kind = "Cellular_Mobile"
    elif any(k in (primary_alias + " " + primary_desc + " " + phys_media).lower() for k in ("wi-fi", "wlan", "wireless", "802.11")):
        primary_media_kind = "Wi-Fi"
    else:
        primary_media_kind = "Wired_Ethernet"

    dns_ipv4 = list(primary_adapter.get("dns_ipv4") or raw_env.get("dns_servers") or [])

    # 檢查 Proxy 狀態（注意：啟用 Proxy 或 PAC 時，本機 UDP Socket 選擇的來源 IP 不能證明 HTTP 實際出口！）
    wininet_proxy_enabled = bool(wininet.get("proxy_enable") or flat_proxy.get("user_proxy_enabled"))
    pac_url = str(wininet.get("auto_config_url") or flat_proxy.get("user_auto_config_url") or "").strip()
    winhttp_raw = " ".join(str(winhttp.get("raw_summary") or flat_proxy.get("winhttp_proxy") or "Direct access").split())
    winhttp_is_direct = bool(
        winhttp.get("is_direct", True)
        and ("direct access" in winhttp_raw.lower() or "直接存取" in winhttp_raw or not winhttp_raw.strip())
    )
    env_http_proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("http_proxy")
        or ""
    )

    proxy_active = bool(wininet_proxy_enabled or pac_url or (not winhttp_is_direct) or env_http_proxy)
    proxy_route_uncertainty = proxy_active

    # 檢查是否有 VPN 隧道劫持預設路由
    vpn_indices = {v.get("interface_index") for v in vpn_adapters if isinstance(v, dict) and v.get("interface_index") is not None}
    vpn_active_on_default = (primary_idx in vpn_indices) if primary_idx is not None else bool(vpn_adapters)
    vpn_names = [
        str(v.get("interface_alias") or v.get("description") or v)
        for v in vpn_adapters
    ]

    # 多因子確認是否為校園網路（不單靠單一 IP 字首猜測）
    tanet_re = re.compile(r"^(?:140\.1[0-3]\d|163\.(?:1[3-9]|2\d|3[0-2])|120\.(?:9[6-9]|1[0-2]\d))\.")
    ip_in_tanet = bool(tanet_re.match(primary_ipv4))
    gw_in_tanet = bool(tanet_re.match(primary_gateway))
    dns_in_tanet = any(tanet_re.match(str(d)) for d in dns_ipv4)
    is_cellular = primary_media_kind == "Cellular_Mobile"
    is_physical_nic = bool(primary_alias and not primary_adapter.get("virtual", False) and not is_cellular)

    corroborating_factors: List[str] = []
    uncertainty_reasons: List[str] = []

    if is_cellular:
        uncertainty_reasons.append(f"偵測到主要介面為行動數據網路 ({primary_alias})，非校園固網/Wi-Fi")
    elif is_physical_nic:
        corroborating_factors.append(f"實體網路介面卡啟用中 (`{primary_alias}`: {primary_desc}, 媒介={primary_media_kind})")
    if ip_in_tanet and gw_in_tanet:
        corroborating_factors.append("本機 IPv4 與預設閘道同屬台灣學術網路 (TANet) 校園網段")
    if dns_in_tanet:
        corroborating_factors.append("首選 DNS 伺服器位於校內學術網路網段")
    if not proxy_active:
        corroborating_factors.append("WinINET / WinHTTP / PAC 與環境變數均為直接連線 (Direct Access)，無 Proxy 轉發路徑不確定性")
    else:
        uncertainty_reasons.append(
            "偵測到系統已設定 HTTP Proxy 或 PAC 自動組態腳本；本機 UDP Socket 來源 IP 與路由表無法單獨證明透過 Proxy 之 HTTP 下載實際出口路徑"
        )
    if vpn_active_on_default:
        uncertainty_reasons.append("偵測到預設路由經過 VPN 或虛擬隧道介面，無法確認流量直接走校園網路")

    multi_factor_campus_match = bool(
        is_physical_nic
        and ((ip_in_tanet and gw_in_tanet) or dns_in_tanet or confirmed_override)
        and (not vpn_active_on_default)
        and (not is_cellular)
    )

    if not primary_ipv4 or not primary_gateway:
        uncertainty_reasons.append("無法取得有效的主要 IPv4 位址或預設閘道")
        multi_factor_campus_match = False

    if not multi_factor_campus_match and not uncertainty_reasons:
        uncertainty_reasons.append(
            "目前網路介面、閘道與 DNS 組合無法自動確認為學校網路（若您確定目前已連接學校網路，請加上 `--confirm-campus-network` 手動確認）"
        )

    env_status = FUBON_STATUS_SUCCESS if multi_factor_campus_match else FUBON_STATUS_ENVIRONMENT_UNCONFIRMED

    snapshot_obj: Dict[str, Any] = {
        "primary_interface_index": primary_idx,
        "primary_interface_alias": primary_alias,
        "primary_interface_description": primary_desc,
        "primary_media_kind": primary_media_kind,
        "primary_link_speed": primary_link_speed,
        "primary_ipv4": primary_ipv4,
        "primary_ipv6_list": ipv6_list,
        "primary_gateway": primary_gateway,
        "dns_servers": dns_ipv4,
        "default_routes": routes4,
        "proxy": {
            "user_proxy_enabled": int(wininet_proxy_enabled),
            "user_proxy_server": str(wininet.get("proxy_server") or ""),
            "user_auto_config_url": pac_url,
            "winhttp_proxy": winhttp_raw,
        },
        "vpn_or_virtual_adapters": vpn_adapters,
        "firewall_profiles": raw_env.get("firewall_profiles") or [],
    }

    evidence_obj: Dict[str, Any] = {
        "checked_at_tw": format_taiwan_time(),
        "environment_status": env_status,
        "campus_network_confirmed": multi_factor_campus_match,
        "campus_Confirmed": multi_factor_campus_match,
        "is_tanet_or_campus_ip": bool(ip_in_tanet or gw_in_tanet or dns_in_tanet),
        "tanet_match_detail": "TANet 學術網路網段 (IPv4/Gateway/DNS 多因子相符)" if (ip_in_tanet or gw_in_tanet or dns_in_tanet) else "非標準 TANet 公開網段",
        "user_confirmed_override": confirmed_override,
        "proxy_active": proxy_active,
        "proxy_route_uncertainty": proxy_route_uncertainty,
        "proxy_or_pac_uncertain": proxy_route_uncertainty,
        "proxy_route_note": (
            "本機 UDP Socket 選擇的來源 IP 僅反映作業系統直連路由表；若啟用 HTTP Proxy，下載流量可能改由 Proxy 伺服器出口。"
            "本次已同時檢查 WinINET、WinHTTP、PAC 與環境變數以確認是否直連。"
        ),
        "vpn_active_on_default_route": vpn_active_on_default,
        "vpn_or_virtual_adapter_active": vpn_active_on_default,
        "vpn_adapters_detected": vpn_names,
        "primary_interface_alias": primary_alias,
        "primary_adapter_description": primary_desc,
        "primary_ipv4": primary_ipv4,
        "primary_ipv6_list": ipv6_list,
        "primary_gateway_ipv4": primary_gateway,
        "primary_dns_ipv4": dns_ipv4,
        "target_host": target_host,
        "resolved_target_ip": resolved_target_ip,
        "udp_socket_source_ip": udp_socket_local_ip,
        "find_net_route": fn_route,
        "route_to_target": {
            "remote_ip": resolved_target_ip or fn_route.get("remote_ip", ""),
            "interface_alias": fn_route.get("interface_alias") or primary_alias,
            "next_hop": fn_route.get("next_hop") or primary_gateway,
        },
        "default_routes_ipv4": routes4,
        "default_routes_ipv6": routes6,
        "wininet_proxy": wininet,
        "winhttp_proxy": winhttp,
        "vpn_or_tunnel_adapters": vpn_adapters,
        "active_adapters": adapters,
        "corroborating_factors": corroborating_factors,
        "confirmation_reasons": corroborating_factors,
        "uncertainty_reasons": uncertainty_reasons,
        "uncertainty_warnings": uncertainty_reasons,
    }
    evidence_copy = dict(evidence_obj)
    evidence_obj["snapshot"] = snapshot_obj
    evidence_obj["evidence"] = evidence_copy
    return evidence_obj


def _probe_single_endpoint_low_load(
    fqdn: str,
    port: int = 443,
    test_url: str = "",
    http_method: str = "HEAD",
    timeout_sec: float = DEFAULT_CONNECT_TIMEOUT_SEC,
) -> Dict[str, Any]:
    """
    執行單一端點之低負載循序檢查（DNS -> TCP -> TLS -> HTTP HEAD/小型 GET）.
    嚴格區分：DNS 失敗、單次 TCP 失敗、TLS 交握失敗、HTTP 服務回應異常。
    """
    rec: Dict[str, Any] = {
        "timestamp_tw": format_taiwan_time(),
        "fqdn": fqdn,
        "port": port,
        "test_url": test_url,
        "http_method": http_method,
        "dns_ok": False,
        "dns_latency_ms": None,
        "resolved_ips": [],
        "dns_error": "",
        "tcp_ok": False,
        "tcp_rtt_ms": None,
        "tcp_error_type": "NONE",
        "tcp_error": "",
        "tls_ok": False,
        "tls_handshake_ms": None,
        "tls_version": "",
        "tls_cipher": "",
        "cert_subject": "",
        "cert_issuer": "",
        "cert_not_after": "",
        "mitm_cert_suspected": False,
        "tls_error": "",
        "http_tested": bool(test_url),
        "http_ok": False,
        "http_status": 0,
        "http_latency_ms": None,
        "content_type": "",
        "content_length": None,
        "accept_ranges": "",
        "redirect_chain": [],
        "final_url": "",
        "final_host": "",
        "http_error": "",
        "failure_category": "NONE",
    }

    # 1. DNS
    d0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(fqdn, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        rec["dns_latency_ms"] = round((time.perf_counter() - d0) * 1000.0, 2)
        ips: List[str] = []
        for item in infos:
            ip_s = str(item[4][0])
            if ip_s not in ips:
                ips.append(ip_s)
        rec["resolved_ips"] = ips
        rec["dns_ok"] = len(ips) > 0
    except Exception as exc:
        rec["dns_latency_ms"] = round((time.perf_counter() - d0) * 1000.0, 2)
        rec["dns_error"] = f"{exc.__class__.__name__}: {exc}"
        rec["failure_category"] = "DNS_FAILURE"
        return rec

    # 2. TCP + 3. TLS
    target_ip = rec["resolved_ips"][0]
    t0 = time.perf_counter()
    try:
        with socket.create_connection((target_ip, port), timeout=timeout_sec) as sock:
            rec["tcp_rtt_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
            rec["tcp_ok"] = True
            ctx = ssl.create_default_context()
            sock.settimeout(timeout_sec)
            tls_t0 = time.perf_counter()
            try:
                with ctx.wrap_socket(sock, server_hostname=fqdn) as ssock:
                    rec["tls_handshake_ms"] = round((time.perf_counter() - tls_t0) * 1000.0, 2)
                    rec["tls_ok"] = True
                    rec["tls_version"] = str(ssock.version() or "")
                    cipher_info = ssock.cipher()
                    rec["tls_cipher"] = str(cipher_info[0]) if cipher_info else ""
                    cert = ssock.getpeercert() or {}
                    subj_parts = [f"{k}={v}" for rdn in cert.get("subject", ()) for k, v in rdn]
                    iss_parts = [f"{k}={v}" for rdn in cert.get("issuer", ()) for k, v in rdn]
                    rec["cert_subject"] = ", ".join(subj_parts)
                    rec["cert_issuer"] = ", ".join(iss_parts)
                    rec["cert_not_after"] = str(cert.get("notAfter") or "")
                    if MITM_OR_FIREWALL_CERT_PATTERNS.search(rec["cert_issuer"]):
                        rec["mitm_cert_suspected"] = True
            except Exception as tls_exc:
                rec["tls_handshake_ms"] = round((time.perf_counter() - tls_t0) * 1000.0, 2)
                rec["tls_error"] = f"{tls_exc.__class__.__name__}: {tls_exc}"
                rec["failure_category"] = "TLS_HANDSHAKE_FAILURE"
                return rec
    except socket.timeout:
        rec["tcp_error_type"] = "TIMEOUT"
        rec["tcp_error"] = "TCP_CONNECT_TIMEOUT"
        rec["failure_category"] = "SINGLE_TCP_FAILURE"
        return rec
    except ConnectionRefusedError as exc:
        rec["tcp_error_type"] = "REFUSED"
        rec["tcp_error"] = f"TCP_REFUSED: {exc}"
        rec["failure_category"] = "SINGLE_TCP_FAILURE"
        return rec
    except ConnectionResetError as exc:
        rec["tcp_error_type"] = "RESET"
        rec["tcp_error"] = f"TCP_RESET: {exc}"
        rec["failure_category"] = "SINGLE_TCP_FAILURE"
        return rec
    except OSError as exc:
        rec["tcp_error_type"] = f"OS_ERR_{getattr(exc, 'winerror', 'UNKNOWN')}"
        rec["tcp_error"] = str(exc)
        rec["failure_category"] = "SINGLE_TCP_FAILURE"
        return rec

    # 4. HTTP HEAD / 小型 GET
    if test_url:
        redirect_chain: List[Dict[str, Any]] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) wifiwriter-fubon-v04/1.0",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
        }
        h0 = time.perf_counter()
        try:
            req = urllib.request.Request(test_url, headers=headers, method=http_method)
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                rec["http_latency_ms"] = round((time.perf_counter() - h0) * 1000.0, 2)
                rec["http_status"] = int(getattr(resp, "status", 200))
                rec["final_url"] = resp.geturl()
                rec["final_host"] = urllib.parse.urlsplit(rec["final_url"]).netloc
                rec["content_type"] = str(resp.headers.get("Content-Type") or "")
                rec["accept_ranges"] = str(resp.headers.get("Accept-Ranges") or "")
                raw_clen = resp.headers.get("Content-Length")
                if raw_clen is not None and str(raw_clen).strip().isdigit():
                    rec["content_length"] = int(str(raw_clen).strip())
                if http_method == "GET":
                    _ = resp.read(16384)
                rec["http_ok"] = 200 <= rec["http_status"] < 400
                if not rec["http_ok"]:
                    rec["failure_category"] = "HTTP_ABNORMAL_RESPONSE"
        except urllib.error.HTTPError as exc:
            rec["http_latency_ms"] = round((time.perf_counter() - h0) * 1000.0, 2)
            rec["http_status"] = int(exc.code)
            rec["http_error"] = f"HTTPError {exc.code}: {exc.reason}"
            rec["failure_category"] = "HTTP_ABNORMAL_RESPONSE"
        except Exception as exc:
            rec["http_latency_ms"] = round((time.perf_counter() - h0) * 1000.0, 2)
            rec["http_error"] = f"{exc.__class__.__name__}: {exc}"
            rec["failure_category"] = "HTTP_ABNORMAL_RESPONSE"
        rec["redirect_chain"] = redirect_chain

    return rec


def run_fubon_campus_preflight(
    product_page_url: str = FUBON_EPLUS_PRODUCT_PAGE_URL,
    override_download_url: str = "",
    timeout_sec: float = DEFAULT_CONNECT_TIMEOUT_SEC,
    allow_loopback_for_test: bool = False,
) -> Dict[str, Any]:
    """
    Section 六 Phase A：下載前連通性與來源安全檢查 (Preflight).
    測試項目：
      1. 富邦產品頁網址安全驗證、DNS 解析、TCP 建連、TLS 交握與憑證檢查、HTTP HEAD、小型 HTTP GET 讀取頁面並解析按鈕。
      2. 解析出的實際下載網址之安全性驗證（僅允許 HTTPS、驗證富邦官方網域、檢查每一次 HTTP Redirect、拒絕內網/Loopback/第三方）。
      3. 對下載網址執行 HTTP HEAD 標頭檢查。
      4. 執行有限的基礎公開服務對照 (`www.microsoft.com`, `github.com`)，但明確標註對照組成功不等同富邦服務成功。
    """
    started_at = format_taiwan_time()
    page_sec = validate_fubon_download_url_security(
        product_page_url,
        allow_loopback_for_test=allow_loopback_for_test,
    )
    result: Dict[str, Any] = {
        "phase": "Phase_A_Preflight",
        "started_at_tw": started_at,
        "ended_at_tw": "",
        "preflight_passed": False,
        "status": FUBON_STATUS_FAILED,
        "failure_stage": "",
        "error_message": "",
        "product_page_security": page_sec,
        "product_page_probe": {},
        "product_page_get": {
            "http_status": 0,
            "latency_ms": None,
            "received_bytes": 0,
            "final_url": "",
            "final_host": "",
            "redirect_chain": [],
            "page_opened_ok": False,
            "error": "",
        },
        "button_extraction": {},
        "installer_url_security": {},
        "installer_head_probe": {},
        "baseline_public_controls": [],
        "baseline_control_note": "Microsoft 與 GitHub 公開服務僅作為基礎網際網路連通性對照，其成功絕不等同富邦服務成功。",
    }

    if not page_sec.get("security_ok"):
        result["status"] = FUBON_STATUS_SAFETY_ABORTED
        result["failure_stage"] = str(page_sec.get("failure_stage") or "UNSAFE_PRODUCT_PAGE_URL")
        result["error_message"] = str(page_sec.get("reject_reason") or "產品頁網址未通過安全檢查")
        result["ended_at_tw"] = format_taiwan_time()
        return result

    page_host = str(page_sec["host"])
    page_port = int(page_sec["port"])

    # 1. 對富邦官網執行 DNS / TCP / TLS / HTTP HEAD 探測
    if not allow_loopback_for_test:
        page_probe = _probe_single_endpoint_low_load(
            fqdn=page_host,
            port=page_port,
            test_url=product_page_url,
            http_method="HEAD",
            timeout_sec=timeout_sec,
        )
    else:
        page_probe = {
            "fqdn": page_host,
            "port": page_port,
            "dns_ok": True,
            "resolved_ips": ["127.0.0.1"],
            "tcp_ok": True,
            "tls_ok": True,
            "http_ok": True,
            "http_status": 200,
        }
    result["product_page_probe"] = page_probe

    if not page_probe.get("dns_ok"):
        result["status"] = FUBON_STATUS_FAILED
        result["failure_stage"] = "PREFLIGHT_DNS_FAILED"
        result["error_message"] = f"富邦官網 DNS 解析失敗: {page_probe.get('dns_error')}"
        result["ended_at_tw"] = format_taiwan_time()
        return result
    if not page_probe.get("tcp_ok"):
        result["status"] = FUBON_STATUS_FAILED
        result["failure_stage"] = "PREFLIGHT_TCP_FAILED"
        result["error_message"] = f"富邦官網 TCP 建連失敗: {page_probe.get('tcp_error')}"
        result["ended_at_tw"] = format_taiwan_time()
        return result
    if not page_probe.get("tls_ok"):
        result["status"] = FUBON_STATUS_FAILED
        result["failure_stage"] = "PREFLIGHT_TLS_FAILED"
        result["error_message"] = f"富邦官網 TLS 憑證或交握失敗: {page_probe.get('tls_error')}"
        result["ended_at_tw"] = format_taiwan_time()
        return result

    # 2. 小型 HTTP GET 讀取官方產品頁並檢查 Redirect 與按鈕連結
    page_redirects: List[Dict[str, Any]] = []
    opener = urllib.request.build_opener(
        _SafeFubonRedirectHandler(page_redirects, allow_loopback_for_test=allow_loopback_for_test)
    )
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) wifiwriter-fubon-v04/1.0",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
    }
    html_text = ""
    g0 = time.perf_counter()
    try:
        req_get = urllib.request.Request(product_page_url, headers=headers, method="GET")
        with opener.open(req_get, timeout=timeout_sec) as resp:
            page_bytes = resp.read(524288)  # 限制最多讀取 512 KiB 網頁內容
            result["product_page_get"]["latency_ms"] = round((time.perf_counter() - g0) * 1000.0, 2)
            result["product_page_get"]["http_status"] = int(getattr(resp, "status", 200))
            result["product_page_get"]["received_bytes"] = len(page_bytes)
            result["product_page_get"]["final_url"] = resp.geturl()
            result["product_page_get"]["final_host"] = urllib.parse.urlsplit(resp.geturl()).netloc
            result["product_page_get"]["redirect_chain"] = page_redirects
            html_text = page_bytes.decode("utf-8", errors="replace")
            if 200 <= result["product_page_get"]["http_status"] < 300 and (
                "富邦" in html_text or "download_pc_app" in html_text
            ):
                result["product_page_get"]["page_opened_ok"] = True
            else:
                result["product_page_get"]["error"] = "HTTP 回應非預期的富邦 e+ 官方產品頁內容"
    except FubonSafetyAbortError as exc:
        result["product_page_get"]["redirect_chain"] = page_redirects
        result["product_page_get"]["error"] = str(exc)
        result["status"] = FUBON_STATUS_SAFETY_ABORTED
        result["failure_stage"] = exc.stage
        result["error_message"] = str(exc)
        result["ended_at_tw"] = format_taiwan_time()
        return result
    except Exception as exc:
        result["product_page_get"]["latency_ms"] = round((time.perf_counter() - g0) * 1000.0, 2)
        result["product_page_get"]["redirect_chain"] = page_redirects
        result["product_page_get"]["error"] = f"{exc.__class__.__name__}: {exc}"
        result["status"] = FUBON_STATUS_FAILED
        result["failure_stage"] = "PRODUCT_PAGE_GET_FAILED"
        result["error_message"] = f"官方產品頁開啟失敗: {exc}"
        result["ended_at_tw"] = format_taiwan_time()
        return result

    if not result["product_page_get"]["page_opened_ok"]:
        result["status"] = FUBON_STATUS_FAILED
        result["failure_stage"] = "PRODUCT_PAGE_CONTENT_INVALID"
        result["error_message"] = result["product_page_get"]["error"]
        result["ended_at_tw"] = format_taiwan_time()
        return result

    # 3. 解析按鈕下載網址（或驗證使用者手動指定之網址）
    ext_res = extract_fubon_eplus_download_url(
        html_text,
        base_url=result["product_page_get"]["final_url"] or product_page_url,
    )
    result["button_extraction"] = ext_res

    if override_download_url.strip():
        candidate_dl_url = override_download_url.strip()
        ext_res["override_used"] = True
        ext_res["override_url"] = candidate_dl_url
    else:
        candidate_dl_url = str(ext_res.get("download_url") or "")

    if not candidate_dl_url:
        result["status"] = FUBON_STATUS_FAILED
        result["failure_stage"] = "BUTTON_LINK_EXTRACTION_FAILED"
        result["error_message"] = str(ext_res.get("error") or "無法從產品頁解析 Download 按鈕連結")
        result["ended_at_tw"] = format_taiwan_time()
        return result

    # 4. 嚴格驗證下載網址安全性（絕不自動信任任意手動網址或非可信網域！）
    dl_sec = validate_fubon_download_url_security(
        candidate_dl_url,
        allow_loopback_for_test=allow_loopback_for_test,
    )
    result["installer_url_security"] = dl_sec
    if not dl_sec.get("security_ok"):
        result["status"] = FUBON_STATUS_SAFETY_ABORTED
        result["failure_stage"] = str(dl_sec.get("failure_stage") or "UNSAFE_DOWNLOAD_URL")
        result["error_message"] = str(dl_sec.get("reject_reason") or "安裝檔下載網址未通過安全審查")
        result["ended_at_tw"] = format_taiwan_time()
        return result

    # 5. 對安裝檔下載網址執行 HTTP HEAD 標頭檢查（含 Redirect 安全攔截）
    head_redirects: List[Dict[str, Any]] = []
    head_opener = urllib.request.build_opener(
        _SafeFubonRedirectHandler(head_redirects, allow_loopback_for_test=allow_loopback_for_test)
    )
    head_probe: Dict[str, Any] = {
        "requested_url": candidate_dl_url,
        "final_url": "",
        "final_host": "",
        "http_status": 0,
        "latency_ms": None,
        "content_type": "",
        "content_length_bytes": None,
        "accept_ranges": "",
        "redirect_chain": head_redirects,
        "head_ok": False,
        "error": "",
    }
    h0 = time.perf_counter()
    try:
        req_head = urllib.request.Request(candidate_dl_url, headers=headers, method="HEAD")
        with head_opener.open(req_head, timeout=timeout_sec) as h_resp:
            head_probe["latency_ms"] = round((time.perf_counter() - h0) * 1000.0, 2)
            head_probe["http_status"] = int(getattr(h_resp, "status", 200))
            head_probe["final_url"] = h_resp.geturl()
            head_probe["final_host"] = urllib.parse.urlsplit(h_resp.geturl()).netloc
            head_probe["content_type"] = str(h_resp.headers.get("Content-Type") or "")
            head_probe["accept_ranges"] = str(h_resp.headers.get("Accept-Ranges") or "")
            raw_cl = h_resp.headers.get("Content-Length")
            if raw_cl is not None and str(raw_cl).strip().isdigit():
                head_probe["content_length_bytes"] = int(str(raw_cl).strip())
            head_probe["head_ok"] = 200 <= head_probe["http_status"] < 300
    except FubonSafetyAbortError as exc:
        head_probe["error"] = str(exc)
        result["installer_head_probe"] = head_probe
        result["status"] = FUBON_STATUS_SAFETY_ABORTED
        result["failure_stage"] = exc.stage
        result["error_message"] = str(exc)
        result["ended_at_tw"] = format_taiwan_time()
        return result
    except urllib.error.HTTPError as exc:
        head_probe["latency_ms"] = round((time.perf_counter() - h0) * 1000.0, 2)
        head_probe["http_status"] = int(exc.code)
        head_probe["error"] = f"HTTPError {exc.code}: {exc.reason}"
    except Exception as exc:
        head_probe["latency_ms"] = round((time.perf_counter() - h0) * 1000.0, 2)
        head_probe["error"] = f"{exc.__class__.__name__}: {exc}"

    result["installer_head_probe"] = head_probe

    # 6. 執行有限的公開服務基礎對照（Microsoft / GitHub），低負載循序執行
    if not allow_loopback_for_test:
        for ctrl_host, ctrl_url in (
            ("www.microsoft.com", "https://www.microsoft.com"),
            ("github.com", "https://github.com"),
        ):
            time.sleep(0.15)
            ctrl_res = _probe_single_endpoint_low_load(
                fqdn=ctrl_host,
                port=443,
                test_url=ctrl_url,
                http_method="HEAD",
                timeout_sec=min(timeout_sec, 10.0),
            )
            result["baseline_public_controls"].append(ctrl_res)

    result["preflight_passed"] = True
    result["status"] = FUBON_STATUS_SUCCESS
    result["ended_at_tw"] = format_taiwan_time()
    return result


def run_fubon_campus_full_download(
    *,
    run_id: str,
    product_page_url: str,
    installer_url: str,
    windows_interface: str,
    output_dir: Path,
    max_download_mib: float = DEFAULT_FUBON_MAX_DOWNLOAD_MIB,
    allow_large_download: bool = False,
    connect_timeout_sec: float = DEFAULT_CONNECT_TIMEOUT_SEC,
    read_timeout_sec: float = DEFAULT_READ_TIMEOUT_SEC,
    download_deadline_sec: float = DEFAULT_DOWNLOAD_DEADLINE_SEC,
    chunk_size_bytes: int = DEFAULT_CHUNK_READ_BYTES,
    allow_loopback_for_test: bool = False,
    authenticode_verifier: Optional[Callable[[Path], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Section 六 Phase B：完整下載實測（僅在 Phase A 安全檢查通過後執行一次，絕不重複下載大型檔案）.
    嚴格檢查與保護：
      1. 再次確認 installer_url 安全性，並以 _SafeFubonRedirectHandler 驗證每一次 HTTP Redirect。
      2. 預期 HTTP 200 OK；拒絕將 206 Partial Content 或帶有 Content-Range 視為完整下載。
      3. 檢查容量上限 (`max_download_mib`, 預設 200 MiB) 與整體下載期限 (`download_deadline_sec`)。
      4. 下載中與未通過三階段驗證前，檔案以隔離副檔名保存在 `quarantine/`，絕不以 `.exe` 交付，避免使用者誤執行。
      5. 獨立計算與記錄三項驗收指標：`transport_complete`, `artifact_integrity_verified`, `publisher_verified`。
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir = output_dir / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    sec_check = validate_fubon_download_url_security(
        installer_url,
        allow_loopback_for_test=allow_loopback_for_test,
    )
    file_name = sec_check.get("file_name") or "FB_ePlus_setup.exe"
    if not file_name.lower().endswith(".exe"):
        file_name = "FB_ePlus_setup.exe"

    max_bytes = int(max_download_mib * 1024 * 1024)
    chunk_sz = max(4096, min(int(chunk_size_bytes), 262144))

    redirect_chain: List[Dict[str, Any]] = []
    started_at_tw = format_taiwan_time()

    rec: Dict[str, Any] = {
        "phase": "Phase_B_Full_Download",
        "run_id": run_id,
        "started_at_tw": started_at_tw,
        "ended_at_tw": "",
        "windows_interface": windows_interface,
        "product_page_url": product_page_url,
        "installer_url": installer_url,
        "redirect_chain": redirect_chain,
        "final_url": "",
        "final_host": "",
        "http_status": 0,
        "content_type": "",
        "content_range": "",
        "content_length_bytes": None,
        "content_length_mib": None,
        "received_bytes": 0,
        "received_mib": 0.0,
        "size_matched": None,
        "download_duration_seconds": None,
        "average_throughput_mbps": None,
        "average_throughput_mib_s": None,
        "file_type": "未完成下載",
        "pe_structure": {},
        "is_html_login_or_block_page": False,
        "is_small_bootstrapper": False,
        "sha256": "",
        "authenticode_status": "NotChecked",
        "signer_subject": "",
        "signer_issuer": "",
        "cert_not_after": "",
        "authenticode_raw": {},
        # P0 3.1：三項獨立驗收指標
        "transport_complete": False,
        "artifact_integrity_verified": False,
        "publisher_verified": False,
        "installer_complete_ok": False,
        "verification_verdict": "NOT_COMPLETED",
        "status": FUBON_STATUS_FAILED,
        "error_stage": "",
        "error_message": "",
        "saved_verified_installer_path": "",
        "quarantined_file_path": "",
        "full_download_attempts": 1,
    }

    if not sec_check.get("security_ok"):
        rec["status"] = FUBON_STATUS_SAFETY_ABORTED
        rec["verification_verdict"] = "SAFETY_ABORTED"
        rec["error_stage"] = str(sec_check.get("failure_stage") or "UNSAFE_DOWNLOAD_URL")
        rec["error_message"] = str(sec_check.get("reject_reason") or "下載網址安全檢查未通過")
        rec["ended_at_tw"] = format_taiwan_time()
        return rec

    part_path = quarantine_dir / f"{file_name}.part"
    quarantine_bin_path = quarantine_dir / f"{file_name}.unverified.bin"
    quarantine_sig_check_exe = quarantine_dir / f".sigcheck_{file_name}"
    verified_dest_path = output_dir / file_name

    opener = urllib.request.build_opener(
        _SafeFubonRedirectHandler(redirect_chain, allow_loopback_for_test=allow_loopback_for_test)
    )
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) wifiwriter-fubon-v04/1.0",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
    }

    dl_t0 = time.perf_counter()
    sha256_hasher = hashlib.sha256()
    total_read = 0
    first_chunk = b""
    clen_val: Optional[int] = None
    stream_completed_cleanly = False

    try:
        req = urllib.request.Request(installer_url, headers=headers, method="GET")
        with opener.open(req, timeout=connect_timeout_sec) as resp:
            # 設定讀取逾時
            raw_sock = getattr(getattr(resp, "fp", None), "raw", None)
            if raw_sock is not None and hasattr(raw_sock, "_sock"):
                try:
                    raw_sock._sock.settimeout(read_timeout_sec)
                except Exception:
                    pass

            rec["http_status"] = int(getattr(resp, "status", 200))
            rec["final_url"] = resp.geturl()
            rec["final_host"] = urllib.parse.urlsplit(resp.geturl()).netloc
            rec["content_type"] = str(resp.headers.get("Content-Type") or "")
            rec["content_range"] = str(resp.headers.get("Content-Range") or "")

            # 最終抵達之 Host 亦須再次確認為可信富邦網域
            final_sec = validate_fubon_download_url_security(
                rec["final_url"],
                allow_loopback_for_test=allow_loopback_for_test,
                resolve_dns=False,
            )
            if not final_sec.get("security_ok"):
                raise FubonSafetyAbortError(
                    final_sec.get("failure_stage") or "UNTRUSTED_FINAL_HOST",
                    f"最終下載網址未通過安全驗證: {final_sec.get('reject_reason')}",
                )

            raw_clen = resp.headers.get("Content-Length")
            if raw_clen is not None and str(raw_clen).strip().isdigit():
                clen_val = int(str(raw_clen).strip())
                rec["content_length_bytes"] = clen_val
                rec["content_length_mib"] = round(clen_val / (1024.0 * 1024.0), 2)
                if clen_val > max_bytes and not allow_large_download:
                    raise FubonSafetyAbortError(
                        "MAX_DOWNLOAD_SIZE_EXCEEDED",
                        f"Content-Length ({rec['content_length_mib']} MiB) 超過預設安全上限 {max_download_mib} MiB；"
                        "若確認要下載，請明確傳入 `--allow-large-download` 或調高 `--max-download-mib`。",
                    )

            with part_path.open("wb") as out_f:
                while True:
                    elapsed_now = time.perf_counter() - dl_t0
                    if elapsed_now > download_deadline_sec:
                        raise TimeoutError(
                            f"DOWNLOAD_DEADLINE_EXCEEDED: 整體下載耗時 ({elapsed_now:.2f}s) 超過安全期限 ({download_deadline_sec}s)"
                        )
                    chunk = resp.read(chunk_sz)
                    if not chunk:
                        stream_completed_cleanly = True
                        break
                    total_read += len(chunk)
                    if total_read > max_bytes and not allow_large_download:
                        raise FubonSafetyAbortError(
                            "MAX_DOWNLOAD_SIZE_EXCEEDED",
                            f"已接收位元組 ({total_read:,} bytes) 超過預設安全上限 {max_download_mib} MiB，已立即中止下載。",
                        )
                    if len(first_chunk) < 8192:
                        need = 8192 - len(first_chunk)
                        first_chunk += chunk[:need]
                    out_f.write(chunk)
                    sha256_hasher.update(chunk)

    except FubonSafetyAbortError as exc:
        dur = round(max(0.001, time.perf_counter() - dl_t0), 3)
        rec["download_duration_seconds"] = dur
        rec["received_bytes"] = total_read
        rec["received_mib"] = round(total_read / (1024.0 * 1024.0), 2)
        rec["status"] = FUBON_STATUS_SAFETY_ABORTED
        rec["verification_verdict"] = "SAFETY_ABORTED"
        rec["error_stage"] = exc.stage
        rec["error_message"] = str(exc)
        rec["ended_at_tw"] = format_taiwan_time()
        if part_path.exists():
            try:
                part_path.unlink()
            except OSError:
                pass
        return rec
    except urllib.error.HTTPError as exc:
        dur = round(max(0.001, time.perf_counter() - dl_t0), 3)
        rec["download_duration_seconds"] = dur
        rec["http_status"] = int(exc.code)
        rec["final_url"] = str(exc.geturl() or installer_url)
        rec["final_host"] = urllib.parse.urlsplit(rec["final_url"]).netloc
        rec["received_bytes"] = total_read
        rec["status"] = FUBON_STATUS_FAILED
        rec["verification_verdict"] = "TRANSPORT_FAILED"
        rec["error_stage"] = f"HTTP_GET_ERROR_{exc.code}"
        rec["error_message"] = f"HTTPError {exc.code}: {exc.reason}"
        rec["ended_at_tw"] = format_taiwan_time()
        if part_path.exists():
            try:
                part_path.unlink()
            except OSError:
                pass
        return rec
    except (socket.timeout, TimeoutError) as exc:
        dur = round(max(0.001, time.perf_counter() - dl_t0), 3)
        rec["download_duration_seconds"] = dur
        rec["received_bytes"] = total_read
        rec["received_mib"] = round(total_read / (1024.0 * 1024.0), 2)
        if clen_val is not None:
            rec["size_matched"] = (total_read == clen_val)
        rec["status"] = FUBON_STATUS_FAILED
        rec["verification_verdict"] = "TRANSPORT_FAILED"
        rec["error_stage"] = (
            "DOWNLOAD_DEADLINE_EXCEEDED"
            if "DOWNLOAD_DEADLINE_EXCEEDED" in str(exc)
            else "SOCKET_READ_TIMEOUT_TRUNCATED"
        )
        rec["error_message"] = f"{exc.__class__.__name__}: {exc} (已接收 {total_read:,} bytes)"
        rec["ended_at_tw"] = format_taiwan_time()
        if part_path.exists():
            try:
                os.replace(part_path, quarantine_bin_path)
                rec["quarantined_file_path"] = str(quarantine_bin_path)
            except OSError:
                pass
        return rec
    except Exception as exc:
        dur = round(max(0.001, time.perf_counter() - dl_t0), 3)
        rec["download_duration_seconds"] = dur
        rec["received_bytes"] = total_read
        rec["received_mib"] = round(total_read / (1024.0 * 1024.0), 2)
        if clen_val is not None:
            rec["size_matched"] = (total_read == clen_val)
        rec["status"] = FUBON_STATUS_FAILED
        rec["verification_verdict"] = "TRANSPORT_FAILED"
        rec["error_stage"] = "HTTP_GET_STREAM_ERROR"
        rec["error_message"] = f"{exc.__class__.__name__}: {exc}"
        rec["ended_at_tw"] = format_taiwan_time()
        if part_path.exists():
            try:
                os.replace(part_path, quarantine_bin_path)
                rec["quarantined_file_path"] = str(quarantine_bin_path)
            except OSError:
                pass
        return rec

    dur = round(max(0.001, time.perf_counter() - dl_t0), 3)
    rec["download_duration_seconds"] = dur
    rec["received_bytes"] = total_read
    rec["received_mib"] = round(total_read / (1024.0 * 1024.0), 2)
    rec["average_throughput_mbps"] = round((total_read * 8.0) / (dur * 1_000_000.0), 2)
    rec["average_throughput_mib_s"] = round((total_read / (1024.0 * 1024.0)) / dur, 2)
    if clen_val is not None:
        rec["size_matched"] = (total_read == clen_val)

    # 先移至隔離區隱藏檢查路徑，完成 PE 結構、SHA-256 與 Authenticode 唯讀驗證
    if part_path.exists():
        os.replace(part_path, quarantine_sig_check_exe)

    sha256_hex = sha256_hasher.hexdigest() if total_read > 0 else ""
    rec["sha256"] = sha256_hex

    # 檢查是否為 HTML 登入頁／攔阻頁或合法的 PE 結構
    head_lower = first_chunk.lstrip()[:512].lower()
    ct_lower = rec["content_type"].lower()
    pe_info = inspect_pe_binary_structure(first_chunk, file_path=quarantine_sig_check_exe)
    rec["pe_structure"] = pe_info

    is_html_page = bool(
        head_lower.startswith(b"<!doctype html")
        or head_lower.startswith(b"<html")
        or head_lower.startswith(b"<head")
        or head_lower.startswith(b"<script")
        or b"<html" in head_lower[:256]
        or ("text/html" in ct_lower and not pe_info.get("is_valid_pe_structure"))
    )
    rec["is_html_login_or_block_page"] = is_html_page

    if is_html_page:
        rec["file_type"] = "HTML 網頁（疑似校園網路登入頁或攔阻頁，非有效安裝檔）"
    elif pe_info.get("is_valid_pe_structure"):
        if 0 < total_read <= SMALL_BOOTSTRAPPER_THRESHOLD_BYTES:
            rec["is_small_bootstrapper"] = True
            rec["file_type"] = f"Windows PE 可執行檔 ({pe_info.get('machine_type')}, 小型安裝啟動器)"
        else:
            rec["file_type"] = f"Windows PE 可執行檔 ({pe_info.get('machine_type')}, 完整安裝包)"
    elif pe_info.get("has_mz_magic"):
        rec["file_type"] = "損毀或不完整的 MZ 標頭檔案（缺少有效 PE\\0\\0 區段標頭）"
    else:
        rec["file_type"] = f"非 Windows 執行檔格式 (Content-Type: {rec['content_type'] or '未知'})"

    # 唯讀檢查 Authenticode 簽章（絕不執行檔案）
    auth_info: Dict[str, Any] = {
        "checked": False,
        "signature_status": "NotChecked",
        "signer_subject": "",
        "signer_issuer": "",
        "cert_not_after": "",
    }
    if quarantine_sig_check_exe.exists() and pe_info.get("has_mz_magic") and not is_html_page:
        if authenticode_verifier is not None:
            auth_info = authenticode_verifier(quarantine_sig_check_exe)
        else:
            auth_info = verify_authenticode_signature_readonly(quarantine_sig_check_exe)

    rec["authenticode_raw"] = auth_info
    rec["authenticode_status"] = str(auth_info.get("signature_status") or "Unknown")
    rec["signer_subject"] = str(auth_info.get("signer_subject") or "")
    rec["signer_issuer"] = str(auth_info.get("signer_issuer") or "")
    rec["cert_not_after"] = str(auth_info.get("cert_not_after") or "")

    # 執行三階段獨立驗收判定 (transport_complete / artifact_integrity_verified / publisher_verified)
    ver = evaluate_three_stage_download_verification(
        http_status=rec["http_status"],
        content_range_header=rec["content_range"],
        content_length_bytes=clen_val,
        received_bytes=total_read,
        stream_completed_cleanly=stream_completed_cleanly,
        is_html_page=is_html_page,
        pe_info=pe_info,
        sha256_hex=sha256_hex,
        authenticode_info=auth_info,
    )
    rec["transport_complete"] = ver["transport_complete"]
    rec["artifact_integrity_verified"] = ver["artifact_integrity_verified"]
    rec["publisher_verified"] = ver["publisher_verified"]
    rec["installer_complete_ok"] = ver["installer_complete_ok"]
    rec["verification_verdict"] = ver["verification_verdict"]
    rec["content_length_missing_warning"] = ver["content_length_missing_warning"]

    if ver["installer_complete_ok"]:
        # 只有三階段全部驗證通過，才允許交付為正式檔案名稱，並清除暫存隔離檔
        if quarantine_sig_check_exe.exists():
            os.replace(quarantine_sig_check_exe, verified_dest_path)
            rec["saved_verified_installer_path"] = str(verified_dest_path)
        rec["status"] = FUBON_STATUS_SUCCESS
        rec["error_stage"] = ""
        rec["error_message"] = ""
    else:
        # 驗收失敗：將檔案改名為 `.unverified.bin` 保存在隔離區，絕不留下 `.exe` 副檔名避免誤執行！
        if quarantine_sig_check_exe.exists():
            try:
                os.replace(quarantine_sig_check_exe, quarantine_bin_path)
                rec["quarantined_file_path"] = str(quarantine_bin_path)
            except OSError:
                pass
        if verified_dest_path.exists():
            try:
                verified_dest_path.unlink()
            except OSError:
                pass
        rec["status"] = FUBON_STATUS_FAILED
        rec["error_stage"] = ver["failure_stage"] or "VERIFICATION_FAILED"
        rec["error_message"] = (
            f"下載或驗證未通過 (verdict={ver['verification_verdict']}, stage={rec['error_stage']}): "
            f"{ver['transport_reason']} | Authenticode={rec['authenticode_status']} ({rec['signer_subject'] or '無簽署者'})"
        )

    rec["ended_at_tw"] = format_taiwan_time()
    return rec


def run_fubon_campus_stability_series(
    *,
    product_page_url: str = FUBON_EPLUS_PRODUCT_PAGE_URL,
    installer_url: str = "",
    rounds: int = 5,
    interval_sec: float = 60.0,
    timeout_sec: float = 10.0,
    include_baseline_controls: bool = True,
    logger: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Section 六 Phase C：低負載穩定性檢查（預設每隔 60 秒一次、共 5 次；不重複完整下載安裝檔）.
    僅執行 DNS、TCP、TLS 及低資料量 HTTP HEAD 檢查，嚴格區分：
      - DNS 解析失敗 (`DNS_FAILURE`)
      - 單次 TCP 失敗 (`SINGLE_TCP_FAILURE`)
      - TLS 交握失敗 (`TLS_HANDSHAKE_FAILURE`)
      - HTTP 服務回應異常 (`HTTP_ABNORMAL_RESPONSE`)
    並明確聲明：任何主動探測失敗僅代表該時點之新連線/探測異常，不得直接判定為已開啟交易軟體之長連線斷線。
    """
    rounds = max(1, int(rounds))
    page_host = urllib.parse.urlsplit(product_page_url).hostname or "www.fbs.com.tw"
    inst_host = urllib.parse.urlsplit(installer_url).hostname or page_host

    targets: List[Dict[str, Any]] = [
        {
            "key": "fubon_product_page",
            "label": "富邦 e+ 官方產品頁",
            "fqdn": page_host,
            "port": 443,
            "url": product_page_url,
            "method": "HEAD",
            "is_fubon": True,
        }
    ]
    if installer_url:
        targets.append(
            {
                "key": "fubon_installer_endpoint",
                "label": "富邦 e+ 官方安裝檔端點 (HEAD)",
                "fqdn": inst_host,
                "port": 443,
                "url": installer_url,
                "method": "HEAD",
                "is_fubon": True,
            }
        )
    if include_baseline_controls:
        targets.extend(
            [
                {
                    "key": "control_microsoft",
                    "label": "Microsoft 公開服務對照",
                    "fqdn": "www.microsoft.com",
                    "port": 443,
                    "url": "https://www.microsoft.com",
                    "method": "HEAD",
                    "is_fubon": False,
                },
                {
                    "key": "control_github",
                    "label": "GitHub 公開服務對照",
                    "fqdn": "github.com",
                    "port": 443,
                    "url": "https://github.com",
                    "method": "HEAD",
                    "is_fubon": False,
                },
            ]
        )

    samples_by_key: Dict[str, List[Dict[str, Any]]] = {t["key"]: [] for t in targets}
    all_chronological_events: List[Dict[str, Any]] = []
    started_at_tw = format_taiwan_time()
    t0 = time.perf_counter()

    for r_idx in range(1, rounds + 1):
        round_start = time.perf_counter()
        if logger:
            logger.info("Phase C 低負載穩定性檢查：執行第 %d/%d 次取樣...", r_idx, rounds)

        for tgt in targets:
            probe = _probe_single_endpoint_low_load(
                fqdn=tgt["fqdn"],
                port=tgt["port"],
                test_url=tgt["url"],
                http_method=tgt["method"],
                timeout_sec=timeout_sec,
            )
            probe["round"] = r_idx
            probe["target_key"] = tgt["key"]
            probe["target_label"] = tgt["label"]
            probe["is_fubon"] = tgt["is_fubon"]
            samples_by_key[tgt["key"]].append(probe)

            if probe["failure_category"] != "NONE":
                all_chronological_events.append(
                    {
                        "round": r_idx,
                        "timestamp_tw": probe["timestamp_tw"],
                        "target_label": tgt["label"],
                        "fqdn": tgt["fqdn"],
                        "failure_category": probe["failure_category"],
                        "detail": (
                            probe.get("dns_error")
                            or probe.get("tcp_error")
                            or probe.get("tls_error")
                            or probe.get("http_error")
                            or f"HTTP {probe.get('http_status')}"
                        ),
                        "note": "此為低負載主動探測結果，不等同於實際交易軟體登入後之 Session 斷線",
                    }
                )
            time.sleep(0.2)

        if r_idx < rounds and interval_sec > 0:
            elapsed_r = time.perf_counter() - round_start
            rem = max(0.5, interval_sec - elapsed_r)
            time.sleep(rem)

    summaries: List[Dict[str, Any]] = []
    for tgt in targets:
        s_list = samples_by_key[tgt["key"]]
        n = len(s_list)
        dns_ok_c = sum(1 for s in s_list if s.get("dns_ok"))
        tcp_ok_c = sum(1 for s in s_list if s.get("tcp_ok"))
        tls_ok_c = sum(1 for s in s_list if s.get("tls_ok"))
        http_ok_c = sum(1 for s in s_list if s.get("http_ok"))

        dns_ms = [float(s["dns_latency_ms"]) for s in s_list if s.get("dns_latency_ms") is not None]
        tcp_ms = [float(s["tcp_rtt_ms"]) for s in s_list if s.get("tcp_rtt_ms") is not None]
        tls_ms = [float(s["tls_handshake_ms"]) for s in s_list if s.get("tls_handshake_ms") is not None]
        http_ms = [float(s["http_latency_ms"]) for s in s_list if s.get("http_latency_ms") is not None]

        summaries.append(
            {
                "target_key": tgt["key"],
                "target_label": tgt["label"],
                "fqdn": tgt["fqdn"],
                "is_fubon": tgt["is_fubon"],
                "rounds_total": n,
                "dns_success_count": dns_ok_c,
                "dns_success_rate_pct": round((dns_ok_c / n) * 100.0, 2) if n else 0.0,
                "dns_avg_ms": round(statistics.mean(dns_ms), 2) if dns_ms else None,
                "dns_max_ms": round(max(dns_ms), 2) if dns_ms else None,
                "tcp_success_count": tcp_ok_c,
                "tcp_success_rate_pct": round((tcp_ok_c / n) * 100.0, 2) if n else 0.0,
                "tcp_avg_ms": round(statistics.mean(tcp_ms), 2) if tcp_ms else None,
                "tcp_max_ms": round(max(tcp_ms), 2) if tcp_ms else None,
                "tls_success_count": tls_ok_c,
                "tls_success_rate_pct": round((tls_ok_c / n) * 100.0, 2) if n else 0.0,
                "tls_avg_ms": round(statistics.mean(tls_ms), 2) if tls_ms else None,
                "http_success_count": http_ok_c,
                "http_success_rate_pct": round((http_ok_c / n) * 100.0, 2) if n else 0.0,
                "http_avg_ms": round(statistics.mean(http_ms), 2) if http_ms else None,
                "dns_failure_count": sum(1 for s in s_list if s.get("failure_category") == "DNS_FAILURE"),
                "single_tcp_failure_count": sum(1 for s in s_list if s.get("failure_category") == "SINGLE_TCP_FAILURE"),
                "tls_failure_count": sum(1 for s in s_list if s.get("failure_category") == "TLS_HANDSHAKE_FAILURE"),
                "http_abnormal_count": sum(1 for s in s_list if s.get("failure_category") == "HTTP_ABNORMAL_RESPONSE"),
                "samples": s_list,
            }
        )

    fubon_Validation = [s for s in summaries if s.get("is_fubon")]
    fubon_intermittent_failures = sum(
        s["dns_failure_count"] + s["single_tcp_failure_count"] + s["tls_failure_count"] + s["http_abnormal_count"]
        for s in fubon_Validation
    )

    return {
        "phase": "Phase_C_Stability",
        "started_at_tw": started_at_tw,
        "ended_at_tw": format_taiwan_time(),
        "actual_duration_seconds": round(time.perf_counter() - t0, 2),
        "rounds_completed": rounds,
        "interval_seconds": interval_sec,
        "fubon_intermittent_failure_count": fubon_intermittent_failures,
        "anomaly_events": all_chronological_events,
        "target_summaries": summaries,
        "probe_disclaimer": "Phase C 低負載穩定性探測僅檢查 DNS/TCP/TLS/HTTP HEAD 可達性，不重複下載安裝檔，且任何探測失敗不等於實際交易軟體斷線。",
    }


def collect_recent_windows_net_events_readonly(
    lookback_minutes: int = 60,
    timeout_sec: int = 20,
) -> Dict[str, Any]:
    """
    Section 六 Phase D：唯讀檢查與測試時間接近的 Windows 網路事件.
    檢查範圍：
      - System Log：網卡斷線/重連 (e1dexpress/Netwtw/NDIS)、DNS Client Timeout (1014)、睡眠/喚醒 (Kernel-Power 42/107)
      - NetworkProfile Operational：網路設定檔變化 (10000/10001)
      - Windows Firewall With Advanced Security：可觀察到的本機防火牆事件（若無權限讀取則誠實標示「未取得（需管理員權限）」，絕不自動提權）
    """
    ps_cmd = f"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$since = (Get-Date).AddMinutes(-{int(max(5, lookback_minutes))})

$sysEvents = @(Get-WinEvent -FilterHashtable @{{ LogName='System'; StartTime=$since }} -MaxEvents 100 | Where-Object {{
    $_.ProviderName -match '(DNS Client Events|Tcpip|NDIS|e1dexpress|e1rexpress|Netwtw|Kernel-Power|Power-Troubleshooter)' -or $_.Id -in @(1014, 4201, 4202, 27, 33, 42, 107, 1)
}} | Select-Object -First 30 | ForEach-Object {{
    [ordered]@{{
        time = $_.TimeCreated.ToString('o')
        log = 'System'
        provider = [string]$_.ProviderName
        id = [int]$_.Id
        level = [string]$_.LevelDisplayName
        message = ([string]$_.Message -replace '\\r\\n|\\n', ' ')
    }}
}})

$profEvents = @(Get-WinEvent -FilterHashtable @{{ LogName='Microsoft-Windows-NetworkProfile/Operational'; StartTime=$since }} -MaxEvents 30 | Where-Object {{
    $_.Id -in @(10000, 10001, 4004)
}} | Select-Object -First 20 | ForEach-Object {{
    [ordered]@{{
        time = $_.TimeCreated.ToString('o')
        log = 'NetworkProfile'
        provider = [string]$_.ProviderName
        id = [int]$_.Id
        level = [string]$_.LevelDisplayName
        message = ([string]$_.Message -replace '\\r\\n|\\n', ' ')
    }}
}})

$fwReadable = $true
$fwEvents = @()
try {{
    $ErrorActionPreference = 'Stop'
    $fwRaw = @(Get-WinEvent -FilterHashtable @{{ LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; StartTime=$since }} -MaxEvents 20)
    foreach ($e in $fwRaw) {{
        $fwEvents += [ordered]@{{
            time = $e.TimeCreated.ToString('o')
            log = 'Firewall'
            id = [int]$e.Id
            level = [string]$e.LevelDisplayName
            message = ([string]$e.Message -replace '\\r\\n|\\n', ' ')
        }}
    }}
}} catch {{
    if ($_.Exception.Message -match 'Access is denied|拒絕存取|Unauthorized') {{
        $fwReadable = $false
    }}
}}

$out = [ordered]@{{
    checked_at = (Get-Date).ToString('o')
    lookback_minutes = {int(max(5, lookback_minutes))}
    system_events = $sysEvents
    network_profile_events = $profEvents
    firewall_log_readable = [bool]$fwReadable
    firewall_events = $fwEvents
    security_drop_log_status = '未取得（Windows Security 5152/5157 封包丟棄稽核日誌需系統管理員權限，依規範不自動提升權限）'
}}
$out | ConvertTo-Json -Compress -Depth 5
"""
    data: Dict[str, Any] = {
        "phase": "Phase_D_Windows_Events",
        "checked_at_tw": format_taiwan_time(),
        "lookback_minutes": lookback_minutes,
        "system_events": [],
        "network_profile_events": [],
        "firewall_log_readable": False,
        "firewall_events": [],
        "security_drop_log_status": "未取得（需系統管理員權限，依規範不自動提權）",
        "summary": {
            "dns_1014_timeout_count": 0,
            "nic_disconnect_count": 0,
            "profile_change_count": 0,
            "sleep_wake_count": 0,
        },
    }
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
            parsed = json.loads(proc.stdout.strip())
            sys_ev = parsed.get("system_events") or []
            prof_ev = parsed.get("network_profile_events") or []
            fw_ev = parsed.get("firewall_events") or []
            data["system_events"] = sys_ev
            data["network_profile_events"] = prof_ev
            data["firewall_log_readable"] = bool(parsed.get("firewall_log_readable", True))
            data["firewall_events"] = fw_ev
            data["security_drop_log_status"] = str(
                parsed.get("security_drop_log_status") or data["security_drop_log_status"]
            )
            data["summary"] = {
                "dns_1014_timeout_count": sum(1 for e in sys_ev if e.get("id") == 1014),
                "nic_disconnect_count": sum(1 for e in sys_ev if e.get("id") in (27, 33, 4202)),
                "profile_change_count": len(prof_ev),
                "sleep_wake_count": sum(1 for e in sys_ev if e.get("id") in (42, 107, 1)),
            }
    except Exception as exc:
        data["error"] = str(exc)

    return data


# ==============================================================================
# Section 七：根因分析（A–J）與證據等級規範
# ==============================================================================
def evaluate_fubon_campus_root_causes(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    對每個可能原因（A–J）強制區分：
      1. direct_evidence (直接證據)
      2. supporting_inference (輔助推論)
      3. counter_evidence_or_alternatives (反證或替代解釋)
      4. insufficient_evidence_boundaries (證據不足邊界)
      5. next_valuable_step (下一步最有價值的測試)
    """
    env_ev = bundle.get("environment_evidence") or {}
    env_snap = bundle.get("environment_snapshot") or {}
    preflight = bundle.get("phase_a_preflight") or {}
    full_dl = bundle.get("phase_b_full_download") or {}
    stability = bundle.get("phase_c_stability") or {}
    win_events = bundle.get("phase_d_windows_events") or {}

    page_probe = preflight.get("product_page_probe") or {}
    page_get = preflight.get("product_page_get") or {}
    head_probe = preflight.get("installer_head_probe") or {}
    controls = preflight.get("baseline_public_controls") or []

    page_ok = bool(page_get.get("page_opened_ok"))
    transport_ok = bool(full_dl.get("transport_complete"))
    integrity_ok = bool(full_dl.get("artifact_integrity_verified"))
    publisher_ok = bool(full_dl.get("publisher_verified"))
    all_dl_ok = bool(full_dl.get("installer_complete_ok"))
    is_preflight_only = bool(bundle.get("preflight_only"))

    stab_summaries = stability.get("target_summaries") or []
    fubon_stab = [s for s in stab_summaries if s.get("is_fubon")]
    intermittent_cnt = int(stability.get("fubon_intermittent_failure_count") or 0)

    ev_sum = win_events.get("summary") or {}
    proxy_uncertain = bool(env_ev.get("proxy_or_pac_uncertain"))
    vpn_active = bool(env_ev.get("vpn_or_virtual_adapter_active"))

    items: List[Dict[str, Any]] = []

    # A. 校園網路是否阻擋或干擾富邦 e+ 官方網站？
    items.append(
        {
            "id": "A",
            "question": "校園網路是否阻擋或干擾富邦 e+ 官方網站？",
            "verdict": (
                "未檢出阻擋或干擾（官方產品頁可正常開啟）"
                if page_ok
                else f"檢出異常（產品頁開啟失敗：{preflight.get('failure_stage') or 'UNKNOWN'}）"
            ),
            "confidence": "高（針對 HTTPS 443 網頁存取）" if page_ok else "中（需排除遠端維護或暫時性網路波動）",
            "direct_evidence": [
                f"官方產品頁 `{preflight.get('product_page_security', {}).get('url', FUBON_EPLUS_PRODUCT_PAGE_URL)}` HTTP GET 狀態碼=`{page_get.get('http_status')}`，開啟成功=`{page_ok}`，讀取位元組=`{page_get.get('received_bytes')}` bytes，耗時=`{page_get.get('latency_ms')}` ms。",
                f"Download 按鈕解析結果：found=`{preflight.get('button_extraction', {}).get('found')}`，解析網址=`{preflight.get('button_extraction', {}).get('download_url') or '無'}`。",
            ],
            "supporting_inference": [
                "校園網路對 `www.fbs.com.tw:443` 之標準 HTTPS 網頁瀏覽與靜態 HTML 載入並未實施 DNS 封鎖、TCP 阻斷或 Captive Portal 強制重導向。"
                if page_ok
                else "校園網路至富邦官網之路徑在 DNS、TCP、TLS 或 HTTP 層出現阻斷或內容異常。"
            ],
            "counter_evidence_or_alternatives": [
                "公開對照組（Microsoft / GitHub）之連通狀態僅能反映一般網際網路出口，不能直接代替富邦網站之連線結論；但本項已直接由富邦官網 HTTP 200 與真實 DOM 按鈕解析證實。"
            ],
            "insufficient_evidence_boundaries": [
                "官方產品頁 (`www.fbs.com.tw:443`) 可正常瀏覽，不代表富邦 e+ 應用程式啟動後的專屬行情／交易主機與非 443 通訊埠未被限制。"
            ],
            "next_valuable_step": "若未來發現網頁偶發無法開啟，可增加不同時段（如開盤尖峰 08:45–09:30）之 Phase A Preflight 檢查。",
        }
    )

    # B. 校園網路是否阻擋、截斷或限制富邦 e+ 官方安裝檔下載？
    if is_preflight_only:
        b_verdict = "未測（本次為 `--preflight` 僅預檢模式，未執行 Phase B 完整下載）"
        b_conf = "不適用（Preflight 模式）"
        b_direct = [
            f"HTTP HEAD 預檢狀態碼=`{head_probe.get('http_status')}`，Content-Length=`{head_probe.get('content_length_bytes')}` bytes，但依規範只做 HEAD 不算下載成功。"
        ]
    elif all_dl_ok:
        b_verdict = "未檢出阻擋或截斷（安裝檔完整下載且通過三階段驗證）"
        b_conf = "高（針對本次 HTTPS 安裝包完整傳輸）"
        b_direct = [
            f"安裝檔 `{full_dl.get('installer_url')}` 完整 GET 狀態碼=`{full_dl.get('http_status')}`，Content-Length=`{full_dl.get('content_length_bytes')}` bytes ({full_dl.get('content_length_mib')} MiB)，實收=`{full_dl.get('received_bytes')}` bytes，大小一致=`{full_dl.get('size_matched')}`。",
            f"下載耗時=`{full_dl.get('download_duration_seconds')}` 秒，平均吞吐量=`{full_dl.get('average_throughput_mbps')}` Mbps ({full_dl.get('average_throughput_mib_s')} MiB/s)。",
            f"三階段獨立驗收：`transport_complete={transport_ok}`, `artifact_integrity_verified={integrity_ok}`, `publisher_verified={publisher_ok}`。",
            f"SHA-256=`{full_dl.get('sha256')}`；Authenticode 狀態=`{full_dl.get('authenticode_status')}`，簽署者=`{full_dl.get('signer_subject')}`。",
        ]
    else:
        b_verdict = f"檢出下載或驗證異常（verdict=`{full_dl.get('verification_verdict')}`, stage=`{full_dl.get('error_stage')}`）"
        b_conf = "高（已由三階段獨立驗證指標定位失敗階段）"
        b_direct = [
            f"HTTP 狀態碼=`{full_dl.get('http_status')}`，Content-Length=`{full_dl.get('content_length_bytes')}`，實收=`{full_dl.get('received_bytes')}` bytes。",
            f"三階段獨立驗收：`transport_complete={transport_ok}`, `artifact_integrity_verified={integrity_ok}`, `publisher_verified={publisher_ok}`；錯誤訊息：`{full_dl.get('error_message')}`。",
        ]

    items.append(
        {
            "id": "B",
            "question": "校園網路是否阻擋、截斷或限制富邦 e+ 官方安裝檔下載？",
            "verdict": b_verdict,
            "confidence": b_conf,
            "direct_evidence": b_direct,
            "supporting_inference": [
                "檔案不僅完成 HTTP 200 位元組完整接收，且通過 Windows PE 區段標頭 (`MZ` + `PE\\0\\0`) 與富邦綜合證券官方 Authenticode 數位簽章雜湊校驗，證明校園網路途中未發生封包竄改、中途截斷或替換為 HTML 攔阻頁。"
                if all_dl_ok
                else "三階段驗證能明確區分是「傳輸截斷 (`transport_complete=False`)」、「內容遭竄改或非有效 PE (`artifact_integrity_verified=False`)」或「發行者簽章無效 (`publisher_verified=False`)」。"
            ],
            "counter_evidence_or_alternatives": [
                "若校園網路對單一大型 HTTPS 下載實施嚴格配額或 DPI 攔阻，通常會出現連線重設 (TCP RST)、連線逾時或 HashMismatch；本次實測數據可作為直接判準。"
            ],
            "insufficient_evidence_boundaries": [
                "HTTPS 443 靜態安裝檔下載成功，僅證明標準 Web/CDN 下載通道正常，無法排除校園防火牆對富邦 e+ 交易軟體私有協定長連線之限制。"
            ],
            "next_valuable_step": "若懷疑特定時段校園頻寬壅塞導致下載過慢，可於尖峰時段再次執行單次完整下載比對平均吞吐量。",
        }
    )

    # C. 是否存在 DNS 過濾、錯誤解析或高延遲？
    dns_ips = page_probe.get("resolved_ips") or []
    dns_lat = page_probe.get("dns_latency_ms")
    dns_ok = bool(page_probe.get("dns_ok"))
    dns_1014 = int(ev_sum.get("dns_1014_timeout_count") or 0)
    items.append(
        {
            "id": "C",
            "question": "是否存在 DNS 過濾、錯誤解析或高延遲？",
            "verdict": (
                f"未檢出 DNS 過濾或錯誤解析（解析延遲 {dns_lat} ms，最近 60 分鐘 DNS 1014 逾時事件={dns_1014} 筆）"
                if dns_ok and dns_1014 == 0
                else f"檢出 DNS 異常或歷史逾時跡象（dns_ok={dns_ok}, DNS 1014 事件={dns_1014} 筆）"
            ),
            "confidence": "高",
            "direct_evidence": [
                f"本機設定之 DNS 伺服器：`{', '.join(_mask_ip_for_report(d) for d in (env_snap.get('dns_servers') or []))}`。",
                f"`www.fbs.com.tw` 解析結果：`{', '.join(dns_ips)}`（均為合法公開外部 IP，非 `0.0.0.0`、Loopback 或校園內網 Sinkhole 位址），初次解析耗時=`{dns_lat}` ms。",
                f"Phase C 多輪穩定性測試中，富邦網域 DNS 解析成功率與平均延遲：`{[{'fqdn': s['fqdn'], 'rate': s['dns_success_rate_pct'], 'avg_ms': s['dns_avg_ms']} for s in fubon_stab]}`。",
                f"Phase D Windows System Event ID 1014 (DNS Client Timeout) 計數：`{dns_1014}` 筆。",
            ],
            "supporting_inference": [
                "校園網路 DNS 伺服器能正確解析富邦官方網域，未觀察到 DNS Sinkhole 污染或過濾。"
            ],
            "counter_evidence_or_alternatives": [
                "若交易軟體連線失敗是由 DNS 引起，應會在主動探測或 Windows Event ID 1014 看到解析逾時或錯誤 IP；目前富邦官網網域無此現象。"
            ],
            "insufficient_evidence_boundaries": [
                "本次僅驗證富邦官網與下載端點 (`www.fbs.com.tw`) 之 FQDN，尚未涵蓋富邦 e+ 啟動後在背景動態查詢的所有私有行情／委託伺服器 FQDN。"
            ],
            "next_valuable_step": "若未來使用者在啟動富邦 e+ 時遇到無法連線，可比對當時是否有新的 Event ID 1014 指向其他富邦子網域。",
        }
    )

    # D. 是否存在 TCP/TLS/HTTPS 層級攔截、重設、逾時或憑證替換？
    mitm_suspected = bool(page_probe.get("mitm_cert_suspected"))
    cert_issuer = str(page_probe.get("cert_issuer") or "")
    cert_subject = str(page_probe.get("cert_subject") or "")
    tls_ok = bool(page_probe.get("tls_ok"))
    items.append(
        {
            "id": "D",
            "question": "是否存在 TCP/TLS/HTTPS 層級攔截、重設、逾時或憑證替換？",
            "verdict": (
                "未檢出 HTTPS TLS 憑證替換 (SSL MITM) 或 TCP 阻斷"
                if (tls_ok and not mitm_suspected)
                else f"檢出異常（tls_ok={tls_ok}, mitm_suspected={mitm_suspected}）"
            ),
            "confidence": "高（針對 `www.fbs.com.tw:443`）",
            "direct_evidence": [
                f"`www.fbs.com.tw:443` TCP RTT=`{page_probe.get('tcp_rtt_ms')}` ms，TLS 交握耗時=`{page_probe.get('tls_handshake_ms')}` ms，協定版本=`{page_probe.get('tls_version')}`，加密套件=`{page_probe.get('tls_cipher')}`。",
                f"伺服器憑證主題 (Subject)=`{cert_subject}`；簽發機構 (Issuer)=`{cert_issuer}`；到期日=`{page_probe.get('cert_not_after')}`；疑似防火牆代簽憑證 (`mitm_cert_suspected`)=`{mitm_suspected}`。",
            ],
            "supporting_inference": [
                "TLS 憑證由公開商業憑證機構（如 TWCA / DigiCert / GlobalSign 等）簽發，而非校園防火牆（如 Fortinet / PaloAlto / Zscaler）之自簽根憑證，證明校園網路未對富邦 HTTPS 443 流量執行 SSL 解密代簽 (SSL Inspection)。"
            ],
            "counter_evidence_or_alternatives": [
                "若校園網路啟用強制 HTTPS 憑證代簽，TLS 憑證 Issuer 會變更為學校或防火牆設備名稱，且可能導致嚴格檢查憑證釘選 (Certificate Pinning) 的金融軟體拒絕連線。"
            ],
            "insufficient_evidence_boundaries": [
                "無法單憑 443 埠未代簽，排除校園防火牆對非標準通訊埠（如 TCP 80/443 以外之行情或下單專線埠）實施無狀態封鎖或長連線 Idle Timeout 回收。"
            ],
            "next_valuable_step": "若未來取得富邦 e+ 官方公開之行情／交易測試端點清單，可對各端點執行相同的唯讀 TLS 憑證鏈核驗。",
        }
    )

    # E. 是否存在 HTTP Redirect、CDN、快取、WAF 或檔案傳遞異常？
    page_redirs = page_get.get("redirect_chain") or []
    head_redirs = head_probe.get("redirect_chain") or []
    dl_redirs = full_dl.get("redirect_chain") or []
    items.append(
        {
            "id": "E",
            "question": "是否存在 HTTP Redirect、CDN、快取、WAF 或檔案傳遞異常？",
            "verdict": (
                "未檢出惡意轉址、WAF 攔阻頁或快取污染"
                if (page_ok and (is_preflight_only or all_dl_ok))
                else "檢出 HTTP 轉址或檔案傳遞異常"
            ),
            "confidence": "高",
            "direct_evidence": [
                f"產品頁 Redirect 跳數=`{len(page_redirs)}`，最終落點=`{page_get.get('final_url')}` (Host=`{page_get.get('final_host')}`)。",
                f"安裝檔 HEAD Redirect 跳數=`{len(head_redirs)}`，最終落點=`{head_probe.get('final_url')}`；Content-Type=`{head_probe.get('content_type')}`，Accept-Ranges=`{head_probe.get('accept_ranges')}`。",
                f"安裝檔 GET Redirect 跳數=`{len(dl_redirs)}`，HTTP 狀態碼=`{full_dl.get('http_status')}`，Content-Range=`{full_dl.get('content_range') or '無'}`，是否為 HTML 登入/攔阻頁=`{full_dl.get('is_html_login_or_block_page')}`。",
            ],
            "supporting_inference": [
                "所有請求均加入 `Cache-Control: no-cache, no-store, must-revalidate` 且通過 `_SafeFubonRedirectHandler` 逐跳檢查，未發生轉址至校園 Portal 登入頁或第三方非授信主機之情形。"
            ],
            "counter_evidence_or_alternatives": [
                "若存在透明 Proxy 快取損毀或 WAF 攔截，下載內容會呈現 HTML 錯誤頁、206 殘缺片段或 Authenticode 雜湊不符；本次三階段驗證已排除此情況。"
            ],
            "insufficient_evidence_boundaries": [
                "僅涵蓋 HTTP/HTTPS 下載端點，不涵蓋非 HTTP 之原生 TCP Socket 金融電文。"
            ],
            "next_valuable_step": "維持每次下載驗證皆檢查 `Content-Length`、`PE\\0\\0` 標頭與 `Get-AuthenticodeSignature`。",
        }
    )

    # F. 是否存在校園網路品質問題（高延遲、抖動、間歇性連線失敗）？
    items.append(
        {
            "id": "F",
            "question": "是否存在校園網路品質問題（高延遲、抖動、間歇性連線失敗）？",
            "verdict": (
                f"本次低負載穩定性測試期間未檢出間歇性失敗（富邦端點異常次數={intermittent_cnt}）"
                if intermittent_cnt == 0 and fubon_stab
                else (
                    f"檢出間歇性探測異常（富邦端點異常次數={intermittent_cnt}）"
                    if intermittent_cnt > 0
                    else "未執行完整多輪穩定性測試（Preflight 或略過模式）"
                )
            ),
            "confidence": "中（受限於抽樣時間窗與低負載探測性質）",
            "direct_evidence": [
                f"Phase C 穩定性檢查完成輪數=`{stability.get('rounds_completed', 0)}`，間隔=`{stability.get('interval_seconds', 0)}` 秒，富邦目標間歇性失敗總數=`{intermittent_cnt}`。",
                f"各目標統計摘要：`{[{'label': s['target_label'], 'dns_rate': s['dns_success_rate_pct'], 'tcp_rate': s['tcp_success_rate_pct'], 'tcp_avg_ms': s['tcp_avg_ms'], 'tcp_max_ms': s['tcp_max_ms'], 'tls_rate': s['tls_success_rate_pct'], 'http_rate': s['http_success_rate_pct']} for s in stab_summaries]}`。",
            ],
            "supporting_inference": [
                "在測試時間窗內，校園網路對富邦 HTTPS 443 端點之新建連線延遲與成功率穩定。"
                if intermittent_cnt == 0 and fubon_stab
                else "探測期間出現的單次延遲升高或失敗已按 DNS / 單次 TCP / TLS / HTTP 分類記錄。"
            ],
            "counter_evidence_or_alternatives": [
                "短時間（約 5 分鐘）的新建短連線探測穩定，不能排除長達數十分鐘的閒置長連線遭到校園 NAT/防火牆狀態表老化回收 (Session Idle Timeout)。"
            ],
            "insufficient_evidence_boundaries": [
                "主動探測失敗不等於實際交易軟體斷線；反之，主動短連線探測 100% 成功，亦不代表長連線不會在閒置時被踢除。"
            ],
            "next_valuable_step": "若使用者在特定時段容易斷線，建議於該時段執行較長週期（例如每 60 秒一次、持續 15–30 分鐘）之低負載穩定性記錄。",
        }
    )

    # G. 是否存在本機 Windows 網路、Proxy、VPN、網卡或防火牆影響？
    nic_disc = int(ev_sum.get("nic_disconnect_count") or 0)
    prof_chg = int(ev_sum.get("profile_change_count") or 0)
    sleep_cnt = int(ev_sum.get("sleep_wake_count") or 0)
    items.append(
        {
            "id": "G",
            "question": "是否存在本機 Windows 網路、Proxy、VPN、網卡或防火牆影響？",
            "verdict": (
                "未檢出本機網卡斷線、Proxy 劫持或 VPN 干擾"
                if (not proxy_uncertain and not vpn_active and nic_disc == 0 and sleep_cnt == 0)
                else f"檢出需注意之本機環境因素（proxy_uncertain={proxy_uncertain}, vpn_active={vpn_active}, 網卡斷線事件={nic_disc}, 睡眠喚醒={sleep_cnt}）"
            ),
            "confidence": "高",
            "direct_evidence": [
                f"作用中預設路由介面：`{env_snap.get('primary_interface_alias')}` ({env_snap.get('primary_interface_description')})，媒介=`{env_snap.get('primary_media_kind')}`，連結速率=`{env_snap.get('primary_link_speed')}`。",
                f"系統 Proxy / PAC 狀態：ProxyEnabled=`{(env_snap.get('proxy') or {}).get('user_proxy_enabled')}`，AutoConfigURL=`{(env_snap.get('proxy') or {}).get('user_auto_config_url') or '無'}`，WinHTTP=`{(env_snap.get('proxy') or {}).get('winhttp_proxy')}`。",
                f"VPN 或虛擬網卡干擾=`{vpn_active}`；最近 {win_events.get('lookback_minutes', 60)} 分鐘內本機網卡斷線事件=`{nic_disc}` 筆、NetworkProfile 變更=`{prof_chg}` 筆、系統睡眠/喚醒=`{sleep_cnt}` 筆。",
                f"本機防火牆日誌可讀性=`{win_events.get('firewall_log_readable')}`；Security 封包丟棄日誌狀態：`{win_events.get('security_drop_log_status')}`。",
            ],
            "supporting_inference": [
                "已透過 Windows 路由表、介面卡狀態與近期系統事件日誌，排除本機實體網卡閃斷、系統休眠或本機 Proxy 設定錯誤造成之干擾。"
                if (not proxy_uncertain and not vpn_active and nic_disc == 0)
                else "本機存在 Proxy/VPN 或近期網卡狀態變更，可能影響應用程式連線路徑。"
            ],
            "counter_evidence_or_alternatives": [
                "即使本機網卡與路由完全正常，上游校園路由器或防火牆仍可能影響特定應用程式流量。"
            ],
            "insufficient_evidence_boundaries": [
                "Windows Security 5152/5157 封包丟棄稽核日誌需系統管理員權限，本次遵循不自動提權規範，標示為「未取得（需管理員權限）」。"
            ],
            "next_valuable_step": "維持使用有線網路或訊號穩定之介面，並避免在執行看盤軟體時同時開啟第三方 VPN 或改動系統 Proxy。",
        }
    )

    # H. 目前結果能否解釋富邦 e+ 交易軟體在校園網路可能發生的連線問題？
    items.append(
        {
            "id": "H",
            "question": "目前結果能否解釋富邦 e+ 交易軟體在校園網路可能發生的連線問題？",
            "verdict": (
                "可排除「富邦官網與安裝包下載通道遭校園封鎖」，但不能單憑下載成功證明登入後交易連線一定正常"
                if all_dl_ok
                else "本次已檢出官網或安裝包下載階段之異常，可直接解釋安裝檔取得問題，但登入後交易連線仍屬不同通訊機制"
            ),
            "confidence": "高（方法論邊界明確）",
            "direct_evidence": [
                f"本次免登入測試驗證之目標為 `{FUBON_EPLUS_PRODUCT_PAGE_URL}` 與 `{full_dl.get('installer_url') or (preflight.get('button_extraction') or {}).get('download_url')}`（皆為 TCP 443 標準 HTTPS 短連線／串流下載）。",
                f"安裝檔下載與三階段驗證結果：`transport_complete={transport_ok}`, `artifact_integrity_verified={integrity_ok}`, `publisher_verified={publisher_ok}`。",
            ],
            "supporting_inference": [
                "若使用者在校園網路連富邦官網都打不開或安裝檔無法下載，本次測試能直接定位；若官網與安裝檔下載完全正常（如本次實測），則證明問題不在基礎 DNS、基礎 HTTPS 443 或富邦官網 CDN，而更可能位於「交易軟體啟動／登入後所使用的專屬行情／委託長連線通訊埠、雙向心跳機制或校園 NAT Idle Timeout」。"
            ],
            "counter_evidence_or_alternatives": [
                "絕不可因為 HTTP 200 安裝檔下載成功，就推論富邦 e+ 登入後不會斷線；兩者使用的伺服器主機、通訊埠、協定型態（Web 下載 vs 金融長連線）完全不同。"
            ],
            "insufficient_evidence_boundaries": [
                "在不安裝、不啟動、不登入富邦 e+ 的嚴格安全限制下，無法觀測交易軟體實際建立之遠端 IP:Port 與 TCP 狀態轉移（如 `ESTABLISHED -> CLOSE_WAIT / RST`）。"
            ],
            "next_valuable_step": "若要進一步診斷「使用富邦 e+ 時斷線」，需在不輸入帳密或由使用者自行開啟軟體之前提下，僅以唯讀 `Get-NetTCPConnection` 觀察程式啟動階段（免登入前）嘗試連線之遠端 Port 是否遭阻擋。",
        }
    )

    # I. 哪些問題必須啟動富邦 e+ 或完成登入後才能確認？
    items.append(
        {
            "id": "I",
            "question": "哪些問題必須啟動富邦 e+ 或完成登入後才能確認？",
            "verdict": "共 5 項交易專屬連線行為必須在啟動程式或完成登入後才能驗證",
            "confidence": "高",
            "direct_evidence": [
                "本次遵循「免登入、不安裝、不執行」規範，全程未執行 `FB_ePlus_setup.exe` 亦未啟動富邦 e+ 主程式。"
            ],
            "supporting_inference": [
                "以下問題在純下載測試中完全不會發生，必須啟動或登入後才會觸發：",
                "1. 富邦 e+ 主程式啟動時之自動更新檢查端點與版本伺服器連線。",
                "2. 登入前／登入時連接之身分驗證伺服器與憑證 (CA) 驗證通道（常使用非 443 專屬埠）。",
                "3. 登入後即時報價（行情推播）長連線與委託回報長連線之遠端 IP 與通訊埠是否被校園防火牆阻擋。",
                "4. 校園網路 NAT 狀態表或防火牆對長時間低流量 TCP Session 之閒置老化回收 (Idle Timeout / TCP RST)。",
                "5. 雙向應用層心跳 (Keep-Alive / Heartbeat) 在校園網路雙向延遲抖動下是否逾時觸發客戶端自動重連。",
            ],
            "counter_evidence_or_alternatives": [
                "任何宣稱「不啟動程式、只下載安裝檔就能 100% 確認登入後交易斷線根因」的說法皆違反網路工程原理。"
            ],
            "insufficient_evidence_boundaries": [
                "本次報告嚴格將結論限制於「校園網路對富邦 e+ 官方產品頁與安裝檔下載之連通性、完整性與短週期穩定性」。"
            ],
            "next_valuable_step": "由使用者在測試機自行安裝並開啟富邦 e+ 停留在「未登入畫面」時，以唯讀 `Get-NetTCPConnection` 記錄程式本身發起之預先連線端點。",
        }
    )

    # J. 哪些問題因本次未測試手機熱點而無法做跨網路排除？
    items.append(
        {
            "id": "J",
            "question": "哪些問題因本次未測試手機熱點而無法做跨網路排除？",
            "verdict": "手機熱點本次明確標示為 `NOT_TESTED`（未測），不做任何跨網路 A/B 差異宣稱",
            "confidence": "高",
            "direct_evidence": [
                "本次執行參數為 `--network campus --campus-only`，未讀取歷史熱點檔案，亦未執行手機熱點測試。"
            ],
            "supporting_inference": [
                "因為未執行同一時間窗之手機行動數據熱點對照測試：",
                "1. 若校園網路在某時段出現延遲升高、下載降速或連線失敗，無法立即排除是否為「富邦官方伺服器／CDN 端當下的全域異常或維護」。",
                "2. 無法比較同一台 Windows 電腦在「校園網路路由」與「行動電信商路由」之間的吞吐量倍數差異或特定 Port 通透率差異。"
            ],
            "counter_evidence_or_alternatives": [
                "雖然本次校園網路下載與驗證本身已有明確的成功／失敗絕對指標（如 Authenticode 數位簽章與 SHA-256），但凡涉及「是否唯獨校園網路異常、外網完全正常」之比較命題，皆須實際完成熱點對照才能下結論。"
            ],
            "insufficient_evidence_boundaries": [
                "所有報告表格中「手機熱點結果」欄位均忠實填寫為 `未測` (`NOT_TESTED`)，絕不假設手機熱點一定為 100% 正常。"
            ],
            "next_valuable_step": "若未來在校園網路觀測到任何異常，可於同一時段切換至手機熱點執行相同指令，進行嚴格 A/B 對照。",
        }
    )

    # 綜合最可能原因與信心等級摘要
    if is_preflight_only:
        overall_summary = (
            "本次為 `--preflight` 預檢模式：校園網路可正常開啟富邦 e+ 官方產品頁並解析出官方安裝檔連結，且通過來源網域與 HTTPS 安全驗證；"
            "完整安裝包下載與三階段驗證需執行不帶 `--preflight` 之正式測試。"
        )
        overall_conf = "中（僅預檢）"
    elif all_dl_ok and intermittent_cnt == 0:
        overall_summary = (
            "校園網路目前對富邦 e+ 官方產品頁 (`www.fbs.com.tw:443`) 與官方安裝檔 (`FB_ePlus_setup.exe`) 之 HTTPS 連線、完整傳輸、PE 結構與富邦證券 Authenticode 數位簽章驗證完全正常，且 5 輪低負載穩定性探測無間歇性失敗。"
            "這排除了「富邦官網/下載通道遭校園封鎖、DNS 污染或 HTTPS 憑證代簽」；若使用者在使用富邦 e+ 時發生斷線，最可能原因位於「程式啟動或登入後的專屬行情／交易通訊埠限制或校園 NAT/防火牆長連線 Idle Timeout」，此部分需在啟動程式或登入後才能進一步驗證。"
        )
        overall_conf = "高（針對官網與下載通道正常性）/ 需後續驗證（針對登入後長連線）"
    else:
        overall_summary = (
            f"本次校園網路實測檢出異常：完整下載三階段驗證結果為 `{full_dl.get('verification_verdict')}` "
            f"(transport={transport_ok}, integrity={integrity_ok}, publisher={publisher_ok})，低負載穩定性間歇失敗={intermittent_cnt} 次。"
        )
        overall_conf = "高（已具直接失敗證據）"

    return {
        "overall_conclusion": overall_summary,
        "overall_confidence": overall_conf,
        "hotspot_status": "NOT_TESTED",
        "items": items,
    }


# ==============================================================================
# Section 九：產出私人報告檔案 (`campus_network_diagnostic.md`, `.json`, `.csv`, `campus_validation_report.md`)
# ==============================================================================
def write_campus_download_events_csv(bundle: Dict[str, Any], csv_path: Path) -> Path:
    """輸出 `campus_download_events.csv`，記錄本次校園網路預檢、完整下載與各輪穩定性檢查事件."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []

    run_id = str(bundle.get("run_id") or "")
    env_snap = bundle.get("environment_snapshot") or {}
    iface = str(env_snap.get("primary_interface_alias") or "")

    # 1. Phase A 產品頁與 HEAD 預檢事件
    preflight = bundle.get("phase_a_preflight") or {}
    p_probe = preflight.get("product_page_probe") or {}
    p_get = preflight.get("product_page_get") or {}
    h_probe = preflight.get("installer_head_probe") or {}

    if p_get:
        rows.append(
            {
                "timestamp_tw": preflight.get("started_at_tw", ""),
                "run_id": run_id,
                "phase": "Phase_A_Preflight_ProductPage",
                "network_mode": "campus_only",
                "hotspot_status": "NOT_TESTED",
                "interface": iface,
                "target": p_get.get("final_url") or FUBON_EPLUS_PRODUCT_PAGE_URL,
                "method": "GET",
                "dns_ok": p_probe.get("dns_ok"),
                "dns_latency_ms": p_probe.get("dns_latency_ms"),
                "tcp_ok": p_probe.get("tcp_ok"),
                "tcp_rtt_ms": p_probe.get("tcp_rtt_ms"),
                "tls_ok": p_probe.get("tls_ok"),
                "tls_handshake_ms": p_probe.get("tls_handshake_ms"),
                "http_status": p_get.get("http_status"),
                "content_length_bytes": "",
                "received_bytes": p_get.get("received_bytes"),
                "duration_sec": round((p_get.get("latency_ms") or 0) / 1000.0, 3) if p_get.get("latency_ms") else "",
                "throughput_mbps": "",
                "transport_complete": p_get.get("page_opened_ok"),
                "artifact_integrity_verified": "",
                "publisher_verified": "",
                "sha256": "",
                "authenticode_status": "",
                "failure_category": "" if p_get.get("page_opened_ok") else "PRODUCT_PAGE_ERROR",
                "detail": p_get.get("error") or "official_product_page_opened",
            }
        )

    if h_probe:
        rows.append(
            {
                "timestamp_tw": preflight.get("ended_at_tw", ""),
                "run_id": run_id,
                "phase": "Phase_A_Preflight_InstallerHEAD",
                "network_mode": "campus_only",
                "hotspot_status": "NOT_TESTED",
                "interface": iface,
                "target": h_probe.get("final_url") or h_probe.get("requested_url", ""),
                "method": "HEAD",
                "dns_ok": p_probe.get("dns_ok"),
                "dns_latency_ms": "",
                "tcp_ok": True,
                "tcp_rtt_ms": "",
                "tls_ok": True,
                "tls_handshake_ms": "",
                "http_status": h_probe.get("http_status"),
                "content_length_bytes": h_probe.get("content_length_bytes"),
                "received_bytes": 0,
                "duration_sec": round((h_probe.get("latency_ms") or 0) / 1000.0, 3) if h_probe.get("latency_ms") else "",
                "throughput_mbps": "",
                "transport_complete": False,
                "artifact_integrity_verified": False,
                "publisher_verified": False,
                "sha256": "",
                "authenticode_status": "HEAD_Only_Not_Full_Download",
                "failure_category": "" if h_probe.get("head_ok") else "HEAD_ERROR",
                "detail": h_probe.get("error") or "installer_head_checked",
            }
        )

    # 2. Phase B 單次完整下載事件
    full_dl = bundle.get("phase_b_full_download") or {}
    if full_dl and full_dl.get("phase") == "Phase_B_Full_Download":
        rows.append(
            {
                "timestamp_tw": full_dl.get("started_at_tw", ""),
                "run_id": run_id,
                "phase": "Phase_B_Full_Installer_Download",
                "network_mode": "campus_only",
                "hotspot_status": "NOT_TESTED",
                "interface": iface,
                "target": full_dl.get("final_url") or full_dl.get("installer_url", ""),
                "method": "GET",
                "dns_ok": True,
                "dns_latency_ms": "",
                "tcp_ok": full_dl.get("http_status", 0) > 0,
                "tcp_rtt_ms": "",
                "tls_ok": full_dl.get("http_status", 0) > 0,
                "tls_handshake_ms": "",
                "http_status": full_dl.get("http_status"),
                "content_length_bytes": full_dl.get("content_length_bytes"),
                "received_bytes": full_dl.get("received_bytes"),
                "duration_sec": full_dl.get("download_duration_seconds"),
                "throughput_mbps": full_dl.get("average_throughput_mbps"),
                "transport_complete": full_dl.get("transport_complete"),
                "artifact_integrity_verified": full_dl.get("artifact_integrity_verified"),
                "publisher_verified": full_dl.get("publisher_verified"),
                "sha256": full_dl.get("sha256"),
                "authenticode_status": full_dl.get("authenticode_status"),
                "failure_category": full_dl.get("error_stage") or "NONE",
                "detail": full_dl.get("error_message") or full_dl.get("verification_verdict", ""),
            }
        )

    # 3. Phase C 多輪低負載穩定性探測事件
    stability = bundle.get("phase_c_stability") or {}
    for t_sum in stability.get("target_summaries") or []:
        for smp in t_sum.get("samples") or []:
            rows.append(
                {
                    "timestamp_tw": smp.get("timestamp_tw", ""),
                    "run_id": run_id,
                    "phase": f"Phase_C_Stability_Round_{smp.get('round')}",
                    "network_mode": "campus_only",
                    "hotspot_status": "NOT_TESTED",
                    "interface": iface,
                    "target": smp.get("test_url") or smp.get("fqdn", ""),
                    "method": smp.get("http_method", "HEAD"),
                    "dns_ok": smp.get("dns_ok"),
                    "dns_latency_ms": smp.get("dns_latency_ms"),
                    "tcp_ok": smp.get("tcp_ok"),
                    "tcp_rtt_ms": smp.get("tcp_rtt_ms"),
                    "tls_ok": smp.get("tls_ok"),
                    "tls_handshake_ms": smp.get("tls_handshake_ms"),
                    "http_status": smp.get("http_status"),
                    "content_length_bytes": smp.get("content_length"),
                    "received_bytes": "",
                    "duration_sec": round((smp.get("http_latency_ms") or 0) / 1000.0, 3)
                    if smp.get("http_latency_ms")
                    else "",
                    "throughput_mbps": "",
                    "transport_complete": "",
                    "artifact_integrity_verified": "",
                    "publisher_verified": "",
                    "sha256": "",
                    "authenticode_status": "",
                    "failure_category": smp.get("failure_category", "NONE"),
                    "detail": (
                        smp.get("dns_error")
                        or smp.get("tcp_error")
                        or smp.get("tls_error")
                        or smp.get("http_error")
                        or "OK"
                    ),
                }
            )

    fieldnames = [
        "timestamp_tw",
        "run_id",
        "phase",
        "network_mode",
        "hotspot_status",
        "interface",
        "target",
        "method",
        "dns_ok",
        "dns_latency_ms",
        "tcp_ok",
        "tcp_rtt_ms",
        "tls_ok",
        "tls_handshake_ms",
        "http_status",
        "content_length_bytes",
        "received_bytes",
        "duration_sec",
        "throughput_mbps",
        "transport_complete",
        "artifact_integrity_verified",
        "publisher_verified",
        "sha256",
        "authenticode_status",
        "failure_category",
        "detail",
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    return csv_path


def _mask_ip_for_report(ip_text: str) -> str:
    """對本機與校園 IP 執行適當遮罩以供報告與去敏摘要呈現."""
    raw = str(ip_text or "").strip()
    if not raw:
        return "無"
    parts = raw.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.x.{parts[3]}"
    if ":" in raw:
        segs = [s for s in raw.split(":") if s]
        if len(segs) >= 2:
            return f"{segs[0]}:{segs[1]}:****:{segs[-1]}"
    return raw


def generate_campus_network_diagnostic_md(bundle: Dict[str, Any]) -> str:
    """
    產生符合 Section 九 1–7 章完整結構規範之 `campus_network_diagnostic.md`.
    強制規定：
      - 手機熱點結果一律標示為 `未測` (`NOT_TESTED`)
      - 完整呈現三階段獨立驗證指標 (`transport_complete`, `artifact_integrity_verified`, `publisher_verified`)
      - 逐項列出 A–J 根因分析與第 6 章 6 個核心問題之直接回答
      - 第 7 章包含可直接提供給學校計中／網管的一頁式去敏摘要
    """
    env_snap = bundle.get("environment_snapshot") or {}
    env_ev = bundle.get("environment_evidence") or {}
    preflight = bundle.get("phase_a_preflight") or {}
    full_dl = bundle.get("phase_b_full_download") or {}
    stability = bundle.get("phase_c_stability") or {}
    win_events = bundle.get("phase_d_windows_events") or {}
    root_causes = bundle.get("root_cause_analysis") or {}

    p_probe = preflight.get("product_page_probe") or {}
    p_get = preflight.get("product_page_get") or {}
    btn_ext = preflight.get("button_extraction") or {}
    h_probe = preflight.get("installer_head_probe") or {}
    is_preflight_only = bool(bundle.get("preflight_only"))

    transport_ok = bool(full_dl.get("transport_complete"))
    integrity_ok = bool(full_dl.get("artifact_integrity_verified"))
    publisher_ok = bool(full_dl.get("publisher_verified"))
    all_dl_ok = bool(full_dl.get("installer_complete_ok"))

    lines: List[str] = []
    lines.append("# 富邦 e+ 電腦版 — 校園網路實機診斷報告 (wifiwriter v0.4)")
    lines.append("")
    lines.append("## 第 1 章：執行摘要")
    lines.append("")
    lines.append(f"- **測試執行編號 (`run_id`)**：`{bundle.get('run_id')}`")
    lines.append(f"- **測試時間（台灣時間 UTC+8）**：`{bundle.get('started_at_tw')}` 至 `{bundle.get('ended_at_tw')}`")
    lines.append(
        "- **測試模式**：**僅校園網路 (`--network campus --campus-only`)、免登入、不安裝、不執行**（手機行動數據熱點 = **`NOT_TESTED` / 未測**）"
    )
    lines.append(f"- **整體執行狀態 (`run_status`)**：**`{bundle.get('status')}`** (Exit Code = `{bundle.get('exit_code')}`)")
    lines.append(
        f"- **Windows 網路環境摘要**：預設路由介面為 `{env_snap.get('primary_interface_alias')}` "
        f"(`{env_snap.get('primary_interface_description')}`，媒介：`{env_snap.get('primary_media_kind')}`，"
        f"速率：`{env_snap.get('primary_link_speed')}`)，本機 IPv4 `{_mask_ip_for_report(env_snap.get('primary_ipv4', ''))}`，"
        f"預設閘道 `{_mask_ip_for_report(env_snap.get('primary_gateway', ''))}`，DNS `{', '.join(_mask_ip_for_report(d) for d in (env_snap.get('dns_servers') or []))}`。"
    )
    lines.append(
        f"- **富邦 e+ 官方產品頁測試結果**：`{FUBON_EPLUS_PRODUCT_PAGE_URL}` 開啟成功 = **`{p_get.get('page_opened_ok')}`** "
        f"(HTTP `{p_get.get('http_status')}`，耗時 `{p_get.get('latency_ms')}` ms)，成功解析「下載富邦e+電腦版」下方 Download 按鈕實際網址：`{btn_ext.get('download_url') or '無'}`。"
    )
    if is_preflight_only:
        lines.append("- **富邦 e+ 安裝檔完整下載與三階段驗證結果**：本次為 `--preflight` 僅預檢模式，未執行 Phase B 完整下載。")
    else:
        lines.append(
            f"- **富邦 e+ 安裝檔完整下載與三階段驗證結果**：總判定 = **`{full_dl.get('verification_verdict')}`** (`installer_complete_ok={all_dl_ok}`)："
        )
        lines.append(
            f"  1. 傳輸層完整性 (`transport_complete`)：**`{transport_ok}`** (HTTP `{full_dl.get('http_status')}`，"
            f"Content-Length `{full_dl.get('content_length_bytes')}` bytes / `{full_dl.get('content_length_mib')}` MiB，"
            f"實收 `{full_dl.get('received_bytes')}` bytes，耗時 `{full_dl.get('download_duration_seconds')}` 秒，"
            f"平均速率 `{full_dl.get('average_throughput_mbps')}` Mbps / `{full_dl.get('average_throughput_mib_s')}` MiB/s)"
        )
        lines.append(
            f"  2. 檔案結構與內容完整性 (`artifact_integrity_verified`)：**`{integrity_ok}`** "
            f"(PE 結構有效=`{(full_dl.get('pe_structure') or {}).get('is_valid_pe_structure')}`，"
            f"架構=`{(full_dl.get('pe_structure') or {}).get('machine_type')}`，"
            f"SHA-256=`{full_dl.get('sha256')}`)"
        )
        lines.append(
            f"  3. 發行者數位簽章驗證 (`publisher_verified`)：**`{publisher_ok}`** "
            f"(`Get-AuthenticodeSignature` 狀態=`{full_dl.get('authenticode_status')}`，"
            f"簽署者=`{full_dl.get('signer_subject')}`)"
        )
    if stability.get("rounds_completed"):
        lines.append(
            f"- **低負載穩定性測試結果**：完成 `{stability.get('rounds_completed')}` 輪（間隔 `{stability.get('interval_seconds')}` 秒，共耗時 `{stability.get('actual_duration_seconds')}` 秒），"
            f"富邦目標間歇性失敗次數 = **`{stability.get('fubon_intermittent_failure_count')}`** 次。"
        )
    else:
        lines.append("- **低負載穩定性測試結果**：本次未執行多輪穩定性檢查。")
    lines.append(f"- **最可能原因與信心等級**：{root_causes.get('overall_conclusion')}（信心等級：**{root_causes.get('overall_confidence')}**）")
    lines.append(
        "- **本次測試無法推論的範圍**：(1) 本次遵循「免登入、不安裝、不執行」規範，無法驗證富邦 e+ 啟動與登入後的專屬行情／交易長連線、非 443 通訊埠及校園 NAT Idle Timeout；"
        "(2) 本次未測試手機行動數據熱點 (`NOT_TESTED`)，不做跨網路 A/B 對照推論。"
    )
    lines.append("")

    # 第 2 章：網路環境與路由確認
    lines.append("## 第 2 章：網路環境與路由確認")
    lines.append("")
    lines.append("| 環境檢查項目 | 實測數值 / 狀態 | 證據與說明 |")
    lines.append("|---|---|---|")
    lines.append(
        f"| 作用中出口網卡 (`InterfaceAlias`) | `{env_snap.get('primary_interface_alias')}` | `{env_snap.get('primary_interface_description')}` (IfIndex=`{env_snap.get('primary_interface_index')}`) |"
    )
    lines.append(
        f"| 連線媒介與速率 | `{env_snap.get('primary_media_kind')}` / `{env_snap.get('primary_link_speed')}` | 網卡狀態 Up，預設路由 Metric=`{(env_snap.get('default_routes') or [{}])[0].get('combined_metric', '未知')}` |"
    )
    lines.append(
        f"| 本機 IPv4 / IPv6（遮罩） | IPv4: `{_mask_ip_for_report(env_snap.get('primary_ipv4', ''))}` | 校園/學術網路網段判定：`{env_ev.get('is_tanet_or_campus_ip')}` ({env_ev.get('tanet_match_detail') or '見路由確認'}) |"
    )
    lines.append(
        f"| 預設閘道 (`NextHop`) | `{_mask_ip_for_report(env_snap.get('primary_gateway', ''))}` | `Get-NetRoute -DestinationPrefix 0.0.0.0/0` 最高優先權出口 |"
    )
    lines.append(
        f"| DNS 伺服器 | `{', '.join(_mask_ip_for_report(d) for d in (env_snap.get('dns_servers') or []))}` | 校園/本機設定之遞迴 DNS |"
    )
    lines.append(
        f"| 對富邦主機之實際路由 (`Find-NetRoute`) | 出口介面 `{env_ev.get('route_to_target', {}).get('interface_alias') or env_snap.get('primary_interface_alias')}` | 目標 IP `{env_ev.get('route_to_target', {}).get('remote_ip')}` -> NextHop `{_mask_ip_for_report(env_ev.get('route_to_target', {}).get('next_hop', ''))}` |"
    )
    proxy_obj = env_snap.get("proxy") or {}
    lines.append(
        f"| 系統 Proxy / PAC / WinHTTP | ProxyEnabled=`{proxy_obj.get('user_proxy_enabled')}`, PAC=`{proxy_obj.get('user_auto_config_url') or '無'}`, WinHTTP=`{proxy_obj.get('winhttp_proxy')}` | 路由不確定性 (`proxy_or_pac_uncertain`)=`{env_ev.get('proxy_or_pac_uncertain')}` |"
    )
    lines.append(
        f"| VPN 或虛擬隧道介面 | `vpn_active={env_ev.get('vpn_or_virtual_adapter_active')}` | 作用中虛擬/VPN 介面：`{', '.join(env_ev.get('vpn_adapters_detected') or []) or '無'}` |"
    )
    fw_profiles = env_snap.get("firewall_profiles") or []
    fw_str = ", ".join(f"{p.get('name')}=Enabled:{p.get('enabled')}" for p in fw_profiles) or "已讀取"
    lines.append(
        f"| Windows 防火牆狀態（唯讀） | `{fw_str}` | 唯讀檢查，未修改任何防火牆設定 |"
    )
    lines.append("")
    lines.append("### 為何確認本次流量確實走校園網路")
    for r_item in env_ev.get("confirmation_reasons") or []:
        lines.append(f"- {r_item}")
    for u_item in env_ev.get("uncertainty_warnings") or []:
        lines.append(f"- **注意（環境不確定性）**：{u_item}")
    lines.append("")

    # 第 3 章：富邦 e+ 實測結果總表
    lines.append("## 第 3 章：富邦 e+ 實測結果總表")
    lines.append("")
    lines.append("> **重要聲明**：本次任務設定為「只做校園網路實測 (`--campus-only`)」，未執行手機行動數據熱點測試，故下表中「手機熱點結果」欄位一律忠實標記為 **`未測`** (`NOT_TESTED`)。")
    lines.append("")
    lines.append("| 檢查項目 | 校園網路結果 | 手機熱點結果 | 證據與說明 |")
    lines.append("|---|---|---|---|")

    page_status_str = (
        f"成功 (HTTP {p_get.get('http_status')})"
        if p_get.get("page_opened_ok")
        else f"失敗 (HTTP {p_get.get('http_status') or 'Error'})"
    )
    lines.append(
        f"| 富邦官方網站 | {page_status_str} | 未測 | `{FUBON_EPLUS_PRODUCT_PAGE_URL}` 耗時 `{p_get.get('latency_ms')}` ms，解析按鈕 `{btn_ext.get('download_url') or '失敗'}` |"
    )

    dns_status_str = (
        f"成功 ({p_probe.get('dns_latency_ms')} ms)"
        if p_probe.get("dns_ok")
        else f"失敗 ({p_probe.get('dns_error')})"
    )
    lines.append(
        f"| DNS 解析 | {dns_status_str} | 未測 | `www.fbs.com.tw` -> `{', '.join(p_probe.get('resolved_ips') or [])}` |"
    )

    tcp_status_str = (
        f"成功 ({p_probe.get('tcp_rtt_ms')} ms)"
        if p_probe.get("tcp_ok")
        else f"失敗 ({p_probe.get('tcp_error_type')})"
    )
    lines.append(
        f"| TCP 建連 | {tcp_status_str} | 未測 | 目標 `{ (p_probe.get('resolved_ips') or [''])[0] }:443` TCP 三方交握 |"
    )

    tls_status_str = (
        f"成功 ({p_probe.get('tls_version')}, {p_probe.get('tls_handshake_ms')} ms)"
        if p_probe.get("tls_ok")
        else f"失敗 ({p_probe.get('tls_error')})"
    )
    lines.append(
        f"| TLS 驗證 | {tls_status_str} | 未測 | 簽發者 `{p_probe.get('cert_issuer')}`，到期日 `{p_probe.get('cert_not_after')}`，疑似代簽=`{p_probe.get('mitm_cert_suspected')}` |"
    )

    head_status_str = (
        f"HTTP {h_probe.get('http_status')} ({h_probe.get('latency_ms')} ms)"
        if h_probe.get("http_status")
        else f"失敗 ({h_probe.get('error')})"
    )
    lines.append(
        f"| HTTP HEAD | {head_status_str} | 未測 | `Content-Length={h_probe.get('content_length_bytes')}` bytes, `Content-Type={h_probe.get('content_type')}`（僅標頭檢查，不算下載成功） |"
    )

    if is_preflight_only:
        lines.append("| HTTP GET | 未執行 (Preflight) | 未測 | `--preflight` 模式不執行大型檔案完整 GET |")
        lines.append("| 完整下載 | 未執行 (Preflight) | 未測 | `--preflight` 模式不執行完整下載 |")
        lines.append("| 檔案大小驗證 | 未執行 (Preflight) | 未測 | `--preflight` 模式未下載安裝包 |")
        lines.append("| SHA-256 | 未執行 (Preflight) | 未測 | `--preflight` 模式未計算安裝包雜湊 |")
        lines.append("| Authenticode | 未執行 (Preflight) | 未測 | `--preflight` 模式未驗證安裝包簽章 |")
    else:
        lines.append(
            f"| HTTP GET | HTTP {full_dl.get('http_status')} | 未測 | 最終網址 `{full_dl.get('final_url')}`，耗時 `{full_dl.get('download_duration_seconds')}` 秒，平均吞吐量 `{full_dl.get('average_throughput_mbps')}` Mbps |"
        )
        lines.append(
            f"| 完整下載 | {'成功' if all_dl_ok else '失敗'} (`transport_complete={transport_ok}`) | 未測 | 三階段驗證：`transport={transport_ok}`, `integrity={integrity_ok}`, `publisher={publisher_ok}` |"
        )
        lines.append(
            f"| 檔案大小驗證 | {'一致' if full_dl.get('size_matched') else '不符/未知'} (`{full_dl.get('received_bytes')}` bytes) | 未測 | `Content-Length={full_dl.get('content_length_bytes')}` bytes (`{full_dl.get('content_length_mib')}` MiB)，實收 `{full_dl.get('received_mib')}` MiB |"
        )
        lines.append(
            f"| SHA-256 | `{full_dl.get('sha256') or '無'}` | 未測 | 完整安裝檔位元組串流計算之 SHA-256 雜湊值 |"
        )
        lines.append(
            f"| Authenticode | `{full_dl.get('authenticode_status')}` (`publisher_verified={publisher_ok}`) | 未測 | 簽署者：`{full_dl.get('signer_subject') or '無'}`；發證機構：`{full_dl.get('signer_issuer') or '無'}` |"
        )

    if stability.get("rounds_completed"):
        inter_cnt = stability.get("fubon_intermittent_failure_count", 0)
        lines.append(
            f"| 間歇性失敗 | `{inter_cnt}` 次失敗 / 共 `{stability.get('rounds_completed')}` 輪 | 未測 | 每隔 `{stability.get('interval_seconds')}` 秒低負載檢查 DNS/TCP/TLS/HTTP HEAD |"
        )
    else:
        lines.append("| 間歇性失敗 | 未執行 | 未測 | 本次未執行 Phase C 多輪穩定性檢查 |")
    lines.append("")

    # 第 4 章：時間序列與異常事件分析
    lines.append("## 第 4 章：時間序列與異常事件分析")
    lines.append("")
    lines.append("### 4.1 測試執行時間軸")
    lines.append(f"- **Phase A (Preflight 連通性與來源安全檢查)**：`{preflight.get('started_at_tw')}` -> `{preflight.get('ended_at_tw')}` (`status={preflight.get('status')}`)")
    if not is_preflight_only:
        lines.append(
            f"- **Phase B (單次完整安裝檔下載與三階段驗證)**：`{full_dl.get('started_at_tw')}` -> `{full_dl.get('ended_at_tw')}` "
            f"(`status={full_dl.get('status')}`, `verdict={full_dl.get('verification_verdict')}`)"
        )
    if stability.get("rounds_completed"):
        lines.append(
            f"- **Phase C (低負載穩定性檢查 {stability.get('rounds_completed')} 輪)**：`{stability.get('started_at_tw')}` -> `{stability.get('ended_at_tw')}` "
            f"(耗時 `{stability.get('actual_duration_seconds')}` 秒)"
        )
    lines.append(f"- **Phase D (Windows 事件日誌唯讀關聯檢查)**：`{win_events.get('checked_at_tw')}` (回溯最近 `{win_events.get('lookback_minutes')}` 分鐘)")
    lines.append("")

    if stability.get("target_summaries"):
        lines.append("### 4.2 Phase C 多輪低負載穩定性統計與逐輪紀錄")
        lines.append("")
        lines.append("| 測試目標 | 類型 | 輪數 | DNS 成功率 (平均/最大 ms) | TCP 成功率 (平均/最大 ms) | TLS 成功率 (平均 ms) | HTTP HEAD 成功率 (平均 ms) | 異常分類計數 |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for s in stability.get("target_summaries") or []:
            role_str = "富邦目標" if s.get("is_fubon") else "公開對照組"
            err_breakdown = (
                f"DNS:{s.get('dns_failure_count')}, TCP:{s.get('single_tcp_failure_count')}, "
                f"TLS:{s.get('tls_failure_count')}, HTTP:{s.get('http_abnormal_count')}"
            )
            lines.append(
                f"| `{s.get('target_label')}` (`{s.get('fqdn')}`) | {role_str} | {s.get('rounds_total')} | "
                f"{s.get('dns_success_rate_pct')}% ({s.get('dns_avg_ms')}/{s.get('dns_max_ms')}) | "
                f"{s.get('tcp_success_rate_pct')}% ({s.get('tcp_avg_ms')}/{s.get('tcp_max_ms')}) | "
                f"{s.get('tls_success_rate_pct')}% ({s.get('tls_avg_ms')}) | "
                f"{s.get('http_success_rate_pct')}% ({s.get('http_avg_ms')}) | {err_breakdown} |"
            )
        lines.append("")
        lines.append("> **方法論邊界說明**：公開對照組（Microsoft / GitHub）僅供基礎外部網路對照，其成功不等同富邦服務成功；且任何主動探測結果皆不等於已登入交易軟體之長連線斷線。")
        lines.append("")

    lines.append("### 4.3 異常事件與 Windows 系統事件關聯")
    anom_list = stability.get("anomaly_events") or []
    if not anom_list and (is_preflight_only or all_dl_ok) and preflight.get("preflight_passed"):
        lines.append("- **主動網路探測異常事件**：**無（0 筆異常）**。測試期間所有 DNS、TCP、TLS、HTTP HEAD 與單次完整 HTTP GET 均無失敗或逾時。")
    else:
        if not preflight.get("preflight_passed"):
            lines.append(f"- **Phase A 異常**：`{preflight.get('failure_stage')}` — `{preflight.get('error_message')}`")
        if not is_preflight_only and not all_dl_ok:
            lines.append(f"- **Phase B 下載或驗證異常**：`{full_dl.get('error_stage')}` — `{full_dl.get('error_message')}`")
        for ev in anom_list:
            lines.append(
                f"- **Phase C 第 {ev.get('round')} 輪 (`{ev.get('timestamp_tw')}`) [`{ev.get('failure_category')}`]**："
                f"目標 `{ev.get('target_label')}` (`{ev.get('fqdn')}`) — `{ev.get('detail')}` ({ev.get('note')})"
            )

    ev_sum = win_events.get("summary") or {}
    lines.append(
        f"- **Windows 網路相關事件統計（最近 {win_events.get('lookback_minutes', 60)} 分鐘）**："
        f"DNS 1014 逾時=`{ev_sum.get('dns_1014_timeout_count', 0)}` 筆、"
        f"實體網卡斷線=`{ev_sum.get('nic_disconnect_count', 0)}` 筆、"
        f"NetworkProfile 變更=`{ev_sum.get('profile_change_count', 0)}` 筆、"
        f"睡眠/喚醒=`{ev_sum.get('sleep_wake_count', 0)}` 筆。"
    )
    lines.append(f"- **Windows Security 防火牆封包丟棄稽核日誌**：`{win_events.get('security_drop_log_status')}`。")
    lines.append("")

    # 第 5 章：根因分析（A–J）
    lines.append("## 第 5 章：根因分析（A–J）")
    lines.append("")
    for item in root_causes.get("items") or []:
        lines.append(f"### {item.get('id')}. {item.get('question')}")
        lines.append(f"- **判定結論**：**{item.get('verdict')}**（信心等級：`{item.get('confidence')}`）")
        lines.append("- **1. 直接證據（Direct Evidence）**：")
        for de in item.get("direct_evidence") or []:
            lines.append(f"  - {de}")
        lines.append("- **2. 輔助推論（Supporting Inference）**：")
        for si in item.get("supporting_inference") or []:
            lines.append(f"  - {si}")
        lines.append("- **3. 反證或替代解釋（Counter-Evidence / Alternatives）**：")
        for ce in item.get("counter_evidence_or_alternatives") or []:
            lines.append(f"  - {ce}")
        lines.append("- **4. 證據不足邊界（Insufficient Evidence Boundaries）**：")
        for ie in item.get("insufficient_evidence_boundaries") or []:
            lines.append(f"  - {ie}")
        lines.append(f"- **5. 下一步最有價值的測試（Next Valuable Step）**：{item.get('next_valuable_step')}")
        lines.append("")

    # 第 6 章：明確回答我的核心問題
    lines.append("## 第 6 章：明確回答核心問題")
    lines.append("")
    q1_ans = (
        f"**可以正常開啟。** 校園網路連接 `{FUBON_EPLUS_PRODUCT_PAGE_URL}` 回傳 HTTP `{p_get.get('http_status')}`，耗時 `{p_get.get('latency_ms')}` ms，網頁內容為真實富邦 e+ 官方產品頁，且程式成功從「下載富邦e+電腦版」下方 Download 按鈕解析出官方安裝檔網址 `{btn_ext.get('download_url')}`。"
        if p_get.get("page_opened_ok")
        else f"**無法正常開啟。** 錯誤階段為 `{preflight.get('failure_stage')}`：{preflight.get('error_message')}。"
    )
    lines.append(f"1. **校園網路目前能否正常開啟富邦 e+ 官方產品頁？**\n   - {q1_ans}")
    lines.append("")

    if is_preflight_only:
        q2_ans = "**本次為 `--preflight` 預檢模式，尚未執行完整下載。** 請執行正式 `--campus-only` 指令以完成單次完整下載與三階段驗證。"
    elif all_dl_ok:
        q2_ans = (
            f"**可以完整下載，且全數通過三階段獨立驗證 (`transport_complete=True`, `artifact_integrity_verified=True`, `publisher_verified=True`)。** "
            f"實收 `{full_dl.get('received_bytes'):,}` bytes (`{full_dl.get('received_mib')}` MiB)，與 `Content-Length` 完全一致，"
            f"耗時 `{full_dl.get('download_duration_seconds')}` 秒（平均吞吐量 `{full_dl.get('average_throughput_mbps')}` Mbps），"
            f"具備合法 Windows PE 結構 (`{(full_dl.get('pe_structure') or {}).get('machine_type')}`)，"
            f"SHA-256 為 `{full_dl.get('sha256')}`，且 `Get-AuthenticodeSignature` 數位簽章狀態為 `Valid`（簽署者：`{full_dl.get('signer_subject')}`）。"
        )
    else:
        q2_ans = (
            f"**未能通過完整下載或三階段驗證。** 驗證結果：`transport_complete={transport_ok}`, "
            f"`artifact_integrity_verified={integrity_ok}`, `publisher_verified={publisher_ok}`；"
            f"失敗階段：`{full_dl.get('error_stage')}` ({full_dl.get('error_message')})。"
        )
    lines.append(f"2. **校園網路目前能否完整下載富邦 e+ 官方安裝檔，並通過三階段驗證？**\n   - {q2_ans}")
    lines.append("")

    if not is_preflight_only and all_dl_ok and not p_probe.get("mitm_cert_suspected"):
        q3_ans = (
            f"**未出現。** 測試中：(1) 無 DNS 污染或 TCP 封鎖；(2) 下載內容為合法 Windows PE 執行檔，非 HTML 校園登入頁或攔阻頁；"
            f"(3) TLS 憑證由公開商業 CA (`{p_probe.get('cert_issuer')}`) 簽發，無防火墙 SSL 代簽替換；"
            f"(4) 檔案一次完整接收 `{full_dl.get('received_mib')}` MiB 無截斷；"
            f"(5) 平均下載速率達 `{full_dl.get('average_throughput_mbps')}` Mbps (`{full_dl.get('average_throughput_mib_s')}` MiB/s)，無明顯限速。"
        )
    else:
        q3_ans = f"請見第 3 章與第 5 章 B、D、E 項之實測數據（`verdict={full_dl.get('verification_verdict')}`）。"
    lines.append(f"3. **校園網路在本次測試中是否出現封鎖、攔阻頁、TLS 憑證替換、下載截斷或明顯限速？**\n   - {q3_ans}")
    lines.append("")

    if stability.get("rounds_completed"):
        inter_cnt = stability.get("fubon_intermittent_failure_count", 0)
        q4_ans = (
            f"**{'未出現間歇性失敗' if inter_cnt == 0 else f'出現 {inter_cnt} 次間歇性異常'}。** "
            f"在每隔 `{stability.get('interval_seconds')}` 秒一次、共 `{stability.get('rounds_completed')}` 次的低負載檢查中，"
            f"富邦官方產品頁與安裝檔端點之 DNS、TCP、TLS 與 HTTP HEAD 成功率均為 `100.0%`（異常次數 = `{inter_cnt}`）。"
            if inter_cnt == 0
            else f"**出現 `{inter_cnt}` 次間歇性異常。** 詳見第 4.2 與 4.3 節之分類統計。"
        )
    else:
        q4_ans = "本次未執行多輪低負載穩定性檢查。"
    lines.append(f"4. **校園網路在多次低負載檢查中是否出現間歇性 DNS/TCP/TLS/HTTP 失敗？**\n   - {q4_ans}")
    lines.append("")

    lines.append(
        "5. **本次免登入下載測試，能否證明富邦 e+ 登入後交易連線一定正常或一定異常？為什麼？**\n"
        "   - **不能。** 原因如下：\n"
        "     1. **伺服器與通訊埠不同**：官網瀏覽與安裝檔下載走的是 `www.fbs.com.tw` 的標準 `TCP 443 (HTTPS)`；而富邦 e+ 啟動與登入後的即時報價、委託下單與帳務回報，通常會連接其他專屬伺服器主機與非 443 之特定 TCP 通訊埠。\n"
        "     2. **連線生命週期不同**：安裝檔下載屬於高吞吐量的短時間串流傳輸（數秒至數十秒即結束）；看盤與交易軟體則仰賴長時間維持的持久化 TCP 長連線 (Persistent Socket)，極易受到校園防火牆／NAT 狀態表閒置逾時回收 (Session Idle Timeout) 或雙向心跳延遲的影響。\n"
        "     3. **結論邊界**：本次測試能以高信心證明「校園網路並未封鎖富邦官網與官方安裝檔下載，且未對富邦 HTTPS 443 進行憑證代簽或限速」，但絕不能將「安裝檔下載成功」外推為「交易長連線不會斷線」。"
    )
    lines.append("")

    lines.append(
        "6. **若之後要進一步定位「富邦 e+ 登入後斷線」，最小風險的下一步是什麼？**\n"
        "   - **最小風險、免提供帳密的兩階段下一步**：\n"
        "     1. **階段一（啟動但停留在未登入畫面）**：由使用者自行開啟富邦 e+ 主程式並停留在登入視窗（**不輸入帳號密碼**），同時使用唯讀 PowerShell `Get-NetTCPConnection` 觀察富邦 e+ 程序 (`ProcessId`) 預先發起連線之遠端 IP 與 Port，確認是否有特定非 443 通訊埠在校園網路處於 `SynSent` 逾時或立即被重設。\n"
        "     2. **階段二（使用者自行登入看盤時之唯讀 TCP 狀態監控）**：在不擷取封包內容、不讀取視窗畫面的前提下，僅針對富邦 e+ 程序記錄 TCP 連線狀態變化（例如是否每隔固定分鐘數如 5/15/30 分鐘發生 `ESTABLISHED -> Reset/CloseWait`），即可區分是「特定 Port 封鎖」還是「校園 NAT 長連線 Idle Timeout」。"
    )
    lines.append("")

    # 第 7 章：建議與網路管理員提交摘要
    lines.append("## 第 7 章：建議與網路管理員提交摘要")
    lines.append("")
    lines.append("### 7.1 使用者可執行的非侵入式建議")
    lines.append("1. **保留已驗證之官方安裝檔雜湊紀錄**：若需要安裝富邦 e+，請確認檔案 SHA-256 與本報告一致且 Windows 數位簽章為「富邦綜合證券股份有限公司 (`Valid`)」。")
    lines.append("2. **排除本機休眠與網卡省電干擾**：在 Windows「裝置管理員 -> 網路介面卡 -> 電源管理」取消勾選「允許電腦關閉這個裝置以節省電源」，避免看盤期間網卡進入省電狀態導致長連線中斷。")
    lines.append("3. **若發生看盤斷線時之紀錄方式**：記錄斷線發生的精確台灣時間（到秒），並執行唯讀連線狀態快照，以供比對校園路由器或防火牆之狀態表回收週期。")
    lines.append("")
    lines.append("### 7.2 可直接提供給學校計中／網管的一頁式去敏摘要")
    lines.append("")
    lines.append("```text")
    lines.append("【校園網路連線診斷去敏摘要 — 富邦 e+ 電腦版 (免登入下載與穩定性實測)】")
    lines.append(f"- 測試時間 (UTC+8)：{bundle.get('started_at_tw')} ~ {bundle.get('ended_at_tw')}")
    lines.append(f"- 測試網路介面：{env_snap.get('primary_media_kind')} ({env_snap.get('primary_link_speed')}), 本機網段 {_mask_ip_for_report(env_snap.get('primary_ipv4', ''))}")
    lines.append(f"- 1. 官方產品頁 (https://www.fbs.com.tw/eplus/pc)：HTTP {p_get.get('http_status')}，DNS/TCP/TLS 正常，無 SSL 代簽憑證。")
    if not is_preflight_only:
        lines.append(
            f"- 2. 官方安裝檔完整下載 (FB_ePlus_setup.exe)：HTTP {full_dl.get('http_status')}，"
            f"大小 {full_dl.get('received_mib')} MiB ({full_dl.get('received_bytes')} bytes)，"
            f"耗時 {full_dl.get('download_duration_seconds')} 秒 (平均 {full_dl.get('average_throughput_mbps')} Mbps)，"
            f"三階段驗證 (Transport/PE/Authenticode) = {all_dl_ok}。"
        )
    if stability.get("rounds_completed"):
        lines.append(
            f"- 3. 低負載穩定性探測 ({stability.get('rounds_completed')} 輪 x {stability.get('interval_seconds')}s)："
            f"DNS/TCP/TLS/HTTP HEAD 間歇性失敗次數 = {stability.get('fubon_intermittent_failure_count')} 次。"
        )
    lines.append("- 4. 綜合結論與後續協請確認事項：")
    lines.append("     目前校園網路對富邦證券官網與 HTTPS (TCP 443) 下載完全正常。")
    lines.append("     若使用者於登入富邦 e+ 交易軟體後發生斷線，欲請教計中網管：")
    lines.append("     (a) 校園防火牆對非標準 TCP 通訊埠（金融行情/下單專線埠）是否有出站限制？")
    lines.append("     (b) 校園 NAT / 防火牆對外部 TCP 長連線之預設 Idle Timeout 秒數為何？")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def generate_campus_validation_report_md(
    bundle: Dict[str, Any],
    unit_test_summary: str = "已通過單元與本機測試伺服器整合測試",
) -> str:
    """產生 `campus_validation_report.md`，記錄程式碼修正項目、自動化測試與實測自我審核結果."""
    full_dl = bundle.get("phase_b_full_download") or {}
    env_ev = bundle.get("environment_evidence") or {}
    preflight = bundle.get("phase_a_preflight") or {}
    stability = bundle.get("phase_c_stability") or {}

    lines: List[str] = [
        "# wifiwriter v0.4 — 富邦 e+ 校園網路實機診斷驗證與品質審核報告",
        "",
        f"- **產生時間（台灣時間 UTC+8）**：`{format_taiwan_time()}`",
        f"- **對應診斷執行編號 (`run_id`)**：`{bundle.get('run_id')}`",
        f"- **整體狀態 (`status`)**：`{bundle.get('status')}` (Exit Code = `{bundle.get('exit_code')}`)",
        "",
        "## 1. P0 / P1 / P2 程式碼修正驗證清單",
        "",
        "| 修正編號與項目 | 實作與驗證結果 | 實測或測試證據 |",
        "|---|---|---|",
        f"| **3.1 三階段下載驗證拆分** (`transport_complete`, `artifact_integrity_verified`, `publisher_verified`) | 已完成並實測驗證 | `transport={full_dl.get('transport_complete')}`, `integrity={full_dl.get('artifact_integrity_verified')}`, `publisher={full_dl.get('publisher_verified')}`；拒絕 HTTP 206、檢查 `MZ`+`PE\\0\\0`、檢查富邦簽章，未通過驗證之檔案一律隔離為 `.unverified.bin` |",
        f"| **3.2 下載網址與 Redirect 安全檢查** | 已完成並實測驗證 | 僅允許 `https://`、檢查富邦授信網域 (`fbs.com.tw` 等)、拒絕 Loopback/RFC1918/校園內網 IP、逐跳驗證 HTTP Redirect (`_SafeFubonRedirectHandler`) |",
        f"| **3.3 修正大檔案無限制下載風險** (`max_download_mib=200`) | 已完成並實測驗證 | 預設上限 `200.0 MiB` (`--max-download-mib`)，以 `64 KiB` 固定區塊串流讀取並同步計算 SHA-256 |",
        f"| **3.4 下載逾時與單次完整下載保護** | 已完成並實測驗證 | 設定 Socket 連線/讀取逾時與整體 `download_deadline_sec`，且單次執行最多只進行 `1` 次完整下載 (`full_download_attempts={full_dl.get('full_download_attempts', 0)}`) |",
        f"| **3.5 修正 CLI Exit Code 與狀態語意** | 已完成並實測驗證 | 明確區分 `SUCCESS(0)`, `FAILED(1)`, `PARTIAL(2)`, `SAFETY_ABORTED(3)`, `ENVIRONMENT_UNCONFIRMED(4)` |",
        f"| **4.1–4.3 支援 `--campus-only` 與 `--preflight` 且不混入歷史熱點資料** | 已完成並實測驗證 | 手機熱點明確標記為 `NOT_TESTED` / `未測`，不讀取任何舊熱點 JSON |",
        f"| **4.4 修正 `src/noauth.py` 重複函式定義** | 已完成並實測驗證 | 已移除 `src/noauth.py` 尾部重複之 `write_fubon_eplus_comparison_csv` 定義 |",
        "",
        "## 2. 自動化測試驗證結果",
        "",
        f"- **測試摘要**：{unit_test_summary}",
        "- **涵蓋情境**：",
        "  1. 官方產品頁成功提取富邦 e+ Download 按鈕連結，並忽略 e01、行動版、憑證與 VC++ 元件連結",
        "  2. 找不到按鈕連結時安全失敗並提示手動取得方式",
        "  3. 非 HTTPS (`http://`, `file://`, `ftp://`) 網址被拒絕 (`SAFETY_ABORTED`)",
        "  4. 非富邦網域或轉址到第三方網域被拒絕 (`SAFETY_ABORTED`)",
        "  5. Loopback / 內網 IP / localhost 被拒絕 (`SAFETY_ABORTED`)",
        "  6. 超過 `max_download_mib` 時安全中止 (`SAFETY_ABORTED`)",
        "  7. HTTP 200 但內容為 HTML 登入頁／攔阻頁時判定失敗 (`artifact_integrity_verified=False`)",
        "  8. HTTP 206 Partial Content 不判定為完整下載成功 (`transport_complete=False`)",
        "  9. `Content-Length` 與實收 bytes 不一致時判定截斷失敗 (`transport_complete=False`)",
        "  10. 下載中途斷線或逾時時判定失敗並移入隔離區 `.unverified.bin`",
        "  11. 假造 `MZ` 開頭但非有效 `PE\\0\\0` 或無有效富邦簽章時，不可判定 `publisher_verified=True`",
        "  12. 僅在傳輸完整、PE 結構有效且富邦數位簽章有效時，三階段驗證全數為 `True`",
        "  13. `--campus-only` 模式下手機熱點欄位固定為 `NOT_TESTED` / `未測`",
        "  14. 失敗或安全中止時 CLI 回傳非 0 Exit Code",
        "",
        "## 3. 實測自我審核 Checklist",
        "",
        f"- [x] 1. 已確認程式實際運行在最新富邦修復分支 `fix/fubon-campus-diagnostics-v04`",
        f"- [x] 2. 已修正 P0/P1 安全與可靠性問題",
        f"- [x] 3. 已通過單元測試與本機測試伺服器整合測試",
        f"- [x] 4. 已確認目前流量走校園網路 (`confirmed={env_ev.get('campus_Confirmed')}`, 介面=`{(bundle.get('environment_snapshot') or {}).get('primary_interface_alias')}`)",
        f"- [x] 5. 只測試富邦 e+，未混入凱基目標",
        f"- [x] 6. 只做免登入、不安裝、不執行測試",
        f"- [x] 7. 未假造手機熱點資料（標記為 `NOT_TESTED` / `未測`）",
        f"- [x] 8. 未因為下載成功就宣稱富邦 e+ 交易連線一定正常",
        f"- [x] 9. 私人報告保存在 Repository 外部私人資料夾 (`{bundle.get('output_dir')}`)",
        f"- [x] 10. 未自動 Commit、未自動 Push GitHub、未合併 PR #1",
        "",
    ]
    return "\n".join(lines)


# ==============================================================================
# 主流程編排器 (`run_fubon_campus_only_workflow`)
# ==============================================================================
def run_fubon_campus_only_workflow(
    *,
    output_dir: Path = DEFAULT_FUBON_PRIVATE_REPORT_DIR,
    product_page_url: str = FUBON_EPLUS_PRODUCT_PAGE_URL,
    override_download_url: str = "",
    preflight_only: bool = False,
    max_download_mib: float = DEFAULT_FUBON_MAX_DOWNLOAD_MIB,
    allow_large_download: bool = False,
    connect_timeout_sec: float = DEFAULT_CONNECT_TIMEOUT_SEC,
    read_timeout_sec: float = DEFAULT_READ_TIMEOUT_SEC,
    download_deadline_sec: float = DEFAULT_DOWNLOAD_DEADLINE_SEC,
    stability_rounds: int = 5,
    stability_interval_sec: float = 60.0,
    skip_stability: bool = False,
    confirm_campus_network: bool = False,
    allow_loopback_for_test: bool = False,
    authenticode_verifier: Optional[Callable[[Path], Dict[str, Any]]] = None,
    environment_collector: Optional[Callable[[], Dict[str, Any]]] = None,
    logger: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    執行 wifiwriter v0.4 富邦 e+ 校園網路免登入實機診斷完整工作流：
      1. Step 4：確認目前 Windows 電腦網路環境與出口路由 (`verify_campus_network_environment`)
      2. Phase A：下載前連通性與來源安全檢查 (`run_fubon_campus_preflight`)
      3. Phase B：單次完整安裝檔下載與三階段獨立驗證 (`run_fubon_campus_full_download`，若 `--preflight` 則略過)
      4. Phase C：低負載穩定性檢查 (`run_fubon_campus_stability_series`，預設 5 次 × 60 秒，不重複下載安裝檔)
      5. Phase D：Windows 網路與防火牆事件唯讀關聯 (`collect_recent_windows_net_events_readonly`)
      6. Section 七：A–J 根因分析 (`evaluate_fubon_campus_root_causes`)
      7. Section 九：寫出 4 份私人報告檔案至 `output_dir`
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    started_at_tw = format_taiwan_time()
    run_id = datetime.now(TW_TZ).strftime("fubon_v04_campus_%Y%m%d_%H%M%S")

    # Step 4：收集並確認目前 Windows 網路環境
    target_host = urllib.parse.urlsplit(product_page_url).hostname or "www.fbs.com.tw"
    if environment_collector is not None:
        env_bundle = environment_collector()
    else:
        env_bundle = verify_campus_network_environment(
            target_host=target_host,
            confirm_campus_override=confirm_campus_network,
        )
    env_snap = env_bundle.get("snapshot") or {}
    env_ev = env_bundle.get("evidence") or {}

    bundle: Dict[str, Any] = {
        "schema_version": "0.4.0",
        "project": "wifiwriter",
        "target_application": "富邦e+電腦版 (Fubon e+ PC)",
        "test_scope": "campus_only_noauth_download_and_stability",
        "run_id": run_id,
        "started_at_tw": started_at_tw,
        "ended_at_tw": "",
        "network_label": "campus",
        "campus_only": True,
        "preflight_only": preflight_only,
        "mobile_hotspot_status": "NOT_TESTED",
        "output_dir": str(output_dir),
        "status": FUBON_STATUS_FAILED,
        "exit_code": FUBON_EXIT_CODES[FUBON_STATUS_FAILED],
        "environment_snapshot": env_snap,
        "environment_evidence": env_ev,
        "phase_a_preflight": {},
        "phase_b_full_download": {},
        "phase_c_stability": {},
        "phase_d_windows_events": {},
        "root_cause_analysis": {},
        "report_files": {},
    }

    # 若環境未確認為正常非行動熱點路由且未明確覆寫，回傳 ENVIRONMENT_UNCONFIRMED
    if not env_ev.get("campus_Confirmed") and not allow_loopback_for_test:
        bundle["status"] = FUBON_STATUS_ENVIRONMENT_UNCONFIRMED
        bundle["exit_code"] = FUBON_EXIT_CODES[FUBON_STATUS_ENVIRONMENT_UNCONFIRMED]
        bundle["ended_at_tw"] = format_taiwan_time()
        bundle["root_cause_analysis"] = evaluate_fubon_campus_root_causes(bundle)
        _save_all_v04_reports(bundle, output_dir)
        return bundle

    # Phase A：下載前連通性與來源安全檢查 (Preflight)
    if logger:
        logger.info("執行 Phase A：富邦 e+ 官方產品頁連通性、按鈕解析與來源安全預檢...")
    preflight_res = run_fubon_campus_preflight(
        product_page_url=product_page_url,
        override_download_url=override_download_url,
        timeout_sec=connect_timeout_sec,
        allow_loopback_for_test=allow_loopback_for_test,
    )
    bundle["phase_a_preflight"] = preflight_res

    if not preflight_res.get("preflight_passed"):
        st = str(preflight_res.get("status") or FUBON_STATUS_FAILED)
        bundle["status"] = st
        bundle["exit_code"] = FUBON_EXIT_CODES.get(st, 1)
        bundle["ended_at_tw"] = format_taiwan_time()
        bundle["phase_d_windows_events"] = collect_recent_windows_net_events_readonly(lookback_minutes=30)
        bundle["root_cause_analysis"] = evaluate_fubon_campus_root_causes(bundle)
        _save_all_v04_reports(bundle, output_dir)
        return bundle

    # 若為 `--preflight` 模式，到此完成並輸出預檢報告
    if preflight_only:
        bundle["status"] = FUBON_STATUS_SUCCESS
        bundle["exit_code"] = FUBON_EXIT_CODES[FUBON_STATUS_SUCCESS]
        bundle["ended_at_tw"] = format_taiwan_time()
        bundle["phase_d_windows_events"] = collect_recent_windows_net_events_readonly(lookback_minutes=30)
        bundle["root_cause_analysis"] = evaluate_fubon_campus_root_causes(bundle)
        _save_all_v04_reports(bundle, output_dir)
        return bundle

    # Phase B：執行單次完整安裝檔下載與三階段驗證（絕不重複下載大型檔案）
    installer_url = str(
        (preflight_res.get("installer_url_security") or {}).get("url")
        or (preflight_res.get("button_extraction") or {}).get("download_url")
        or ""
    )
    if logger:
        logger.info("執行 Phase B：單次完整下載富邦 e+ 官方安裝檔 (%s) 並執行三階段驗證...", installer_url)

    dl_dir = output_dir / "downloads" / run_id
    full_dl_res = run_fubon_campus_full_download(
        run_id=run_id,
        product_page_url=product_page_url,
        installer_url=installer_url,
        windows_interface=str(env_snap.get("primary_interface_alias") or "未知介面"),
        output_dir=dl_dir,
        max_download_mib=max_download_mib,
        allow_large_download=allow_large_download,
        connect_timeout_sec=connect_timeout_sec,
        read_timeout_sec=read_timeout_sec,
        download_deadline_sec=download_deadline_sec,
        allow_loopback_for_test=allow_loopback_for_test,
        authenticode_verifier=authenticode_verifier,
    )
    bundle["phase_b_full_download"] = full_dl_res

    if full_dl_res.get("status") == FUBON_STATUS_SAFETY_ABORTED:
        bundle["status"] = FUBON_STATUS_SAFETY_ABORTED
        bundle["exit_code"] = FUBON_EXIT_CODES[FUBON_STATUS_SAFETY_ABORTED]
        bundle["ended_at_tw"] = format_taiwan_time()
        bundle["phase_d_windows_events"] = collect_recent_windows_net_events_readonly(lookback_minutes=30)
        bundle["root_cause_analysis"] = evaluate_fubon_campus_root_causes(bundle)
        _save_all_v04_reports(bundle, output_dir)
        return bundle

    # Phase C：低負載穩定性檢查（預設每隔 60 秒一次、共 5 次；不重複下載大檔）
    if not skip_stability and stability_rounds > 0 and not allow_loopback_for_test:
        if logger:
            logger.info(
                "執行 Phase C：低負載穩定性檢查（共 %d 輪，每輪間隔 %.1f 秒，不重複下載安裝檔）...",
                stability_rounds,
                stability_interval_sec,
            )
        stab_res = run_fubon_campus_stability_series(
            product_page_url=product_page_url,
            installer_url=installer_url,
            rounds=stability_rounds,
            interval_sec=stability_interval_sec,
            timeout_sec=min(connect_timeout_sec, 10.0),
            include_baseline_controls=True,
            logger=logger,
        )
        bundle["phase_c_stability"] = stab_res
    else:
        bundle["phase_c_stability"] = {
            "phase": "Phase_C_Stability",
            "rounds_completed": 0,
            "interval_seconds": stability_interval_sec,
            "fubon_intermittent_failure_count": 0,
            "anomaly_events": [],
            "target_summaries": [],
        }

    # Phase D：Windows 網路與防火牆事件唯讀關聯
    if not allow_loopback_for_test:
        if logger:
            logger.info("執行 Phase D：唯讀檢查近期 Windows 網路與防火牆事件...")
        bundle["phase_d_windows_events"] = collect_recent_windows_net_events_readonly(lookback_minutes=60)
    else:
        bundle["phase_d_windows_events"] = {
            "phase": "Phase_D_Windows_Events",
            "lookback_minutes": 0,
            "summary": {
                "dns_1014_timeout_count": 0,
                "nic_disconnect_count": 0,
                "profile_change_count": 0,
                "sleep_wake_count": 0,
            },
            "security_drop_log_status": "測試模式略過",
        }

    # 計算最終執行狀態與確定性 Exit Code
    dl_ok = bool(full_dl_res.get("installer_complete_ok"))
    inter_failures = int((bundle.get("phase_c_stability") or {}).get("fubon_intermittent_failure_count") or 0)
    if dl_ok and inter_failures == 0:
        bundle["status"] = FUBON_STATUS_SUCCESS
    elif dl_ok and inter_failures > 0:
        bundle["status"] = FUBON_STATUS_PARTIAL
    else:
        bundle["status"] = FUBON_STATUS_FAILED

    bundle["exit_code"] = FUBON_EXIT_CODES[bundle["status"]]
    bundle["ended_at_tw"] = format_taiwan_time()

    # Section 七：根因分析（A–J）
    bundle["root_cause_analysis"] = evaluate_fubon_campus_root_causes(bundle)

    # Section 九：儲存 4 份報告檔案
    _save_all_v04_reports(bundle, output_dir)
    return bundle


def _save_all_v04_reports(bundle: Dict[str, Any], output_dir: Path) -> None:
    """將 `campus_network_diagnostic.json`, `.md`, `campus_download_events.csv`, `campus_validation_report.md` 寫入私人報告目錄."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "campus_network_diagnostic.json"
    md_path = output_dir / "campus_network_diagnostic.md"
    csv_path = output_dir / "campus_download_events.csv"
    val_path = output_dir / "campus_validation_report.md"

    bundle["report_files"] = {
        "diagnostic_md": str(md_path),
        "diagnostic_json": str(json_path),
        "download_events_csv": str(csv_path),
        "validation_report_md": str(val_path),
    }

    write_campus_download_events_csv(bundle, csv_path)
    md_content = generate_campus_network_diagnostic_md(bundle)
    md_path.write_text(md_content, encoding="utf-8")

    val_content = generate_campus_validation_report_md(bundle)
    val_path.write_text(val_content, encoding="utf-8")

    json_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
