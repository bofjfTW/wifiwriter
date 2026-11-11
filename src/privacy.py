"""隱私保護、敏感資訊掃描與內外診斷資料分離模組 (v0.2)."""

from __future__ import annotations

import argparse
import copy
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 知名公開 DNS / RFC 5737 測試專用網段（不屬於個人或校園端點識別資訊）
SAFE_PUBLIC_OR_TEST_IPS = {
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",
    "255.255.255.0",
    "255.255.0.0",
    "255.0.0.0",
    "::",
    "::1",
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

SAFE_USER_PLACEHOLDERS = {
    "<user>",
    "public",
    "default",
    "defaultuser0",
    "all users",
    "synthetic_user",
    "example_user",
    "student_demo",
}

# Git 允許提交之路徑白名單規則（防止原始報告、個人設定或憑證意外進版控）
GIT_ALLOWED_EXACT_FILES = {
    ".gitignore",
    "AGENTS.md",
    "CHANGELOG.md",
    "README.md",
    "requirements.txt",
    "config/targets.example.json",
    "reports/.gitkeep",
}

GIT_ALLOWED_PREFIXES = (
    "src/",
    "scripts/",
    "docs/",
    "tests/",
    ".github/",
)

GIT_FORBIDDEN_EXTENSIONS = {
    ".pfx",
    ".p12",
    ".cer",
    ".crt",
    ".key",
    ".pem",
    ".pcap",
    ".pcapng",
    ".etl",
    ".dmp",
    ".log",
    ".flag",
    ".pyc",
    ".exe",
    ".msi",
    ".part",
}


def is_rfc5737_test_ip(ip_str: str) -> bool:
    """檢查是否為 IETF RFC 5737 文件與合成測試保留網段 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)."""
    return bool(
        re.match(
            r"^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$",
            ip_str.strip(),
        )
    )


def is_sensitive_client_or_internal_ipv4(ip_str: str) -> bool:
    """檢查是否為未遮罩之內網 (RFC1918)、電信/校網 CGNAT (RFC6598) 或台灣學術網路 (TANet) 位址."""
    val = ip_str.strip()
    if val in SAFE_PUBLIC_OR_TEST_IPS or is_rfc5737_test_ip(val):
        return False
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", val)
    if not m:
        return False
    octets = [int(m.group(i)) for i in range(1, 5)]
    if any(o > 255 for o in octets):
        return False
    a, b, _, _ = octets
    # RFC 1918 Private IPv4
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    # Link-local APIPA
    if a == 169 and b == 254:
        return True
    # RFC 6598 CGNAT
    if a == 100 and 64 <= b <= 127:
        return True
    # TANet common campus IPv4 ranges
    if a == 140 and 109 <= b <= 138:
        return True
    if a == 163 and 13 <= b <= 32:
        return True
    if a == 120 and 96 <= b <= 127:
        return True
    return False


def mask_ip_strict(ip_str: str, preserve_public_target: bool = False) -> str:
    """遮罩 IPv4 / IPv6 位址；對外分享版本連校園 /16 第二段亦一併遮罩以降低學校/系所指紋辨識風險."""
    if not ip_str:
        return ""
    val = ip_str.strip()
    if val in SAFE_PUBLIC_OR_TEST_IPS or is_rfc5737_test_ip(val):
        return val
    if preserve_public_target and not is_sensitive_client_or_internal_ipv4(val.split("/")[0]):
        return val
    m4 = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/\d+)?$", val)
    if m4:
        cidr = m4.group(5) or ""
        a, b = int(m4.group(1)), int(m4.group(2))
        if (a == 140 and 109 <= b <= 138) or (a == 163 and 13 <= b <= 32) or (a == 120 and 96 <= b <= 127):
            return f"{a}.xxx.xxx.xxx{cidr}"
        return f"{a}.{b}.xxx.xxx{cidr}"
    if ":" in val:
        parts = val.split(":")
        if len(parts) >= 2 and parts[0]:
            return f"{parts[0]}:xxxx:xxxx::xxxx"
        return "xxxx:xxxx::xxxx"
    return val


def sanitize_text(
    text: str,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    mask_all_private_ips: bool = True,
) -> str:
    """遮罩文字中之本機路徑、帳號、主機名、Token/密碼/Cookie、身分證、MAC/BSSID 與內網/校園 IP."""
    if not text:
        return ""
    res = text
    uname = username if username is not None else os.environ.get("USERNAME", "")
    hname = hostname if hostname is not None else os.environ.get("COMPUTERNAME", "")

    # 1. Windows / Unix 使用者家目錄路徑
    res = re.sub(
        r"([A-Za-z]:[\\/]+Users[\\/]+)([^\\/\r\n\"'<>]+)",
        lambda m: m.group(1) + ("<USER>" if m.group(2).lower() not in SAFE_USER_PLACEHOLDERS else m.group(2)),
        res,
        flags=re.IGNORECASE,
    )
    res = re.sub(
        r"(/Users/|/home/)([^/\r\n\"'<>]+)",
        lambda m: m.group(1) + ("<USER>" if m.group(2).lower() not in SAFE_USER_PLACEHOLDERS else m.group(2)),
        res,
    )

    # 2. 明確使用者名稱與電腦名稱
    if uname and len(uname) >= 2:
        res = re.sub(re.escape(uname), "<USER>", res, flags=re.IGNORECASE)
    if hname and len(hname) >= 2:
        res = re.sub(re.escape(hname), "<HOST>", res, flags=re.IGNORECASE)

    # 3. 密碼、Token、Cookie、Session、Authorization Secret 欄位
    res = re.sub(
        r"(?i)\b(password|passwd|pwd|token|access_token|refresh_token|session_id|sessionid|cookie|set-cookie|api_key|apikey|secret)\s*([:=])\s*([^\s,;\"']+)",
        r"\1\2[REDACTED_SECRET]",
        res,
    )
    res = re.sub(
        r"(?i)\b(Authorization\s*:\s*(?:Bearer|Basic))\s+[A-Za-z0-9._~+/=-]+",
        r"\1 [REDACTED_TOKEN]",
        res,
    )
    res = re.sub(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b", "[REDACTED_GH_TOKEN]", res)
    res = re.sub(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "[REDACTED_GH_TOKEN]", res)

    # 4. 台灣身分證字號格式
    res = re.sub(r"\b[A-Za-z][12]\d{8}\b", "[REDACTED_TW_ID]", res)

    # 5. MAC / BSSID 位址（保留前 3 組 OUI 或若已為 xx 則維持）
    def _replace_mac(match: re.Match[str]) -> str:
        full_mac = match.group(0)
        if full_mac.lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "00-00-00-00-00-00", "ff-ff-ff-ff-ff-ff"):
            return full_mac
        prefix = match.group(1)
        sep = ":" if ":" in prefix else "-"
        return f"{prefix}{sep}xx{sep}xx{sep}xx"

    res = re.sub(
        r"\b([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})(?:[:-][0-9A-Fa-f]{2}){3}\b",
        _replace_mac,
        res,
    )

    # 6. 內網與校園 IPv4
    if mask_all_private_ips:
        def _replace_ip(match: re.Match[str]) -> str:
            candidate = match.group(0)
            if is_sensitive_client_or_internal_ipv4(candidate):
                return mask_ip_strict(candidate, preserve_public_target=False)
            return candidate

        res = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", _replace_ip, res)

    return res


SENSITIVE_DICT_KEYS = {
    "password",
    "passwd",
    "pwd",
    "token",
    "access_token",
    "refresh_token",
    "cookie",
    "cookies",
    "session_token",
    "session_id",
    "secret",
    "private_key",
    "account_no",
    "account_number",
    "cust_id",
    "idno",
}


def sanitize_data_for_sharing(
    data: Any,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
) -> Any:
    """將內部完整診斷資料深層轉換為可對外分享之去識別化遮罩版本."""
    if isinstance(data, dict):
        sanitized: Dict[str, Any] = {}
        for k, v in data.items():
            key_str = str(k)
            key_lower = key_str.lower()
            if key_lower in SENSITIVE_DICT_KEYS:
                sanitized[key_str] = "[REDACTED_SENSITIVE_FIELD]"
            elif key_lower in ("last_boot_time",):
                # 僅保留日期，避免精確到秒的開機指紋
                val_str = str(v or "")
                sanitized[key_str] = val_str[:10] if len(val_str) >= 10 else val_str
            elif key_lower in ("ip_masked", "next_hop_masked", "address_masked"):
                # 進一步強化 TANet 第二段遮罩
                val_str = str(v or "")
                val_str = re.sub(r"^(140|163|120)\.\d{1,3}\.xxx\.xxx", r"\1.xxx.xxx.xxx", val_str)
                sanitized[key_str] = sanitize_text(val_str, username=username, hostname=hostname)
            else:
                sanitized[key_str] = sanitize_data_for_sharing(v, username=username, hostname=hostname)
        return sanitized
    if isinstance(data, list):
        return [sanitize_data_for_sharing(item, username=username, hostname=hostname) for item in data]
    if isinstance(data, str):
        return sanitize_text(data, username=username, hostname=hostname, mask_all_private_ips=True)
    return copy.deepcopy(data)


def scan_text_for_sensitive_data(
    text: str,
    source_label: str = "<memory>",
    username: Optional[str] = None,
    hostname: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """掃描文字中是否殘留未遮罩之敏感資訊，回傳結構化發現清單."""
    findings: List[Dict[str, Any]] = []
    if not text:
        return findings

    uname = username if username is not None else os.environ.get("USERNAME", "")
    hname = hostname if hostname is not None else os.environ.get("COMPUTERNAME", "")

    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        # 1. 本機真實使用者路徑 C:\Users\<name>
        for m in re.finditer(r"[A-Za-z]:[\\/]+Users[\\/]+([^\\/\r\n\"'<>`]+)", line, flags=re.IGNORECASE):
            user_seg = m.group(1).strip()
            if user_seg.lower() not in SAFE_USER_PLACEHOLDERS and not user_seg.startswith("$"):
                findings.append(
                    {
                        "file": source_label,
                        "line": line_no,
                        "rule": "LOCAL_USER_PATH",
                        "detail": f"偵測到未遮罩本機使用者路徑片段 ({user_seg[:2]}***)",
                    }
                )

        # 2. 環境變數中的真實使用者帳號與電腦主機名
        if uname and len(uname) >= 3 and uname.lower() not in ("user", "admin", "runner", "root"):
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(uname)}(?![A-Za-z0-9_])", line, flags=re.IGNORECASE):
                findings.append(
                    {
                        "file": source_label,
                        "line": line_no,
                        "rule": "REAL_USERNAME",
                        "detail": "偵測到本機目前登入之真實使用者帳號",
                    }
                )
        if hname and len(hname) >= 3:
            if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(hname)}(?![A-Za-z0-9_-])", line, flags=re.IGNORECASE):
                findings.append(
                    {
                        "file": source_label,
                        "line": line_no,
                        "rule": "REAL_HOSTNAME",
                        "detail": "偵測到本機電腦主機名稱",
                    }
                )

        # 3. 私鑰、GitHub Token、Bearer Token、密碼/Cookie 明文賦值
        _pem_begin = "-----" + "BEGIN "
        _pem_key = "PRIVATE " + "KEY-----"
        if _pem_begin in line and _pem_key in line:
            findings.append(
                {
                    "file": source_label,
                    "line": line_no,
                    "rule": "PRIVATE_KEY_BLOCK",
                    "detail": "偵測到 PEM 私鑰標頭",
                }
            )
        if re.search(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b", line):
            findings.append(
                {
                    "file": source_label,
                    "line": line_no,
                    "rule": "GITHUB_TOKEN",
                    "detail": "偵測到 GitHub Personal Access Token",
                }
            )
        for sm in re.finditer(
            r"(?i)\b(password|passwd|pwd|access_token|refresh_token|session_id|cookie|api_key|secret)\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=-]{8,})['\"]?",
            line,
        ):
            val_part = sm.group(2)
            if (
                not val_part.startswith("[REDACTED")
                and val_part.lower() not in ("none", "null", "false", "example_value", "synthetic_token")
                and not val_part.startswith("$")
            ):
                findings.append(
                    {
                        "file": source_label,
                        "line": line_no,
                        "rule": "CREDENTIAL_OR_COOKIE",
                        "detail": f"偵測到疑似明文憑證/Token/Cookie 欄位 ({sm.group(1)})",
                    }
                )

        # 4. 台灣身分證字號格式（排除全重複測試碼以外之格式）
        for idm in re.finditer(r"\b([A-Z][12]\d{8})\b", line):
            findings.append(
                {
                    "file": source_label,
                    "line": line_no,
                    "rule": "TW_NATIONAL_ID_PATTERN",
                    "detail": f"偵測到疑似未遮罩身分證字號格式 ({idm.group(1)[:2]}********)",
                }
            )

        # 5. 未遮罩之完整 6 組十六進位 MAC / BSSID 位址
        for mm in re.finditer(
            r"\b([0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2})\b",
            line,
        ):
            mac_val = mm.group(1).lower()
            if mac_val not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "00-00-00-00-00-00", "ff-ff-ff-ff-ff-ff"):
                findings.append(
                    {
                        "file": source_label,
                        "line": line_no,
                        "rule": "UNMASKED_MAC_BSSID",
                        "detail": f"偵測到完整未遮罩 MAC/BSSID ({mac_val[:8]}:xx:xx:xx)",
                    }
                )

        # 6. 未遮罩之內網 / CGNAT / TANet 校園 IPv4 位址
        for ipm in re.finditer(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", line):
            ip_candidate = ipm.group(1)
            # 排除明顯為軟體四段版本號之情境 (如 v3.0.0.1 或 FileVersion 10.0.19041.1)
            prefix_ctx = line[max(0, ipm.start() - 18) : ipm.start()].lower()
            if any(w in prefix_ctx for w in ("v", "ver", "version", "build")):
                continue
            if is_sensitive_client_or_internal_ipv4(ip_candidate):
                findings.append(
                    {
                        "file": source_label,
                        "line": line_no,
                        "rule": "UNMASKED_INTERNAL_OR_CAMPUS_IP",
                        "detail": f"偵測到未遮罩內網或校園網路 IPv4 ({mask_ip_strict(ip_candidate)})",
                    }
                )

    return findings


def is_path_allowed_for_git(rel_posix_path: str) -> Tuple[bool, str]:
    """驗證相對路徑是否屬於允許提交至 GitHub 之安全範圍."""
    norm = rel_posix_path.replace("\\", "/").strip()
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/")
    if not norm:
        return False, "空白路徑"

    ext = Path(norm).suffix.lower()
    if ext in GIT_FORBIDDEN_EXTENSIONS:
        return False, f"副檔名 {ext} 屬於禁止提交之憑證/日誌/封包/暫存類型"

    if norm in ("network_environment.json", "network_environment.md"):
        return False, "本機網路環境快照不得提交至 GitHub"
    if norm.startswith("reports/") and norm != "reports/.gitkeep":
        return False, "reports/ 下的原始或遮罩診斷產物不得提交至 GitHub（僅允許 reports/.gitkeep）"
    if norm == "config/targets.json" or norm.endswith(".local.json") or norm.endswith(".user.json"):
        return False, "使用者個人目標設定檔不得提交至 GitHub"

    if norm in GIT_ALLOWED_EXACT_FILES:
        return True, "允許之根目錄/範例設定檔"
    if any(norm.startswith(pfx) for pfx in GIT_ALLOWED_PREFIXES):
        return True, "允許之程式碼/文件/測試/CI 目錄"

    return False, f"路徑 `{norm}` 未列入 GitHub 提交白名單"


def scan_files_for_git(
    rel_paths: Iterable[str],
    repo_root: Path = PROJECT_ROOT,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
) -> Dict[str, Any]:
    """針對預備提交至 Git 之檔案清單執行路徑白名單檢查與內容敏感資訊掃描."""
    violations: List[Dict[str, Any]] = []
    checked_count = 0

    for rel in rel_paths:
        norm = rel.replace("\\", "/").strip()
        if not norm:
            continue
        full_path = repo_root / norm
        # 若檔案在暫存區是刪除狀態 (git rm --cached)，允許移除歷史追蹤檔案
        if not full_path.exists():
            continue

        checked_count += 1
        allowed, reason = is_path_allowed_for_git(norm)
        if not allowed:
            violations.append(
                {
                    "file": norm,
                    "line": 0,
                    "rule": "DISALLOWED_GIT_PATH",
                    "detail": reason,
                }
            )
            continue

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            violations.append(
                {
                    "file": norm,
                    "line": 0,
                    "rule": "READ_ERROR",
                    "detail": f"無法讀取檔案進行隱私檢查: {exc}",
                }
            )
            continue

        findings = scan_text_for_sensitive_data(
            content,
            source_label=norm,
            username=username,
            hostname=hostname,
        )
        violations.extend(findings)

    return {
        "passed": len(violations) == 0,
        "checked_files": checked_count,
        "violation_count": len(violations),
        "violations": violations,
    }


def get_git_staged_files(repo_root: Path = PROJECT_ROOT) -> List[str]:
    """取得目前 Git Index 暫存區中新增/修改之檔案清單（排除已刪除 D 狀態）."""
    proc = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"無法讀取 git staged 清單: {proc.stderr.strip()}")
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.privacy",
        description="wifiwriter 隱私與敏感資訊掃描器（Git 提交前強制防護）",
    )
    parser.add_argument(
        "--check-staged",
        action="store_true",
        help="掃描目前 Git 暫存區 (staged) 中所有新增/修改之檔案",
    )
    parser.add_argument(
        "--files",
        nargs="*",
        default=[],
        help="指定要掃描之相對檔案路徑清單",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    target_files: List[str] = []
    if args.check_staged:
        target_files.extend(get_git_staged_files(PROJECT_ROOT))
    if args.files:
        target_files.extend(args.files)

    if not args.check_staged and not args.files:
        # 預設掃描目前所有 git ls-files 已追蹤檔案
        proc = subprocess.run(
            ["git", "ls-files"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        target_files = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]

    result = scan_files_for_git(target_files, repo_root=PROJECT_ROOT)
    if result["passed"]:
        print(f"OK: Privacy scan passed ({result['checked_files']} files verified, 0 violations).")
        return 0

    print(
        f"ABORTED: Privacy scan detected {result['violation_count']} violation(s) across {result['checked_files']} file(s):",
        file=sys.stderr,
    )
    for v in result["violations"]:
        loc = f"{v['file']}:{v['line']}" if v.get("line") else v["file"]
        print(f"  - [{v['rule']}] {loc} -> {v['detail']}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
