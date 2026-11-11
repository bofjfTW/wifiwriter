"""wifiwriter v0.4 — 富邦 e+ 校園網路實機診斷與可靠性升級 單元與本機伺服器整合測試."""

from __future__ import annotations

import hashlib
import http.server
import json
import socketserver
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, Dict, Tuple
from unittest import mock

from src.diagnostics import build_parser, cmd_fubon_eplus, setup_logger
from src.fubon_v04 import (
    FUBON_EPLUS_PRODUCT_PAGE_URL,
    FUBON_EXIT_CODES,
    FUBON_STATUS_ENVIRONMENT_UNCONFIRMED,
    FUBON_STATUS_FAILED,
    FUBON_STATUS_PARTIAL,
    FUBON_STATUS_SAFETY_ABORTED,
    FUBON_STATUS_SUCCESS,
    evaluate_campus_environment_evidence,
    evaluate_fubon_campus_root_causes,
    evaluate_three_stage_download_verification,
    extract_fubon_eplus_download_url,
    generate_campus_network_diagnostic_md,
    inspect_pe_binary_structure,
    is_ip_disallowed_for_official_download,
    is_trusted_fubon_domain,
    run_fubon_campus_full_download,
    run_fubon_campus_only_workflow,
    run_fubon_campus_preflight,
    validate_fubon_download_url_security,
)


def _build_synthetic_valid_pe_bytes(payload_size: int = 8192) -> bytes:
    """構造具備合法 DOS Header (`MZ`)、`e_lfanew=0x80`、`PE\\0\\0` 簽章與 x86 (`0x014c`) 標頭之合成測試二進位資料."""
    buf = bytearray(max(payload_size, 512))
    buf[0:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_offset)
    buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, pe_offset + 4, 0x014C)  # IMAGE_FILE_MACHINE_I386
    # 填入可重現之非零內容
    for i in range(pe_offset + 24, len(buf)):
        buf[i] = (i * 31 + 7) & 0xFF
    return bytes(buf)


def _mock_valid_fubon_authenticode(_path: Path) -> Dict[str, Any]:
    """模擬通過富邦綜合證券股份有限公司 Authenticode 簽章驗證."""
    return {
        "checked": True,
        "signature_status": "Valid",
        "status_message": "Signature verified.",
        "signer_subject": "CN=富邦綜合證券股份有限公司, O=富邦綜合證券股份有限公司, L=臺北市, C=TW",
        "signer_issuer": "CN=TWCA Code Signing CA, O=TAIWAN-CA, C=TW",
        "signer_thumbprint": "AABBCCDDEEFF00112233445566778899AABBCCDD",
        "cert_not_after": "2027-12-31T23:59:59",
    }


def _mock_unsigned_authenticode(_path: Path) -> Dict[str, Any]:
    """模擬無數位簽章之檔案."""
    return {
        "checked": True,
        "signature_status": "NotSigned",
        "status_message": "The file is not signed.",
        "signer_subject": "",
        "signer_issuer": "",
        "signer_thumbprint": "",
        "cert_not_after": "",
    }


class _LocalFubonTestServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class TestFubonV04UnitAndIntegration(unittest.TestCase):
    """涵蓋 Section 八全部 19 項單元測試與本機測試伺服器整合測試情境."""

    def test_01_extract_button_and_ignore_other_links(self) -> None:
        """情境 1 & 2：成功提取「下載富邦 e+ 電腦版」按鈕連結，並忽略同頁面的 e01、行動版、憑證工具、Microsoft VC++ 連結."""
        sample_html = """
        <html><body>
          <div class="other-links">
            <a href="https://www.fbs.com.tw/H5Web/Template/download_pc_app/Fubon_e01_setup.exe">下載富邦e01</a>
            <a href="https://www.fbs.com.tw/mobile/eplus_mobile.apk">富邦行動版</a>
            <a href="https://www.fbs.com.tw/ca/FubonCertTool.exe">憑證工具</a>
            <a href="https://aka.ms/vs/17/release/vc_redist.x86.exe">Microsoft VC++ 元件</a>
          </div>
          <section class="eplus-pc">
            <h3>下載富邦e+電腦版</h3>
            <p>系統需求說明</p>
            <a class="btn-download" href="/H5Web/Template/download_pc_app/FB_ePlus_setup.exe">Download</a>
          </section>
        </body></html>
        """
        res = extract_fubon_eplus_download_url(sample_html, base_url=FUBON_EPLUS_PRODUCT_PAGE_URL)
        self.assertTrue(res["found"])
        self.assertEqual(
            res["download_url"],
            "https://www.fbs.com.tw/H5Web/Template/download_pc_app/FB_ePlus_setup.exe",
        )
        self.assertEqual(res["file_name"], "FB_ePlus_setup.exe")
        self.assertGreaterEqual(len(res["ignored_other_links"]), 3)

    def test_02_missing_button_fails_safely_with_manual_instructions(self) -> None:
        """情境 3：找不到按鈕連結時安全失敗並提示手動取得方式."""
        html_without_eplus = """
        <html><body>
          <a href="https://www.fbs.com.tw/H5Web/Template/download_pc_app/Fubon_e01_setup.exe">下載富邦e01</a>
          <a href="https://aka.ms/vs/17/release/vc_redist.x86.exe">Download Microsoft</a>
        </body></html>
        """
        res = extract_fubon_eplus_download_url(html_without_eplus, base_url=FUBON_EPLUS_PRODUCT_PAGE_URL)
        self.assertFalse(res["found"])
        self.assertEqual(res["download_url"], "")
        self.assertIn("如何在瀏覽器手動取得", res["browser_manual_instructions"])

    def test_03_reject_non_https_schemes(self) -> None:
        """情境 4：非 HTTPS 連結被拒絕 (`http://`, `file://`, `ftp://`)."""
        for bad_url in (
            "http://www.fbs.com.tw/H5Web/Template/download_pc_app/FB_ePlus_setup.exe",
            "file:///C:/Windows/System32/cmd.exe",
            "ftp://www.fbs.com.tw/pub/FB_ePlus_setup.exe",
        ):
            check = validate_fubon_download_url_security(bad_url, resolve_dns=False)
            self.assertFalse(check["security_ok"], f"Should reject {bad_url}")
            self.assertEqual(check["failure_stage"], "UNSAFE_URL_SCHEME")

    def test_04_reject_untrusted_domains(self) -> None:
        """情境 5：非富邦網域或偽造子網域被拒絕."""
        self.assertTrue(is_trusted_fubon_domain("www.fbs.com.tw"))
        self.assertTrue(is_trusted_fubon_domain("fbs.com.tw"))
        self.assertFalse(is_trusted_fubon_domain("fbs.com.tw.evil.example.com"))
        self.assertFalse(is_trusted_fubon_domain("evil-phishing.org"))

        check = validate_fubon_download_url_security(
            "https://evil.example.com/FB_ePlus_setup.exe",
            resolve_dns=False,
        )
        self.assertFalse(check["security_ok"])
        self.assertEqual(check["failure_stage"], "UNTRUSTED_DOWNLOAD_DOMAIN")

    def test_05_reject_loopback_private_and_campus_ips(self) -> None:
        """情境 6：Loopback / 內網 IP / localhost / 校園網段 IP 被拒絕作為下載目標."""
        loopback_ip = ".".join(["127", "0", "0", "1"])
        private_ip = ".".join(["192", "168", "1", "10"])
        campus_ip = ".".join(["140", "112", "8", "9"])
        public_ip = ".".join(["8", "8", "8", "8"])

        for bad_ip in (loopback_ip, "::1", private_ip, campus_ip, "0.0.0.0"):
            disallowed, reason = is_ip_disallowed_for_official_download(bad_ip)
            self.assertTrue(disallowed, f"IP {bad_ip} should be disallowed")
            self.assertTrue(len(reason) > 0)

        disallowed_pub, _ = is_ip_disallowed_for_official_download(public_ip)
        self.assertFalse(disallowed_pub)

        for bad_url in (
            f"https://{loopback_ip}/FB_ePlus_setup.exe",
            "https://localhost/FB_ePlus_setup.exe",
            f"https://{private_ip}/FB_ePlus_setup.exe",
        ):
            chk = validate_fubon_download_url_security(bad_url, resolve_dns=False)
            self.assertFalse(chk["security_ok"])

    def test_06_fake_mz_and_three_stage_verification_split(self) -> None:
        """情境 8, 9, 10, 12, 13, 14：驗證三階段布林指標拆分，拒絕假造 MZ、HTTP 206、截斷與無效簽章."""
        valid_pe_bytes = _build_synthetic_valid_pe_bytes(4096)
        valid_pe_info = inspect_pe_binary_structure(valid_pe_bytes)
        self.assertTrue(valid_pe_info["has_mz_magic"])
        self.assertTrue(valid_pe_info["has_pe_signature"])
        self.assertTrue(valid_pe_info["is_valid_pe_structure"])

        # 假造 MZ 開頭但無 PE\0\0 結構
        fake_mz_bytes = b"MZ" + b"This is not a real PE file, just starts with MZ!" * 20
        fake_pe_info = inspect_pe_binary_structure(fake_mz_bytes)
        self.assertTrue(fake_pe_info["has_mz_magic"])
        self.assertFalse(fake_pe_info["is_valid_pe_structure"])

        sha_valid = hashlib.sha256(valid_pe_bytes).hexdigest()

        # (a) 假造 MZ + 無簽章 -> artifact_integrity_verified=False, publisher_verified=False
        v_fake_mz = evaluate_three_stage_download_verification(
            http_status=200,
            content_range_header="",
            content_length_bytes=len(fake_mz_bytes),
            received_bytes=len(fake_mz_bytes),
            stream_completed_cleanly=True,
            is_html_page=False,
            pe_info=fake_pe_info,
            sha256_hex=hashlib.sha256(fake_mz_bytes).hexdigest(),
            authenticode_info=_mock_unsigned_authenticode(Path("dummy.exe")),
        )
        self.assertTrue(v_fake_mz["transport_complete"])
        self.assertFalse(v_fake_mz["artifact_integrity_verified"])
        self.assertFalse(v_fake_mz["publisher_verified"])
        self.assertFalse(v_fake_mz["installer_complete_ok"])

        # (b) HTTP 206 Partial Content -> transport_complete=False
        v_206 = evaluate_three_stage_download_verification(
            http_status=206,
            content_range_header="bytes 0-4095/8192",
            content_length_bytes=4096,
            received_bytes=4096,
            stream_completed_cleanly=True,
            is_html_page=False,
            pe_info=valid_pe_info,
            sha256_hex=sha_valid,
            authenticode_info=_mock_valid_fubon_authenticode(Path("dummy.exe")),
        )
        self.assertFalse(v_206["transport_complete"])
        self.assertEqual(v_206["failure_stage"], "PARTIAL_CONTENT_206_REJECTED")
        self.assertFalse(v_206["installer_complete_ok"])

        # (c) Content-Length 與實收 bytes 不一致 -> transport_complete=False
        v_trunc = evaluate_three_stage_download_verification(
            http_status=200,
            content_range_header="",
            content_length_bytes=8192,
            received_bytes=4096,
            stream_completed_cleanly=True,
            is_html_page=False,
            pe_info=valid_pe_info,
            sha256_hex=sha_valid,
            authenticode_info=_mock_valid_fubon_authenticode(Path("dummy.exe")),
        )
        self.assertFalse(v_trunc["transport_complete"])
        self.assertEqual(v_trunc["failure_stage"], "CONTENT_LENGTH_MISMATCH_TRUNCATED")
        self.assertFalse(v_trunc["installer_complete_ok"])

        # (d) 有效 PE 但未簽章或非富邦簽署者 -> transport=True, integrity=True, publisher=False
        v_unsigned = evaluate_three_stage_download_verification(
            http_status=200,
            content_range_header="",
            content_length_bytes=4096,
            received_bytes=4096,
            stream_completed_cleanly=True,
            is_html_page=False,
            pe_info=valid_pe_info,
            sha256_hex=sha_valid,
            authenticode_info=_mock_unsigned_authenticode(Path("dummy.exe")),
        )
        self.assertTrue(v_unsigned["transport_complete"])
        self.assertTrue(v_unsigned["artifact_integrity_verified"])
        self.assertFalse(v_unsigned["publisher_verified"])
        self.assertFalse(v_unsigned["installer_complete_ok"])
        self.assertEqual(v_unsigned["verification_verdict"], "VERIFICATION_FAILED")

        # (e) 三階段全數通過 -> installer_complete_ok=True
        v_all_ok = evaluate_three_stage_download_verification(
            http_status=200,
            content_range_header="",
            content_length_bytes=4096,
            received_bytes=4096,
            stream_completed_cleanly=True,
            is_html_page=False,
            pe_info=valid_pe_info,
            sha256_hex=sha_valid,
            authenticode_info=_mock_valid_fubon_authenticode(Path("dummy.exe")),
        )
        self.assertTrue(v_all_ok["transport_complete"])
        self.assertTrue(v_all_ok["artifact_integrity_verified"])
        self.assertTrue(v_all_ok["publisher_verified"])
        self.assertTrue(v_all_ok["installer_complete_ok"])
        self.assertEqual(v_all_ok["verification_verdict"], "VERIFIED_OFFICIAL_INSTALLER")

    def test_07_local_http_server_integration_scenarios(self) -> None:
        """
        本機測試伺服器整合測試（涵蓋完整下載成功、超過大小上限、HTTP 200 HTML 攔阻頁、HTTP 206 Partial、
        Content-Length 截斷、Redirect 至非授信第三方網域、假造 MZ 隔離為 .unverified.bin）.
        """
        valid_pe_payload = _build_synthetic_valid_pe_bytes(16384)
        fake_mz_payload = b"MZ" + b"corrupted_non_pe_payload" * 100
        html_portal_payload = b"<!DOCTYPE html><html><head><title>Campus Captive Portal Login</title></head><body>Please login</body></html>"

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def do_HEAD(self) -> None:
                if self.path == "/eplus/pc":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                elif self.path == "/H5Web/Template/download_pc_app/FB_ePlus_setup.exe":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(valid_pe_payload)))
                    self.send_header("Accept-Ranges", "bytes")
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_GET(self) -> None:
                if self.path == "/eplus/pc":
                    page = (
                        "<html><body><h3>下載富邦e+電腦版</h3>"
                        '<a href="/H5Web/Template/download_pc_app/FB_ePlus_setup.exe">Download</a>'
                        "</body></html>"
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(page)))
                    self.end_headers()
                    self.wfile.write(page)
                elif self.path == "/H5Web/Template/download_pc_app/FB_ePlus_setup.exe":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(valid_pe_payload)))
                    self.end_headers()
                    self.wfile.write(valid_pe_payload)
                elif self.path == "/partial_206.exe":
                    self.send_response(206)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Range", f"bytes 0-1023/{len(valid_pe_payload)}")
                    self.send_header("Content-Length", "1024")
                    self.end_headers()
                    self.wfile.write(valid_pe_payload[:1024])
                elif self.path == "/html_block.exe":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html_portal_payload)))
                    self.end_headers()
                    self.wfile.write(html_portal_payload)
                elif self.path == "/truncated.exe":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(valid_pe_payload) * 2))
                    self.end_headers()
                    self.wfile.write(valid_pe_payload)
                elif self.path == "/fake_mz.exe":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(fake_mz_payload)))
                    self.end_headers()
                    self.wfile.write(fake_mz_payload)
                elif self.path == "/redirect_evil.exe":
                    self.send_response(302)
                    self.send_header("Location", "https://evil-attacker.example.org/malware.exe")
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()

        server = _LocalFubonTestServer(("127.0.0.1", 0), _Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        base_url = f"http://127.0.0.1:{port}"
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)

                # 1. Preflight + 完整下載成功且通過三階段驗證
                pre_ok = run_fubon_campus_preflight(
                    product_page_url=f"{base_url}/eplus/pc",
                    allow_loopback_for_test=True,
                )
                self.assertTrue(pre_ok["preflight_passed"])
                self.assertEqual(
                    pre_ok["button_extraction"]["download_url"],
                    f"{base_url}/H5Web/Template/download_pc_app/FB_ePlus_setup.exe",
                )

                dl_ok = run_fubon_campus_full_download(
                    run_id="test_ok",
                    product_page_url=f"{base_url}/eplus/pc",
                    installer_url=f"{base_url}/H5Web/Template/download_pc_app/FB_ePlus_setup.exe",
                    windows_interface="Ethernet_Test",
                    output_dir=tmp_path / "dl_ok",
                    allow_loopback_for_test=True,
                    authenticode_verifier=_mock_valid_fubon_authenticode,
                )
                self.assertEqual(dl_ok["status"], FUBON_STATUS_SUCCESS)
                self.assertTrue(dl_ok["transport_complete"])
                self.assertTrue(dl_ok["artifact_integrity_verified"])
                self.assertTrue(dl_ok["publisher_verified"])
                self.assertTrue(dl_ok["installer_complete_ok"])
                self.assertEqual(dl_ok["sha256"], hashlib.sha256(valid_pe_payload).hexdigest())
                self.assertTrue(Path(dl_ok["saved_verified_installer_path"]).exists())

                # 2. 超過 max_download_mib 上限 -> SAFETY_ABORTED
                dl_oversize = run_fubon_campus_full_download(
                    run_id="test_oversize",
                    product_page_url=f"{base_url}/eplus/pc",
                    installer_url=f"{base_url}/H5Web/Template/download_pc_app/FB_ePlus_setup.exe",
                    windows_interface="Ethernet_Test",
                    output_dir=tmp_path / "dl_oversize",
                    max_download_mib=0.005,  # ~5 KiB < 16 KiB
                    allow_large_download=False,
                    allow_loopback_for_test=True,
                    authenticode_verifier=_mock_valid_fubon_authenticode,
                )
                self.assertEqual(dl_oversize["status"], FUBON_STATUS_SAFETY_ABORTED)
                self.assertEqual(dl_oversize["error_stage"], "MAX_DOWNLOAD_SIZE_EXCEEDED")
                self.assertFalse(dl_oversize["installer_complete_ok"])

                # 3. HTTP 206 Partial Content -> 拒絕視為完整下載
                dl_206 = run_fubon_campus_full_download(
                    run_id="test_206",
                    product_page_url=f"{base_url}/eplus/pc",
                    installer_url=f"{base_url}/partial_206.exe",
                    windows_interface="Ethernet_Test",
                    output_dir=tmp_path / "dl_206",
                    allow_loopback_for_test=True,
                    authenticode_verifier=_mock_valid_fubon_authenticode,
                )
                self.assertEqual(dl_206["status"], FUBON_STATUS_FAILED)
                self.assertFalse(dl_206["transport_complete"])
                self.assertFalse(dl_206["installer_complete_ok"])
                self.assertEqual(dl_206["error_stage"], "PARTIAL_CONTENT_206_REJECTED")
                # 確認未留下 .exe 檔案，而是隔離為 .unverified.bin
                self.assertEqual(dl_206["saved_verified_installer_path"], "")
                self.assertTrue(dl_206["quarantined_file_path"].endswith(".unverified.bin"))

                # 4. HTTP 200 但內容為 HTML 登入頁／攔阻頁 -> 判定失敗
                dl_html = run_fubon_campus_full_download(
                    run_id="test_html",
                    product_page_url=f"{base_url}/eplus/pc",
                    installer_url=f"{base_url}/html_block.exe",
                    windows_interface="Ethernet_Test",
                    output_dir=tmp_path / "dl_html",
                    allow_loopback_for_test=True,
                    authenticode_verifier=_mock_valid_fubon_authenticode,
                )
                self.assertEqual(dl_html["status"], FUBON_STATUS_FAILED)
                self.assertTrue(dl_html["is_html_login_or_block_page"])
                self.assertFalse(dl_html["artifact_integrity_verified"])
                self.assertFalse(dl_html["installer_complete_ok"])

                # 5. Content-Length 與實收 bytes 不一致 -> 截斷失敗
                dl_trunc = run_fubon_campus_full_download(
                    run_id="test_trunc",
                    product_page_url=f"{base_url}/eplus/pc",
                    installer_url=f"{base_url}/truncated.exe",
                    windows_interface="Ethernet_Test",
                    output_dir=tmp_path / "dl_trunc",
                    allow_loopback_for_test=True,
                    authenticode_verifier=_mock_valid_fubon_authenticode,
                )
                self.assertEqual(dl_trunc["status"], FUBON_STATUS_FAILED)
                self.assertFalse(dl_trunc["transport_complete"])
                self.assertFalse(dl_trunc["size_matched"])
                self.assertEqual(dl_trunc["error_stage"], "CONTENT_LENGTH_MISMATCH_TRUNCATED")

                # 6. 假造 MZ 但無 PE\0\0 且無簽章 -> 拒絕當成有效安裝檔並隔離為 .unverified.bin
                dl_fakemz = run_fubon_campus_full_download(
                    run_id="test_fakemz",
                    product_page_url=f"{base_url}/eplus/pc",
                    installer_url=f"{base_url}/fake_mz.exe",
                    windows_interface="Ethernet_Test",
                    output_dir=tmp_path / "dl_fakemz",
                    allow_loopback_for_test=True,
                    authenticode_verifier=_mock_unsigned_authenticode,
                )
                self.assertEqual(dl_fakemz["status"], FUBON_STATUS_FAILED)
                self.assertTrue(dl_fakemz["transport_complete"])
                self.assertFalse(dl_fakemz["artifact_integrity_verified"])
                self.assertFalse(dl_fakemz["publisher_verified"])
                self.assertFalse(dl_fakemz["installer_complete_ok"])
                self.assertTrue(Path(dl_fakemz["quarantined_file_path"]).exists())
                self.assertFalse((tmp_path / "dl_fakemz" / "FB_ePlus_setup.exe").exists())

                # 7. HTTP 302 Redirect 到非富邦第三方網域 -> 立即觸發 SAFETY_ABORTED
                dl_redir = run_fubon_campus_full_download(
                    run_id="test_redir",
                    product_page_url=f"{base_url}/eplus/pc",
                    installer_url=f"{base_url}/redirect_evil.exe",
                    windows_interface="Ethernet_Test",
                    output_dir=tmp_path / "dl_redir",
                    allow_loopback_for_test=True,
                    authenticode_verifier=_mock_valid_fubon_authenticode,
                )
                self.assertEqual(dl_redir["status"], FUBON_STATUS_SAFETY_ABORTED)
                self.assertIn(dl_redir["error_stage"], ("UNTRUSTED_DOWNLOAD_DOMAIN", "UNSAFE_REDIRECT_TARGET"))
        finally:
            server.shutdown()
            server.server_close()

    def test_08_campus_environment_confirmation_and_hotspot_not_tested(self) -> None:
        """情境 15, 16, 17：驗證校園網路環境確認、熱點欄位固定為 NOT_TESTED / 未測，以及非 0 Exit Code."""
        # 行動網路介面應拒絕誤判為校園網路
        cellular_snap = {
            "primary_interface_alias": "Cellular",
            "primary_interface_description": "Generic Mobile Broadband Adapter",
            "primary_media_kind": "Cellular_Mobile",
            "primary_ipv4": ".".join(["10", "100", "1", "5"]),
            "primary_gateway": ".".join(["10", "100", "1", "1"]),
            "dns_servers": ["8.8.8.8"],
            "proxy": {"user_proxy_enabled": 0, "user_auto_config_url": "", "winhttp_proxy": "Direct access"},
            "vpn_or_virtual_adapters": [],
        }
        ev_cell = evaluate_campus_environment_evidence(cellular_snap)
        self.assertFalse(ev_cell["campus_Confirmed"])

        # 校園 TANet 有線網路應確認通過，且若有 PAC / Proxy 則標記路由不確定性
        tanet_ip = ".".join(["140", "112", "42", "18"])
        tanet_gw = ".".join(["140", "112", "42", "254"])
        tanet_dns = ".".join(["140", "112", "254", "4"])
        campus_snap = {
            "primary_interface_alias": "乙太網路",
            "primary_interface_description": "Intel(R) Ethernet Connection",
            "primary_media_kind": "Wired_Ethernet",
            "primary_link_speed": "1 Gbps",
            "primary_ipv4": tanet_ip,
            "primary_gateway": tanet_gw,
            "dns_servers": [tanet_dns],
            "proxy": {
                "user_proxy_enabled": 0,
                "user_auto_config_url": "http://pac.example.edu.tw/proxy.pac",
                "winhttp_proxy": "Direct access (no proxy server)",
            },
            "vpn_or_virtual_adapters": [],
            "route_to_target": {"remote_ip": "203.0.113.10", "interface_alias": "乙太網路", "next_hop": tanet_gw},
        }
        ev_campus = evaluate_campus_environment_evidence(campus_snap)
        self.assertTrue(ev_campus["campus_Confirmed"])
        self.assertTrue(ev_campus["proxy_or_pac_uncertain"])

        # 驗證 Exit Codes 語意
        self.assertEqual(FUBON_EXIT_CODES[FUBON_STATUS_SUCCESS], 0)
        self.assertEqual(FUBON_EXIT_CODES[FUBON_STATUS_FAILED], 1)
        self.assertEqual(FUBON_EXIT_CODES[FUBON_STATUS_PARTIAL], 2)
        self.assertEqual(FUBON_EXIT_CODES[FUBON_STATUS_SAFETY_ABORTED], 3)
        self.assertEqual(FUBON_EXIT_CODES[FUBON_STATUS_ENVIRONMENT_UNCONFIRMED], 4)

        # 驗證 CLI 在安全性中止時回傳非 0 Exit Code (3)
        parser = build_parser()
        logger = setup_logger()
        with tempfile.TemporaryDirectory() as tmp:
            args_bad = parser.parse_args(
                [
                    "fubon-eplus",
                    "--network",
                    "hotspot",
                    "--campus-only",
                    "--output-dir",
                    tmp,
                ]
            )
            code = cmd_fubon_eplus(args_bad, logger)
            self.assertEqual(code, FUBON_EXIT_CODES[FUBON_STATUS_SAFETY_ABORTED])

    def test_09_campus_only_report_generation_and_no_kgi_contamination(self) -> None:
        """確認 `--campus-only` 產生之 4 份報告結構完整、熱點固定為未測 (`NOT_TESTED`)，且無凱基殘留."""
        tanet_ip = ".".join(["140", "112", "42", "18"])
        tanet_gw = ".".join(["140", "112", "42", "254"])
        tanet_dns = ".".join(["140", "112", "254", "4"])
        mock_env = {
            "snapshot": {
                "primary_interface_alias": "乙太網路",
                "primary_interface_description": "Intel(R) Ethernet Connection",
                "primary_media_kind": "Wired_Ethernet",
                "primary_link_speed": "1 Gbps",
                "primary_ipv4": tanet_ip,
                "primary_gateway": tanet_gw,
                "dns_servers": [tanet_dns],
                "proxy": {"user_proxy_enabled": 0, "user_auto_config_url": "", "winhttp_proxy": "Direct access"},
                "vpn_or_virtual_adapters": [],
                "firewall_profiles": [{"name": "Public", "enabled": True}],
            },
            "evidence": {
                "campus_Confirmed": True,
                "is_tanet_or_campus_ip": True,
                "tanet_match_detail": "TANet",
                "proxy_or_pac_uncertain": False,
                "vpn_or_virtual_adapter_active": False,
                "confirmation_reasons": ["預設路由走校園有線網路"],
                "uncertainty_warnings": [],
                "route_to_target": {"remote_ip": "203.0.113.10", "interface_alias": "乙太網路", "next_hop": tanet_gw},
            },
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            # 先放一個假造的舊熱點檔案，確認 --campus-only 絕不會讀取或混入
            (out_dir / "latest_hotspot_round.json").write_text(
                json.dumps({"network_label": "hotspot", "installer_download": {"sha256": "OLD_HOTSPOT_SHA"}}),
                encoding="utf-8",
            )
            bundle = run_fubon_campus_only_workflow(
                output_dir=out_dir,
                product_page_url="http://127.0.0.1:9/unreached",
                preflight_only=True,
                allow_loopback_for_test=False,
                environment_collector=lambda: mock_env,
            )
            # 因為 http:// 非 https，Phase A 會 SAFETY_ABORTED (Exit Code 3)
            self.assertEqual(bundle["status"], FUBON_STATUS_SAFETY_ABORTED)
            self.assertEqual(bundle["exit_code"], 3)
            self.assertEqual(bundle["mobile_hotspot_status"], "NOT_TESTED")

            md_path = Path(bundle["report_files"]["diagnostic_md"])
            json_path = Path(bundle["report_files"]["diagnostic_json"])
            csv_path = Path(bundle["report_files"]["download_events_csv"])
            val_path = Path(bundle["report_files"]["validation_report_md"])
            for p in (md_path, json_path, csv_path, val_path):
                self.assertTrue(p.exists(), f"Missing report file: {p}")

            md_text = md_path.read_text(encoding="utf-8")
            self.assertNotIn("OLD_HOTSPOT_SHA", md_text)
            self.assertNotIn("超級大三元", md_text)
            self.assertIn("| 富邦官方網站 |", md_text)
            self.assertIn("| 未測 |", md_text)
            self.assertIn("## 第 5 章：根因分析（A–J）", md_text)
            self.assertIn("## 第 6 章：明確回答核心問題", md_text)
            self.assertIn("## 第 7 章：建議與網路管理員提交摘要", md_text)


if __name__ == "__main__":
    unittest.main()
