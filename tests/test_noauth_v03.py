"""wifiwriter v0.3 免登入診斷模式 (noauth) 與 13+ 項邊界驗收情境測試套件."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analyzer import (  # noqa: E402
    CAT_INSUFFICIENT,
    CAT_MAYBE_RESTRICTED,
    PROTO_UNKNOWN,
    STATUS_SUCCESS,
    TLS_HANDSHAKE_TIMEOUT,
    classify_application_evidence,
    classify_download_evidence,
)
from src.diagnostics import (  # noqa: E402
    DiagnosticStepError,
    build_parser,
    cmd_noauth,
    probe_kgi_endpoint,
    setup_logger,
)
from src.noauth import (  # noqa: E402
    VERDICT_INSUFFICIENT_EVIDENCE,
    VERDICT_INTERMITTENT,
    VERDICT_NOT_APPLICABLE,
    VERDICT_NOT_TESTED,
    VERDICT_POSSIBLE_RESTRICTION,
    VERDICT_VERIFIED_FAILURE,
    VERDICT_VERIFIED_SUCCESS,
    classify_downloaded_file_content,
    classify_noauth_download_evidence,
    compare_fubon_eplus_rounds,
    compare_noauth_ab_runs,
    evaluate_prelogin_mode_gate,
    extract_fubon_eplus_download_url,
    extract_official_download_links_from_html,
    generate_fubon_eplus_report_md,
    generate_noauth_diagnostic_report_md,
    generate_noauth_validation_report_md,
    run_official_download_Verification,
    summarize_single_endpoint_series,
    write_fubon_eplus_comparison_csv,
    write_noauth_ab_csv,
)
from src.privacy import sanitize_data_for_sharing  # noqa: E402


class TestNoAuthV03Scenarios(unittest.TestCase):
    """涵蓋第九節要求之全部 13 項免登入診斷與邊界情境測試."""

    def test_v03_01_only_installer_not_installed(self) -> None:
        """情境 1：只有安裝檔、本機沒有安裝程式 -> 不可判定為受限，且安裝檔可獨立完成簽章與下載驗證."""
        app_verdict = classify_application_evidence(
            {"installed": False, "is_running": False, "firewall_block_rules": 0, "active_tcp_count": 0}
        )
        self.assertEqual(app_verdict["classification"], CAT_INSUFFICIENT)

        dl_rec = {
            "dns_ok": True,
            "tcp_ok": True,
            "tls_ok": True,
            "head_status_code": 200,
            "full_download_attempted": True,
            "prematurely_truncated": False,
            "download_stages": {
                "page_accessible": True,
                "head_ok": True,
                "partial_download_ok": True,
                "full_download_ok": True,
                "installer_verified": True,
                "installer_unverified": False,
            },
        }
        res = classify_noauth_download_evidence(dl_rec)
        self.assertEqual(res["verdict"], VERDICT_VERIFIED_SUCCESS)

    def test_v03_02_installed_but_not_logged_in(self) -> None:
        """情境 2：原本已安裝，但沒有登入 -> 絕不可將尚未登入的交易程式判定為交易連線正常."""
        app_unlogged = classify_application_evidence(
            {
                "installed": True,
                "is_running": True,
                "login_state": "prelogin",
                "firewall_block_rules": 0,
                "active_tcp_count": 2,
            }
        )
        self.assertEqual(app_unlogged["classification"], CAT_INSUFFICIENT)
        self.assertIn("不得將尚未登入的交易程式判定為交易連線正常", app_unlogged["reason"])

        gate = evaluate_prelogin_mode_gate(
            mode="download-only",
            user_consent_launch=False,
            kgi_inspection={"is_installed": True, "is_currently_running": False},
        )
        self.assertEqual(gate["verdict"], VERDICT_NOT_APPLICABLE)
        self.assertFalse(gate["trading_session_verified"])

    def test_v03_03_website_ok_download_endpoint_failed(self) -> None:
        """情境 3：官方網站正常，但下載端點失敗 -> 判定為 POSSIBLE_RESTRICTION."""
        dl_rec = {
            "dns_ok": True,
            "tcp_ok": False,
            "tls_ok": False,
            "head_status_code": 0,
            "full_download_attempted": True,
            "error_summary": "TCP Connection Timed Out",
            "download_stages": {
                "page_accessible": True,
                "head_ok": False,
                "partial_download_ok": False,
                "full_download_ok": False,
                "installer_verified": False,
                "installer_unverified": False,
            },
        }
        res = classify_noauth_download_evidence(dl_rec)
        self.assertEqual(res["verdict"], VERDICT_POSSIBLE_RESTRICTION)
        self.assertIn("官方產品頁可開啟，但下載伺服器 DNS 或 TCP 連線失敗", res["reason"])

    def test_v03_04_head_ok_get_failed(self) -> None:
        """情境 4：HTTP HEAD 成功 (200)，但 HTTP GET 失敗 -> 絕不可視為完整檔案下載成功."""
        dl_rec = {
            "dns_ok": True,
            "tcp_ok": True,
            "tls_ok": True,
            "head_status_code": 200,
            "full_download_attempted": True,
            "prematurely_truncated": False,
            "download_stages": {
                "page_accessible": True,
                "head_ok": True,
                "partial_download_ok": False,
                "full_download_ok": False,
                "installer_verified": False,
                "installer_unverified": False,
            },
        }
        res = classify_noauth_download_evidence(dl_rec)
        self.assertEqual(res["verdict"], VERDICT_POSSIBLE_RESTRICTION)
        self.assertIn("HEAD 200 不能證明完整 EXE 可下載", res["reason"])

        # 同時確認僅執行 HEAD 時僅能標為 INSUFFICIENT_EVIDENCE
        dl_head_only = dict(dl_rec, full_download_attempted=False)
        res_head_only = classify_noauth_download_evidence(dl_head_only)
        self.assertEqual(res_head_only["verdict"], VERDICT_INSUFFICIENT_EVIDENCE)

        legacy_dl = classify_download_evidence(
            {"base_site_status": 200, "download_status": 200, "file_type": ".exe", "get_attempted": True, "get_ok": False}
        )
        self.assertEqual(legacy_dl["classification"], CAT_MAYBE_RESTRICTED)

    def test_v03_05_partial_ok_full_download_interrupted(self) -> None:
        """情境 5：部分下載 (Range) 成功，但完整下載中途截斷 -> 標記為 POSSIBLE_RESTRICTION，不冒充完整下載."""
        dl_rec = {
            "dns_ok": True,
            "tcp_ok": True,
            "tls_ok": True,
            "head_status_code": 200,
            "full_download_attempted": True,
            "prematurely_truncated": True,
            "content_length_bytes": 131800168,
            "downloaded_bytes": 1048576,
            "download_stages": {
                "page_accessible": True,
                "head_ok": True,
                "partial_download_ok": True,
                "full_download_ok": False,
                "installer_verified": False,
                "installer_unverified": False,
            },
        }
        res = classify_noauth_download_evidence(dl_rec)
        self.assertEqual(res["verdict"], VERDICT_POSSIBLE_RESTRICTION)
        self.assertIn("提前中斷", res["reason"])

        # 若只做 Range 未做 Full GET，也只能標為 INSUFFICIENT_EVIDENCE
        dl_partial_only = dict(dl_rec, full_download_attempted=False, prematurely_truncated=False)
        res_partial = classify_noauth_download_evidence(dl_partial_only)
        self.assertEqual(res_partial["verdict"], VERDICT_INSUFFICIENT_EVIDENCE)
        self.assertIn("部分下載不能冒充完整下載成功", res_partial["reason"])

    def test_v03_06_tcp_ok_tls_failed_neutral(self) -> None:
        """情境 6：TCP 成功，但 TLS 失敗 -> 記錄實際錯誤，標為 UNKNOWN，不直接聲稱是專屬協定或學校封鎖."""
        fake_sock = mock.MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.__exit__.return_value = False
        with (
            mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("210.61.188.55", 443))]),
            mock.patch("socket.create_connection", return_value=fake_sock),
            mock.patch("ssl.SSLContext.wrap_socket", side_effect=socket.timeout("TLS timed out")),
        ):
            res = probe_kgi_endpoint("gtstrade.kgieworld.com.tw", 443, "SecServer_URL", "static_ini_candidate", probe_count=1)
        self.assertEqual(res["tls_probe"]["tls_status"], TLS_HANDSHAKE_TIMEOUT)
        self.assertEqual(res["tls_probe"]["application_protocol"], PROTO_UNKNOWN)

    def test_v03_07_installer_signature_unverified(self) -> None:
        """情境 7：下載檔案簽章無法驗證 -> 標為 VERIFIED_FAILURE (INSTALLER_UNVERIFIED) 並停止後續操作."""
        dl_rec = {
            "dns_ok": True,
            "tcp_ok": True,
            "tls_ok": True,
            "head_status_code": 200,
            "full_download_attempted": True,
            "prematurely_truncated": False,
            "download_stages": {
                "page_accessible": True,
                "head_ok": True,
                "partial_download_ok": True,
                "full_download_ok": True,
                "installer_verified": False,
                "installer_unverified": True,
            },
        }
        res = classify_noauth_download_evidence(dl_rec)
        self.assertEqual(res["verdict"], VERDICT_VERIFIED_FAILURE)
        self.assertIn("INSTALLER_UNVERIFIED", res["reason"])

    def test_v03_08_campus_vs_hotspot_dns_diff(self) -> None:
        """情境 8：校園與熱點 DNS 結果不同（如 CDN Anycast 分流）-> 記錄差異並說明 CDN/DNS 分流，不誤判為封鎖."""
        campus_run = {
            "schema_version": "3.0-noauth",
            "run_id": "noauth_campus_1",
            "run_status": STATUS_SUCCESS,
            "network_label": "campus",
            "official_download": {
                "primary_installer_test": {
                    "verdict": VERDICT_VERIFIED_SUCCESS,
                    "download_rate_mbps": 85.0,
                    "sha256": "abc1234567890",
                    "download_stages": {"full_download_ok": True, "installer_verified": True},
                }
            },
            "connectivity": {
                "rounds_completed": 2,
                "interval_seconds": 30.0,
                "endpoints": [
                    {
                        "fqdn": "event.kgi.com.tw",
                        "port": 443,
                        "endpoint_source": "kgi_official_download",
                        "expect_tls": True,
                        "rounds_total": 2,
                        "dns_success_rate_pct": 100.0,
                        "tcp_success_rate_pct": 100.0,
                        "tcp_avg_ms": 10.0,
                        "tls_ok_count": 2,
                        "resolved_ips": ["104.18.16.88"],
                        "verdict": VERDICT_VERIFIED_SUCCESS,
                    }
                ],
            },
        }
        hotspot_run = json.loads(json.dumps(campus_run))
        hotspot_run["run_id"] = "noauth_hotspot_2"
        hotspot_run["network_label"] = "hotspot"
        hotspot_run["connectivity"]["endpoints"][0]["resolved_ips"] = ["172.64.150.10"]

        comp = compare_noauth_ab_runs(campus_run, hotspot_run)
        self.assertTrue(comp["scientifically_comparable"])
        self.assertEqual(comp["verdict"], VERDICT_VERIFIED_SUCCESS)
        self.assertEqual(len(comp["dns_anycast_or_resolver_differences"]), 1)
        self.assertIn("CDN", comp["dns_anycast_or_resolver_differences"][0]["note"])

    def test_v03_09_ab_incomplete_data(self) -> None:
        """情境 9：A/B 資料不完整（缺少手機熱點或輪數不符）-> 標記為無效或不完整對照."""
        campus_only = {
            "schema_version": "3.0-noauth",
            "run_id": "noauth_campus_only",
            "run_status": STATUS_SUCCESS,
            "network_label": "campus",
            "official_download": {},
            "connectivity": {"rounds_completed": 10, "interval_seconds": 30.0, "endpoints": []},
        }
        comp = compare_noauth_ab_runs(campus_only, None)
        self.assertFalse(comp["scientifically_comparable"])
        self.assertEqual(comp["verdict"], VERDICT_INSUFFICIENT_EVIDENCE)
        self.assertIn("無效或不完整對照", comp["conclusion"])

    def test_v03_10_noauth_all_public_ok_session_unverified(self) -> None:
        """情境 10：完全未登入但所有公開端點正常 -> 報告必須明確指出無法因此推論登入後交易 Session 正常."""
        bundle = {
            "run_id": "noauth_test_10",
            "generated_at": "2026-11-10T12:00:00+08:00",
            "mode": "download-only",
            "network_label": "campus",
            "network_environment": {},
            "kgi_static_inspection": {"is_installed": True, "supertsc64_running": False, "axis_running": False},
            "prelogin_evaluation": evaluate_prelogin_mode_gate("download-only", False, {}),
            "official_download": {
                "page_check": {"verdict": VERDICT_VERIFIED_SUCCESS, "http_status": 200},
                "primary_installer_test": {
                    "verdict": VERDICT_VERIFIED_SUCCESS,
                    "download_stages": {"full_download_ok": True, "installer_verified": True},
                },
            },
            "connectivity": {"rounds_completed": 10, "interval_seconds": 30, "endpoints": []},
            "ab_comparison": compare_noauth_ab_runs(None, None),
        }
        md = generate_noauth_diagnostic_report_md(bundle)
        self.assertIn("絕對不能因為安裝檔下載成功或 TCP 初次建連成功，就推論登入後的交易 Session 正常", md)
        self.assertIn("免登入無法驗證的交易 Session 行為", md)

    def test_v03_11_timeout_handling(self) -> None:
        """情境 11：連線測試超時 -> 正確記錄 TIMEOUT 次數並分類為 VERIFIED_FAILURE 或 INTERMITTENT."""
        meta = {"fqdn": "gtstrade.kgieworld.com.tw", "port": 443, "role": "SecServer_URL", "expect_tls": False}
        samples_all_timeout = [
            {"round": 1, "dns_ok": True, "dns_ms": 5.0, "resolved_ips": ["210.61.188.55"], "tcp_ok": False, "tcp_error_type": "TIMEOUT"},
            {"round": 2, "dns_ok": True, "dns_ms": 4.0, "resolved_ips": ["210.61.188.55"], "tcp_ok": False, "tcp_error_type": "TIMEOUT"},
        ]
        summary_fail = summarize_single_endpoint_series(meta, samples_all_timeout)
        self.assertEqual(summary_fail["verdict"], VERDICT_VERIFIED_FAILURE)
        self.assertEqual(summary_fail["tcp_timeout_count"], 2)

        samples_intermittent = [
            {"round": 1, "dns_ok": True, "dns_ms": 5.0, "resolved_ips": ["210.61.188.55"], "tcp_ok": True, "tcp_ms": 18.0, "tcp_error_type": "NONE"},
            {"round": 2, "dns_ok": True, "dns_ms": 4.0, "resolved_ips": ["210.61.188.55"], "tcp_ok": False, "tcp_error_type": "TIMEOUT"},
        ]
        summary_int = summarize_single_endpoint_series(meta, samples_intermittent)
        self.assertEqual(summary_int["verdict"], VERDICT_INTERMITTENT)

    def test_v03_12_official_download_link_unreachable(self) -> None:
        """情境 12：無法存取官方下載連結或頁面無安裝檔連結 -> 不猜測 URL，標記為 VERIFIED_FAILURE."""
        extracted = extract_official_download_links_from_html("<html><body><a href='/about'>About</a></body></html>")
        self.assertIsNone(extracted["primary_installer"])

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("urllib.request.urlopen", side_effect=OSError("Network unreachable")):
                res = run_official_download_Verification(Path(tmp), perform_full_download=False)
            self.assertEqual(res["primary_installer_test"]["verdict"], VERDICT_VERIFIED_FAILURE)
            self.assertEqual(res["primary_installer_test"]["url"], "")

    def test_v03_13_raw_report_sensitive_data_sanitized(self) -> None:
        """情境 13：原始報告可能包含敏感資訊 -> 去識別化版本完全移除路徑帳號、內網 IP 與 Set-Cookie."""
        raw_user_path = "C:\\Users\\" + "secret_student" + "\\Desktop\\NEWgts.exe"
        raw_cookie = "BIGipServerPool=" + "SecretSessionCookieValue12345"
        synthetic_campus_ip = ".".join(["163", "13", "100", "25"])
        dirty_bundle = {
            "run_id": "noauth_dirty",
            "saved_path": raw_user_path,
            "client_ip": synthetic_campus_ip,
            "cookie_leak": f"cookie={raw_cookie}",
        }
        san = sanitize_data_for_sharing(dirty_bundle, username="secret_student")
        dumped = json.dumps(san, ensure_ascii=False)
        self.assertNotIn("secret_student", dumped)
        self.assertNotIn(synthetic_campus_ip, dumped)
        self.assertNotIn("SecretSessionCookieValue12345", dumped)

    def test_v03_14_prelogin_consent_gate_and_cli_parsing(self) -> None:
        """驗證新 CLI 參數解析 (`noauth` / `noauth-compare`) 以及未經授權執行 `prelogin` 時強制阻擋."""
        parser = build_parser()
        a1 = parser.parse_args(["noauth", "--mode", "download-only", "--network", "campus"])
        self.assertEqual(a1.mode, "download-only")
        self.assertEqual(a1.network, "campus")

        a2 = parser.parse_args(["noauth", "--mode", "prelogin", "--network", "campus"])
        self.assertFalse(a2.confirm_user_consent_launch)

        with tempfile.TemporaryDirectory() as tmp:
            logger = setup_logger()
            with self.assertRaises(DiagnosticStepError) as ctx:
                cmd_noauth(a2, logger, base_reports_dir=Path(tmp))
            self.assertEqual(ctx.exception.exit_code, 5)

            csv_p = write_noauth_ab_csv(compare_noauth_ab_runs(None, None), Path(tmp) / "noauth_ab_comparison.csv")
            self.assertTrue(csv_p.exists())
            val_md = generate_noauth_validation_report_md({"run_id": "r1"}, {"total_tests": 31, "passed_tests": 31, "failed_tests": 0})
            self.assertIn("真正的 Windows 實測", val_md)
            self.assertIn("Mock 或合成測試", val_md)
            self.assertIn("無法執行的測試", val_md)

    def test_v03_15_fubon_eplus_button_parser_and_substitute_rejection(self) -> None:
        """驗證富邦e+電腦版按鈕解析：精準提取 #download_pc_app 並拒絕 vcredist/e01/PDF 代測."""
        sample_html = """
        <div class="download_box_pc">
            <p>下載富邦e+電腦版</p>
            <button class="btn_hover_1_page" id="download_pc_app">Download</button>
            <a href="https://download.microsoft.com/download/vcredist_x86.exe">VC++ 2010</a>
            <a href="https://aka.ms/vs/17/release/vc_redist.x86.exe">VC++ 2015</a>
            <a href="/wcm/new_web/download_app/eplus_ap_guide.pdf">使用手冊</a>
        </div>
        <script>
        $("#download_pc_app").on("click", function () {
            var url = '/wcm/new_web/download_app/FB_ePlus_setup.exe';
            window.location.href = url;
        });
        </script>
        """
        res = extract_fubon_eplus_download_url(sample_html)
        self.assertTrue(res["button_found"])
        self.assertEqual(res["download_url"], "https://www.fbs.com.tw/wcm/new_web/download_app/FB_ePlus_setup.exe")
        self.assertEqual(res["file_name"], "FB_ePlus_setup.exe")

        # 若按鈕被錯誤綁定到 Microsoft 元件，必須拒絕代測
        bad_html = sample_html.replace("/wcm/new_web/download_app/FB_ePlus_setup.exe", "https://aka.ms/vc_redist.x86.exe")
        bad_res = extract_fubon_eplus_download_url(bad_html)
        self.assertEqual(bad_res["download_url"], "")
        self.assertIn("拒絕代測", bad_res["error"])

    def test_v03_16_fubon_eplus_html_intercept_and_side_by_side_report(self) -> None:
        """驗證富邦e+電腦版：HTML 攔阻頁不得算成功、未執行標示「未測」、兩輪 SHA-256 相同標示「兩次取得的檔案內容一致」，且完全不含凱基資料."""
        html_ft = classify_downloaded_file_content(b"<!DOCTYPE html><html>Login</html>", "text/html", 32, "FB_ePlus_setup.exe")
        self.assertTrue(html_ft["is_html_login_or_block_page"])
        self.assertFalse(html_ft["is_windows_executable"])

        pe_ft = classify_downloaded_file_content(b"MZ\x90\x00\x03\x00\x00\x00", "application/x-msdownload", 2639140, "FB_ePlus_setup.exe")
        self.assertTrue(pe_ft["is_windows_executable"])
        self.assertTrue(pe_ft["is_small_bootstrapper"])

        campus_round = {
            "route_check_passed": True,
            "taiwan_time": "2026-11-11 10:40:00 +08:00",
            "route_verification": {
                "primary_interface_alias": "Ethernet_Sim",
                "primary_ipv4": "203.0.113.10",
                "primary_gateway": "203.0.113.1",
            },
            "product_page": {
                "page_opened_ok": True,
                "button_extracted": True,
                "http_status": 200,
                "elapsed_seconds": 0.12,
                "extracted_download_url": "https://www.fbs.com.tw/wcm/new_web/download_app/FB_ePlus_setup.exe",
            },
            "installer_download": {
                "taiwan_time": "2026-11-11 10:40:01 +08:00",
                "final_host": "www.fbs.com.tw",
                "head_status": 200,
                "http_status": 200,
                "elapsed_seconds": 0.45,
                "content_length_bytes": 2639140,
                "received_bytes": 2639140,
                "size_matched": True,
                "file_type": pe_ft["file_type_label"],
                "is_windows_executable": True,
                "is_small_bootstrapper": True,
                "bootstrapper_note": "小型安裝啟動器已取得",
                "installer_complete_ok": True,
                "sha256": "abc123def456",
                "authenticode": {"signature_status": "NotSigned", "signer_subject": "無數位簽章"},
                "saved_file_path": "C:\\temp\\round1\\FB_ePlus_setup.exe",
            },
        }

        # 僅完成第一輪時，第二輪必須顯示「未測」
        comp_r1_only = compare_fubon_eplus_rounds(campus_round, None)
        md_r1 = generate_fubon_eplus_report_md(comp_r1_only)
        self.assertIn("未測", md_r1)
        self.assertNotIn("kgi", md_r1.lower())
        self.assertNotIn("超級大三元", md_r1)

        # 兩輪皆完成且 SHA-256 相同時，必須明確寫出「兩次取得的檔案內容一致」
        hotspot_round = json.loads(json.dumps(campus_round))
        comp_both = compare_fubon_eplus_rounds(campus_round, hotspot_round)
        md_both = generate_fubon_eplus_report_md(comp_both)
        self.assertIn("兩次取得的檔案內容一致", md_both)

        with tempfile.TemporaryDirectory() as tmp:
            csv_p = write_fubon_eplus_comparison_csv(comp_both, Path(tmp) / "fubon_eplus_comparison.csv")
            self.assertTrue(csv_p.exists())
            csv_txt = csv_p.read_text(encoding="utf-8-sig")
            self.assertIn("abc123def456", csv_txt)


if __name__ == "__main__":
    unittest.main()
