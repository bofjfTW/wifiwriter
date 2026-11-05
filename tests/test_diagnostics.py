"""單元測試：驗證隱私遮罩、限制證據分類、根本原因決策規則、A/B 對照與報告產生器."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analyzer import (  # noqa: E402
    CAT_CONFIRMED_BLOCK,
    CAT_CONN_FAIL,
    CAT_INSUFFICIENT,
    CAT_MAYBE_RESTRICTED,
    CAT_NORMAL,
    analyze_kgi_endpoint_probes,
    classify_application_evidence,
    classify_download_evidence,
    classify_website_evidence,
    compare_ab_results,
    evaluate_root_causes,
    mask_ip,
    mask_sensitive_text,
)
from src.diagnostics import build_parser  # noqa: E402
from src.report_generator import (  # noqa: E402
    generate_html_report,
    generate_network_environment_markdown,
    generate_research_report_markdown,
    write_csv_summary,
)


class TestPrivacyMasking(unittest.TestCase):
    def test_mask_ip_masks_campus_and_private_ips(self) -> None:
        self.assertEqual(mask_ip("140.113.24.89"), "140.113.xxx.xxx")
        self.assertEqual(mask_ip("192.168.1.105"), "192.168.xxx.xxx")
        self.assertEqual(mask_ip("8.8.8.8"), "8.8.8.8")
        self.assertEqual(mask_ip("168.95.1.1"), "168.95.1.1")
        self.assertEqual(mask_ip("203.69.12.34", preserve_public_target=True), "203.69.12.34")

    def test_mask_sensitive_text(self) -> None:
        raw = r"User student01 on DESKTOP-9988AA MAC aa:bb:cc:11:22:33 ID A123456789"
        masked = mask_sensitive_text(raw, username="student01", hostname="DESKTOP-9988AA")
        self.assertNotIn("student01", masked)
        self.assertNotIn("DESKTOP-9988AA", masked)
        self.assertNotIn("11:22:33", masked)
        self.assertNotIn("A123456789", masked)
        self.assertIn("<USER>", masked)
        self.assertIn("<HOST>", masked)
        self.assertIn("[REDACTED_ID]", masked)


class TestRestrictionClassifiers(unittest.TestCase):
    def test_http_403_not_misclassified_as_school_block(self) -> None:
        res = classify_website_evidence(
            {
                "url": "https://example.com/",
                "dns_ok": True,
                "tcp_success_rate": "3/3",
                "intermittent": False,
                "tls": {"ok": True, "issuer": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"},
                "http": {"status_code": 403, "location": ""},
            }
        )
        self.assertEqual(res["classification"], CAT_INSUFFICIENT)

    def test_explicit_block_redirect_classified_confirmed_block(self) -> None:
        res = classify_website_evidence(
            {
                "url": "https://example.com/",
                "dns_ok": True,
                "tcp_success_rate": "3/3",
                "intermittent": False,
                "tls": {"ok": True, "issuer": "CN=DigiCert"},
                "http": {"status_code": 302, "location": "http://10.0.0.1/fortiguard/blockpage"},
            }
        )
        self.assertEqual(res["classification"], CAT_CONFIRMED_BLOCK)

    def test_mitm_cert_classified_maybe_restricted(self) -> None:
        res = classify_website_evidence(
            {
                "url": "https://www.kgi.com.tw/",
                "dns_ok": True,
                "tcp_success_rate": "3/3",
                "intermittent": False,
                "tls": {"ok": False, "issuer": "CN=Fortinet_CA_SSL"},
                "http": {"status_code": 200, "location": ""},
            }
        )
        self.assertEqual(res["classification"], CAT_MAYBE_RESTRICTED)

    def test_normal_website(self) -> None:
        res = classify_website_evidence(
            {
                "url": "https://www.microsoft.com/",
                "dns_ok": True,
                "tcp_success_rate": "3/3",
                "intermittent": False,
                "tls": {"ok": True, "issuer": "CN=Microsoft Azure RSA TLS Issuing CA"},
                "http": {"status_code": 200, "location": ""},
            }
        )
        self.assertEqual(res["classification"], CAT_NORMAL)

    def test_non_running_application_never_marked_restricted(self) -> None:
        res = classify_application_evidence(
            {
                "installed": True,
                "is_running": False,
                "firewall_block_rules": 0,
                "active_tcp_count": 0,
            }
        )
        self.assertEqual(res["classification"], CAT_INSUFFICIENT)
        self.assertIn("未啟動", res["reason"])

    def test_firewall_blocked_application(self) -> None:
        res = classify_application_evidence(
            {
                "installed": True,
                "is_running": True,
                "firewall_block_rules": 1,
                "active_tcp_count": 0,
            }
        )
        self.assertEqual(res["classification"], CAT_CONFIRMED_BLOCK)

    def test_download_classifier(self) -> None:
        ok_res = classify_download_evidence(
            {"base_site_status": 200, "download_status": 200, "file_type": ".exe"}
        )
        self.assertEqual(ok_res["classification"], CAT_NORMAL)

        drop_res = classify_download_evidence(
            {"base_site_status": 200, "download_status": 0, "file_type": ".exe"}
        )
        self.assertEqual(drop_res["classification"], CAT_MAYBE_RESTRICTED)

        fail_res = classify_download_evidence(
            {"base_site_status": 0, "download_status": 0, "file_type": ".exe"}
        )
        self.assertEqual(fail_res["classification"], CAT_CONN_FAIL)


class TestKgiAndRootCauseEngine(unittest.TestCase):
    def test_proprietary_protocol_over_443_detected(self) -> None:
        probes = [
            {
                "fqdn": "gtstrade.kgieworld.com.tw",
                "primary_ip": "203.69.0.1",
                "port": 443,
                "dns_ok": True,
                "tcp_ok_count": 3,
                "tcp_rtts_ms": [11.2, 12.0, 11.5],
                "tcp_rst_observed": False,
                "tls_probe": {"tls_handshake_ok": False, "detail": "Non-TLS HTS socket"},
            }
        ]
        summary = analyze_kgi_endpoint_probes(probes)
        self.assertEqual(summary["tcp_reachable_count"], 1)
        self.assertEqual(len(summary["proprietary_binary_over_443_endpoints"]), 1)

    def test_evaluate_root_causes_covers_all_seven_categories(self) -> None:
        causes = evaluate_root_causes(
            network_env={"primary_connection": {"connection_type": "Ethernet"}},
            restrictions={},
            kgi_inspection={"is_currently_running": False},
            kgi_probe_analysis={
                "total_endpoints_tested": 4,
                "tcp_reachable_count": 4,
                "proprietary_binary_over_443_endpoints": [
                    {"fqdn": "gtstrade.kgieworld.com.tw", "ip": "1.2.3.4", "port": 443}
                ],
            },
        )
        codes = {c["code"] for c in causes}
        self.assertEqual(codes, {"A", "B", "C", "D", "E", "F", "G"})
        for c in causes:
            self.assertTrue(len(c["supporting_evidence"]) >= 1)
            self.assertTrue(len(c["counter_evidence"]) >= 1)

    def test_ab_comparison_conservative_conclusion(self) -> None:
        untested = compare_ab_results(None, None)
        self.assertEqual(untested["status"], "未測試")

        campus = {
            "sample_count": 60,
            "metrics": {
                "connection_success_rate_pct": 88.0,
                "tcp_connect_avg_ms": 25.0,
                "disconnect_count": 4,
                "avg_connection_duration_sec": 360.0,
                "dns_success_rate_pct": 100.0,
                "reconnect_count": 6,
                "network_anomaly_events": 1,
                "app_error_count": 0,
            },
        }
        hotspot = {
            "sample_count": 60,
            "metrics": {
                "connection_success_rate_pct": 100.0,
                "tcp_connect_avg_ms": 42.0,
                "disconnect_count": 0,
                "avg_connection_duration_sec": 1800.0,
                "dns_success_rate_pct": 100.0,
                "reconnect_count": 0,
                "network_anomaly_events": 0,
                "app_error_count": 0,
            },
        }
        comp = compare_ab_results(campus, hotspot)
        self.assertIn("與學校網路環境有關", comp["conclusion"])
        self.assertIn("不能直接證實", comp["conclusion"])


class TestReportAndCli(unittest.TestCase):
    def test_cli_parser_commands(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["monitor", "start", "--interval", "30", "--label", "campus"])
        self.assertEqual(args.command, "monitor")
        self.assertEqual(args.monitor_action, "start")
        self.assertEqual(args.label, "campus")

    def test_report_generators_produce_valid_outputs(self) -> None:
        dummy_bundle = {
            "generated_at": "2026-11-05T22:00:00+08:00",
            "network_environment": {"primary_connection": {"connection_type": "Ethernet"}},
            "restrictions": {"websites": [], "applications": [], "downloads": []},
            "kgi_inspection": {"is_installed": True, "install_directories": ["D:\\超級大三元"]},
            "kgi_endpoint_probes": [],
            "kgi_probe_analysis": {},
            "ab_comparison": compare_ab_results(None, None),
            "root_causes": [],
        }
        env_md = generate_network_environment_markdown(dummy_bundle["network_environment"])
        rep_md = generate_research_report_markdown(dummy_bundle)
        rep_html = generate_html_report(dummy_bundle)
        self.assertIn("network_environment.md", env_md)
        self.assertIn("證據可信度分級", rep_md)
        self.assertIn("<!DOCTYPE html>", rep_html)

        with tempfile.TemporaryDirectory() as tmp:
            csvs = write_csv_summary(
                dummy_bundle["restrictions"],
                [],
                dummy_bundle["ab_comparison"],
                Path(tmp),
            )
            self.assertTrue(Path(csvs["diagnostic_summary_csv"]).exists())
            self.assertTrue(Path(csvs["ab_comparison_csv"]).exists())


if __name__ == "__main__":
    unittest.main()

