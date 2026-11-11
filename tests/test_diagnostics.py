"""完整單元測試套件 (v0.2)：涵蓋 14+ 項核心可靠性、事件分類、TLS 無預設推論、生命週期、A/B 驗證與隱私防護情境."""

from __future__ import annotations

import argparse
import copy
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analyzer import (  # noqa: E402
    CAT_CONFIRMED_BLOCK,
    CAT_CONN_FAIL,
    CAT_INSUFFICIENT,
    CAT_MAYBE_RESTRICTED,
    CAT_NORMAL,
    EV_CONTROL_ENDPOINT_FAILURE,
    EV_KGI_APP_DISCONNECT_REPORTED,
    EV_KGI_PROBE_FAILURE,
    EV_KGI_PROCESS_EXITED,
    EV_KGI_RECONNECTED,
    EV_KGI_SOCKET_DISCONNECTED,
    PROTO_UNKNOWN,
    STATUS_FAILED,
    STATUS_NOT_TESTED,
    STATUS_PARTIAL,
    STATUS_SUCCESS,
    TIER_CONFIRMED_FACT,
    TIER_UNVERIFIED_HYPOTHESIS,
    TLS_HANDSHAKE_EOF,
    TLS_HANDSHAKE_RESET,
    TLS_HANDSHAKE_TIMEOUT,
    analyze_kgi_endpoint_probes,
    analyze_monitor_dataset,
    classify_application_evidence,
    classify_download_evidence,
    classify_website_evidence,
    compare_ab_results,
    evaluate_root_causes,
    mask_ip,
    mask_sensitive_text,
    validate_artifact_freshness,
)
from src.diagnostics import (  # noqa: E402
    DiagnosticStepError,
    build_parser,
    cmd_all,
    cmd_mark,
    cmd_simulate,
    probe_kgi_endpoint,
    setup_logger,
    verify_step_output_json,
)
from src.privacy import (  # noqa: E402
    is_path_allowed_for_git,
    sanitize_data_for_sharing,
    scan_files_for_git,
    scan_text_for_sensitive_data,
)
from src.report_generator import (  # noqa: E402
    generate_html_report,
    generate_network_environment_markdown,
    generate_research_report_markdown,
    write_csv_summary,
)

FIXTURE_PATH = PROJECT_ROOT / "tests" / "fixtures" / "synthetic_monitor_data.json"


class TestEventTaxonomyAndMonitorStats(unittest.TestCase):
    """對應第三節與第九節：修正斷線定義、Socket 正常輪替、程序退出分離與手動標記關聯."""

    def test_1_kgi_not_running_probe_failure_is_not_trading_disconnect(self) -> None:
        """驗收情境 1：凱基程式未啟動，探測失敗，必須顯示『探測失敗，尚無交易程式斷線證據』且斷線數為 0."""
        samples = [
            {
                "timestamp": "2026-11-06T10:00:00+08:00",
                "sample_index": 1,
                "net_up": True,
                "kgi_running": False,
                "process_identity_summary": "not_running",
                "kgi_established_sockets": 0,
                "kgi_socket_keys": [],
                "active_probe_executed": True,
                "kgi_quote_probe": {"dns_ok": True, "tcp_ok": False, "error": "TCP_TIMEOUT"},
                "kgi_trade_probe": {"dns_ok": True, "tcp_ok": False, "error": "TCP_TIMEOUT"},
                "control_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 15.0},
            }
        ]
        res = analyze_monitor_dataset(samples, manual_marks=[], run_id="run_test_idle")
        self.assertEqual(res["metrics"]["confirmed_trading_disconnect_count"], 0)
        self.assertEqual(res["metrics"]["disconnect_count"], 0)
        evs = res["event_timeline"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["event_type"], EV_KGI_PROBE_FAILURE)
        self.assertIn("探測失敗，尚無交易程式斷線證據", evs[0]["observed_state"])

    def test_2_kgi_running_but_public_control_website_fails(self) -> None:
        """情境 2：凱基程式正常運作，但公開對照網站失敗 -> 僅記為 CONTROL_ENDPOINT_FAILURE."""
        samples = [
            {
                "timestamp": "2026-11-06T10:05:00+08:00",
                "sample_index": 1,
                "net_up": True,
                "kgi_running": True,
                "process_identity_summary": "axis.exe(PID=1234,Sig=Valid:KGI)",
                "kgi_established_sockets": 2,
                "kgi_socket_keys": ["1234:50001->203.0.113.10:443", "1234:50002->203.0.113.11:443"],
                "active_probe_executed": True,
                "kgi_quote_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 12.0},
                "kgi_trade_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 12.5},
                "control_probe": {"dns_ok": True, "tcp_ok": False, "error": "TCP_TIMEOUT"},
            }
        ]
        res = analyze_monitor_dataset(samples, manual_marks=[], run_id="run_ctrl_fail")
        self.assertEqual(res["metrics"]["confirmed_trading_disconnect_count"], 0)
        self.assertEqual(res["metrics"]["event_counts"][EV_CONTROL_ENDPOINT_FAILURE], 1)
        self.assertEqual(res["metrics"]["event_counts"][EV_KGI_PROBE_FAILURE], 0)

    def test_4_normal_socket_turnover_without_app_disconnect_report(self) -> None:
        """情境 4：Socket 正常更新（開啟新子通道並關閉短連線），交易軟體未回報斷線 -> 不算已確認交易斷線，且精確計算可辨識時長."""
        samples = [
            {
                "timestamp": "2026-11-06T10:10:00+08:00",
                "sample_index": 1,
                "net_up": True,
                "kgi_running": True,
                "kgi_socket_keys": ["1234:50001->203.0.113.10:443"],
                "active_probe_executed": False,
            },
            {
                "timestamp": "2026-11-06T10:10:05+08:00",
                "sample_index": 2,
                "net_up": True,
                "kgi_running": True,
                "kgi_socket_keys": [
                    "1234:50001->203.0.113.10:443",
                    "1234:50099->203.0.113.12:443",
                ],
                "active_probe_executed": False,
            },
            {
                "timestamp": "2026-11-06T10:10:20+08:00",
                "sample_index": 3,
                "net_up": True,
                "kgi_running": True,
                "kgi_socket_keys": ["1234:50001->203.0.113.10:443"],
                "active_probe_executed": False,
            },
        ]
        res = analyze_monitor_dataset(samples, manual_marks=[], run_id="run_turnover")
        m = res["metrics"]
        self.assertEqual(m["observed_socket_open_count"], 1)
        self.assertEqual(m["observed_socket_close_count"], 1)
        self.assertEqual(m["confirmed_trading_disconnect_count"], 0)
        self.assertEqual(m["avg_identifiable_socket_duration_sec"], 15.0)
        self.assertEqual(m["event_counts"][EV_KGI_SOCKET_DISCONNECTED], 1)

    def test_5_process_exit_separated_from_socket_disconnect_and_unbounded_duration_marked_unestimable(self) -> None:
        """情境 5：程式退出 (KGI_PROCESS_EXITED) 與 Socket 中斷分開處理；無法精確觀測生滅之連線標示為『無法精確估計』."""
        samples = [
            {
                "timestamp": "2026-11-06T10:20:00+08:00",
                "sample_index": 1,
                "net_up": True,
                "kgi_running": True,
                "kgi_socket_keys": ["1234:50001->203.0.113.10:443"],
                "active_probe_executed": False,
            },
            {
                "timestamp": "2026-11-06T10:20:05+08:00",
                "sample_index": 2,
                "net_up": True,
                "kgi_running": False,
                "kgi_socket_keys": [],
                "active_probe_executed": False,
            },
        ]
        res = analyze_monitor_dataset(samples, manual_marks=[], run_id="run_proc_exit")
        m = res["metrics"]
        self.assertEqual(m["event_counts"][EV_KGI_PROCESS_EXITED], 1)
        self.assertEqual(m["event_counts"][EV_KGI_SOCKET_DISCONNECTED], 0)
        self.assertEqual(m["confirmed_trading_disconnect_count"], 0)
        self.assertIsNone(m["avg_identifiable_socket_duration_sec"])
        self.assertEqual(m["identifiable_connection_duration_display"], "無法精確估計")

    def test_manual_mark_correlates_with_process_socket_dns_tcp_and_win_events(self) -> None:
        """驗收情境 2：使用者手動標記斷線時，與同時間程序、Socket、DNS、TCP 與 Windows 網路狀態建立可追溯關聯."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            rt_dir = tmp_dir / "internal" / "monitor_runtime"
            rt_dir.mkdir(parents=True, exist_ok=True)
            jsonl_file = rt_dir / "monitor_run_live1.jsonl"
            marks_file = rt_dir / "marks_run_live1.jsonl"
            sample = {
                "timestamp": datetime.now().isoformat() if False else "2026-11-06T11:00:00+08:00",
                "sample_index": 1,
                "net_up": True,
                "kgi_running": True,
                "process_identity_summary": "axis.exe(PID=8888,Sig=Valid:KGI)",
                "kgi_established_sockets": 0,
                "kgi_socket_keys": [],
                "kgi_quote_probe": {"dns_ok": True, "tcp_ok": False, "error": "TCP_RST"},
                "kgi_trade_probe": {"dns_ok": True, "tcp_ok": False, "error": "TCP_TIMEOUT"},
                "control_probe": {"dns_ok": True, "tcp_ok": True, "tcp_ms": 11.0},
                "system_event_types": ["DNS_Timeout_1014"],
            }
            jsonl_file.write_text(json.dumps(sample) + "\n", encoding="utf-8")

            res = analyze_monitor_dataset(
                samples=[sample],
                manual_marks=[
                    {
                        "timestamp": "2026-11-06T11:00:04+08:00",
                        "run_id": "run_live1",
                        "event": "kgi-disconnected",
                        "note": "看盤報價停止更新",
                    },
                    {
                        "timestamp": "2026-11-06T11:00:25+08:00",
                        "run_id": "run_live1",
                        "event": "kgi-reconnected",
                        "note": "手動重連成功",
                    },
                ],
                run_id="run_live1",
            )
            self.assertEqual(res["metrics"]["confirmed_trading_disconnect_count"], 1)
            self.assertEqual(res["metrics"]["event_counts"][EV_KGI_APP_DISCONNECT_REPORTED], 1)
            self.assertEqual(res["metrics"]["event_counts"][EV_KGI_RECONNECTED], 1)
            self.assertEqual(len(res["mark_correlations"]), 2)
            self.assertIn("DNS_Timeout_1014", res["mark_correlations"][0]["correlation_summary"])

            # 測試 cmd_mark CLI 函式（完全離線 skip_live_probe=True）
            logger = setup_logger()
            ns = argparse.Namespace(event="kgi-disconnected", note="UI alert", run_id="run_cli_mark")
            out = cmd_mark(ns, logger, base_reports_dir=tmp_dir, skip_live_probe=True)
            self.assertEqual(out["status"], STATUS_SUCCESS)
            self.assertTrue(Path(out["marks_file"]).exists())


class TestTlsAndProtocolNeutrality(unittest.TestCase):
    """對應第四節與第九節情境 3：TCP 443 成功但 TLS 失敗時，不得推論專屬協定或膨脹防火牆評分."""

    def _mock_probe_with_ssl_exc(self, side_effect_exc: BaseException) -> dict:
        fake_sock = mock.MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.__exit__.return_value = False

        with mock.patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.50", 443))]), \
             mock.patch("socket.create_connection", return_value=fake_sock), \
             mock.patch("ssl.SSLContext.wrap_socket", side_effect=side_effect_exc), \
             mock.patch("time.sleep"):
            return probe_kgi_endpoint("gtstrade.example.invalid", 443, "SecServer_URL", probe_count=1)

    def test_3_tcp_443_ok_tls_failures_recorded_separately_and_protocol_is_unknown(self) -> None:
        res_timeout = self._mock_probe_with_ssl_exc(socket.timeout("timed out"))
        self.assertEqual(res_timeout["tls_probe"]["tls_status"], TLS_HANDSHAKE_TIMEOUT)
        self.assertEqual(res_timeout["tls_probe"]["application_protocol"], PROTO_UNKNOWN)
        self.assertNotIn("專屬", res_timeout["tls_probe"]["protocol_summary"])

        res_rst = self._mock_probe_with_ssl_exc(ConnectionResetError("reset by peer"))
        self.assertEqual(res_rst["tls_probe"]["tls_status"], TLS_HANDSHAKE_RESET)
        self.assertEqual(res_rst["tls_probe"]["application_protocol"], PROTO_UNKNOWN)

        res_eof = self._mock_probe_with_ssl_exc(EOFError("eof"))
        self.assertEqual(res_eof["tls_probe"]["tls_status"], TLS_HANDSHAKE_EOF)
        self.assertEqual(res_eof["tls_probe"]["application_protocol"], PROTO_UNKNOWN)

        analysis = analyze_kgi_endpoint_probes([res_timeout, res_rst, res_eof])
        self.assertEqual(analysis["tls_status_counts"][TLS_HANDSHAKE_TIMEOUT], 1)
        self.assertEqual(analysis["tls_status_counts"][TLS_HANDSHAKE_RESET], 1)
        self.assertEqual(analysis["tls_status_counts"][TLS_HANDSHAKE_EOF], 1)
        self.assertEqual(len(analysis["unknown_protocol_endpoints"]), 3)
        self.assertNotIn("proprietary_binary_over_443_endpoints", analysis)

        causes = evaluate_root_causes(
            network_env={"primary_connection": {"connection_type": "Ethernet"}},
            restrictions={},
            kgi_inspection={"is_currently_running": False},
            kgi_probe_analysis=analysis,
        )
        cause_a = next(c for c in causes if c["code"] == "A")
        self.assertEqual(cause_a["evidence_tier"], TIER_UNVERIFIED_HYPOTHESIS)
        self.assertIsNone(cause_a["score"])
        cause_g = next(c for c in causes if c["code"] == "G")
        self.assertEqual(cause_g["evidence_tier"], TIER_CONFIRMED_FACT)
        self.assertEqual(cause_g["rank"], 1)


class TestMonitorLifecycleAndSubprocessSafety(unittest.TestCase):
    """對應第六節、第八節與第九節情境 6、7、8、9：重複啟動保護、優雅停止存檔、非零結束碼與過期報告攔截."""

    @unittest.skipUnless(sys.platform == "win32", "Requires Windows PowerShell 5.1+")
    def test_6_and_7_monitor_duplicate_conflict_and_graceful_stop_persistence(self) -> None:
        """在 Windows PowerShell 實測：啟動監控時重複啟動會回傳衝突碼 3，且 Stop 後資料原子保存、舊 StopFlag 不影響新工作."""
        with tempfile.TemporaryDirectory() as tmp:
            rt_dir = Path(tmp) / "runtime"
            rt_dir.mkdir(parents=True, exist_ok=True)
            # 先故意放一個舊的殘留 stop flag，驗證新監控不會被舊 flag 誤殺
            (rt_dir / "stop_stale_old.flag").write_text("2026-01-01T00:00:00Z", encoding="utf-8")

            ps_script = str(PROJECT_ROOT / "scripts" / "monitor_connections.ps1")
            base_cmd = [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                ps_script,
            ]
            # 使用 127.0.0.1 迴路埠作為離線快速探測目標，絕不連線外部真實金融端點
            start1 = subprocess.run(
                base_cmd
                + [
                    "-Action",
                    "Start",
                    "-RunId",
                    "test_lifecycle_1",
                    "-PassiveIntervalSeconds",
                    "2",
                    "-ActiveProbeIntervalSeconds",
                    "60",
                    "-DurationSeconds",
                    "30",
                    "-KgiQuoteHost",
                    "127.0.0.1",
                    "-KgiTradeHost",
                    "127.0.0.1",
                    "-ControlHost",
                    "127.0.0.1",
                    "-OutputDir",
                    str(rt_dir),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            self.assertEqual(start1.returncode, 0, msg=start1.stderr or start1.stdout)

            try:
                # 情境 6：重複啟動第二次監控必須被拒絕 (Exit Code == 3)
                start2 = subprocess.run(
                    base_cmd
                    + [
                        "-Action",
                        "Start",
                        "-RunId",
                        "test_lifecycle_2",
                        "-DurationSeconds",
                        "30",
                        "-OutputDir",
                        str(rt_dir),
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=10,
                )
                self.assertEqual(start2.returncode, 3)
                self.assertIn("CONFLICT", (start2.stderr or "") + (start2.stdout or ""))
            finally:
                # 情境 7：優雅停止監控並確認 summary JSON 與 state 完整寫入
                stop_proc = subprocess.run(
                    base_cmd + ["-Action", "Stop", "-OutputDir", str(rt_dir)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=20,
                )
                self.assertEqual(stop_proc.returncode, 0, msg=stop_proc.stderr or stop_proc.stdout)

            state_data = json.loads((rt_dir / "monitor_state.json").read_text(encoding="utf-8"))
            self.assertEqual(state_data["run_id"], "test_lifecycle_1")
            self.assertEqual(state_data["status"], "completed")
            summary_file = Path(state_data["summary_path"])
            self.assertTrue(summary_file.exists())
            summary_json = json.loads(summary_file.read_text(encoding="utf-8"))
            self.assertGreaterEqual(summary_json["sample_count"], 1)
            self.assertEqual(summary_json["completion_reason"], "manual_stop")

            # 驗證背景程序異常消失偵測（偽造 running 狀態加上不存在/時間不符之 PID）
            fake_dead_state = dict(state_data)
            fake_dead_state["status"] = "running"
            fake_dead_state["pid"] = 999999
            (rt_dir / "monitor_state.json").write_text(json.dumps(fake_dead_state), encoding="utf-8")
            status_dead = subprocess.run(
                base_cmd + ["-Action", "Status", "-OutputDir", str(rt_dir)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            self.assertEqual(status_dead.returncode, 4)
            parsed_status = json.loads(status_dead.stdout)
            self.assertEqual(parsed_status["status"], "abnormal_exit")
            self.assertEqual(parsed_status["run_status"], "FAILED")

    def test_8_powershell_nonzero_exit_code_halts_and_writes_error_summary(self) -> None:
        """情境 8：PowerShell 子程序回傳非零 Exit Code 時，CLI 不得宣稱成功，且必須寫入安全 error_summary.json."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_reports = Path(tmp)
            logger = setup_logger()
            fake_proc = subprocess.CompletedProcess(
                args=["powershell.exe"],
                returncode=2,
                stdout="",
                stderr="Simulated failure for " + "C:\\Users\\" + "real_alice\\secret.json",
            )
            with mock.patch("subprocess.run", return_value=fake_proc):
                ns = argparse.Namespace(lookback_hours=24, targets="")
                with self.assertRaises(DiagnosticStepError) as ctx:
                    cmd_all(ns, logger, base_reports_dir=tmp_reports)
                self.assertEqual(ctx.exception.exit_code, 2)

            err_files = list((tmp_reports / "internal").glob("*/error_summary.json"))
            self.assertEqual(len(err_files), 1)
            err_json = json.loads(err_files[0].read_text(encoding="utf-8"))
            self.assertEqual(err_json["run_status"], STATUS_FAILED)
            self.assertNotIn("real_alice", json.dumps(err_json))
            self.assertIn("<USER>", json.dumps(err_json))

    def test_9_stale_report_cannot_masquerade_as_new_run(self) -> None:
        """情境 9：舊報告（Run ID 不符或跨日資料）不得偽裝為本次新結果."""
        with tempfile.TemporaryDirectory() as tmp:
            stale_file = Path(tmp) / "network_environment.json"
            stale_file.write_text(
                json.dumps(
                    {
                        "run_id": "old_run_20261101",
                        "run_status": "SUCCESS",
                        "collected_at": "2026-11-01T10:00:00+08:00",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(DiagnosticStepError):
                verify_step_output_json(stale_file, expected_run_id="new_run_20261106", step_name="collect_network")

            cross_day = validate_artifact_freshness(
                {"run_id": "r1", "collected_at": "2026-11-01T10:00:00+08:00"},
                reference_date_str="2026-11-06",
            )
            self.assertFalse(cross_day["is_fresh"])
            self.assertEqual(cross_day["status"], STATUS_PARTIAL)


class TestScientificAbComparison(unittest.TestCase):
    """對應第七節與第九節情境 10、11、12：A/B 樣本為零、Label 錯誤、時長不一致與每小時標準化率."""

    def setUp(self) -> None:
        raw = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        self.valid_campus = raw["campus_valid_run"]
        self.valid_hotspot = raw["hotspot_valid_run"]

    def test_valid_ab_comparison_computes_hourly_rates_and_conservative_conclusion(self) -> None:
        comp = compare_ab_results(self.valid_campus, self.valid_hotspot)
        self.assertEqual(comp["status"], STATUS_SUCCESS)
        self.assertTrue(comp["is_scientifically_comparable"])
        rate_row = next(r for r in comp["metrics_table"] if r["metric_key"] == "confirmed_disconnects_per_hour")
        self.assertEqual(rate_row["campus_value"], 6.0)
        self.assertEqual(rate_row["hotspot_value"], 0.0)
        self.assertIn("不能直接證明學校防火牆設有針對凱基證券之刻意封鎖政策", comp["conclusion"])

    def test_10_ab_zero_samples_rejected(self) -> None:
        bad_campus = copy.deepcopy(self.valid_campus)
        bad_campus["sample_count"] = 0
        comp = compare_ab_results(bad_campus, self.valid_hotspot)
        self.assertFalse(comp["is_scientifically_comparable"])
        self.assertIn(STATUS_PARTIAL, comp["status"])
        chk = next(c for c in comp["validation_checks"] if c["check"] == "sample_count_nonzero")
        self.assertFalse(chk["passed"])

    def test_11_ab_wrong_label_rejected(self) -> None:
        wrong_label_hotspot = copy.deepcopy(self.valid_hotspot)
        wrong_label_hotspot["network_profile"] = "Campus_TANet_Ethernet"
        comp = compare_ab_results(self.valid_campus, wrong_label_hotspot)
        self.assertFalse(comp["is_scientifically_comparable"])
        chk = next(c for c in comp["validation_checks"] if c["check"] == "label_matches_network_profile")
        self.assertFalse(chk["passed"])

    def test_12_ab_mismatched_monitoring_duration_rejected(self) -> None:
        short_hotspot = copy.deepcopy(self.valid_hotspot)
        short_hotspot["total_duration_sec"] = 180.0  # 3 min vs 30 min (ratio 10x > 2.0x)
        comp = compare_ab_results(self.valid_campus, short_hotspot)
        self.assertFalse(comp["is_scientifically_comparable"])
        chk = next(c for c in comp["validation_checks"] if c["check"] == "comparable_test_duration")
        self.assertFalse(chk["passed"])


class TestPrivacyScannerAndFinancialDataRedaction(unittest.TestCase):
    """對應第二節與第九節情境 13、14：隱私遮罩、Git 提交白名單掃描與報告零金融敏感資訊."""

    def test_13_privacy_masking_and_git_commit_scanner(self) -> None:
        # 動態組合合成敏感字串以避免測試原始碼本身含有明文樣式
        raw_priv_ip = ".".join(["192", "168", "10", "55"])
        raw_campus_ip = ".".join(["140", "113", "24", "89"])
        raw_mac = ":".join(["aa", "bb", "cc", "11", "22", "33"])
        raw_tw_id = "A1" + "23456789"
        raw_path = "C:\\" + "Users\\" + "realstudent99\\Desktop\\data.json"
        raw_secret = "password" + "=SuperSecret98765"

        dirty_blob = f"{raw_path} {raw_priv_ip} {raw_campus_ip} {raw_mac} {raw_tw_id} {raw_secret}"
        findings = scan_text_for_sensitive_data(
            dirty_blob,
            source_label="synthetic_dirty.txt",
            username="realstudent99",
            hostname="LAPTOP-XYZ123",
        )
        rules_hit = {f["rule"] for f in findings}
        self.assertIn("LOCAL_USER_PATH", rules_hit)
        self.assertIn("REAL_USERNAME", rules_hit)
        self.assertIn("UNMASKED_MAC_BSSID", rules_hit)
        self.assertIn("TW_NATIONAL_ID_PATTERN", rules_hit)
        self.assertIn("UNMASKED_INTERNAL_OR_CAMPUS_IP", rules_hit)
        self.assertIn("CREDENTIAL_OR_COOKIE", rules_hit)

        # 驗證 Git 路徑白名單阻擋 reports/ 與 network_environment.json
        ok_rep, _ = is_path_allowed_for_git("reports/diagnostic_report.json")
        ok_env, _ = is_path_allowed_for_git("network_environment.json")
        ok_keep, _ = is_path_allowed_for_git("reports/.gitkeep")
        ok_src, _ = is_path_allowed_for_git("src/analyzer.py")
        self.assertFalse(ok_rep)
        self.assertFalse(ok_env)
        self.assertTrue(ok_keep)
        self.assertTrue(ok_src)

        self.assertEqual(mask_ip(raw_campus_ip), "140.xxx.xxx.xxx")
        self.assertEqual(mask_ip(raw_priv_ip), "192.168.xxx.xxx")
        masked = mask_sensitive_text(dirty_blob, username="realstudent99", hostname="LAPTOP-XYZ123")
        self.assertNotIn("realstudent99", masked)
        self.assertNotIn("SuperSecret98765", masked)
        self.assertNotIn(raw_tw_id, masked)
        self.assertNotIn("11:22:33", masked)

    def test_14_report_outputs_contain_zero_raw_financial_or_personal_secrets(self) -> None:
        raw_tw_id = "F1" + "29876543"
        raw_token = "SessionTokenValue998877"
        raw_user_path = "C:\\" + "Users\\" + "trader_lin\\AppData\\Local\\KGI"

        tainted_bundle = {
            "run_id": "run_sec_check",
            "overall_status": STATUS_PARTIAL,
            "step_statuses": {"env": STATUS_SUCCESS},
            "generated_at": "2026-11-06T12:00:00+08:00",
            "network_environment": {"primary_connection": {"connection_type": "Ethernet"}},
            "restrictions": {
                "websites": [],
                "applications": [
                    {
                        "name": "KGI",
                        "executable_path": raw_user_path,
                        "installed": True,
                        "is_running": False,
                        "classification": CAT_INSUFFICIENT,
                        "evidence_summary": f"id={raw_tw_id} token={raw_token}",
                    }
                ],
                "downloads": [],
            },
            "kgi_inspection": {"is_installed": True, "install_directories": [raw_user_path]},
            "kgi_endpoint_probes": [],
            "kgi_probe_analysis": {},
            "event_timeline": [
                {
                    "timestamp": "2026-11-06T12:00:00+08:00",
                    "run_id": "run_sec_check",
                    "network_profile": "campus",
                    "process_identity": "axis.exe",
                    "event_type": EV_KGI_PROBE_FAILURE,
                    "observed_state": f"note cookie={raw_token}",
                    "supporting_evidence": f"acct {raw_tw_id}",
                    "alternative_explanations": "none",
                    "confidence_classification": TIER_CONFIRMED_FACT,
                    "evidence_source": "unit_test",
                }
            ],
            "ab_comparison": compare_ab_results(None, None),
            "root_causes": [],
        }

        sanitized = sanitize_data_for_sharing(tainted_bundle, username="trader_lin", hostname="PC-SECRET01")
        md_out = generate_research_report_markdown(sanitized)
        html_out = generate_html_report(sanitized)

        for output_str in (json.dumps(sanitized, ensure_ascii=False), md_out, html_out):
            self.assertNotIn("trader_lin", output_str)
            self.assertNotIn(raw_tw_id, output_str)
            self.assertNotIn(raw_token, output_str)

        with tempfile.TemporaryDirectory() as tmp:
            csv_paths = write_csv_summary(
                sanitized["restrictions"],
                [],
                sanitized["ab_comparison"],
                Path(tmp),
                event_timeline=sanitized["event_timeline"],
            )
            for p_str in csv_paths.values():
                txt = Path(p_str).read_text(encoding="utf-8-sig")
                self.assertNotIn("trader_lin", txt)
                self.assertNotIn(raw_tw_id, txt)
                self.assertNotIn(raw_token, txt)


class TestLegacyClassifiersAndSimulationCli(unittest.TestCase):
    """確保第二階段限制分類器、CLI 參數解析與離線模擬測試 (`simulate`) 完整運作."""

    def test_restriction_classifiers_remain_accurate(self) -> None:
        self.assertEqual(
            classify_website_evidence(
                {
                    "url": "https://example.com/",
                    "dns_ok": True,
                    "tcp_success_rate": "3/3",
                    "tls": {"ok": True, "issuer": "CN=DigiCert"},
                    "http": {"status_code": 403, "location": ""},
                }
            )["classification"],
            CAT_INSUFFICIENT,
        )
        self.assertEqual(
            classify_website_evidence(
                {
                    "url": "https://example.com/",
                    "dns_ok": True,
                    "tcp_success_rate": "3/3",
                    "tls": {"ok": True, "issuer": "CN=DigiCert"},
                    "http": {"status_code": 302, "location": "http://198.51.100.1/fortiguard/blockpage"},
                }
            )["classification"],
            CAT_CONFIRMED_BLOCK,
        )
        self.assertEqual(
            classify_application_evidence(
                {"installed": True, "is_running": False, "firewall_block_rules": 0, "active_tcp_count": 0}
            )["classification"],
            CAT_INSUFFICIENT,
        )
        self.assertEqual(
            classify_download_evidence({"base_site_status": 200, "download_status": 200, "file_type": ".exe"})[
                "classification"
            ],
            CAT_NORMAL,
        )
        self.assertEqual(
            classify_download_evidence({"base_site_status": 0, "download_status": 0, "file_type": ".exe"})[
                "classification"
            ],
            CAT_CONN_FAIL,
        )
        self.assertEqual(
            classify_download_evidence({"base_site_status": 200, "download_status": 0, "file_type": ".exe"})[
                "classification"
            ],
            CAT_MAYBE_RESTRICTED,
        )

    def test_cli_parser_and_offline_simulate_command(self) -> None:
        parser = build_parser()
        m_args = parser.parse_args(
            ["monitor", "start", "--passive-interval", "5", "--active-interval", "30", "--label", "campus"]
        )
        self.assertEqual(m_args.passive_interval, 5)
        self.assertEqual(m_args.active_interval, 30)

        mk_args = parser.parse_args(["mark", "--event", "kgi-disconnected"])
        self.assertEqual(mk_args.event, "kgi-disconnected")

        with tempfile.TemporaryDirectory() as tmp:
            logger = setup_logger()
            sim_ns = argparse.Namespace(output_dir=tmp)
            sim_res = cmd_simulate(sim_ns, logger, base_reports_dir=Path(tmp))
            self.assertEqual(
                sim_res["scenario_1_idle_probe_failure"]["confirmed_trading_disconnect_count"],
                0,
            )
            self.assertEqual(
                sim_res["scenario_2_correlated_live_disconnect"]["metrics"]["confirmed_trading_disconnect_count"],
                1,
            )

        env_md = generate_network_environment_markdown({"primary_connection": {"connection_type": "Ethernet"}})
        self.assertIn("network_environment.md", env_md)


if __name__ == "__main__":
    unittest.main()
