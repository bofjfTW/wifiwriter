"""github-safe-sync 與 Git 提交白名單之自動化測試（純合成資料，不觸碰真實儲存庫歷史）."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src import privacy  # noqa: E402

SYNC_SCRIPT = PROJECT_ROOT / "scripts" / "sync_github.ps1"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")
GIT = shutil.which("git")


class TestGitAllowlist(unittest.TestCase):
    def assertAllowed(self, path):
        ok, reason = privacy.is_path_allowed_for_git(path)
        self.assertTrue(ok, f"{path} should be allowed: {reason}")

    def assertRejected(self, path):
        ok, _ = privacy.is_path_allowed_for_git(path)
        self.assertFalse(ok, f"{path} should be rejected")

    def test_skill_files_allowed(self):
        self.assertAllowed(".agents/skills/github-safe-sync/SKILL.md")
        self.assertAllowed(".agents/skills/github-safe-sync/references/report-publishing.md")

    def test_other_agents_paths_rejected(self):
        self.assertRejected(".agents/other.md")
        self.assertRejected(".agents/skills/other/SKILL.md")
        self.assertRejected(".agents/skills/github-safe-sync-evil/SKILL.md")

    def test_field_test_reports_allowed(self):
        self.assertAllowed("docs/field-tests/2026-11-11-campus-fubon/summary.md")
        self.assertAllowed("docs/field-tests/2026-11-11-campus-fubon/evidence.json")

    def test_installers_and_archives_rejected(self):
        for p in ("docs/FB_ePlus_setup.exe", "tests/setup.msi", "docs/bundle.zip", "src/x.part"):
            self.assertRejected(p)

    def test_raw_reports_rejected_anywhere(self):
        for p in (
            "reports/internal/a.json",
            "reports/foo.md",
            "docs/campus_network_diagnostic.json",
            "docs/field-tests/x/campus_download_events.csv",
            "network_environment.json",
            "config/targets.json",
        ):
            self.assertRejected(p)

    def test_unlisted_root_file_rejected(self):
        self.assertRejected("random.txt")


class TestSensitiveContentScan(unittest.TestCase):
    def test_public_field_test_files_are_clean(self):
        base = PROJECT_ROOT / "docs" / "field-tests" / "2026-11-11-campus-fubon"
        for name in ("summary.md", "evidence.json"):
            text = (base / name).read_text(encoding="utf-8")
            findings = privacy.scan_text_for_sensitive_data(text, name, username="", hostname="")
            self.assertEqual(findings, [], f"{name}: {findings}")

    def test_evidence_json_has_required_keys(self):
        path = PROJECT_ROOT / "docs" / "field-tests" / "2026-11-11-campus-fubon" / "evidence.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        required = [
            "schema_version", "test_date", "run_id", "git_commit", "environment_label",
            "application_name", "download_transport_status", "downloaded_bytes", "content_length",
            "sha256", "signature_status", "signer", "dns_results", "tcp_results", "tls_results",
            "http_results", "error_counts", "incomplete_checks", "evidence_limitations",
        ]
        for key in required:
            self.assertIn(key, data)
        self.assertEqual(data["downloaded_bytes"], data["content_length"])

    def test_sensitive_values_detected(self):
        campus_ip = ".".join(["163", "13", "5", "86"])
        private_ip = ".".join(["192", "168", "1", "10"])
        mac = ":".join(["aa", "bb", "cc", "dd", "ee", "ff"])
        token = "ghp_" + "A" * 30
        local_path = "C:" + "\\Users\\" + "realperson\\Desktop"
        for sample in (campus_ip, private_ip, mac, token, local_path):
            findings = privacy.scan_text_for_sensitive_data(f"value {sample}", "t", username="", hostname="")
            self.assertTrue(findings, f"should detect: {sample[:6]}...")


@unittest.skipUnless(POWERSHELL and GIT and sys.platform.startswith("win"), "requires Windows PowerShell and git")
class TestSyncScriptInTempRepo(unittest.TestCase):
    """在暫存 Git 儲存庫 + 本地 bare remote 中執行 sync_github.ps1."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.remote = root / "remote.git"
        self.repo = root / "work"
        self._git(root, "init", "--bare", "-q", str(self.remote))
        self._git(root, "init", "-q", str(self.repo))
        self._git(self.repo, "config", "user.email", "test@example.invalid")
        self._git(self.repo, "config", "user.name", "synthetic-test")
        self._git(self.repo, "remote", "add", "origin", str(self.remote))
        (self.repo / "src").mkdir()
        (self.repo / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
        self._git(self.repo, "add", "--", "src/app.py")
        self._git(self.repo, "commit", "-q", "-m", "init")
        self._git(self.repo, "branch", "-M", "main")
        self._git(self.repo, "checkout", "-q", "-b", "feat/test")

    def tearDown(self):
        self.tmp.cleanup()

    def _git(self, cwd, *args):
        return subprocess.run([GIT, *args], cwd=str(cwd), capture_output=True, text=True, check=True)

    def _sync(self, *args):
        cmd = [
            POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SYNC_SCRIPT),
            "-RepoRoot", str(self.repo), "-AllowCustomRemote", "-TestCommand", "cmd /c exit 0", *args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")

    def test_clean_tree_skips_without_empty_commit(self):
        before = self._git(self.repo, "rev-parse", "HEAD").stdout.strip()
        proc = self._sync()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("SKIP", proc.stdout)
        self.assertEqual(before, self._git(self.repo, "rev-parse", "HEAD").stdout.strip())

    def test_main_branch_blocked(self):
        self._git(self.repo, "checkout", "-q", "main")
        (self.repo / "src" / "b.py").write_text("x = 1\n", encoding="utf-8")
        proc = self._sync("-Paths", "src/b.py")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)

    def test_sensitive_content_rejected(self):
        campus_ip = ".".join(["163", "13", "5", "86"])
        (self.repo / "src" / "leak.py").write_text(f"IP = '{campus_ip}'\n", encoding="utf-8")
        proc = self._sync("-Paths", "src/leak.py")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_installer_rejected(self):
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "setup.exe").write_bytes(b"MZ\x00\x00")
        proc = self._sync("-Paths", "docs/setup.exe")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_raw_report_rejected(self):
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "campus_network_diagnostic.md").write_text("# raw\n", encoding="utf-8")
        proc = self._sync("-Paths", "docs/campus_network_diagnostic.md")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_test_failure_aborts(self):
        (self.repo / "src" / "ok.py").write_text("y = 2\n", encoding="utf-8")
        cmd = [
            POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SYNC_SCRIPT),
            "-RepoRoot", str(self.repo), "-AllowCustomRemote", "-TestCommand", "cmd /c exit 1",
            "-Paths", "src/ok.py",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 5, proc.stdout + proc.stderr)

    def test_unexpected_remote_rejected(self):
        (self.repo / "src" / "ok.py").write_text("y = 2\n", encoding="utf-8")
        cmd = [
            POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SYNC_SCRIPT),
            "-RepoRoot", str(self.repo), "-TestCommand", "cmd /c exit 0", "-Paths", "src/ok.py",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)

    def test_safe_push_and_remote_sha_verified(self):
        (self.repo / "docs" / "field-tests" / "x").mkdir(parents=True)
        (self.repo / "docs" / "field-tests" / "x" / "summary.md").write_text("# sanitized 163.xxx.xxx.xxx\n", encoding="utf-8")
        proc = self._sync("-Paths", "docs/field-tests/x/summary.md", "-CommitMessage", "docs: add report")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        local = self._git(self.repo, "rev-parse", "HEAD").stdout.strip()
        remote = self._git(self.repo, "ls-remote", "--heads", "origin", "feat/test").stdout.split()[0]
        self.assertEqual(local, remote)

    def test_remote_divergence_rejected_without_force(self):
        (self.repo / "src" / "a.py").write_text("a = 1\n", encoding="utf-8")
        self.assertEqual(self._sync("-Paths", "src/a.py", "-CommitMessage", "a").returncode, 0)
        # 模擬他人在遠端推送了新 Commit
        other = Path(self.tmp.name) / "other"
        self._git(Path(self.tmp.name), "clone", "-q", "-b", "feat/test", str(self.remote), str(other))
        self._git(other, "config", "user.email", "o@example.invalid")
        self._git(other, "config", "user.name", "other")
        (other / "src" / "o.py").write_text("o = 1\n", encoding="utf-8")
        self._git(other, "add", "--", "src/o.py")
        self._git(other, "commit", "-q", "-m", "other")
        self._git(other, "push", "-q", "origin", "feat/test")
        remote_before = self._git(self.repo, "ls-remote", "--heads", "origin", "feat/test").stdout.split()[0]
        (self.repo / "src" / "c.py").write_text("c = 1\n", encoding="utf-8")
        proc = self._sync("-Paths", "src/c.py", "-CommitMessage", "c")
        self.assertEqual(proc.returncode, 6, proc.stdout + proc.stderr)
        remote_after = self._git(self.repo, "ls-remote", "--heads", "origin", "feat/test").stdout.split()[0]
        self.assertEqual(remote_before, remote_after)


if __name__ == "__main__":
    unittest.main()

