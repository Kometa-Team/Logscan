import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from logscan_web.scanner import extract_kometa_integrity, scan_archive_path, scan_log


class KometaIntegrityTests(unittest.TestCase):
    def test_clean_report_from_logged_configuration_comments(self):
        report = "\n".join([
            "# [Quickstart] Kometa integrity begin",
            "# Kometa Integrity: CLEAN",
            "# Installed Commit: " + "a" * 40,
            "# Checked At: 2026-10-10T14:00:00Z",
            "# Changes: 0 modified, 0 missing, 0 added",
            "# [Quickstart] Kometa integrity end",
        ])
        content = "\n".join(f"[kometa.py:1] [INFO] | {line} |" for line in report.splitlines())
        integrity = extract_kometa_integrity(content)
        self.assertEqual(integrity["state"], "clean")
        self.assertEqual(integrity["source"], "config")
        self.assertEqual(integrity["counts"], {"modified": 0, "missing": 0, "added": 0})
        self.assertEqual(integrity["commit"], "a" * 40)
        self.assertEqual(integrity["checked_at"], "2026-10-10T14:00:00Z")
        self.assertEqual(integrity["evidence_lines"], [2, 3, 4, 5])

    def test_modified_run_report_includes_file_diagnostics_and_totals(self):
        content = "\n".join([
            "[Quickstart] Kometa Integrity: MODIFIED",
            "[Quickstart] Changes: 24 modified, 1 missing, 1 added",
            "[Quickstart] Modified: kometa.py",
            "[Quickstart] Modified: 23 more",
            "[Quickstart] Missing: requirements.txt",
            r"[Quickstart] Added: modules/odd\nname.py",
            "[Quickstart] WARNING: Installed Kometa files differ from the upstream baseline. Runs are not blocked.",
            "[Quickstart] Use Force update to restore vanilla Kometa; the entire runtime config/ directory is preserved.",
            "[kometa.py:9] [INFO] | Changes: 999 added |",
        ])
        integrity = extract_kometa_integrity(content)
        self.assertEqual(integrity["state"], "modified")
        self.assertEqual(integrity["counts"], {"modified": 24, "missing": 1, "added": 1})
        self.assertEqual(integrity["modified"], ["kometa.py", "23 more"])
        self.assertEqual(integrity["missing"], ["requirements.txt"])
        self.assertEqual(integrity["added"], [r"modules/odd\nname.py"])
        self.assertEqual(len(integrity["details"]), 2)
        self.assertEqual(integrity["evidence_lines"], list(range(1, 9)))

    def test_run_report_takes_priority_over_stale_config_in_either_order(self):
        comment = "# Kometa Integrity: CLEAN\n# Changes: 0 modified, 0 missing, 0 added"
        marker = "[Quickstart] Kometa Integrity: MODIFIED\n[Quickstart] Changes: 1 modified, 0 missing, 0 added"
        for content in (comment + "\n" + marker, marker + "\n" + comment):
            with self.subTest(content=content):
                integrity = extract_kometa_integrity(content)
                self.assertEqual(integrity["state"], "modified")
                self.assertEqual(integrity["counts"]["modified"], 1)
                self.assertEqual(integrity["source"], "run")

    def test_latest_run_report_replaces_previous_diagnostics(self):
        integrity = extract_kometa_integrity("\n".join([
            "[Quickstart] Kometa Integrity: MODIFIED",
            "[Quickstart] Modified: kometa.py",
            "[Quickstart] Kometa Integrity: CLEAN",
            "[Quickstart] Changes: 0 modified, 0 missing, 0 added",
        ]))
        self.assertEqual(integrity["state"], "clean")
        self.assertEqual(integrity["modified"], [])

    def test_unverified_failed_and_unknown_reports_never_become_clean(self):
        states = {
            "NOT VERIFIED": "not_verified", "NOT APPLICABLE": "not_applicable",
            "CHECK FAILED": "check_failed", "UNRECOGNIZED": "unknown",
        }
        for reported, state in states.items():
            with self.subTest(reported=reported):
                integrity = extract_kometa_integrity(f"[Quickstart] Kometa Integrity: {reported}")
                self.assertTrue(integrity["detected"])
                self.assertEqual(integrity["state"], state)
        self.assertEqual(extract_kometa_integrity("[kometa.py:1] [INFO] | Version: 2.5.0 |"), {
            "detected": False, "state": "not_reported",
        })

    def test_check_failed_report_preserves_errors_and_explanation(self):
        integrity = extract_kometa_integrity("\n".join([
            "[Quickstart] Kometa Integrity: CHECK FAILED",
            "[Quickstart] Changes: 0 modified, 0 missing, 0 added",
            "[Quickstart] Errors: Unable to read kometa.py",
            "[Quickstart] Unable to verify the pristine baseline or installed files. Use Force update to restore managed Kometa.",
        ]))
        self.assertEqual(integrity["errors"], ["Unable to read kometa.py"])
        self.assertEqual(len(integrity["details"]), 1)

    def test_regular_and_streaming_scans_keep_complete_integrity_reports(self):
        # Report fields need to survive sampling even when they do not match existing terms.
        lines = ["[kometa.py:1] [INFO] | Version: 2.5.0 |"]
        lines.extend(["# Kometa Integrity: CLEAN", "# Changes: 0 modified, 0 missing, 0 added"])
        lines.extend(["[kometa.py:2] [DEBUG] | Unrelated work |"] * 220)
        lines.extend([
            "[Quickstart] Kometa Integrity: MODIFIED",
            "[Quickstart] Installed Commit: " + "b" * 40,
            "[Quickstart] Checked At: 2026-10-10T15:00:00Z",
            "[Quickstart] Changes: 20 modified, 0 missing, 0 added",
        ])
        lines.extend(f"[Quickstart] Modified: modules/file{index}.py" for index in range(20))
        content = "\n".join(lines).encode()
        regular = scan_log("kometa.log", content)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "kometa.log")
            path.write_bytes(content)
            with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
                streamed = scan_archive_path("kometa.log", path)[0][2]
        integrity = regular.metadata["kometa_integrity"]
        self.assertEqual(integrity["state"], "modified")
        self.assertEqual(len(integrity["modified"]), 20)
        self.assertEqual(streamed.metadata["kometa_integrity"], integrity)


if __name__ == "__main__":
    unittest.main()
