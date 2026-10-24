import json
import re
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from logscan_web.scanner import extract_kometa_integrity, scan_archive_path, scan_log
from logscan_web.models import Finding
from logscan_web.storage import ScanStore


def native_log(*messages):
    return "\n".join(f"[2026-10-12 11:15:42,625] [integrity.py:674] [INFO] | {message} |" for message in messages)


class NativeSourceIntegrityTests(unittest.TestCase):
    def scan(self, content):
        return scan_log("standalone-kometa.log", ("[kometa.py:505] [INFO] | Version: 2.5.3 (Docker: nightly) |\n" + content).encode())

    def finding(self, result):
        return [item for item in result.recommendations if item["id"].startswith("source_integrity_")]

    def test_standalone_modified_report_lists_changed_missing_and_added_files(self):
        content = native_log(
            "    Source Integrity: MODIFIED", "    Modified:", "      modules/logs.py", "    Missing:", "      requirements.txt", "    Added:", r"      modules/odd\nname.py"
        )
        content += "\n[kometa.py:509] [INFO] | Platform: Linux |"
        result = self.scan(content)
        integrity = result.metadata["kometa_integrity"]
        self.assertEqual(integrity["source"], "kometa")
        self.assertEqual(integrity["state"], "modified")
        self.assertFalse(result.metadata["quickstart_run"])
        self.assertEqual(integrity["modified"], ["modules/logs.py"])
        self.assertEqual(integrity["missing"], ["requirements.txt"])
        self.assertEqual(integrity["added"], [r"modules/odd\nname.py"])
        self.assertEqual(integrity["counts"], {"modified": 1, "missing": 1, "added": 1})
        (finding,) = self.finding(result)
        self.assertEqual(finding["severity"], "warning")
        self.assertEqual(finding["evidence_lines"], list(range(2, 9)))
        for path in ("modules/logs.py", "requirements.txt", r"modules/odd\nname.py"):
            self.assertIn(path, finding["message"])
        self.assertNotIn("Platform", finding["message"])
        self.assertIn("not a run-blocking error", finding["description"])

    def test_verified_native_report_is_a_clean_indicator_without_an_advice_finding(self):
        result = self.scan(native_log("    Source Integrity: Verified"))
        self.assertEqual(result.metadata["kometa_integrity"]["state"], "clean")
        self.assertEqual(self.finding(result), [])
        with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
            streamed = self.scan(native_log("    Source Integrity: Verified"))
        self.assertEqual(self.finding(streamed), [])
        self.assertEqual(streamed.metadata["kometa_integrity"], result.metadata["kometa_integrity"])

    def test_retained_scan_hides_legacy_verified_advice_and_corrects_counts(self):
        from logscan_web.app import create_app

        content = ("[kometa.py:1] [INFO] | Version: 2.5.3 |\n" + native_log("Source Integrity: Verified")).encode()
        result = scan_log("meta.log", content)
        result.recommendations.append(Finding("source_integrity_verified", "advice", "Kometa source integrity: verified", "No changes.").as_dict())
        result.metadata["counts"]["advice"] += 1
        with tempfile.TemporaryDirectory() as directory:
            store = ScanStore(directory)
            scan_id, _token = store.create("meta.log", content, result)
            with patch.dict("os.environ", SCAN_STORE=directory), patch("logscan_web.app.threading.Thread"):
                app = create_app()
            response = app.test_client().get(f"/scan/{scan_id}")
            self.assertEqual(response.status_code, 200)
            script = re.search(r'<script id="initial-scan" type="application/json">(.*?)</script>', response.get_data(as_text=True), re.DOTALL)
            public = json.loads(script.group(1))
            self.assertNotIn("source_integrity_verified", [item["id"] for item in public["recommendations"]])
            self.assertEqual(public["metadata"]["counts"]["advice"], sum(item["severity"] == "advice" for item in public["recommendations"]))
            self.assertEqual(public["metadata"]["kometa_integrity"]["state"], "clean")

    def test_unavailable_timeout_and_disabled_never_indicate_changed_files(self):
        for status, expected in (
            ("Check unavailable (startup time limit reached; local files were not verified)", "check_unavailable"),
            ("Check unavailable (could not complete upstream validation; local files were not verified)", "check_unavailable"),
            ("Disabled (source-integrity option)", "disabled"),
        ):
            with self.subTest(status=status):
                result = self.scan(native_log(f"    Source Integrity: {status}"))
                report = result.metadata["kometa_integrity"]
                self.assertEqual(report["state"], expected)
                self.assertEqual(report["counts"], {"modified": 0, "missing": 0, "added": 0})
                if expected == "disabled":
                    self.assertEqual(self.finding(result), [])
                    continue
                (finding,) = self.finding(result)
                self.assertEqual(finding["severity"], "advice")
                self.assertNotEqual(finding["id"], "source_integrity_modified")
                self.assertIn(status, finding["message"])
                self.assertIn("not verified", finding["description"])

    def test_startup_result_wins_over_repeated_or_conflicting_summary(self):
        for startup, summary in (("MODIFIED", "Verified"), ("Check unavailable (startup time limit reached; local files were not verified)", "MODIFIED")):
            with self.subTest(startup=startup):
                content = native_log(f"    Source Integrity: {startup}")
                if startup == "MODIFIED":
                    content += "\n" + native_log("    Modified:", "      modules/logs.py")
                content += "\n[kometa.py:509] [INFO] | Platform: Linux |\n"
                content += native_log("=== Source Integrity Summary (startup check) ===", f"Source Integrity: {summary}", "Modified:", "  late.py")
                result = self.scan(content)
                self.assertEqual(result.metadata["kometa_integrity"]["reported_state"], startup)
                self.assertEqual(len(self.finding(result)), 1)
                self.assertNotIn("late.py", self.finding(result)[0]["message"])
                self.assertTrue(all(number < 6 for number in self.finding(result)[0]["evidence_lines"]))

    def test_repeated_modified_summary_does_not_duplicate_paths_counts_or_finding(self):
        block = native_log("Source Integrity: MODIFIED", "Modified:", "  modules/logs.py")
        content = block + "\n" + native_log("=== Source Integrity Summary (startup check) ===") + "\n" + block
        result = self.scan(content)
        self.assertEqual(len(self.finding(result)), 1)
        self.assertEqual(result.metadata["kometa_integrity"]["modified"], ["modules/logs.py"])
        self.assertEqual(result.metadata["kometa_integrity"]["counts"]["modified"], 1)

    def test_native_startup_takes_priority_over_quickstart_markers_and_config(self):
        stale = "[Quickstart] Kometa Integrity: CLEAN\n[Quickstart] Changes: 0 modified, 0 missing, 0 added\n# Kometa Integrity: CLEAN"
        native = native_log("    Source Integrity: MODIFIED", "    Modified:", "      modules/logs.py")
        for content in (stale + "\n" + native, native + "\n" + stale):
            with self.subTest(content=content):
                report = extract_kometa_integrity(content)
                self.assertEqual(report["state"], "modified")
                self.assertEqual(report["source"], "kometa")
                self.assertEqual(report["modified"], ["modules/logs.py"])

    def test_native_unavailable_does_not_inherit_stale_quickstart_changes(self):
        content = "[Quickstart] Kometa Integrity: MODIFIED\n[Quickstart] Modified: stale.py\n"
        content += native_log("Source Integrity: Check unavailable (startup time limit reached; local files were not verified)")
        result = self.scan(content)
        self.assertEqual(result.metadata["kometa_integrity"]["modified"], [])
        self.assertEqual(self.finding(result)[0]["id"], "source_integrity_unavailable")
        self.assertNotIn("stale.py", self.finding(result)[0]["message"])

    def test_web_and_bot_uploads_return_integrity_and_reuse_the_same_scan(self):
        from logscan_web.app import ANALYSIS_VERSION, create_app

        content = ("[kometa.py:505] [INFO] | Version: 2.5.3 |\n" + native_log("Source Integrity: MODIFIED", "Modified:", "  modules/logs.py")).encode()
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", SCAN_STORE=directory, LOGSCAN_API_KEY="test-secret"), patch("logscan_web.app.threading.Thread"):
                app = create_app()
            app.config["TESTING"] = True
            client = app.test_client()
            first = client.post("/api/scan", data={"log": (BytesIO(content), "meta.log")}).get_json()
            second = client.post("/api/bot/scan", data={"log": (BytesIO(content), "discord.log")}, headers={"Authorization": "Bearer test-secret"}).get_json()["scans"][0]
            self.assertEqual(first["id"], second["id"])
            self.assertTrue(second["already_uploaded"])
            self.assertEqual(first["metadata"]["analysis_version"], ANALYSIS_VERSION)
            self.assertEqual(first["metadata"]["kometa_integrity"]["modified"], ["modules/logs.py"])
            self.assertFalse(first["metadata"]["quickstart_run"])
            self.assertIn("source_integrity_modified", [item["id"] for item in first["recommendations"]])
            self.assertEqual(client.get("/api/analytics").get_json()["totals"]["tools"], {"kometa": 1})

    def test_summary_only_report_is_identified_and_files_have_exact_evidence(self):
        result = self.scan(native_log("=== Source Integrity Summary (startup check) ===", "Source Integrity: MODIFIED", "Missing:", "  modules/logs.py"))
        report = result.metadata["kometa_integrity"]
        self.assertEqual(report["report_location"], "summary")
        self.assertEqual(report["missing"], ["modules/logs.py"])
        self.assertEqual(report["evidence_lines"], [3, 4, 5])
        self.assertIn("end-of-run summary", self.finding(result)[0]["message"])

    def test_unknown_and_config_echoes_are_not_confirmed_native_results(self):
        report = extract_kometa_integrity(native_log("    Source Integrity: FUTURE STATUS"))
        self.assertEqual(report["state"], "unknown")
        for content in ("# Source Integrity: MODIFIED\n# Modified:\n#   fake.py", "[kometa.py:1] [INFO] | Version: 2.5.3 |"):
            self.assertFalse(extract_kometa_integrity(content)["detected"])
            self.assertEqual(self.finding(self.scan(content)), [])
        report = extract_kometa_integrity("# Source Integrity Summary (startup check)\n" + native_log("Source Integrity: Verified"))
        self.assertEqual(report["report_location"], "startup")

    def test_plain_pipe_reports_preserve_indented_category_members(self):
        report = extract_kometa_integrity("| Source Integrity: MODIFIED |\n| Modified: |\n|   LICENSE |\n| Added: |\n|   docs/new.md |\n| Platform: Linux |")
        self.assertEqual(report["modified"], ["LICENSE"])
        self.assertEqual(report["added"], ["docs/new.md"])
        self.assertEqual(report["evidence_lines"], [1, 2, 3, 4, 5])

    def test_streamed_and_regular_reports_preserve_all_paths_counts_and_evidence(self):
        messages = ["    Source Integrity: MODIFIED"]
        for category in ("Modified", "Missing", "Added"):
            messages.append(f"    {category}:")
            messages.extend(f"      modules/{category.lower()}{index}.py" for index in range(20))
            messages.append("      23 more")
        content = "[kometa.py:505] [INFO] | Version: 2.5.3 |\n" + "[kometa.py:2] [DEBUG] | Working |\n" * 250 + native_log(*messages)
        content += "\n[kometa.py:509] [INFO] | Platform: Linux |\n" + native_log("=== Source Integrity Summary (startup check) ===", "Source Integrity: Verified")
        regular = scan_log("kometa.log", content.encode())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "kometa.log")
            path.write_bytes(content.encode())
            with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
                streamed = scan_archive_path("kometa.log", path)[0][2]
        self.assertEqual(regular.metadata["kometa_integrity"], streamed.metadata["kometa_integrity"])
        self.assertEqual(self.finding(regular), self.finding(streamed))
        self.assertEqual(regular.metadata["kometa_integrity"]["counts"], {"modified": 43, "missing": 43, "added": 43})
        self.assertEqual(regular.metadata["kometa_integrity"]["evidence_lines"], list(range(252, 319)))
        self.assertIn("23 more", self.finding(regular)[0]["message"])


class KometaIntegrityTests(unittest.TestCase):
    def test_clean_report_from_logged_configuration_comments(self):
        report = "\n".join(
            [
                "# [Quickstart] Kometa integrity begin",
                "# Kometa Integrity: CLEAN",
                "# Installed Commit: " + "a" * 40,
                "# Checked At: 2026-10-10T14:00:00Z",
                "# Changes: 0 modified, 0 missing, 0 added",
                "# [Quickstart] Kometa integrity end",
            ]
        )
        content = "\n".join(f"[kometa.py:1] [INFO] | {line} |" for line in report.splitlines())
        integrity = extract_kometa_integrity(content)
        self.assertEqual(integrity["state"], "clean")
        self.assertEqual(integrity["source"], "config")
        self.assertEqual(integrity["counts"], {"modified": 0, "missing": 0, "added": 0})
        self.assertEqual(integrity["commit"], "a" * 40)
        self.assertEqual(integrity["checked_at"], "2026-10-10T14:00:00Z")
        self.assertEqual(integrity["evidence_lines"], [2, 3, 4, 5])

    def test_modified_run_report_includes_file_diagnostics_and_totals(self):
        content = "\n".join(
            [
                "[Quickstart] Kometa Integrity: MODIFIED",
                "[Quickstart] Changes: 24 modified, 1 missing, 1 added",
                "[Quickstart] Modified: kometa.py",
                "[Quickstart] Modified: 23 more",
                "[Quickstart] Missing: requirements.txt",
                r"[Quickstart] Added: modules/odd\nname.py",
                "[Quickstart] WARNING: Installed Kometa files differ from the upstream baseline. Runs are not blocked.",
                "[Quickstart] Use Force update to restore vanilla Kometa; the entire runtime config/ directory is preserved.",
                "[kometa.py:9] [INFO] | Changes: 999 added |",
            ]
        )
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
        integrity = extract_kometa_integrity(
            "\n".join(
                [
                    "[Quickstart] Kometa Integrity: MODIFIED",
                    "[Quickstart] Modified: kometa.py",
                    "[Quickstart] Kometa Integrity: CLEAN",
                    "[Quickstart] Changes: 0 modified, 0 missing, 0 added",
                ]
            )
        )
        self.assertEqual(integrity["state"], "clean")
        self.assertEqual(integrity["modified"], [])

    def test_unverified_failed_and_unknown_reports_never_become_clean(self):
        states = {
            "NOT VERIFIED": "not_verified",
            "NOT APPLICABLE": "not_applicable",
            "CHECK FAILED": "check_failed",
            "UNRECOGNIZED": "unknown",
        }
        for reported, state in states.items():
            with self.subTest(reported=reported):
                integrity = extract_kometa_integrity(f"[Quickstart] Kometa Integrity: {reported}")
                self.assertTrue(integrity["detected"])
                self.assertEqual(integrity["state"], state)
        self.assertEqual(
            extract_kometa_integrity("[kometa.py:1] [INFO] | Version: 2.5.0 |"),
            {
                "detected": False,
                "state": "not_reported",
            },
        )

    def test_check_failed_report_preserves_errors_and_explanation(self):
        integrity = extract_kometa_integrity(
            "\n".join(
                [
                    "[Quickstart] Kometa Integrity: CHECK FAILED",
                    "[Quickstart] Changes: 0 modified, 0 missing, 0 added",
                    "[Quickstart] Errors: Unable to read kometa.py",
                    "[Quickstart] Unable to verify the pristine baseline or installed files. Use Force update to restore managed Kometa.",
                ]
            )
        )
        self.assertEqual(integrity["errors"], ["Unable to read kometa.py"])
        self.assertEqual(len(integrity["details"]), 1)

    def test_regular_and_streaming_scans_keep_complete_integrity_reports(self):
        # Report fields need to survive sampling even when they do not match existing terms.
        lines = ["[kometa.py:1] [INFO] | Version: 2.5.0 |"]
        lines.extend(["# Kometa Integrity: CLEAN", "# Changes: 0 modified, 0 missing, 0 added"])
        lines.extend(["[kometa.py:2] [DEBUG] | Unrelated work |"] * 220)
        lines.extend(
            [
                "[Quickstart] Kometa Integrity: MODIFIED",
                "[Quickstart] Installed Commit: " + "b" * 40,
                "[Quickstart] Checked At: 2026-10-10T15:00:00Z",
                "[Quickstart] Changes: 20 modified, 0 missing, 0 added",
            ]
        )
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
