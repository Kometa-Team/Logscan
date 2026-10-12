import tempfile
import unittest
import json
import re
from pathlib import Path
from unittest.mock import patch

from logscan_web.log_facts import count_log_occurrences
from logscan_web.scanner import scan_archive_path, scan_log

HEADER = "[kometa.py:1] [INFO] | Version: 2.2.2 |\n"


class LogFactsTests(unittest.TestCase):
    def scans(self, content):
        data = (HEADER + content).encode()
        normal = scan_log("meta.log", data)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "meta.log"
            path.write_bytes(data)
            with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
                streamed = scan_archive_path("meta.log", path)[0][2]
        return normal, streamed

    def test_repeated_errors_count_entries_without_changing_finding_counts(self):
        for result in self.scans("[kometa.py:2] [ERROR] | TMDb Error: Invalid API key |\n" * 3):
            self.assertEqual(result.metadata["log_counts"]["error"], 3)
            self.assertEqual(result.metadata["log_counts"]["info"], 1)
            self.assertEqual(sum(item["id"] == "tmdb_key" for item in result.recommendations), 1)
            self.assertEqual(sum(item["id"] == "kometa_error" for item in result.recommendations), 1)
            for severity, count in result.metadata["counts"].items():
                self.assertEqual(count, sum(item["severity"] == severity for item in result.recommendations))

    def test_occurrences_are_exact_past_evidence_limit(self):
        for result in self.scans("[kometa.py:2] [ERROR] | Failure |\n" * 10_005):
            self.assertEqual(result.metadata["log_counts"]["error"], 10_005)

    def test_levels_case_and_line_endings(self):
        counts = count_log_occurrences(b"[ERROR] [ERROR]\r\n[error]\r[Warning]\n[CRITICAL]\n[DEBUG]\n[TRACE]")
        self.assertEqual(counts, {"critical": 1, "error": 2, "warning": 1, "info": 0, "debug": 1, "trace": 1})
        self.assertTrue(all(value == 0 for value in count_log_occurrences(b"").values()))

    def test_validation_terminal_outcomes_are_complete_without_runtime(self):
        for outcome in ("PASSED", "FAILED", "SKIPPED"):
            for result in self.scans("[kometa.py:441] [INFO] | Validation Report (structure+schema) |\n" f"[validator.py:100] [INFO] | Result: {outcome} |\n"):
                with self.subTest(outcome=outcome, result=result.metadata):
                    self.assertTrue(result.metadata["complete"])
                    self.assertTrue(result.metadata["validation_run"])
                    self.assertEqual(result.metadata["validation_level"], "structure+schema")
                    self.assertEqual(result.metadata["validation_result"], outcome.lower())
                    self.assertIsNone(result.metadata["run_time"])
                    self.assertNotIn("incomplete_log", [item["id"] for item in result.recommendations])

    def test_terminal_validator_line_without_report_matches_quickstart(self):
        for result in self.scans("[validator.py:100] [INFO] | Result: FAILED |\n"):
            self.assertTrue(result.metadata["complete"])
            self.assertEqual(result.metadata["validation_result"], "failed")
            self.assertIsNone(result.metadata["validation_level"])

    def test_validation_report_without_terminal_result_stays_incomplete(self):
        for result in self.scans("[kometa.py:441] [INFO] | Validation Report (syntax) |\n"):
            self.assertFalse(result.metadata["complete"])
            self.assertIsNone(result.metadata["validation_result"])
            self.assertIn("incomplete_log", [item["id"] for item in result.recommendations])

    def test_unrelated_result_does_not_complete_validation(self):
        for result in self.scans("[kometa.py:441] [INFO] | Validation Report (syntax) |\n" "[other.py:100] [INFO] | Result: PASSED |\n"):
            self.assertFalse(result.metadata["complete"])
            self.assertIsNone(result.metadata["validation_result"])

    def test_new_validation_report_clears_old_terminal_result(self):
        for result in self.scans(
            "[kometa.py:441] [INFO] | Validation Report (syntax) |\n" "[validator.py:100] [INFO] | Result: PASSED |\n" "[kometa.py:441] [INFO] | Validation Report (full) |\n"
        ):
            self.assertFalse(result.metadata["complete"])
            self.assertIsNone(result.metadata["validation_result"])
            self.assertEqual(result.metadata["validation_level"], "full")

    def test_stream_validation_result_beyond_sampling_limit(self):
        for result in self.scans(
            "[kometa.py:441] [INFO] | Validation Report (full) |\n" + "[other.py:100] [INFO] | Result: intermediate |\n" * 205 + "[validator.py:100] [INFO] | Result: PASSED |\n"
        ):
            self.assertTrue(result.metadata["complete"])
            self.assertEqual(result.metadata["validation_result"], "passed")

    def test_normal_finished_run_completion_remains_unchanged(self):
        for result in self.scans("[kometa.py:3] [INFO] | Start Time: 08:00:00 Finished: 08:01:00 Run Time: 0:01:00 |\n"):
            self.assertTrue(result.metadata["complete"])
            self.assertEqual(result.metadata["run_time"], "0:01:00")
            self.assertNotIn("validation_run", result.metadata)

    def test_mixed_case_findings_and_evidence_match_normal_scanner(self):
        normal, streamed = self.scans(
            "[kometa.py:2] [eRrOr] | tMdB eRrOr: iNvAlId aPi KeY |\n"
            "[kometa.py:3] [wArNiNg] | cAcHe: fAlSe |\n"
            "[kometa.py:4] [eRrOr] | cOnFiG eRrOr: Operation mass_genre_update without a successful service |\n"
        )
        normal_findings = {item["id"]: item["evidence_lines"] for item in normal.recommendations}
        streamed_findings = {item["id"]: item["evidence_lines"] for item in streamed.recommendations}
        self.assertEqual(normal_findings, streamed_findings)
        self.assertEqual(streamed_findings["tmdb_key"], [2])
        self.assertEqual(streamed_findings["cache_disabled"], [3])
        self.assertEqual(streamed_findings["mass_update"], [4])

    def test_mixed_case_detector_crosses_stream_chunk_boundary(self):
        # The scanner samples in 4 MiB chunks. Place the detector across that
        # boundary and assert original evidence line numbers are retained.
        padding = "x" * (4 * 1024 * 1024 - len(HEADER.encode()) - 10)
        normal, streamed = self.scans(padding + "tMdB eRrOr: iNvAlId aPi KeY\n")
        for result in (normal, streamed):
            finding = next(item for item in result.recommendations if item["id"] == "tmdb_key")
            self.assertEqual(finding["evidence_lines"], [2])

    def test_stored_result_page_preserves_occurrences_and_validation_metadata(self):
        from logscan_web.app import app, ANALYSIS_VERSION
        from logscan_web.storage import ScanStore

        data = (HEADER + "[kometa.py:2] [ERROR] | TMDb Error: Invalid API key |\n" * 3 + "[validator.py:100] [INFO] | Result: FAILED |\n").encode()
        result = scan_log("meta.log", data)
        result.metadata.update(analysis_version=ANALYSIS_VERSION, schema_validation_count=0)
        store = ScanStore(app.config["SCAN_STORE"])
        scan_id, token = store.create("meta.log", data, result)
        try:
            response = app.test_client().get(f"/scan/{scan_id}")
            self.assertEqual(response.status_code, 200)
            match = re.search(r'<script id="initial-scan" type="application/json">(.*?)</script>', response.get_data(as_text=True), re.S)
            record = json.loads(match.group(1))
            self.assertEqual(record["metadata"]["log_counts"]["error"], 3)
            finding = next(item for item in record["recommendations"] if item["id"] == "tmdb_key")
            self.assertEqual(finding["occurrence_count"], 3)
            self.assertFalse(finding["evidence_truncated"])
            self.assertTrue(record["metadata"]["complete"])
            self.assertEqual(record["metadata"]["validation_result"], "failed")
            self.assertNotIn("incomplete_log", [item["id"] for item in record["recommendations"]])
            self.assertEqual(record["overview"]["finding_count"], sum(record["metadata"]["counts"].values()))
            self.assertNotIn("delete_token_hash", record)
        finally:
            store.delete(scan_id, token)


if __name__ == "__main__":
    unittest.main()
