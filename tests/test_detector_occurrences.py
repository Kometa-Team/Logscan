import json
import mmap
import re
import tempfile
import tracemalloc
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from logscan_web.models import ScanContext
from logscan_web.recommendations import RecommendationRule
from logscan_web.rules.base import EVIDENCE_LIMIT, TextRule, evaluate_text_rules_bytes
from logscan_web.rules.kometa import PlexSecurityRule
from logscan_web.scanner import scan_archive_path, scan_log
from logscan_web.storage import ScanStore

HEADER = "[kometa.py:1] [INFO] | Version: 2.2.2 |\n"


class DetectorOccurrenceTests(unittest.TestCase):
    def scans(self, text):
        data = (HEADER + text).encode()
        normal = scan_log("meta.log", data)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "meta.log"
            path.write_bytes(data)
            with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
                streamed = scan_archive_path("meta.log", path)[0][2]
        return normal, streamed

    def finding(self, result, identifier):
        return next(item for item in result.recommendations if item["id"] == identifier)

    def test_repeated_occurrences_do_not_change_findings_or_raw_counts(self):
        for result in self.scans("[kometa.py:2] [ERROR] | TMDb Error: Invalid API key |\n" * 3):
            for identifier in ("tmdb_key", "kometa_error"):
                finding = self.finding(result, identifier)
                self.assertEqual(finding["occurrence_count"], 3)
                self.assertEqual(finding["evidence_lines"], [2, 3, 4])
                self.assertFalse(finding["evidence_truncated"])
            self.assertEqual(result.metadata["log_counts"]["error"], 3)
            self.assertEqual(result.overview["finding_count"], len(result.recommendations))
            self.assertEqual(result.metadata["counts"]["error"], sum(item["severity"] == "error" for item in result.recommendations))
            self.assertIsNone(self.finding(result, "incomplete_log")["occurrence_count"])

    def test_multiple_keywords_and_repeated_keywords_count_one_line(self):
        for result in self.scans(
            "[kometa.py:2] [ERROR] | Config Error: anidb sub-attribute; AniDB Error: Login failed; AniDB Error: Login failed |\n"
            "[kometa.py:3] [ERROR] | AniDB Error: Login failed |\n"
        ):
            finding = self.finding(result, "anidb_auth")
            self.assertEqual(finding["occurrence_count"], 2)
            self.assertEqual(finding["evidence_lines"], [2, 3])

    def test_same_line_predicate_counts_only_complete_matches(self):
        partial = "Config Error: Operation mass_genre_update\nwithout a successful service\n"
        for result in self.scans(partial):
            self.assertNotIn("mass_update", [item["id"] for item in result.recommendations])
        for result in self.scans(partial + "cOnFiG eRrOr: Operation mass_genre_update without a successful service\n" + partial):
            finding = self.finding(result, "mass_update")
            self.assertEqual(finding["occurrence_count"], 1)
            self.assertEqual(finding["evidence_lines"], [4])

    def test_same_line_match_after_more_than_evidence_cap_partial_anchors(self):
        for result in self.scans(
            "Config Error: Operation mass_genre_update\n" * (EVIDENCE_LIMIT + 5) + "Config Error: Operation mass_genre_update without a successful service\n" * 2
        ):
            finding = self.finding(result, "mass_update")
            self.assertEqual(finding["occurrence_count"], 2)
            self.assertEqual(finding["evidence_lines"], [EVIDENCE_LIMIT + 7, EVIDENCE_LIMIT + 8])
            self.assertFalse(finding["evidence_truncated"])

    def test_word_boundaries_and_mixed_case_match_in_both_scans(self):
        for result in self.scans("database_cache: false\ncache: false_suffix\n\u00e9cache: false\ncache: false\u00e9\n" "(cAcHe: FaLsE) cAcHe: FaLsE\ncache: false\n"):
            finding = self.finding(result, "cache_disabled")
            self.assertEqual(finding["occurrence_count"], 2)
            self.assertEqual(finding["evidence_lines"], [6, 7])

    def test_occurrences_continue_after_evidence_cap_and_keep_parity(self):
        normal, streamed = self.scans("[kometa.py:2] [ERROR] | TMDb Error: Invalid API key; TMDb Error: Invalid API key |\n" * (EVIDENCE_LIMIT + 5))
        for identifier in ("tmdb_key", "kometa_error"):
            regular = self.finding(normal, identifier)
            self.assertEqual(regular, self.finding(streamed, identifier))
            self.assertEqual(regular["occurrence_count"], EVIDENCE_LIMIT + 5)
            self.assertTrue(regular["evidence_truncated"])
            self.assertEqual(regular["evidence_lines"], list(range(2, EVIDENCE_LIMIT + 2)))
        self.assertEqual(normal.metadata["log_counts"], streamed.metadata["log_counts"])
        self.assertEqual(normal.metadata["counts"], streamed.metadata["counts"])

    def test_exact_cap_is_not_truncated(self):
        rule = TextRule(RecommendationRule("test", "error", "Test", "Test", "Test"), any_of=("failure",))
        for evaluate in (
            lambda: rule.evaluate(ScanContext.from_content("test.log", "failure\n" * EVIDENCE_LIMIT)),
            lambda: evaluate_text_rules_bytes([rule], b"failure\n" * EVIDENCE_LIMIT),
        ):
            finding = evaluate()[0]
            self.assertEqual(finding.occurrence_count, EVIDENCE_LIMIT)
            self.assertFalse(finding.evidence_truncated)

    def test_complete_combined_predicate_and_log_wide_prerequisites(self):
        definition = RecommendationRule("test", "error", "Test", "Test", "Test")
        rule = TextRule(definition, any_of=("problem",), word_bounded_any_of=("cache", "cache: false"), all_of=("enabled", "confirmed"), all_on_same_line=("alpha", "beta"))
        text = "enabled\nconfirmed\nproblem alpha\ncache beta\nproblem alpha beta cache: false_suffix\n"
        for findings in (rule.evaluate(ScanContext.from_content("test.log", text)), evaluate_text_rules_bytes([rule], text.encode())):
            self.assertEqual(findings[0].occurrence_count, 1)
            self.assertEqual(findings[0].evidence_lines, (5,))
        for data in (text.replace("confirmed", "absent"), text.rsplit("\nproblem", 1)[0]):
            self.assertEqual(rule.evaluate(ScanContext.from_content("test.log", data)), [])
            self.assertEqual(evaluate_text_rules_bytes([rule], data.encode()), [])

    def test_overlapping_word_terms_and_any_terms_are_not_masked(self):
        definition = RecommendationRule("test", "error", "Test", "Test", "Test")
        for rule, text in (
            (TextRule(definition, any_of=("failure", "failure detail")), "FAILURE DETAIL failure\n"),
            (TextRule(definition, word_bounded_any_of=("cache", "cache: false")), "cache: false\u00e9\n"),
        ):
            for finding in (rule.evaluate(ScanContext.from_content("test.log", text))[0], evaluate_text_rules_bytes([rule], text.encode())[0]):
                self.assertEqual(finding.occurrence_count, 1)
                self.assertEqual(finding.evidence_lines, (1,))

    def test_line_endings_and_evidence_numbers_match(self):
        rule = TextRule(RecommendationRule("test", "error", "Test", "Test", "Test"), any_of=("failure",))
        text = "\r\nfailure\r\n\rFAILURE\nfailure"
        regular = rule.evaluate(ScanContext.from_content("test.log", text))[0]
        streamed = evaluate_text_rules_bytes([rule], text.encode())[0]
        self.assertEqual(regular, streamed)
        self.assertEqual(regular.evidence_lines, (2, 4, 5))
        self.assertEqual(regular.occurrence_count, 3)

    def test_custom_detectors_use_full_log_after_sampling_limit(self):
        normal, streamed = self.scans(
            "Connected to server Example version 1.41.8.10000\n" * 250
            + "Connected to server Old version 1.40.1.8000\n"
            + "mass_user_rating_update mass_episode_user_ratings_update\n" * 250
            + "run_order:\n- metadata\n" * 250
            + "run_order:\n- operations\n"
        )
        for identifier in ("plex_security", "rating_rounding", "run_order"):
            finding = self.finding(normal, identifier)
            self.assertEqual(finding, self.finding(streamed, identifier))
            self.assertEqual(finding["occurrence_count"], 250)
            self.assertEqual(len(finding["evidence_lines"]), 250)
            self.assertFalse(finding["evidence_truncated"])

    def test_custom_detector_applies_version_range_and_evidence_cap(self):
        rule = PlexSecurityRule(RecommendationRule("test", "critical", "Test", "Test", "Test"))
        text = "Connected to server Safe version 1.43.0.10000\n" + "cOnNeCtEd to server Vulnerable version 1.41.8.10000\n" * (EVIDENCE_LIMIT + 5)
        normal = rule.evaluate(ScanContext.from_content("test.log", text))[0]
        streamed = rule.evaluate_bytes(text.encode())[0]
        self.assertEqual(normal, streamed)
        self.assertEqual(normal.occurrence_count, EVIDENCE_LIMIT + 5)
        self.assertTrue(normal.evidence_truncated)
        self.assertEqual(normal.evidence_lines, tuple(range(2, EVIDENCE_LIMIT + 2)))

    def test_mmap_matching_has_bounded_memory_even_for_long_lines(self):
        rule = TextRule(RecommendationRule("test", "error", "Test", "Test", "Test"), all_on_same_line=("anchor", "complete"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.log"
            path.write_bytes(b"anchor complete\n" * 12_000 + b"anchor " + b"x" * (8 * 1024 * 1024) + b" complete\n")
            with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as content:
                tracemalloc.start()
                try:
                    finding = evaluate_text_rules_bytes([rule], content)[0]
                    _current, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
        self.assertEqual(finding.occurrence_count, 12_001)
        self.assertEqual(len(finding.evidence_lines), EVIDENCE_LIMIT)
        self.assertTrue(finding.evidence_truncated)
        self.assertLess(peak, 3 * 1024 * 1024)

    def test_stored_results_and_older_records_without_fields(self):
        from logscan_web.app import ANALYSIS_VERSION, app

        content = (HEADER + "[kometa.py:2] [ERROR] | TMDb Error: Invalid API key |\n" * (EVIDENCE_LIMIT + 5)).encode()
        result = scan_log("meta.log", content)
        result.metadata.update(analysis_version=ANALYSIS_VERSION, schema_validation_count=0)
        store = ScanStore(app.config["SCAN_STORE"])
        scan_id, token = store.create("meta.log", content, result)
        try:
            body = app.test_client().get(f"/scan/{scan_id}").get_data(as_text=True)
            record = json.loads(re.search(r'<script id="initial-scan" type="application/json">(.*?)</script>', body, re.S).group(1))
            finding = next(item for item in record["recommendations"] if item["id"] == "tmdb_key")
            self.assertEqual(finding["occurrence_count"], EVIDENCE_LIMIT + 5)
            self.assertTrue(finding["evidence_truncated"])
            for item in result.recommendations:
                item.pop("occurrence_count", None)
                item.pop("evidence_truncated", None)
            self.assertTrue(store.replace_analysis(scan_id, result))
            older_body = app.test_client().get(f"/scan/{scan_id}").get_data(as_text=True)
            older = json.loads(re.search(r'<script id="initial-scan" type="application/json">(.*?)</script>', older_body, re.S).group(1))
            self.assertTrue(all("occurrence_count" not in item for item in older["recommendations"]))
            self.assertNotIn("delete_token_hash", older)
        finally:
            store.delete(scan_id, token)

    def test_startup_backfill_preserves_retained_record_identity_and_metadata(self):
        from logscan_web.app import ANALYSIS_VERSION, SCHEMA_VALIDATION_VERSION, create_app

        self.assertEqual(ANALYSIS_VERSION, 8)
        native_integrity = (
            "[integrity.py:674] [INFO] |     Source Integrity: MODIFIED |\n" "[integrity.py:674] [INFO] |     Modified: |\n" "[integrity.py:674] [INFO] |       modules/logs.py |\n"
        )
        content = (HEADER + native_integrity + "[kometa.py:2] [ERROR] | TMDb Error: Invalid API key |\n" * 3).encode()
        result = scan_log("meta.log", content)
        result.recommendations[:] = [item for item in result.recommendations if not item["id"].startswith("source_integrity_")]
        result.metadata["kometa_integrity"] = {"detected": False, "state": "not_reported"}
        for item in result.recommendations:
            item.pop("occurrence_count", None)
            item.pop("evidence_truncated", None)
        schema = {
            "schema_validation_count": 0,
            "schema_validation_version": SCHEMA_VALIDATION_VERSION,
            "schema_validation_checked_at": datetime.now(UTC).isoformat(),
            "schema_validation_failures": [],
            "schema_validation_branch": "develop",
            "schema_directive_missing": True,
        }
        result.metadata.update(analysis_version=7, **schema)
        attribution = {"upload_source": "discord", "uploaded_by": "Tester", "uploaded_by_id": "42", "message_url": "https://example.test/message"}
        result.overview.update(attribution)
        with tempfile.TemporaryDirectory() as directory:
            store = ScanStore(directory)
            scan_id, token = store.create("meta.log", content, result)
            before = store.get(scan_id)
            with (
                patch.dict("os.environ", SCAN_STORE=directory),
                patch("logscan_web.app.threading.Thread") as thread,
                patch("logscan_web.app.AnonymousAnalyticsStore.record_success") as success,
            ):
                app = create_app()
                migration = next(call.kwargs["target"] for call in thread.call_args_list if call.kwargs.get("name") == "retained-scan-migration")
                migration()
                with patch("logscan_web.app.scan_archive_path") as scan:
                    migration()
                    scan.assert_not_called()
                success.assert_not_called()
            after = store.get(scan_id)
            for key in ("id", "created_at", "delete_token_hash"):
                self.assertEqual(after[key], before[key])
            self.assertEqual(store.log_path(scan_id).read_bytes(), content)
            self.assertEqual(after["metadata"]["analysis_version"], ANALYSIS_VERSION)
            self.assertEqual({key: after["metadata"][key] for key in schema}, schema)
            self.assertEqual({key: after["overview"][key] for key in attribution}, attribution)
            self.assertEqual(next(item for item in after["recommendations"] if item["id"] == "tmdb_key")["occurrence_count"], 3)
            self.assertEqual(after["metadata"]["kometa_integrity"]["modified"], ["modules/logs.py"])
            integrity_finding = next(item for item in after["recommendations"] if item["id"] == "source_integrity_modified")
            self.assertIn("modules/logs.py", integrity_finding["message"])
            self.assertEqual(integrity_finding["evidence_lines"], after["metadata"]["kometa_integrity"]["evidence_lines"])
            client = app.test_client()
            with client.session_transaction() as account:
                account["support_authorized_at"] = 9999999999
                account["discord_user"] = {"id": "42", "username": "Tester"}
                account["support_access"] = False
            console = client.get("/support/logs?integrity=modified").get_data(as_text=True)
            self.assertIn('data-title="meta.log"', console)
            self.assertIn('class="support-integrity integrity-modified"', console)
            self.assertIn("Integrity: Modified", console)
            self.assertTrue(store.delete(scan_id, token))


if __name__ == "__main__":
    unittest.main()
