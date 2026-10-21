"""Offline advisory behavior and integration with both portal scan paths."""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from logscan_web.plex_security import assess_log, assessment_message, evaluate_advisories, legacy_affected, parse_pms_version, server_observation
from logscan_web.rules.base import EVIDENCE_LIMIT
from logscan_web.scanner import plex_analytics, plex_server_summaries, scan_archive_path, scan_log
from logscan_web.support import _support_row

HEADER = "[kometa.py:1] [INFO] | Version: 2.2.2 |\n"


@pytest.mark.parametrize(
    "version,status",
    [
        ("1.42.0.99999", "affected"),
        ("1.43.2.99999", "affected"),
        ("1.43.3.10860", "affected"),
        ("1.43.3.10861", "patched"),
        ("1.43.3.10861-07dfddaeb", "patched"),
        ("1.43.4.10000", "patched"),
        ("1.43.5.11029-6bf8af3f0", "patched"),
        ("'1.43.5.11029-6bf8af3f0'", "patched"),
        ('"1.43.5.11029-6bf8af3f0"', "patched"),
        (None, "unknown"),
        ("", "unknown"),
        ("1.43.3", "unknown"),
        ("1.43", "unknown"),
        ("1.43.3.10861junk", "unknown"),
        ("1.43.3.10861.0", "unknown"),
        ("1.43.3.10861-hash", "unknown"),
        ("1.43.3.10861-", "unknown"),
        ("'1.43.5.11029-6bf8af3f0", "unknown"),
        ("'1.43.5.11029-6bf8af3f0junk'", "unknown"),
        ("bad", "unknown"),
        ("1.43.3.-1", "unknown"),
    ],
)
def test_version_boundaries(version, status):
    assessment = evaluate_advisories(version)[0]
    assert assessment["status"] == status
    assert assessment["advisory_id"] == "PLEX-PMS-2026-09"
    assert assessment["published_date"] == "2026-09-01"
    assert "not an official CVSS" in assessment["severity_source"]
    if status == "unknown":
        assert parse_pms_version(version) is None


def test_legacy_range_is_preserved_without_false_partial_matches():
    assert legacy_affected("1.41.7.9100")
    assert legacy_affected("1.42.0.99999-abc123")
    assert not legacy_affected("1.40.5.8000")
    assert not legacy_affected("1.42.1.0")
    assert not legacy_affected("1.41.7")
    assert not legacy_affected("1.41.7.9100garbage")


def test_multiple_historical_runs_deduplicate_and_keep_evidence():
    text = (
        "Connected to server A version 1.43.2.99999\n" * 2
        + "Finished run\nStarted run\n"
        + "Connected to server A (Version: 1.43.3.10861)\n"
        + "Connected to server B version 1.43.3.10860\n"
    )
    assessments = assess_log(enumerate(text.splitlines(), 1))
    assert len(assessments) == 2
    assert all(item["status"] == "affected" for item in assessments)
    assert assessments[0]["evidence_lines"] == [1, 2, 5]
    assert assessments[0]["observations"][0]["occurrence_count"] == 2
    assert assessments[0]["observations"][1]["status"] == "patched"


def test_invalid_suffix_is_not_silently_stripped():
    assessment = assess_log([(1, "Connected to server A version 1.43.3.10861)")])[0]
    assert assessment["status"] == "unknown"


@pytest.mark.parametrize("field", ["version {version}", "version '{version}'", 'version "{version}"', "(Version: {version})", "(Version: '{version}')"])
def test_patched_alexandria_version_is_consistent_in_normal_and_streaming_scans(tmp_path, field):
    version = "1.43.5.11029-6bf8af3f0"
    connection = f"Connected to server Alexandria {field.format(version=version)}"
    content = (
        HEADER
        + "[plex.py:1] [INFO] | Plex Configuration |\n"
        + f"[plex.py:2] [INFO] | {connection} |\n"
        + "[plex.py:3] [INFO] | Running on Windows version 10.0.19045.6036 |\n"
        + "[plex.py:4] [INFO] | Connected to library Movies |\n"
        + "[plex.py:5] [INFO] | Type: Movie |\n"
        + "[plex.py:6] [INFO] | Library Connection Successful |\n"
        + f"[plex.py:7] [INFO] | {connection} |\n"
    ).encode()
    normal = scan_log("meta.log", content)
    path = tmp_path / "meta.log"
    path.write_bytes(content)
    with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
        streamed = scan_archive_path("meta.log", path)[0][2]
    assessment = assess_log(enumerate(content.decode().splitlines(), 1))[0]
    assert assessment["status"] == "patched" and assessment["occurrence_count"] == 2
    assert assessment["normalized_version"] == "1.43.5.11029"
    assert "not affected by this advisory" in assessment_message(assessment)
    assert "Validate the current server version" not in assessment_message(assessment)
    for result in (normal, streamed):
        assert result.overview["plex_servers"] == [{"name": "Alexandria", "version": version, "platform": "Windows version 10.0.19045.6036"}]
        assert result.overview["plex_analytics"]["versions"] == [version]
        assert not any(item.get("security_assessment") for item in result.recommendations)
    assert normal.recommendations == streamed.recommendations


def test_server_identity_quotes_and_invalid_version_do_not_corrupt_other_version_consumers():
    assert server_observation('Connected to server "Alexandria" version "1.43.5.11029-6bf8af3f0" |') == ("Alexandria", "1.43.5.11029-6bf8af3f0")
    sections = [{"lines": ["Connected to server Alexandria version 1.43.3.10861junk", "Running on Linux version 6.8.0.100"]}]
    assert plex_analytics(sections)["versions"] == []
    assert plex_server_summaries(sections)[0]["version"] == "1.43.3.10861junk"


def test_patched_then_affected_observations_keep_update_remediation():
    assessment = assess_log([(1, "Connected to server A version 1.43.5.11029-6bf8af3f0"), (2, "Connected to server A version 1.43.3.10860")])[0]
    assert assessment["status"] == "affected"
    assert assessment["remediation"].startswith("Update Plex Media Server")
    assert "No advisory-related update is needed" not in assessment_message(assessment)


def test_retained_scan_reanalysis_updates_plex_versions_and_removes_patched_advice(tmp_path):
    from logscan_web.app import ANALYSIS_VERSION, create_app
    from logscan_web.models import Finding
    from logscan_web.storage import AnonymousAnalyticsStore, ScanStore

    version = "1.43.5.11029-6bf8af3f0"
    content = (
        HEADER + "Plex Configuration\n" + f"Connected to server Alexandria version '{version}'\n" + "Running on Windows version 10.0.19045.6036\nLibrary Connection Successful\n"
    ).encode()
    result = scan_log("old.log", content)
    result.metadata["analysis_version"] = 10
    result.overview["plex_analytics"]["versions"] = ["10.0.19045.6036"]
    result.recommendations.append(Finding("plex_security_patched", "advice", "Plex advisory assessment: patched", "Validate the current server version.").as_dict())
    store = ScanStore(tmp_path)
    scan_id, _token = store.create("old.log", content, result)
    before = store.get(scan_id)
    with patch.dict("os.environ", SCAN_STORE=str(tmp_path)), patch("logscan_web.app.threading.Thread"):
        app = create_app()
    stats = AnonymousAnalyticsStore(tmp_path).snapshot()
    public = app.test_client().get(f"/scan/{scan_id}").get_data(as_text=True)
    assert "plex_security_patched" not in public
    app.extensions["backfill_scan_analysis"]()
    after = store.get(scan_id)
    assert after["metadata"]["analysis_version"] == ANALYSIS_VERSION == 13
    assert after["overview"]["plex_servers"][0]["version"] == version
    assert after["overview"]["plex_analytics"]["versions"] == [version]
    assert not any(item["id"] == "plex_security_patched" for item in after["recommendations"])
    for field in ("id", "created_at", "delete_token_hash"):
        assert after[field] == before[field]
    assert AnonymousAnalyticsStore(tmp_path).snapshot() == stats


def test_future_definitions_do_not_replace_current_advisory(monkeypatch):
    from dataclasses import replace
    from logscan_web import plex_security

    original = plex_security.ADVISORIES[0]
    future = replace(original, advisory_id="TEST-FUTURE", minimum_patched_version="1.44.0.10000")
    monkeypatch.setattr(plex_security, "ADVISORIES", (*plex_security.ADVISORIES, future))
    assessments = evaluate_advisories("1.43.3.10861")
    assert [(item["advisory_id"], item["status"]) for item in assessments] == [("PLEX-PMS-2026-09", "patched"), ("TEST-FUTURE", "affected")]


@pytest.mark.parametrize(
    "body",
    [
        "",
        "Connected to server A version unknown\n",
        "Connected to server A version 1.43.3\n",
        "Connected to server A version 1.41.7.9100malformed\n",
        "Connected to server A version \n",
    ],
)
def test_unknown_is_neutral(body):
    result = scan_log("meta.log", (HEADER + body).encode())
    security = [item for item in result.recommendations if item.get("security_assessment")]
    assert len(security) == 1
    assert security[0]["severity"] == "advice"
    assert security[0]["security_assessment"]["status"] == "unknown"
    assert result.metadata["counts"]["critical"] == 0


def test_normal_streaming_support_and_semantic_counts(tmp_path):
    content = (HEADER + "Connected to server Old version 1.41.7.9100\n" * (EVIDENCE_LIMIT + 5) + "Connected to server Other version 1.43.3.10860\n").encode()
    normal = scan_log("meta.log", content)
    path = tmp_path / "meta.log"
    path.write_bytes(content)
    with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
        streamed = scan_archive_path("meta.log", Path(path))[0][2]
    for result in (normal, streamed):
        findings = [item for item in result.recommendations if item["id"] == "plex_security"]
        assert len(findings) == 2
        assert result.metadata["counts"]["critical"] == 2
        assert result.metadata["log_counts"]["critical"] == 0
        assert findings[0]["occurrence_count"] == EVIDENCE_LIMIT + 5
        assert findings[0]["evidence_truncated"]
        assert len(findings[0]["evidence_lines"]) == EVIDENCE_LIMIT
        assert findings[0]["security_assessment"]["legacy_vulnerability_affected"]
        assert "observed in this log" in findings[0]["message"]
        record = {"recommendations": result.recommendations, "metadata": result.metadata, "created_at": datetime.now(UTC).isoformat()}
        row = _support_row(record, 3600, datetime.now(UTC))
        assert row["counts"]["critical"] == 2
    assert normal.recommendations == streamed.recommendations


def test_date_context_matches_full_log_in_normal_and_streaming_scans(tmp_path):
    # The final timestamp occurs after the security evidence limit; it still
    # contributes to the log date range, including multiple historical runs.
    content = (
        HEADER
        + "[2023-09-25 01:23:45,678] [plex.py:1] [INFO] | Connected to server Classic Connection version 1.32.5.7349-8f4248874 |\n" * (EVIDENCE_LIMIT + 1)
        + "[2026-10-18 01:00:00,000] [kometa.py:1] [INFO] | Next historical run |\n"
    ).encode()
    normal = scan_log("meta.log", content)
    path = tmp_path / "meta.log"
    path.write_bytes(content)
    with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
        streamed = scan_archive_path("meta.log", path)[0][2]
    assert normal.metadata["log_date_range"] == {"first": "2023-09-25", "last": "2026-10-18"}
    assert streamed.metadata["log_date_range"] == normal.metadata["log_date_range"]


@pytest.mark.parametrize("content", [b"No timestamp", b"[2026-02-30 12:00:00,123] message", b"[2026-10-18 25:00:00] message"])
def test_missing_or_invalid_dates_are_not_fabricated(content):
    from logscan_web.log_facts import extract_log_date_range

    assert extract_log_date_range(content) is None
