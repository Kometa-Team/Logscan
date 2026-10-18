"""Offline advisory behavior and integration with both portal scan paths."""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from logscan_web.plex_security import assess_log, evaluate_advisories, legacy_affected, parse_pms_version
from logscan_web.rules.base import EVIDENCE_LIMIT
from logscan_web.scanner import scan_archive_path, scan_log
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
        (None, "unknown"),
        ("", "unknown"),
        ("1.43.3", "unknown"),
        ("1.43", "unknown"),
        ("1.43.3.10861junk", "unknown"),
        ("1.43.3.10861.0", "unknown"),
        ("1.43.3.10861-hash", "unknown"),
        ("1.43.3.10861-", "unknown"),
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
