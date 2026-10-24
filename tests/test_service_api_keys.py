"""Service attribution, evidence and retained-scan API-key regressions."""

from pathlib import Path
from unittest.mock import patch

import pytest

from logscan_web.models import Finding, ScanContext
from logscan_web.rules.base import EVIDENCE_LIMIT
from logscan_web.rules.services import MissingApiKeyRule
from logscan_web.scanner import scan_log
from logscan_web.storage import ScanStore

HEADER = "[kometa.py:1] [INFO] | Version: 2.2.2 (Git: develop) |\n"
MDBLIST_ERROR = "[config.py:1126] [WARNING] | Config Error: mdblist sub-attribute apikey is blank |"


def test_actual_mdblist_log_lines_keep_service_and_exact_occurrences():
    lines = [HEADER.rstrip()] + ["unrelated"] * 83804
    lines[451] = lines[83804] = MDBLIST_ERROR
    content = "\n".join(lines).encode()
    normal = scan_log("meta.log", content)
    with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
        streamed = scan_log("meta.log", content)
    findings = [item for item in normal.recommendations if item["id"].startswith("api_key_missing")]
    assert findings == [item for item in streamed.recommendations if item["id"].startswith("api_key_missing")]
    finding = findings[0]
    assert finding["id"] == "api_key_missing_mdblist"
    assert finding["title"] == "MDBList API key is missing"
    assert finding["service"] == "mdblist"
    assert finding["evidence_lines"] == [452, 83805]
    assert finding["occurrence_count"] == 2
    assert "`mdblist.apikey`" in finding["solution"]
    assert "/en/develop/config/mdblist/" in finding["message"]
    assert "trakt" not in finding["solution"]


@pytest.mark.parametrize(
    "message, service, field",
    [
        (MDBLIST_ERROR.swapcase(), "mdblist", "apikey"),
        ("Config Error: tmdb sub-attribute apikey not found", "tmdb", "apikey"),
        ("OMDb Error: api_key is missing", "omdb", "api_key"),
        ("Config Error: radarr sub-attribute api_key is blank", "radarr", "api_key"),
    ],
)
def test_known_api_key_formats_match_normal_and_byte_scans(message, service, field):
    rule = MissingApiKeyRule()
    findings = rule.evaluate(ScanContext.from_content("meta.log", message))
    assert findings == rule.evaluate_bytes(message.encode())
    assert findings[0].service == service
    assert f"`{service}.{field}`" in findings[0].solution


def test_services_and_unidentified_entries_have_independent_counts_and_evidence():
    content = "\n".join(
        [MDBLIST_ERROR, "Config Error: omdb sub-attribute apikey is blank", MDBLIST_ERROR, "apikey is blank", "Config Error: new_service sub-attribute apikey is blank"]
    )
    findings = {item.id: item for item in MissingApiKeyRule().evaluate_bytes(content.encode())}
    assert findings["api_key_missing_mdblist"].evidence_lines == (1, 3)
    assert findings["api_key_missing_mdblist"].occurrence_count == 2
    assert findings["api_key_missing_omdb"].evidence_lines == (2,)
    unknown = findings["api_key_missing"]
    assert unknown.evidence_lines == (4, 5)
    assert unknown.service is None
    assert "could not be identified" in unknown.description
    assert "trakt" not in unknown.solution
    assert "service" not in unknown.as_dict()


def test_more_than_sampling_and_evidence_limits_keep_exact_counts_per_service():
    content = (MDBLIST_ERROR + "\r\n") * (EVIDENCE_LIMIT + 5) + "Config Error: omdb sub-attribute apikey is blank"
    rule = MissingApiKeyRule()
    normal = rule.evaluate(ScanContext.from_content("meta.log", content))
    assert normal == rule.evaluate_bytes(content.encode())
    mdblist, omdb = normal
    assert mdblist.occurrence_count == EVIDENCE_LIMIT + 5
    assert mdblist.evidence_lines == tuple(range(1, EVIDENCE_LIMIT + 1))
    assert mdblist.evidence_truncated
    assert omdb.evidence_lines == (EVIDENCE_LIMIT + 6,)


def test_api_key_values_and_unrelated_service_names_are_not_reported():
    content = "Config Error: mdblist sub-attribute apikey is blank\nOMDb setting: apikey: secret-value\n"
    finding = MissingApiKeyRule().evaluate_bytes(content.encode())[0]
    assert finding.service == "mdblist"
    assert "secret-value" not in finding.as_dict()["message"]
    assert MissingApiKeyRule().evaluate_bytes(b"apikey: abc123\napi_key is not blank\n") == []
    assert MissingApiKeyRule().evaluate_bytes(b"apikey\nis blank\napi_key is\nmissing") == []


def test_version_12_retained_scan_is_upgraded_without_changing_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    from logscan_web.app import ANALYSIS_VERSION, create_app

    content = (HEADER + MDBLIST_ERROR).encode()
    result = scan_log("meta.log", content)
    result.metadata["analysis_version"] = 12
    result.recommendations[:] = [Finding("api_key_missing", "error", "API key is missing", "Generic old advice.").as_dict()]
    store = ScanStore(tmp_path)
    scan_id, _token = store.create("meta.log", content, result)
    before = store.get(scan_id)
    with patch("logscan_web.app.threading.Thread"), patch("logscan_web.app.AnonymousAnalyticsStore.record_success") as analytics:
        app = create_app()
        app.extensions["backfill_scan_analysis"]()
        with patch("logscan_web.app.scan_archive_path") as rescan:
            app.extensions["backfill_scan_analysis"]()
            rescan.assert_not_called()
        analytics.assert_not_called()
    after = store.get(scan_id)
    assert after["metadata"]["analysis_version"] == ANALYSIS_VERSION == 14
    for field in ("id", "created_at", "delete_token_hash"):
        assert after[field] == before[field]
    finding = next(item for item in after["recommendations"] if item["id"] == "api_key_missing_mdblist")
    assert finding["service"] == "mdblist" and finding["evidence_lines"] == [2]
    assert all(item["id"] != "api_key_missing" for item in after["recommendations"])
    assert store.log_path(scan_id).read_bytes() == content
    # These are bundled assets, served by Logscan without a Quickstart runtime.
    client = app.test_client()
    for icon in Path("logscan_web/static/service-icons").glob("*.png"):
        response = client.get(f"/static/service-icons/{icon.name}")
        assert response.status_code == 200 and response.mimetype == "image/png"
