"""Configuration issue identity, defaults, service icons and retained scans."""

from unittest.mock import patch

import pytest

from logscan_web.models import Finding, ScanContext
from logscan_web.rules.base import EVIDENCE_LIMIT
from logscan_web.rules.configuration import ConfigurationDefaultRule, ServiceConfigurationRule
from logscan_web.scanner import scan_log
from logscan_web.storage import ScanStore

HEADER = "[kometa.py:1] [INFO] | Version: 2.5.1 (Branch: develop) |\n"


def warning(section, field, value):
    return f"Config Warning: {section} sub-attribute {field} not found using {value} as default"


def test_actual_six_log_entries_become_three_precise_findings_in_both_scan_modes():
    lines = [HEADER.rstrip()] + ["unrelated"] * 37934
    for source, summary, section, field, value in [
        (340, 37933, "settings", "playlist_sync_to_users", "None"),
        (342, 37934, "settings", "overlay_artwork_quality", "90"),
        (392, 37935, "tracearr", "server_id", "None"),
    ]:
        lines[source - 1] = "[config.py:679] [WARNING] | " + warning(section, field, value) + " |"
        lines[summary - 1] = "[kometa.py:743] [INFO] | 1 | " + warning(section, field, value) + " |"
    content = "\n".join(lines).encode()
    normal = scan_log("meta.log", content)
    with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
        streamed = scan_log("meta.log", content)

    def select(result):
        return [item for item in result.recommendations if item["id"].startswith("config_subattribute_default")]

    findings = select(normal)
    assert findings == select(streamed)
    assert len(findings) == 3
    for field, value, evidence, service in [
        ("playlist_sync_to_users", "None", [340, 37933], "kometa"),
        ("overlay_artwork_quality", "90", [342, 37934], "kometa"),
        ("server_id", "None", [392, 37935], "tracearr"),
    ]:
        finding = next(item for item in findings if field in item["title"])
        assert f"{field} defaults to {value}" in finding["title"]
        assert finding["evidence_lines"] == evidence and finding["occurrence_count"] == 2
        assert finding["service"] == service and finding["severity"] == "warning"
        assert f"logged default `{value}`" in finding["description"]
        assert "No change is required" in finding["solution"]
        assert "/en/develop/config/" in finding["solution"]
    tracearr = next(item for item in findings if item["service"] == "tracearr")
    assert "automatically" in tracearr["description"]
    assert "no unique match" in tracearr["solution"]
    assert "/config/tracearr/" in tracearr["solution"]
    playlist = next(item for item in findings if "playlist_sync_to_users" in item["title"])
    assert "owner-only" in playlist["solution"]


def test_different_defaults_for_one_field_keep_their_own_lines_and_identity():
    text = "\n".join(warning("settings", "overlay_artwork_quality", value) for value in ("90", "75", "90"))
    findings = ConfigurationDefaultRule().evaluate_bytes(text.encode())
    assert len(findings) == 2 and findings[0].id != findings[1].id
    assert findings[0].evidence_lines == (1, 3) and findings[1].evidence_lines == (2,)
    assert "`90`" in findings[0].description and "`75`" in findings[1].description


def test_unknown_sections_are_named_without_inventing_a_service_icon_or_docs_route():
    text = warning("custom_section", "custom_field", "True")
    finding = ConfigurationDefaultRule().evaluate_bytes(text.encode())[0]
    assert finding.service is None
    assert "`custom_section.custom_field`" in finding.description
    assert "/config/overview/" in finding.solution
    assert "service" not in finding.as_dict()


@pytest.mark.parametrize("field", ["apikey", "api_key", "password", "access_token", "url"])
def test_credential_defaults_are_not_copied_into_findings(field):
    finding = ConfigurationDefaultRule().evaluate_bytes(warning("tracearr", field, "secret-value").encode())[0]
    assert "secret-value" not in finding.title + finding.description + finding.solution
    assert "[redacted]" in finding.description


def test_mixed_case_and_line_endings_have_identical_text_and_byte_evidence():
    text = "\r\n" + warning("Tracearr", "server_id", "None").swapcase() + "\r\n" + warning("settings", "verify_ssl", "True")
    rule = ConfigurationDefaultRule()
    findings = rule.evaluate(ScanContext.from_content("meta.log", text))
    assert findings == rule.evaluate_bytes(text.encode())
    assert [item.evidence_lines for item in findings] == [(2,), (3,)]
    assert [item.service for item in findings] == ["tracearr", "kometa"]


def test_unparsed_warnings_keep_generic_evidence_and_split_lines_do_not_match():
    rule = ConfigurationDefaultRule()
    text = "Config Warning: strange section sub-attribute field not found using value as default"
    finding = rule.evaluate_bytes(text.encode())[0]
    assert finding.id == rule.id and finding.evidence_lines == (1,) and finding.service is None
    assert rule.evaluate_bytes(b"Config Warning: settings\nsub-attribute field not found using None as default") == []


def test_configuration_evidence_caps_do_not_lose_counts_or_late_settings():
    text = (warning("tracearr", "server_id", "None") + "\n") * (EVIDENCE_LIMIT + 5) + warning("settings", "verify_ssl", "True")
    rule = ConfigurationDefaultRule()
    findings = rule.evaluate_bytes(text.encode())
    assert findings == rule.evaluate(ScanContext.from_content("meta.log", text))
    assert findings[0].occurrence_count == EVIDENCE_LIMIT + 5 and findings[0].evidence_truncated
    assert findings[0].evidence_lines == tuple(range(1, EVIDENCE_LIMIT + 1))
    assert findings[1].evidence_lines == (EVIDENCE_LIMIT + 6,)


def test_many_distinct_settings_preserve_overflow_evidence_with_bounded_groups():
    text = "\n".join(warning("settings", f"field_{number}", "None") for number in range(110))
    findings = ConfigurationDefaultRule().evaluate_bytes(text.encode())
    assert len(findings) == 101
    overflow = next(item for item in findings if item.id == "config_subattribute_default")
    assert overflow.evidence_lines == tuple(range(101, 111)) and overflow.occurrence_count == 10
    assert sum(item.occurrence_count for item in findings) == 110


def test_unusually_long_messages_keep_generic_evidence_without_copying_their_contents():
    padding = "x" * (1024 * 1024)
    for rule, text in [
        (ConfigurationDefaultRule(), f"Config Warning: {padding} sub-attribute field not found using None as default"),
        (ServiceConfigurationRule(), f"Collection Error: {padding} requires Tracearr to be configured"),
    ]:
        findings = rule.evaluate_bytes(text.encode())
        assert findings == rule.evaluate(ScanContext.from_content("meta.log", text))
        assert len(findings) == 1 and findings[0].id == rule.id and findings[0].evidence_lines == (1,)
        assert padding not in findings[0].as_dict()["message"]


def test_service_configuration_errors_name_each_feature_and_use_service_aliases():
    text = "\n".join(
        [
            "Collection Error: 'tracearr_history' requires Tracearr to be configured",
            "Collection Error: 'sonarr_all' requires Sonarr to be configured",
            "Collection Error: 'tracearr_history' requires Tracearr to be configured",
            "Collection Error: 'mal_all'requires MyAnimeList to be configured",
            "Collection Error: 'custom' requires NewService to be configured",
        ]
    )
    rule = ServiceConfigurationRule()
    findings = rule.evaluate(ScanContext.from_content("meta.log", text))
    assert findings == rule.evaluate_bytes(text.encode())
    tracearr, sonarr, mal, unknown = findings
    assert tracearr.id == "service_config_tracearr_tracearr_history" and tracearr.service == "tracearr"
    assert tracearr.evidence_lines == (1, 3) and tracearr.occurrence_count == 2
    assert "`tracearr_history`" in tracearr.description and "`tracearr`" in tracearr.solution
    assert sonarr.service == "sonarr" and sonarr.evidence_lines == (2,)
    assert mal.service == "mal" and "/config/myanimelist/" in mal.solution
    assert unknown.id == "service_config" and unknown.service is None
    assert rule.evaluate_bytes(b"Collection Error: method\nrequires Tracearr to be configured") == []


def test_version_13_retained_default_warning_is_replaced_once_without_new_submission(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    from logscan_web.app import ANALYSIS_VERSION, create_app

    content = (HEADER + warning("tracearr", "server_id", "None")).encode()
    result = scan_log("meta.log", content)
    result.metadata["analysis_version"] = 13
    result.recommendations[:] = [Finding("config_subattribute_default", "warning", "Configuration setting is using its default", "Old generic advice.").as_dict()]
    result.overview.update(upload_source="discord", uploaded_by="Uploader", uploaded_by_id="42")
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
    for field in ("upload_source", "uploaded_by", "uploaded_by_id"):
        assert after["overview"][field] == before["overview"][field]
    finding = next(item for item in after["recommendations"] if item.get("service") == "tracearr")
    assert finding["evidence_lines"] == [2] and "`tracearr.server_id`" in finding["description"]
    assert all(item["id"] != "config_subattribute_default" for item in after["recommendations"])
    assert store.log_path(scan_id).read_bytes() == content
