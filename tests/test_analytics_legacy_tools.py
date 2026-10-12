import json

import pytest

from logscan_web.storage import AnonymousAnalyticsStore


@pytest.mark.parametrize("tools", [None, {}, {"imagemaid": 3}, {"kometa": 20, "imagemaid": 3}])
def test_historical_tool_counts_are_backfilled_without_changing_totals(tmp_path, tools):
    day = {"successful_logs": 526, "kometa_versions": {"2.5.0": 42}, "sources": {"legacy": 500, "web": 26}, "imagemaid_files_removed": 27448}
    if tools is not None:
        day["tools"] = tools
    path = tmp_path / "usage_analytics.json"
    path.write_text(json.dumps({"started_at": "2026-09-20T12:00:00+00:00", "days": {"2026-09-20": day}, "legacy_usage_imported": True}), encoding="utf-8")
    store = AnonymousAnalyticsStore(tmp_path)
    expected_imagemaid = (tools or {}).get("imagemaid", 0)
    for _ in range(2):
        snapshot = store.snapshot()
        assert snapshot["totals"]["tools"]["kometa"] == 526 - expected_imagemaid
        assert snapshot["totals"]["tools"].get("imagemaid", 0) == expected_imagemaid
        assert snapshot["totals"]["successful_logs"] == 526
        assert snapshot["totals"]["kometa_versions"] == {"2.5.0": 42}
        assert snapshot["totals"]["sources"] == {"legacy": 500, "web": 26}
        assert snapshot["totals"]["imagemaid_files_removed"] == 27448
        assert snapshot["days"]["2026-09-20"]["tools"] == snapshot["totals"]["tools"]
    store.record_rejection("not_supported_log", "web")
    assert AnonymousAnalyticsStore(tmp_path).snapshot()["totals"]["tools"] == snapshot["totals"]["tools"]
    assert json.loads(path.read_text(encoding="utf-8"))["days"]["2026-09-20"]["tools"] == snapshot["totals"]["tools"]


def test_legacy_baseline_backfills_tool_counts_once_and_preserves_other_tools(tmp_path):
    store = AnonymousAnalyticsStore(tmp_path)
    store.record_success(
        logs=3,
        lines=10,
        bytes_processed=100,
        source="web",
        batch=False,
        versions=[],
        kometa_branches=[],
        launchers=[],
        quickstart_versions=[],
        quickstart_branches=[],
        recommendations=[],
        people=0,
        tools=["imagemaid"] * 3,
    )
    legacy = {"logs_submitted": 526, "started_at": "2026-09-20T12:00:00+00:00"}
    for _ in range(2):
        store.import_legacy_baseline(legacy)
        assert store.snapshot()["totals"]["tools"] == {"kometa": 523, "imagemaid": 3}
        assert store.snapshot()["totals"]["successful_logs"] == 526


def test_fully_classified_days_and_other_tools_are_unchanged(tmp_path):
    path = tmp_path / "usage_analytics.json"
    tools = {"kometa": 4, "imagemaid": 2, "another_tool": 1}
    path.write_text(json.dumps({"days": {"2026-09-20": {"successful_logs": 7, "tools": tools}}}), encoding="utf-8")
    assert AnonymousAnalyticsStore(tmp_path).snapshot()["totals"]["tools"] == tools
