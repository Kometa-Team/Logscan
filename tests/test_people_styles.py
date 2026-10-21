"""Cross-style People detection, verification and unified queue regressions."""

import importlib
import json
from datetime import UTC, datetime
from io import BytesIO
from unittest.mock import patch
from urllib.error import URLError
from urllib.parse import quote, urlsplit

import pytest

from logscan_web.people_images import PEOPLE_IMAGE_STYLES, assess_people_images, parse_people_inventory, person_name_key
from logscan_web.scanner import extract_missing_people, scan_log
from logscan_web.storage import AnonymousAnalyticsStore, PeopleStore, ScanStore

BRUCE_ERROR = (
    "[2026-10-21 05:16:37,153] [library.py:329] [ERROR] | Metadata: url_poster failed to update poster to [URL] "
    "https://raw.githubusercontent.com/Kometa-Team/People-Images-bw/master/B/Images/Bruce%20Langley.jpg |"
)
HEADER = "[kometa.py:1] [INFO] | Version: 2.5.3 |\n"


def poster_error(style="bw", name="Bruce Langley", extension="jpg"):
    repository = next(item.repository for item in PEOPLE_IMAGE_STYLES if item.key == style)
    return f"Metadata: url_poster failed to update poster to [URL] https://raw.githubusercontent.com/Kometa-Team/{repository}/master/B/Images/{quote(name)}.{extension}"


class Response:
    def __init__(self, value, age=0):
        self.value = value
        self.headers = {"Age": str(age)}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.value).encode()


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    monkeypatch.setenv("TMDB_API_KEY", "test-key")
    monkeypatch.setenv("DISCORD_PEOPLE_WEBHOOK_URL", "https://example.test/webhook")
    with patch("threading.Thread"):
        module = importlib.import_module("logscan_web.app")
    (tmp_path / "popular_people_cache.json").write_text(
        json.dumps({"updated_at": datetime.now(UTC).isoformat(), "people": [{"id": 909, "name": "Bruce Langley", "profile_path": "/bruce.jpg"}]}), encoding="utf-8"
    )
    state = {"missing": {"bw"}, "unavailable": set(), "truncated": set(), "stale": set(), "calls": [], "notifications": [], "matches": [{"id": 909, "name": "Bruce Langley"}]}

    def urlopen(request, timeout=0):
        url = request.full_url
        state["calls"].append(url)
        if url == "https://example.test/webhook":
            state["notifications"].append(json.loads(request.data))
            return Response({})
        if "api.github.com/repos/Kometa-Team/" in url:
            style = next(item for item in PEOPLE_IMAGE_STYLES if item.repository == urlsplit(url).path.split("/")[3])
            if style.key in state["unavailable"]:
                raise URLError("offline")
            paths = (
                [] if style.key in state["missing"] else [{"type": "blob", "path": "B/Images/Bruce Langley.png" if style.key == "transparent" else "B/Images/Bruce Langley.jpg"}]
            )
            return Response({"sha": "verified", "truncated": style.key in state["truncated"], "tree": paths}, age=3601 if style.key in state["stale"] else 0)
        if "/search/person?" in url:
            return Response({"results": state["matches"]})
        if "/person/909/images?" in url:
            return Response({"profiles": [{"file_path": "/bruce.jpg"}]})
        if "/person/909?" in url:
            return Response({"id": 909, "name": "Bruce Langley", "profile_path": "/bruce.jpg"})
        raise AssertionError(f"Unexpected network request: {url}")

    monkeypatch.setattr(module, "urlopen", urlopen)

    def create():
        with patch("logscan_web.app.threading.Thread"):
            app = module.create_app()
        app.config["TESTING"] = True
        return app

    return state, create, tmp_path


def upload(app, content=BRUCE_ERROR):
    response = app.test_client().post("/api/scan", data={"log": (BytesIO((HEADER + content).encode()), "people.log")})
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()


def test_exact_bruce_error_and_streaming_parity():
    content = (HEADER + (BRUCE_ERROR + "\n") * 2000 + poster_error("signature")).encode()
    normal = scan_log("people.log", content)
    with patch("logscan_web.scanner.STREAM_SCAN_THRESHOLD", 1):
        streamed = scan_log("people.log", content)
    assert streamed.missing_people == normal.missing_people
    assert normal.missing_people == [{"name": "Bruce Langley", "tmdb_image_found": False, "source_styles": ["bw", "signature"], "detection_reasons": ["url_poster_update_failed"]}]


@pytest.mark.parametrize("name,extension", [("Hikaru Kondô", "jpg"), ("Lupita Nyong'o", "JPG"), ("Jean-Claude Van Damme", "png"), ("张子枫", "jpg")])
def test_encoded_unicode_names_and_mixed_case(name, extension):
    error = poster_error(name=name, extension=extension).replace("Metadata: url_poster failed to update poster", "METADATA: URL_POSTER FAILED TO UPDATE POSTER")
    result = extract_missing_people(error)
    assert result[0]["name"] == name
    assert result[0]["source_styles"] == ["bw"]


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test/Bruce.jpg",
        "https://raw.githubusercontent.com.evil.test/Kometa-Team/People-Images-bw/master/B/Images/Bruce.jpg",
        "https://raw.githubusercontent.com@evil.test/Kometa-Team/People-Images-bw/master/B/Images/Bruce.jpg",
        "https://raw.githubusercontent.com/Other-Team/People-Images-bw/master/B/Images/Bruce.jpg",
        "https://raw.githubusercontent.com/Kometa-Team/People-Images-evil/master/B/Images/Bruce.jpg",
        "https://raw.githubusercontent.com/Kometa-Team/People-Images-bw/develop/B/Images/Bruce.jpg",
        "https://raw.githubusercontent.com/Kometa-Team/People-Images-bw/master/B/Images/Bruce.svg",
        "https://raw.githubusercontent.com/Kometa-Team/People-Images-bw/master/B/Images/%2e%2e%2fBruce.jpg",
        "https://raw.githubusercontent.com/Kometa-Team/People-Images-bw/master/B/Images/Bruce.jpg?redirect=evil",
        "https://raw.githubusercontent.com/Kometa-Team/Movie-Images/master/B/Images/Bruce.jpg",
    ],
)
def test_unrelated_and_malicious_failures_are_ignored(url):
    assert extract_missing_people("Metadata: url_poster failed to update poster to [URL] " + url) == []


def test_legacy_signals_preserve_tmdb_image_found():
    content = (
        "Detail: tmdb_person updated poster to [URL] https://image.tmdb.org/image.jpg\nline\nline\nFinished Bruce Langley Collection\n"
        "Collection Warning: No Poster Found at https://raw.githubusercontent.com/Kometa-Team/People-Images/master/Bruce%20Langley.jpg\n" + BRUCE_ERROR
    )
    result = extract_missing_people(content)
    assert len(result) == 1 and result[0]["tmdb_image_found"] is True
    assert result[0]["source_styles"] == ["bw", "primary"]
    assert set(result[0]["detection_reasons"]) == {"tmdb_person_updated_poster", "no_poster_found", "url_poster_update_failed"}


@pytest.mark.parametrize("missing", [{"bw"}, {"primary"}, {"bw", "rainier"}, {style.key for style in PEOPLE_IMAGE_STYLES}, set()])
def test_cross_style_assessment(missing):
    inventories = {style.label: {} if style.key in missing else {"bruce langley": "image"} for style in PEOPLE_IMAGE_STYLES}
    result = assess_people_images({"name": "BRUCE LANGLEY"}, inventories)
    assert result["people_image_status"] == ("incomplete" if missing else "complete")
    assert {key for key, value in result["style_availability"].items() if value["status"] == "missing"} == missing


def test_unknown_and_not_applicable(monkeypatch):
    from dataclasses import replace

    primary = replace(PEOPLE_IMAGE_STYLES[0], excluded_names=frozenset({"bruce langley"}))
    monkeypatch.setattr("logscan_web.people_images.PEOPLE_IMAGE_STYLES", (primary, PEOPLE_IMAGE_STYLES[1]))
    result = assess_people_images({"name": "Bruce Langley"}, {})
    assert result["style_availability"]["primary"]["status"] == "not_applicable"
    assert result["people_image_status"] == "pending_verification"


def test_inventory_paths_capitalization_and_incomplete_responses():
    style = PEOPLE_IMAGE_STYLES[0]
    tree = {"sha": "verified", "truncated": False, "tree": [{"type": "blob", "path": "B/Images/BRUCE LANGLEY.JPG"}, {"type": "blob", "path": "README.md"}]}
    inventory = parse_people_inventory(style, tree)
    assert "bruce langley" in inventory
    assert parse_people_inventory(style, {**tree, "truncated": True}) is None
    assert parse_people_inventory(style, {"tree": []}) is None
    assert parse_people_inventory(style, {**tree, "tree": [{"path": 5}]}) is None
    assert person_name_key("Hikaru Kondô") == person_name_key("HIKARU KONDO")
    transparent = PEOPLE_IMAGE_STYLES[-1]
    assert parse_people_inventory(transparent, {**tree, "tree": [{"type": "blob", "path": "B/Images/Bruce Langley.png"}]})["bruce langley"].endswith(".png")


def test_existing_person_multiple_uploads_styles_notifications_and_export(service):
    state, create, root = service
    app = create()
    first = upload(app)
    second = upload(app, poster_error("primary"))
    duplicate = upload(app)
    records = PeopleStore(root).list()
    assert len(records) == 1
    assert records[0]["source_styles"] == ["bw", "primary"]
    assert len(records[0]["log_provenance"]) == 2
    assert records[0]["style_availability"]["primary"]["status"] == "present"
    assert records[0]["style_availability"]["bw"]["status"] == "missing"
    assert len(state["notifications"]) == 1
    assert sum("/search/person?" in url for url in state["calls"]) == 1
    assert sum("api.github.com" in url for url in state["calls"]) == len(PEOPLE_IMAGE_STYLES)
    assert first["id"] == duplicate["id"] != second["id"]
    client = app.test_client()
    people = client.get("/api/people").json["people"]
    assert len(people) == 1 and people[0]["sources"] == ["missing", "trending"]
    assert client.get("/api/people/export").text == "909|Bruce Langley"
    assert AnonymousAnalyticsStore(root).snapshot()["totals"]["people_submitted"] == 1


def test_all_present_is_diagnostic_without_false_queue_entry(service):
    state, create, root = service
    state["missing"] = set()
    result = upload(create())
    assert not PeopleStore(root).list()
    advice = next(item for item in result["recommendations"] if item["id"] == "missing_people_images_available")
    assert "Plex connectivity" in advice["solution"]
    assert "Delete the collection" not in advice["solution"]
    assert not state["notifications"]


@pytest.mark.parametrize("failure", ["unavailable", "truncated", "stale"])
def test_inconclusive_inventory_retains_pending_person(service, failure):
    state, create, root = service
    state["missing"] = set()
    state[failure] = {"bw"}
    app = create()
    result = upload(app)
    assert PeopleStore(root).list()[0]["people_image_status"] == "pending_verification"
    assert any(item["id"] == "missing_people_images_unverified" for item in result["recommendations"])
    person = app.test_client().get("/api/people").json["people"][0]
    assert person["people_image_status"] == "pending_verification"
    assert "missing" in person["sources"]
    assert not state["notifications"]


def test_reconciliation_retains_gap_then_completes_only_missing_source(service):
    state, create, root = service
    upload(create())
    state["missing"] = {"signature"}
    app = create()
    person = app.test_client().get("/api/people").json["people"][0]
    assert person["sources"] == ["missing", "trending"]
    assert person["style_availability"]["signature"]["status"] == "missing"
    state["missing"] = set()
    app = create()
    assert app.test_client().get("/api/people").json["people"][0]["sources"] == ["trending"]
    assert PeopleStore(root).list()[0]["people_image_status"] == "complete"
    assert len(state["notifications"]) == 1


def test_ambiguous_identity_remains_unresolved(service):
    state, create, root = service
    state["matches"] = [{"id": 909, "name": "Bruce Langley"}, {"id": 910, "name": "Bruce Langley"}]
    app = create()
    upload(app)
    record = PeopleStore(root).list()[0]
    assert record["tmdb_id"] is None and record["key"].startswith("name-")
    unresolved = next(person for person in app.test_client().get("/api/people").json["people"] if person["person_key"].startswith("name-"))
    assert unresolved["tmdb_id"] is None


def test_name_fallback_upgrades_without_duplicate_identity(tmp_path):
    store = PeopleStore(tmp_path)
    store.upsert({"key": "name-old", "name": "Hikaru Kondô", "source_styles": ["bw"], "log_provenance": [{"log_url": "/scan/one"}]})
    person, created = store.upsert_with_status({"key": "tmdb-123", "tmdb_id": 123, "name": "Hikaru Kondo", "source_styles": ["primary"]})
    assert not created and len(store.list()) == 1
    assert person["key"] == "tmdb-123" and person["source_styles"] == ["bw", "primary"]
    assert person["log_provenance"] == [{"log_url": "/scan/one"}]


def test_inventory_reconciliation_batches_writes_and_preserves_last_log_timestamp(tmp_path):
    store = PeopleStore(tmp_path)
    for person_id in (1, 2):
        store.upsert({"key": f"tmdb-{person_id}", "tmdb_id": person_id, "name": f"Person {person_id}", "requested_by": [{"name": "Uploader"}]})
    before = store.list()
    with patch.object(store, "_write", wraps=store._write) as write:
        after = store.reconcile_image_availability({})
        write.assert_called_once()
    with patch.object(store, "_write") as write:
        store.reconcile_image_availability({})
        write.assert_not_called()
    for original, updated in zip(before, after):
        assert updated["last_seen_at"] == original["last_seen_at"]
        assert updated["requested_by"] == original["requested_by"]
        assert updated["people_image_status"] == "pending_verification"


def test_ambiguous_name_does_not_select_one_existing_identity(tmp_path):
    store = PeopleStore(tmp_path)
    for person_id in (1, 2):
        store.upsert({"key": f"tmdb-{person_id}", "tmdb_id": person_id, "name": "Shared Name"})
    record, created = store.upsert_with_status({"key": "name-shared", "name": "Shared Name", "identity_ambiguous": True})
    assert created and record["key"] == "name-shared" and len(store.list()) == 3


def test_manual_missing_completion_survives_return_of_trending_source(service):
    _state, create, root = service
    app = create()
    upload(app)
    PeopleStore(root).upsert({"key": "tmdb-909", "manually_completed": True})
    person = app.test_client().get("/api/people").json["people"][0]
    assert person["sources"] == ["trending"]


def test_distinct_style_path_conventions(monkeypatch):
    from dataclasses import replace

    style = replace(PEOPLE_IMAGE_STYLES[-1], image_paths=(r"portraits/[^/]+",))
    monkeypatch.setattr("logscan_web.people_images.PEOPLE_IMAGE_STYLES", (style,))
    inventory = parse_people_inventory(style, {"sha": "verified", "truncated": False, "tree": [{"type": "blob", "path": "portraits/Bruce Langley.png"}]})
    assert "bruce langley" in inventory


@pytest.mark.parametrize("action", ["check", "exclude"])
def test_manual_completion_and_exclusion_survive_later_upload_and_backfill(service, action):
    _state, create, root = service
    app = create()
    first = upload(app)
    client = app.test_client()
    with client.session_transaction() as session:
        session["support_authorized_at"] = 9999999999
        session["support_user"] = {"id": "42", "username": "Support Person"}
    assert client.post(f"/api/people/tmdb-909/{action}").status_code == 204
    upload(app, poster_error("signature"))
    ScanStore(root).update_metadata(first["id"], analysis_version=8)
    app.extensions["backfill_scan_analysis"]()
    assert client.get("/api/people").json["people"] == []


def test_historical_reanalysis_enqueues_new_candidates_without_receipts_or_statistics_changes(service):
    state, create, root = service
    from logscan_web.app import ANALYSIS_VERSION

    store = ScanStore(root)
    content = (HEADER + BRUCE_ERROR).encode()
    result = scan_log("old.log", content)
    result.metadata["analysis_version"] = 8
    result.overview.update(upload_source="discord", uploaded_by="Old Uploader", uploaded_by_id="42", message_url="https://example.test/message")
    scan_id, _token = store.create("old.log", content, result)
    before = store.get(scan_id)
    app = create()
    analytics_before = AnonymousAnalyticsStore(root).snapshot()
    app.extensions["backfill_scan_analysis"]()
    after = store.get(scan_id)
    for field in ("id", "created_at", "delete_token_hash"):
        assert after[field] == before[field]
    assert after["metadata"]["analysis_version"] == ANALYSIS_VERSION == 11
    assert after["overview"]["uploaded_by_id"] == "42"
    record = PeopleStore(root).list()[0]
    assert record["name"] == "Bruce Langley" and record["source_styles"] == ["bw"]
    assert record["requested_by"] == [{"name": "Old Uploader", "id": "42"}]
    assert any(item["id"] == "missing_people_images_pending" for item in after["recommendations"])
    with patch("logscan_web.app.scan_archive_path") as scan:
        app.extensions["backfill_scan_analysis"]()
        scan.assert_not_called()
    assert AnonymousAnalyticsStore(root).snapshot() == analytics_before
    assert not state["notifications"]
