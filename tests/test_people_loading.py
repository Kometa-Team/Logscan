import importlib
import json
import threading
import time
from datetime import UTC, datetime
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

import pytest

from logscan_web.people_images import PEOPLE_IMAGE_STYLES, PeopleImageInventories, verify_people_image_urls
from logscan_web.people_loading import PeopleLoader
from logscan_web.storage import PeopleStore


def test_visitors_share_one_refresh_and_can_read_its_progress():
    started = threading.Event()
    release = threading.Event()

    def build(progress):
        progress("repositories", "Checking poster repositories.", 2, 7)
        started.set()
        assert release.wait(5)
        return [{"name": "Gabee"}]

    builder = Mock(side_effect=build)
    loader = PeopleLoader(builder)
    try:
        snapshot, state = loader.read()
        assert snapshot is None and state["refreshing"]
        assert started.wait(2)
        for _ in range(3):
            snapshot, state = loader.read()
            assert snapshot is None
            assert state["phase"] == "repositories" and state["completed"] == 2 and state["total"] == 7
        builder.assert_called_once()
        release.set()
        loader.future.result(timeout=2)
        snapshot, state = loader.read()
        assert snapshot == [{"name": "Gabee"}]
        assert state["phase"] == "complete" and not state["refreshing"]
        builder.assert_called_once()
    finally:
        release.set()
        loader.executor.shutdown()


def test_failed_refresh_preserves_saved_results_and_can_be_retried():
    builder = Mock(return_value=[{"name": "Gabee"}])
    loader = PeopleLoader(builder)
    try:
        loader.read()
        loader.future.result(timeout=2)
        builder.side_effect = OSError("Service offline")
        loader.read(retry=True)
        loader.future.result(timeout=2)
        snapshot, state = loader.read()
        assert snapshot == [{"name": "Gabee"}]
        assert state["phase"] == "failed" and not state["refreshing"]
        assert builder.call_count == 2
        builder.side_effect = None
        loader.read(retry=True)
        loader.future.result(timeout=2)
        assert loader.read()[1]["phase"] == "complete"
    finally:
        loader.executor.shutdown()


def test_invalidation_prevents_an_old_refresh_from_restoring_removed_people():
    release = threading.Event()
    loader = PeopleLoader(lambda progress: release.wait(5) and [{"name": "Removed"}])
    try:
        loader.read()
        loader.invalidate()
        release.set()
        loader.future.result(timeout=2)
        assert loader.snapshot is None
        loader.build = lambda progress: []
        loader.read()
        loader.future.result(timeout=2)
        assert loader.read()[0] == []
    finally:
        release.set()
        loader.executor.shutdown()


def test_fallback_probe_budget_preserves_unknown_without_starting_more_requests():
    fetch = Mock()
    progress = Mock()
    images = verify_people_image_urls([{"name": "Gabee"}], PeopleImageInventories(), open_url=fetch, cache={}, max_seconds=0, progress=progress)
    fetch.assert_not_called()
    assert not images
    assert progress.call_args.args[2:] == (len(PEOPLE_IMAGE_STYLES), len(PEOPLE_IMAGE_STYLES))


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    monkeypatch.setenv("TMDB_API_KEY", "test-key")
    monkeypatch.setenv("GITHUB_TOKEN", "test-read-only-token")
    (tmp_path / "popular_people_cache.json").write_text(
        json.dumps({"updated_at": datetime.now(UTC).isoformat(), "people": [{"id": 1, "name": "Cached Trending Person", "profile_path": "/cached.jpg"}]})
    )
    PeopleStore(tmp_path).upsert({"key": "tmdb-2", "tmdb_id": 2, "name": "Saved Request", "requested_by": [{"name": "Support Person", "id": "42"}]})
    with patch("threading.Thread"):
        module = importlib.import_module("logscan_web.app")
        app = module.create_app()
    app.config["TESTING"] = True
    fetch = Mock(side_effect=AssertionError("A preview or progress poll must not make network requests"))
    monkeypatch.setattr(module, "urlopen", fetch)
    loader = app.extensions["people_loader"]
    yield app, loader, fetch
    loader.executor.shutdown()


def test_people_api_returns_cached_cards_and_progress_while_verification_is_blocked(service):
    app, loader, fetch = service
    started = threading.Event()
    release = threading.Event()

    def build(progress):
        progress("repositories", "Checking Kometa poster repositories.", 1, 7)
        started.set()
        assert release.wait(5)
        return []

    loader.build = Mock(side_effect=build)
    try:
        before = time.monotonic()
        client = app.test_client()
        response = client.get("/api/people?background=1")
        assert time.monotonic() - before < 2
        assert response.status_code == 200
        payload = response.get_json()
        assert {person["name"] for person in payload["people"]} == {"Cached Trending Person", "Saved Request"}
        assert payload["loading"]["refreshing"]
        assert payload["actions_enabled"] is False
        assert started.wait(2)
        again = client.get("/api/people?background=1&tags=Requested+by+Support+Person").get_json()
        assert [person["name"] for person in again["people"]] == ["Saved Request"]
        assert again["loading"]["phase"] == "repositories"
        assert again["loading"]["completed"] == 1
        fetch.assert_not_called()
        loader.build.assert_called_once()
        release.set()
        loader.future.result(timeout=2)
        final = client.get("/api/people?background=1").get_json()
        assert final["people"] == [] and final["loading"]["phase"] == "complete"
        assert not final["loading"]["refreshing"]
    finally:
        release.set()


def test_people_api_rejects_invalid_page_size_before_starting_work(service):
    app, loader, _ = service
    loader.build = Mock()
    assert app.test_client().get("/api/people?background=1&per_page=500").status_code == 400
    loader.build.assert_not_called()


def test_people_worker_builds_real_payload_with_relative_image_links(service, monkeypatch):
    app, loader, _ = service
    module = importlib.import_module("logscan_web.app")

    class Response:
        headers = {}

        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(self.body).encode()

    def fetch(request, **_kwargs):
        url = request.full_url
        if "api.github.com" in url:
            return Response({"sha": "current", "truncated": False, "tree": []})
        if "/person/2?" in url:
            return Response({"id": 2, "name": "Saved Request", "profile_path": "/request.jpg"})
        raise AssertionError(urlsplit(url).path)

    monkeypatch.setattr(module, "urlopen", fetch)
    client = app.test_client()
    client.get("/api/people?background=1")
    loader.future.result(timeout=5)
    payload = client.get("/api/people?background=1").get_json()
    assert payload["loading"]["phase"] == "complete"
    assert payload["loading"]["github_authentication"] == {"state": "valid", "expires_at": None}
    assert "test-read-only-token" not in json.dumps(payload)
    person = next(person for person in payload["people"] if person["tmdb_id"] == 2)
    assert person["tmdb_image"]["download_url"].startswith("/api/tmdb/image-download?")
