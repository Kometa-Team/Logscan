"""Trending feed labels must agree with direct English TMDb person details."""

import importlib
import json
from datetime import UTC, datetime
from unittest.mock import patch
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit

import pytest

from logscan_web.storage import PeopleStore, TMDbFindCacheStore


class Response:
    headers = {}

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return self.value.encode() if isinstance(self.value, str) else json.dumps(self.value).encode()


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    monkeypatch.setenv("TMDB_API_KEY", "test-key")
    monkeypatch.delenv("DISCORD_PEOPLE_WEBHOOK_URL", raising=False)
    with patch("threading.Thread"):
        module = importlib.import_module("logscan_web.app")
    person = {"id": 2746726, "name": "铃木浩介", "profile_path": "/suzuki.jpg", "known_for": [{"id": 123, "media_type": "tv", "name": "The Interrogator Special"}]}
    state = {"source": "imdb", "calls": [], "details_name": "Kosuke Suzuki", "offline": False}

    def fetch(request, timeout=0):
        url = urlsplit(request.full_url)
        state["calls"].append(url.path)
        if url.hostname == "caching.graphql.imdb.com":
            edges = [{"node": {"id": "nm1234567"}}] if state["source"] == "imdb" else []
            return Response({"data": {"chartNames": {"edges": edges}}})
        if url.hostname == "raw.githubusercontent.com":
            if state.get("posters_present"):
                repository = url.path.split("/")[2]
                extension = "png" if repository.endswith("-transparent") else "jpg"
                return Response(
                    f"# Kometa People Images (1 Images)\n* [Kosuke Suzuki](https://raw.githubusercontent.com/Kometa-Team/{repository}/master/K/Images/Kosuke%20Suzuki.{extension})\n"
                )
            return Response("# Kometa People Images (0 Images)\n")
        assert url.hostname == "api.themoviedb.org", request.full_url
        assert parse_qs(url.query)["language"] == ["en-US"]
        if url.path == "/3/find/nm1234567":
            return Response({"person_results": [person]})
        if url.path == "/3/person/popular":
            return Response({"results": [person], "total_pages": 1})
        if url.path == f"/3/person/{person["id"]}":
            if state["offline"]:
                raise URLError("offline")
            return Response({**person, "name": state["details_name"]})
        raise AssertionError(url.path)

    monkeypatch.setattr(module, "urlopen", fetch)

    def create():
        with patch("logscan_web.app.threading.Thread"):
            app = module.create_app()
        app.config["TESTING"] = True
        return app.test_client()

    return state, create, tmp_path, person


@pytest.mark.parametrize("source", ["imdb", "popular", "cached", "cached_find"])
def test_trending_cards_exports_and_saved_requests_use_english_details(service, source):
    state, create, root, person = service
    state["source"] = "imdb" if source == "cached_find" else source
    if source == "cached":
        (root / "popular_people_cache.json").write_text(json.dumps({"updated_at": datetime.now(UTC).isoformat(), "people": [person]}), encoding="utf-8")
        PeopleStore(root).upsert({"key": "tmdb-2746726", "tmdb_id": 2746726, "name": person["name"], "original_name": person["name"]})
    if source == "cached_find":
        TMDbFindCacheStore(root).save("nm1234567", person)
    client = create()
    for _ in range(2):
        response = client.get("/api/people")
        assert response.status_code == 200
        card = response.json["people"][0]
        assert card["tmdb_id"] == 2746726 and card["name"] == "Kosuke Suzuki"
        assert card["known_for"][0]["title"] == "The Interrogator Special"
        assert "Trending" in card["metadata_tags"] or "trending" in card["sources"]
        assert client.get("/api/people/export").get_data(as_text=True).splitlines() == ["2746726|Kosuke Suzuki"]
    assert state["calls"].count("/3/person/2746726") == 1
    if source != "cached":
        assert PeopleStore(root).list()[0]["name"] == "Kosuke Suzuki"
        snapshot = json.loads((root / "popular_people_cache.json").read_text(encoding="utf-8"))
        assert snapshot["people"][0]["name"] == "Kosuke Suzuki"
    if source == "cached_find":
        assert "/3/find/nm1234567" not in state["calls"]


def test_unavailable_english_details_retains_original_identity_without_guessing(service):
    state, create, _root, person = service
    state["offline"] = True
    client = create()
    card = client.get("/api/people").json["people"][0]
    assert card["tmdb_id"] == person["id"] and card["name"] == person["name"]
    client.get("/api/people")
    assert state["calls"].count("/3/person/2746726") == 1


def test_details_without_romanization_are_cached_without_inventing_a_label(service):
    state, create, _root, person = service
    state["details_name"] = person["name"]
    client = create()
    assert client.get("/api/people").json["people"][0]["name"] == person["name"]
    client.get("/api/people/export")
    assert state["calls"].count("/3/person/2746726") == 1


def test_old_automated_request_reconciles_against_corrected_english_filename(service):
    state, create, root, person = service
    state["posters_present"] = True
    (root / "popular_people_cache.json").write_text(json.dumps({"updated_at": datetime.now(UTC).isoformat(), "people": [person]}), encoding="utf-8")
    PeopleStore(root).upsert({"key": "tmdb-2746726", "tmdb_id": 2746726, "name": person["name"], "original_name": person["name"]})
    client = create()
    assert client.get("/api/people?tags=Missing+Kometa").json["people"] == []
    saved = PeopleStore(root).list()[0]
    assert saved["name"] == "Kosuke Suzuki"
    assert saved["original_name"] == person["name"]
    assert saved["people_image_status"] == "complete"


@pytest.mark.parametrize("name", ["吴 梦梦", "宋雨川", "梁佳芯", "温芮欣", "박지", "桜みお", "Catherine Lagaʻaia", "Lương Bích Hữu", "Ronkẹ Adékoluẹjo", "Văn Phượng"])
def test_export_excludes_unsupported_names_but_keeps_cards_for_review(service, name):
    state, create, _root, person = service
    person["name"] = state["details_name"] = name
    client = create()
    assert client.get("/api/people").json["people"][0]["name"] == name
    assert client.get("/api/people/export").get_data(as_text=True) == ""


def test_export_keeps_verified_english_name_despite_an_unsupported_native_alias(service):
    state, create, root, person = service
    state["details_name"] = "Mio Sakura"
    person["id"] = 6285230
    (root / "popular_people_cache.json").write_text(json.dumps({"updated_at": datetime.now(UTC).isoformat(), "people": [person]}), encoding="utf-8")
    PeopleStore(root).upsert({"key": "tmdb-6285230", "tmdb_id": 6285230, "name": person["name"], "original_name": "桜みお"})
    client = create()
    assert client.get("/api/people/export").get_data(as_text=True).splitlines() == ["6285230|Mio Sakura"]
