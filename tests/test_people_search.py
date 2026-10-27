"""Search, request attribution and the unchanged People processing export."""

import importlib
import json
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import pytest

from logscan_web.people_images import PEOPLE_IMAGE_STYLES
from logscan_web.storage import PeopleStore


class Response:
    headers = {}

    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.data).encode()


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    monkeypatch.setenv("TMDB_API_KEY", "test-key")
    with patch("threading.Thread"):
        module = importlib.import_module("logscan_web.app")
    state = {
        "name": "Lupita Nyong'o",
        "missing": {"bw"},
        "unavailable": set(),
        "calls": [],
        "profile": "/profile.jpg",
        "tmdb_offline": False,
        "matches": [{"id": 777, "name": "Lupita Nyong'o"}, {"id": 778, "name": "Lupita Nyong'o"}],
    }
    (tmp_path / "popular_people_cache.json").write_text(
        json.dumps({"updated_at": datetime.now(UTC).isoformat(), "people": [{"id": 909, "name": "Trending Person", "profile_path": "/trending.jpg"}]})
    )

    def urlopen(request, timeout=0):
        url = request.full_url
        state["calls"].append(url)
        if "api.github.com" in url:
            style = next(item for item in PEOPLE_IMAGE_STYLES if item.repository == urlsplit(url).path.split("/")[3])
            if style.key in state["unavailable"]:
                raise URLError("offline")
            names = ["Trending Person"] + ([] if style.key in state["missing"] else [state["name"]])
            return Response({"sha": "verified", "truncated": False, "tree": [{"type": "blob", "path": f"P/Images/{name}.jpg"} for name in names]})
        if "raw.githubusercontent.com" in url:
            raise URLError("offline")
        if state["tmdb_offline"]:
            raise URLError("offline")
        if "/search/person?" in url:
            return Response({"results": state["matches"]})
        if "/person/777/images?" in url:
            return Response({"profiles": state.get("profiles", [])})
        if "/person/777?" in url or "/person/778?" in url or "/person/2011?" in url:
            return Response(
                {"id": int(urlsplit(url).path.rsplit("/", 1)[1]), "name": state["name"], "profile_path": state["profile"], "combined_credits": state.get("credits", {})}
            )
        raise HTTPError(url, 404, "Not found", {}, None)

    monkeypatch.setattr(module, "urlopen", urlopen)

    def create():
        with patch("logscan_web.app.threading.Thread"):
            app = module.create_app()
        app.config.update(TESTING=True)
        return app

    return state, create, tmp_path, module


def visitor(app, user=None):
    client = app.test_client()
    client.get("/people")
    with client.session_transaction() as session:
        token = session["people_csrf"]
        if user:
            session.update(discord_user=user, support_authorized_at=time.time())
    return client, {"X-CSRF-Token": token}


def submit(client, headers, **extra):
    return client.post("/api/people/request", json={"tmdb_id": 777, **extra}, headers=headers)


def test_search_request_ready_export_and_publication_end_to_end(service):
    state, create, root, _ = service
    app = create()
    client, headers = visitor(app)
    assert PeopleStore(root).list() == []
    person = client.get("/api/people/search?q=777").get_json()["people"][0]
    assert person["tmdb_id"] == 777 and person["can_add"]
    assert len(person["style_availability"]) == 7
    assert person["style_availability"]["bw"]["status"] == "missing"
    assert submit(client, headers).status_code == 201
    ready = client.get("/api/people?tags=TMDb+Ready").get_json()["people"]
    assert [person["tmdb_id"] for person in ready] == [777]
    export = client.get("/api/people/export?tags=TMDb+Ready")
    assert export.get_data(as_text=True).splitlines() == ["777|Lupita Nyong'o"]
    assert "filename=people-to-process.txt" in export.headers["Content-Disposition"]
    state["missing"] = set()
    # A fresh inventory cache after publication uses the same persisted request.
    refreshed, _ = visitor(create())
    person = refreshed.get("/api/people/search?q=777").get_json()["people"][0]
    assert not person["can_add"] and person["people_image_status"] == "complete"
    assert all(style.get("image_url") for style in person["style_availability"].values())
    assert refreshed.get("/api/people?tags=TMDb+Ready").get_json()["people"] == []
    assert refreshed.get("/api/people/export?tags=TMDb+Ready").data == b""
    assert PeopleStore(root).list()[0]["manual_requests"]


@pytest.mark.parametrize("name", ["Hikaru Kondô", "张子枫", "Lupita Nyong'o", "Jean-Claude Van Damme"])
def test_name_choices_preserve_unicode_and_distinct_tmdb_identities(service, name):
    state, create, root, _ = service
    state.update(name=name, matches=[{"id": 777, "name": name}, {"id": 778, "name": name}])
    client, headers = visitor(create())
    choices = client.get("/api/people/search", query_string={"q": name}).get_json()["choices"]
    assert [item["tmdb_id"] for item in choices] == [777, 778]
    assert all(item["name"] == name for item in choices)
    search_url = next(url for url in state["calls"] if "/search/person?" in url)
    assert parse_qs(urlsplit(search_url).query)["query"] == [name]
    assert submit(client, headers).status_code == 201
    assert client.post("/api/people/request", json={"tmdb_id": 778}, headers=headers).status_code == 201
    assert {item["tmdb_id"] for item in PeopleStore(root).list()} == {777, 778}


@pytest.mark.parametrize(
    "profile,expected", [("/mel.jpg", "https://image.tmdb.org/t/p/w185/mel.jpg"), (None, None), ("https://evil.test/photo.jpg", None), ("/../photo.jpg", None)]
)
def test_name_choices_include_only_verified_tmdb_profile_paths(service, profile, expected):
    state, create, _, _ = service
    state["matches"] = [{"id": 777, "name": "Mel Gibson", "profile_path": profile}]
    client, _ = visitor(create())
    choices = client.get("/api/people/search?q=Mel+Gibson").get_json()["choices"]
    assert choices[0]["profile_image_url"] == expected
    assert len([url for url in state["calls"] if "api.themoviedb.org" in url]) == 1


def test_selected_identity_keeps_bounded_known_for_credits(service):
    state, create, _, _ = service
    movie = {"media_type": "movie", "id": 100, "title": "Braveheart", "popularity": 20}
    state["credits"] = {
        "cast": [movie, {"media_type": "movie", "id": 200, "title": "Signs", "popularity": 10}, {"media_type": "tv", "id": 300, "name": "Show", "popularity": 5}],
        "crew": [movie, {"media_type": "movie", "id": 400, "title": "Other", "popularity": 1}],
    }
    client, _ = visitor(create())
    person = client.get("/api/people/search?q=777").get_json()["people"][0]
    assert [credit["title"] for credit in person["known_for"]] == ["Braveheart", "Signs", "Show"]
    assert person["known_for"][0]["url"] == "https://www.themoviedb.org/movie/100"
    detail_url = next(url for url in state["calls"] if "/person/777?" in url)
    assert parse_qs(urlsplit(detail_url).query)["append_to_response"] == ["combined_credits"]


@pytest.mark.parametrize("missing", [set(), {"bw"}, {style.key for style in PEOPLE_IMAGE_STYLES}])
def test_seven_styles_preview_download_sources_and_request_eligibility(service, missing):
    state, create, _, _ = service
    state["missing"] = missing
    client, headers = visitor(create())
    person = client.get("/api/people/search?q=777").get_json()["people"][0]
    assert len(person["style_availability"]) == 7
    for style in PEOPLE_IMAGE_STYLES:
        item = person["style_availability"][style.key]
        assert item["status"] == ("missing" if style.key in missing else "present")
        if style.key not in missing:
            assert item["image_url"].startswith(f"https://raw.githubusercontent.com/Kometa-Team/{style.repository}/master/")
    assert submit(client, headers).status_code == (201 if missing else 409)


def test_unavailable_inventory_never_means_missing_or_complete(service):
    state, create, root, _ = service
    state.update(missing=set(), unavailable={style.key for style in PEOPLE_IMAGE_STYLES})
    client, headers = visitor(create())
    person = client.get("/api/people/search?q=777").get_json()["people"][0]
    assert person["people_image_status"] == "pending_verification"
    assert all(style["status"] == "unknown" for style in person["style_availability"].values())
    assert submit(client, headers).status_code == 409
    assert PeopleStore(root).list() == []


def test_anonymous_duplicate_and_existing_discovery_history(service):
    _, create, root, _ = service
    store = PeopleStore(root)
    store.upsert(
        {
            "key": "tmdb-777",
            "tmdb_id": 777,
            "name": "Lupita Nyong'o",
            "provenance_tags": ["Log Upload", "IMDb Trending"],
            "log_url": "/scan/old",
            "requested_by": [{"id": "old", "name": "Uploader"}],
        }
    )
    client, headers = visitor(create())
    assert submit(client, headers).status_code == 201
    first = store.list()[0]
    assert submit(client, headers).get_json()["already_added"]
    record = store.list()[0]
    assert len(store.list()) == 1 and record["manual_requests"] == first["manual_requests"]
    assert record["log_url"] == "/scan/old" and record["requested_by"] == [{"id": "old", "name": "Uploader"}]
    assert record["provenance_tags"] == ["Log Upload", "IMDb Trending", "Manually Added"]
    assert record["manual_requests"][0]["id"] is None
    assert client.get("/api/people/search?q=777").get_json()["people"][0]["already_added"]


def test_discord_request_stays_requested_for_other_accounts_and_changed_names(service):
    _, create, root, _ = service
    app = create()
    for identity, name in [("111", "First user"), ("222", "Second user"), ("111", "Renamed user")]:
        client, headers = visitor(app, {"id": identity, "username": name})
        assert client.get("/api/people/search?q=777").get_json()["people"][0]["already_added"] == (name != "First user")
        response = submit(client, headers)
        assert response.status_code == (201 if name == "First user" else 200)
    record = PeopleStore(root).list()[0]
    assert len(record["manual_requests"]) == 1 and record["requested_by"] == [{"id": "111", "name": "First user"}]
    assert record["manual_requests"][0]["name"] == "First user"
    ready = client.get("/api/people?tags=TMDb+Ready").get_json()["people"][0]
    assert "Manually Added by First user" in ready["provenance_tags"]
    assert client.get("/api/people/export?tags=TMDb+Ready").get_data(as_text=True).splitlines() == ["777|Lupita Nyong'o"]


def test_anonymous_2011_request_then_discord_login_keeps_original_request(service):
    _, create, root, _ = service
    app = create()
    client, headers = visitor(app)
    assert not client.get("/api/people/search?q=2011").get_json()["people"][0]["already_added"]
    response = client.post("/api/people/request", json={"tmdb_id": 2011}, headers=headers)
    assert response.status_code == 201
    original = (root / "people.json").read_bytes()
    with client.session_transaction() as session:
        session.update(discord_user={"id": "111", "username": "Signed in user"}, support_authorized_at=time.time())
    assert client.get("/api/people/search?q=2011").get_json()["people"][0]["already_added"]
    response = client.post("/api/people/request", json={"tmdb_id": 2011}, headers=headers)
    assert response.status_code == 200 and response.get_json()["message"] == "Already requested"
    assert (root / "people.json").read_bytes() == original
    record = PeopleStore(root).list()[0]
    assert record["manual_requests"][0]["id"] is None and not record.get("requested_by")
    ready = client.get("/api/people?tags=TMDb+Ready").get_json()["people"][0]
    assert "Manually Added" in ready["provenance_tags"]
    assert not any(tag.startswith("Manually Added by ") for tag in ready["provenance_tags"])
    assert client.get("/api/people/export?tags=TMDb+Ready").get_data(as_text=True).splitlines() == ["2011|Lupita Nyong'o"]


def test_existing_requester_history_is_not_rewritten_by_another_manual_request(service):
    _, create, root, _ = service
    store = PeopleStore(root)
    for user_id in ["111", "222"]:
        store.upsert(
            {
                "key": "tmdb-777",
                "tmdb_id": 777,
                "name": "Lupita Nyong'o",
                "manual_requests": [{"id": user_id, "name": user_id, "requested_at": "original"}],
                "requested_by": [{"id": user_id, "name": user_id}],
                "provenance_tags": ["Log Upload", "Manually Added"],
                "log_url": "/scan/original",
            }
        )
    original = (root / "people.json").read_bytes()
    client, headers = visitor(create(), {"id": "333", "username": "Other user"})
    assert client.get("/api/people/search?q=777").get_json()["people"][0]["already_added"]
    assert submit(client, headers).status_code == 200
    assert (root / "people.json").read_bytes() == original
    assert len(store.list()[0]["manual_requests"]) == 2


def test_discord_request_stays_requested_after_logout_and_when_services_are_offline(service):
    state, create, root, _ = service
    app = create()
    client, headers = visitor(app, {"id": "111", "username": "Original requester"})
    assert submit(client, headers).status_code == 201
    original = (root / "people.json").read_bytes()
    anonymous, anonymous_headers = visitor(create())
    assert anonymous.get("/api/people/search?q=777").get_json()["people"][0]["already_added"]
    state["tmdb_offline"] = True
    assert submit(anonymous, anonymous_headers).get_json()["already_added"]
    assert (root / "people.json").read_bytes() == original


@pytest.mark.parametrize(
    "payload",
    [
        {"tmdb_id": True},
        {"tmdb_id": -1},
        {"tmdb_id": "777"},
        {"tmdb_id": 0},
        {"tmdb_id": 2147483648},
        {"tmdb_id": 777, "discord_id": "spoof"},
        {"tmdb_id": 777, "username": "spoof"},
        [],
        None,
    ],
)
def test_validation_and_identity_spoofing(service, payload):
    _, create, root, _ = service
    client, headers = visitor(create())
    assert client.post("/api/people/request", json=payload, headers=headers).status_code == 400
    assert PeopleStore(root).list() == []


@pytest.mark.parametrize("query", ["", "x" * 201, "name\nother", "bad|name", "0", "2147483648", "１２３"])
def test_search_validation(service, query):
    _, create, _, _ = service
    assert create().test_client().get("/api/people/search", query_string={"q": query}).status_code == 400


def test_csrf_and_expired_discord_session(service):
    _, create, root, _ = service
    client, headers = visitor(create(), {"id": "111", "username": "Expired"})
    assert submit(client, {}).status_code == 403
    assert submit(client, {"X-CSRF-Token": "é"}).status_code == 403
    with client.session_transaction() as session:
        session["support_authorized_at"] = 0
    assert submit(client, headers).status_code == 201
    assert PeopleStore(root).list()[0]["manual_requests"][0]["id"] is None


def test_tmdb_unavailable_and_unknown_id(service):
    state, create, root, _ = service
    client, headers = visitor(create())
    assert client.get("/api/people/search?q=99999").status_code == 404
    state["tmdb_offline"] = True
    assert client.get("/api/people/search?q=777").status_code == 503
    assert client.get("/api/people/search?q=Name").status_code == 503
    assert submit(client, headers).status_code == 503
    assert PeopleStore(root).list() == []


@pytest.mark.parametrize("profile,profiles,ready", [(None, [], False), (None, [{"file_path": "/fallback.jpg"}], True), ("https://evil.test/photo.jpg", [], False)])
def test_requests_without_verified_artwork_are_retained_but_not_ready(service, profile, profiles, ready):
    state, create, root, _ = service
    state.update(profile=profile, profiles=profiles)
    client, headers = visitor(create())
    assert submit(client, headers).status_code == 201
    assert len(PeopleStore(root).list()) == 1
    assert bool(client.get("/api/people?tags=TMDb+Ready").get_json()["people"]) == ready
    assert bool(client.get("/api/people/export?tags=TMDb+Ready").data) == ready


def test_unknown_inventory_after_request_does_not_remain_ready(service):
    state, create, root, _ = service
    client, headers = visitor(create())
    assert submit(client, headers).status_code == 201
    state.update(missing=set(), unavailable={style.key for style in PEOPLE_IMAGE_STYLES})
    client, _ = visitor(create())
    assert client.get("/api/people/export?tags=TMDb+Ready").data == b""
    assert PeopleStore(root).list()[0]["people_image_status"] == "pending_verification"


def test_concurrent_requests_from_independent_store_instances_keep_one_identity(tmp_path):
    def request(number):
        store = PeopleStore(tmp_path)
        return store.upsert_with_status(
            {
                "key": f"old-{number}" if number == 0 else "tmdb-777",
                "tmdb_id": 777,
                "name": "Person",
                "manual_requests": [{"id": str(number % 4), "name": f"User {number % 4}", "requested_at": str(number)}],
            }
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        responses = list(executor.map(request, range(24)))
    assert sum(created for _, created in responses) == 1
    records = PeopleStore(tmp_path).list()
    assert len(records) == 1 and len(records[0]["manual_requests"]) == 4


def test_throttles_survive_app_recreation_and_bound_searches(service):
    _, create, _, _ = service
    client, headers = visitor(create())
    for _ in range(10):
        assert submit(client, headers).status_code in {200, 201}
    client, headers = visitor(create())
    assert submit(client, headers).status_code == 429
    for _ in range(30):
        assert client.get("/api/people/search?q=777").status_code == 200
    response = client.get("/api/people/search?q=777")
    assert response.status_code == 429 and response.headers["Retry-After"]


def test_atomic_persistence_failure_preserves_existing_requests(service):
    _, create, root, _ = service
    client, headers = visitor(create())
    assert submit(client, headers).status_code == 201
    original = (root / "people.json").read_bytes()
    with patch("logscan_web.storage.PeopleStore._write", side_effect=OSError("private failure detail")):
        response = client.post("/api/people/request", json={"tmdb_id": 778}, headers=headers)
    assert response.status_code == 503
    assert "private failure" not in response.get_data(as_text=True)
    assert (root / "people.json").read_bytes() == original


def test_corrupt_store_is_not_silently_overwritten(tmp_path):
    path = tmp_path / "people.json"
    path.write_text("corrupt")
    with pytest.raises(ValueError):
        PeopleStore(tmp_path).upsert({"key": "tmdb-777", "tmdb_id": 777, "name": "Person"})
    assert path.read_text() == "corrupt"


def _worker_request(arguments):
    root, number, manual_request_once = arguments
    return PeopleStore(root).upsert_with_status(
        {
            "key": "tmdb-777",
            "tmdb_id": 777,
            "name": "Person",
            "manual_requests": [{"id": str(number % 3), "name": f"User {number % 3}", "requested_at": str(number)}],
        },
        manual_request_once=manual_request_once,
    )[1]


@pytest.mark.parametrize("manual_request_once", [False, True])
def test_multiple_worker_processes_preserve_requesters_and_deduplicate(tmp_path, manual_request_once):
    with ProcessPoolExecutor(max_workers=3) as executor:
        created = list(executor.map(_worker_request, [(str(tmp_path), number, manual_request_once) for number in range(12)]))
    assert sum(created) == 1
    records = PeopleStore(tmp_path).list()
    assert len(records) == 1 and len(records[0]["manual_requests"]) == (1 if manual_request_once else 3)


def test_rate_limit_persistence_errors_have_a_safe_response(service):
    _, create, _, _ = service
    client, headers = visitor(create())
    with patch("logscan_web.storage.PeopleStore.allow_lookup", side_effect=OSError("private path")):
        for response in [client.get("/api/people/search?q=777"), submit(client, headers)]:
            assert response.status_code == 503
            assert "private path" not in response.get_data(as_text=True)


def test_search_and_request_use_exact_returned_identity(service):
    state, create, root, _ = service
    client, headers = visitor(create())
    state["matches"] *= 20
    choices = client.get("/api/people/search?q=Lupita").get_json()["choices"]
    assert [item["tmdb_id"] for item in choices] == [777, 778]
    # Never treat another TMDb identity returned at this endpoint as the selected person.
    with patch("logscan_web.app.urlopen", return_value=Response({"id": 778, "name": "Other Person"})):
        assert submit(client, headers).status_code == 404
    assert PeopleStore(root).list() == []


@pytest.mark.parametrize("authenticated", [False, True])
def test_concurrent_http_requests_preserve_the_first_person_request(service, authenticated):
    _, create, root, _ = service
    app = create()
    barrier = Barrier(6)
    original_upsert = PeopleStore.upsert_with_status

    def concurrent_upsert(store, person, **kwargs):
        # Every caller has seen the old, requestable state before anyone writes.
        barrier.wait(timeout=20)
        return original_upsert(store, person, **kwargs)

    def request(number):
        user = {"id": str(number), "username": f"User {number}"} if authenticated else None
        client, headers = visitor(app, user)
        return submit(client, headers).status_code

    with patch.object(PeopleStore, "upsert_with_status", new=concurrent_upsert), ThreadPoolExecutor(max_workers=6) as executor:
        codes = list(executor.map(request, range(6)))
    assert codes.count(201) == 1 and codes.count(200) == 5
    records = PeopleStore(root).list()
    assert len(records) == 1 and len(records[0]["manual_requests"]) == 1
    assert len(records[0].get("requested_by", [])) == (1 if authenticated else 0)
