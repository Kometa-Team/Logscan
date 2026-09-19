import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch


STORE = tempfile.TemporaryDirectory()
os.environ["SCAN_STORE"] = STORE.name
os.environ["TMDB_API_KEY"] = "test-key"

Path(STORE.name, "popular_people_cache.json").write_text(json.dumps({
    "updated_at": datetime.now(UTC).isoformat(),
    "people": [
        {"id": 1, "name": "Alice Person", "profile_path": "/alice.jpg", "known_for_department": "Acting"},
        {"id": 2, "name": "Completed Person", "profile_path": "/complete.jpg", "known_for_department": "Acting"},
    ],
}), encoding="utf-8")

from logscan_web.app import app
from logscan_web.storage import PeopleStore


class Response:
    def __init__(self, payload, content_type="application/json"):
        self.payload = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


def fake_urlopen(request, timeout=0):
    url = request.full_url
    if "raw.githubusercontent.com" in url:
        readme = "* [Completed Person](https://example.test/completed.jpg)\n" if "People-Images/refs" in url else ""
        return Response(readme, "text/plain")
    if "/person/1?" in url:
        return Response({"id": 1, "name": "Alice Person", "profile_path": "/alice.jpg", "known_for_department": "Acting"})
    if "/person/3?" in url:
        return Response({"id": 3, "name": "Bob Person", "profile_path": "/bob.jpg", "known_for_department": "Directing"})
    raise AssertionError(f"Unexpected URL: {url}")


class PeopleUnionTests(unittest.TestCase):
    def setUp(self):
        app.config["PEOPLE_ACTIONS_ENABLED"] = True
        Path(STORE.name, "people.json").write_text(json.dumps([
            {"key": "tmdb-1", "tmdb_id": 1, "name": "Alice Person", "log_url": "/scan/alice", "requested_by": [{"name": "Request User", "id": "123"}]},
            {"key": "tmdb-3", "tmdb_id": 3, "name": "Bob Person", "log_url": "/scan/bob"},
            {"key": "tmdb-4", "tmdb_id": 4, "name": "Completed Person", "log_url": "/scan/completed"},
        ]), encoding="utf-8")
        for filename in ("popular_people_checked.json", "popular_people_exclusions.json", "popular_people_flags.json"):
            Path(STORE.name, filename).write_text("[]" if filename != "popular_people_flags.json" else "{}", encoding="utf-8")
        self.client = app.test_client()

    def request_people(self, sources="missing,trending", tag=""):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string={"sources": sources, "tag": tag})
        self.assertEqual(response.status_code, 200)
        return response.get_json()["people"]

    def test_union_deduplicates_by_tmdb_id_and_adds_source_tags(self):
        people = self.request_people()
        self.assertEqual([person["tmdb_id"] for person in people], [1, 3, 2])
        self.assertEqual(people[0]["sources"], ["missing", "trending"])
        self.assertEqual(people[1]["sources"], ["missing"])
        self.assertEqual(people[2]["sources"], ["trending"])

    def test_source_filters_use_or_semantics(self):
        self.assertEqual([person["tmdb_id"] for person in self.request_people("missing")], [1, 3])
        self.assertEqual([person["tmdb_id"] for person in self.request_people("trending")], [1, 2])

    def test_known_requester_is_returned_with_missing_person(self):
        person = next(person for person in self.request_people() if person["tmdb_id"] == 1)
        self.assertEqual(person["requested_by"], [{"name": "Request User", "id": "123"}])

    def test_requesters_accumulate_without_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            store = PeopleStore(directory)
            store.upsert({"key": "tmdb-9", "name": "Person", "requested_by": [{"name": "First Name", "id": "1"}]})
            store.upsert({"key": "tmdb-9", "name": "Person", "requested_by": [{"name": "Updated Name", "id": "1"}]})
            person = store.upsert({"key": "tmdb-9", "name": "Person", "requested_by": [{"name": "Second User", "id": "2"}]})
        self.assertEqual(person["requested_by"], [
            {"name": "Updated Name", "id": "1"},
            {"name": "Second User", "id": "2"},
        ])

    def test_api_supports_smaller_mobile_page_size(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string={"sources": "missing,trending", "per_page": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["people"]), 1)
        self.assertEqual(response.get_json()["per_page"], 1)
        self.assertEqual(response.get_json()["total"], 3)
        self.assertEqual(response.get_json()["total_pages"], 3)

    def test_tag_filter_supports_contains_and_wildcards(self):
        self.assertEqual([person["tmdb_id"] for person in self.request_people(tag="user")], [1])
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string={"sources": "missing,trending", "tag": "user"})
        self.assertEqual(response.get_json()["total"], 1)
        self.assertEqual([person["tmdb_id"] for person in self.request_people(tag="Request*User")], [1])
        self.assertEqual([person["tmdb_id"] for person in self.request_people(tag="trend?ng")], [1, 2])

    def test_missing_filter_includes_trending_gaps_without_uploaded_logs(self):
        Path(STORE.name, "people.json").write_text("[]", encoding="utf-8")
        people = self.request_people("missing")
        self.assertEqual([person["tmdb_id"] for person in people], [1])
        self.assertEqual(people[0]["sources"], ["missing", "trending"])

    def test_repository_image_reconciliation_only_removes_missing_source(self):
        completed = next(person for person in self.request_people() if person["name"] == "Completed Person")
        self.assertEqual(completed["sources"], ["trending"])
        self.assertEqual(completed["kometa_image"], "https://example.test/completed.jpg")

    def test_export_uses_the_same_filtered_union(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people/export", query_string={"sources": "missing,trending"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True).splitlines(), ["1|Alice Person", "3|Bob Person", "2|Completed Person"])

    def test_export_respects_requester_tag_filter(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get(
                "/api/people/export",
                query_string={"sources": "missing,trending", "tag": "request*user"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True).splitlines(), ["1|Alice Person"])

    def test_people_actions_are_hidden_and_rejected_when_disabled(self):
        app.config["PEOPLE_ACTIONS_ENABLED"] = False
        try:
            with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
                payload = self.client.get("/api/people", query_string={"sources": "trending"}).get_json()
            self.assertFalse(payload["actions_enabled"])
            for action in ("check", "flag", "exclude"):
                self.assertEqual(self.client.post(f"/api/people/tmdb-1/{action}").status_code, 404)
        finally:
            app.config["PEOPLE_ACTIONS_ENABLED"] = True

    def test_complete_removes_missing_and_temporarily_checks_trending(self):
        response = self.client.post("/api/people/tmdb-1/check")
        self.assertEqual(response.status_code, 204)
        self.assertEqual([person["tmdb_id"] for person in self.request_people()], [3, 2])

    def test_people_header_uses_official_kometa_icon(self):
        response = self.client.get("/people")
        self.assertEqual(response.status_code, 200)
        self.assertIn('class="brand-mark" src="/static/favicon.png"', response.get_data(as_text=True))
        self.assertNotIn('<span class="brand-mark">K</span>', response.get_data(as_text=True))

    def test_favicon_is_available_at_browser_default_path(self):
        response = self.client.get("/favicon.ico")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "image/png")
        self.assertGreater(len(response.data), 100)

    def test_old_beta_routes_are_removed(self):
        self.assertEqual(self.client.get("/people/popular").status_code, 404)
        self.assertEqual(self.client.get("/people/tmdb-1").status_code, 404)
        self.assertEqual(self.client.get("/api/people/popular").status_code, 404)

    def test_invalid_source_filter_is_json_error(self):
        response = self.client.get("/api/people?sources=unknown")
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())


if __name__ == "__main__":
    unittest.main()
