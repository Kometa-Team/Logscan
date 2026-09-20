import json
import os
import tempfile
import unittest
from types import SimpleNamespace
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

from logscan_web.app import add_missing_people_recommendations, app
from logscan_web.scanner import extract_missing_people
from logscan_web.storage import AnonymousAnalyticsStore, PeopleStore, UsageStatsStore


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
    if "/person/5?" in url:
        return Response({"id": 5, "name": "Blocked Person", "profile_path": None, "known_for_department": "Acting"})
    raise AssertionError(f"Unexpected URL: {url}")


class MissingPeopleExtractionTests(unittest.TestCase):
    def test_pending_recommendation_links_to_filtered_people_queue(self):
        result = SimpleNamespace(
            recommendations=[],
            metadata={"counts": {"advice": 0}},
            overview={"recommendation_count": 0},
        )
        people_url = "https://logscan.example/people?tags=Missing+Kometa&tags=Requested+by+User"
        add_missing_people_recommendations(
            result,
            [{"name": "Hikaru Kondô", "tmdb_image_found": True}],
            {},
            people_url,
        )
        self.assertIn(people_url, result.recommendations[0]["solution"])

    def test_repository_filename_is_fully_url_decoded(self):
        content = (
            "Collection Warning: No Poster Found at "
            "https://raw.githubusercontent.com/Kometa-Team/People-Images/master/"
            "Hikaru%20Kond%C3%B4.jpg\n"
        )
        self.assertEqual(extract_missing_people(content), [
            {"name": "Hikaru Kondô", "tmdb_image_found": False},
        ])


class AnonymousAnalyticsTests(unittest.TestCase):
    def test_daily_analytics_are_aggregate_and_persistent(self):
        with tempfile.TemporaryDirectory() as directory:
            analytics = AnonymousAnalyticsStore(directory)
            analytics.record_rejection("not_kometa_log", "web")
            analytics.record_success(
                logs=2, lines=1200, bytes_processed=5000, source="discord", batch=True,
                versions=["2.1.0", "unknown"],
                recommendations=[{"id": "test_rule", "severity": "warning"}], people=3,
            )
            analytics.record_addressed([{"key": "tmdb-1", "created_at": datetime.now(UTC).isoformat()}])
            analytics.record_addressed([{"key": "tmdb-1", "created_at": datetime.now(UTC).isoformat()}])
            snapshot = AnonymousAnalyticsStore(directory).snapshot()
            raw = Path(directory, "usage_analytics.json").read_text(encoding="utf-8")
        self.assertEqual(snapshot["totals"]["successful_logs"], 2)
        self.assertEqual(snapshot["totals"]["people_addressed"], 1)
        self.assertEqual(snapshot["totals"]["sources"], {"discord": 2})
        self.assertNotIn("tmdb-1", raw)


class UsageStatsTests(unittest.TestCase):
    def test_counters_persist_and_addressed_people_are_only_counted_once(self):
        with tempfile.TemporaryDirectory() as directory:
            stats = UsageStatsStore(directory)
            stats.ensure_people_baseline(2)
            stats.record_submission(logs=2, lines=12500, people=1)
            stats.ensure_people_baseline(1)
            self.assertEqual(stats.mark_addressed(["tmdb-1", "tmdb-2"]), 2)
            self.assertEqual(stats.mark_addressed(["tmdb-1"]), 0)
            restored = UsageStatsStore(directory).snapshot()
        self.assertEqual(restored["logs_submitted"], 2)
        self.assertEqual(restored["lines_processed"], 12500)
        self.assertEqual(restored["people_submitted"], 3)
        self.assertEqual(restored["people_addressed"], 2)


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

    def request_people(self, sources="missing,trending", tag="", selected_tags=()):
        query = [("sources", sources), ("tag", tag)]
        query.extend(("tags", value) for value in selected_tags)
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string=query)
        self.assertEqual(response.status_code, 200)
        return response.get_json()["people"]

    def test_union_deduplicates_by_tmdb_id_and_adds_source_tags(self):
        people = self.request_people()
        self.assertEqual([person["tmdb_id"] for person in people], [1, 3, 2])
        self.assertEqual(people[0]["sources"], ["missing", "trending"])
        self.assertEqual(people[1]["sources"], ["missing"])
        self.assertEqual(people[2]["sources"], ["trending"])

    def test_legacy_source_parameter_is_ignored_for_the_unified_page(self):
        self.assertEqual([person["tmdb_id"] for person in self.request_people("missing")], [1, 3, 2])
        self.assertEqual([person["tmdb_id"] for person in self.request_people("trending")], [1, 3, 2])

    def test_trending_and_missing_kometa_tags_find_the_intersection(self):
        people = self.request_people(selected_tags=("Trending", "Missing Kometa"))
        self.assertEqual([person["tmdb_id"] for person in people], [1])

    def test_known_requester_is_returned_with_missing_person(self):
        person = next(person for person in self.request_people() if person["tmdb_id"] == 1)
        self.assertEqual(person["requested_by"], [{"name": "Request User", "id": "123"}])
        self.assertEqual(person["provenance_tags"], ["Log Upload"])

    def test_log_upload_tag_is_searchable_for_historical_records(self):
        people = self.request_people(tag="log upload")
        self.assertEqual([person["tmdb_id"] for person in people], [1, 3])
        self.assertTrue(all(person["provenance_tags"] == ["Log Upload"] for person in people))

    def test_historical_log_record_uses_searchable_unknown_requester(self):
        people = self.request_people(tag="unknown")
        self.assertEqual([person["tmdb_id"] for person in people], [3])
        self.assertEqual(people[0]["requested_by"], [{"name": "Unknown", "id": None}])

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

    def test_dynamic_tags_include_counts_and_group_requesters_with_or_semantics(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string=[
                ("sources", "missing,trending"),
                ("tags", "Requested by Request User"),
                ("tags", "Requested by Unknown"),
            ])
        payload = response.get_json()
        self.assertEqual([person["tmdb_id"] for person in payload["people"]], [1, 3])
        facets = {(item["category"], item["tag"]): item["count"] for item in payload["available_tags"]}
        self.assertEqual(facets[("discovery", "Log Upload")], 2)
        self.assertEqual(facets[("requester", "Requested by Unknown")], 1)
        self.assertEqual(facets[("requester", "Requested by Request User")], 1)

    def test_dynamic_tags_combine_different_categories_with_and_semantics(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people", query_string=[
                ("sources", "missing,trending"),
                ("tags", "Log Upload"),
                ("tags", "Requested by Unknown"),
            ])
        self.assertEqual([person["tmdb_id"] for person in response.get_json()["people"]], [3])

    def test_missing_filter_includes_trending_gaps_without_uploaded_logs(self):
        Path(STORE.name, "people.json").write_text("[]", encoding="utf-8")
        people = self.request_people(selected_tags=("Missing Kometa",))
        self.assertEqual([person["tmdb_id"] for person in people], [1])
        self.assertEqual(people[0]["sources"], ["missing", "trending"])

    def test_missing_tmdb_is_searchable_and_excluded_from_processing_export(self):
        Path(STORE.name, "people.json").write_text(json.dumps([
            {"key": "tmdb-5", "tmdb_id": 5, "name": "Blocked Person", "log_url": "/scan/blocked"},
        ]), encoding="utf-8")
        people = self.request_people("missing", "Missing TMDb")
        blocked = next(person for person in people if person["tmdb_id"] == 5)
        self.assertEqual(blocked["metadata_tags"], ["Missing TMDb"])
        self.assertEqual(blocked["tmdb_images_url"], "https://www.themoviedb.org/person/5/images/profiles")
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get(
                "/api/people/export",
                query_string={"sources": "missing", "tag": "Missing TMDb"},
            )
        self.assertEqual(response.get_data(as_text=True), "")

    def test_missing_people_with_tmdb_images_are_ready(self):
        person = next(person for person in self.request_people("missing") if person["tmdb_id"] == 3)
        self.assertEqual(person["metadata_tags"], ["TMDb Ready"])
        self.assertEqual(person["tmdb_images_url"], "https://www.themoviedb.org/person/3/images/profiles")

    def test_verified_tmdb_image_survives_transient_profile_lookup_gap(self):
        Path(STORE.name, "people.json").write_text(json.dumps([
            {"key": "tmdb-5", "tmdb_id": 5, "name": "Blocked Person", "tmdb_image_found": True},
        ]), encoding="utf-8")
        person = next(person for person in self.request_people("missing") if person["tmdb_id"] == 5)
        self.assertEqual(person["metadata_tags"], ["TMDb Ready"])
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people/export", query_string={"sources": "missing"})
        self.assertEqual(response.get_data(as_text=True).splitlines(), ["1|Alice Person", "5|Blocked Person", "2|Completed Person"])

    def test_repository_image_reconciliation_only_removes_missing_source(self):
        completed = next(person for person in self.request_people() if person["name"] == "Completed Person")
        self.assertEqual(completed["sources"], ["trending"])
        self.assertEqual(completed["kometa_image"], "https://example.test/completed.jpg")

    def test_export_uses_the_same_filtered_union(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people/export", query_string={"sources": "missing,trending"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True).splitlines(), ["1|Alice Person", "3|Bob Person", "2|Completed Person"])

    def test_export_preserves_original_accented_log_name(self):
        Path(STORE.name, "people.json").write_text(json.dumps([
            {
                "key": "tmdb-1", "tmdb_id": 1, "name": "Hikaru Kondo",
                "original_name": "Hikaru Kondô", "log_url": "/scan/hikaru",
            },
        ]), encoding="utf-8")
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get(
                "/api/people/export",
                query_string=[("tags", "Log Upload")],
            )
        self.assertEqual(response.get_data(as_text=True).splitlines(), ["1|Hikaru Kondô"])

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

    def test_people_page_uses_card_level_tmdb_guidance(self):
        response = self.client.get("/people")
        html = response.get_data(as_text=True)
        self.assertNotIn("people-status-note", html)
        self.assertNotIn("Image status", html)

    def test_service_activity_is_visible_on_scanner_and_people_pages(self):
        for path in ("/", "/people"):
            html = self.client.get(path).get_data(as_text=True)
            self.assertIn('class="usage-stats"', html)
            self.assertIn("Logs processed", html)
            self.assertIn("Lines processed", html)
            self.assertIn("People submitted", html)
            self.assertIn("People addressed", html)

    def test_log_scanner_header_links_to_people(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn('href="/people">People</a>', html)
        self.assertIn('aria-label="Utilities"', html)

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

    def test_anonymous_analytics_endpoint_contains_only_aggregates(self):
        payload = self.client.get("/api/analytics").get_json()
        self.assertIn("totals", payload)
        self.assertIn("days", payload)
        self.assertNotIn("users", payload)
        self.assertNotIn("filenames", payload)

    def test_old_beta_routes_are_removed(self):
        self.assertEqual(self.client.get("/people/popular").status_code, 404)
        self.assertEqual(self.client.get("/people/tmdb-1").status_code, 404)
        self.assertEqual(self.client.get("/api/people/popular").status_code, 404)

    def test_legacy_source_filter_does_not_limit_the_unified_page(self):
        with patch("logscan_web.app.urlopen", side_effect=fake_urlopen):
            response = self.client.get("/api/people?sources=unknown")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["total"], 3)

    def test_people_page_uses_dynamic_tags_and_discreet_examples(self):
        html = self.client.get("/people").get_data(as_text=True)
        self.assertNotIn('class="source-filter"', html)
        self.assertIn('class="tag-filter-examples"', html)
        self.assertIn("Missing Kometa", html)


if __name__ == "__main__":
    unittest.main()
