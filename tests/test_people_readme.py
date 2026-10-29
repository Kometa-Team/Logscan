import json
from io import BytesIO
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest

from logscan_web.people_images import PEOPLE_IMAGE_STYLES
from logscan_web.people_readme import PeopleReadmeCache

STYLE = PEOPLE_IMAGE_STYLES[-1]
README = "# Kometa People Images (1 Images)\n* [Bruce Langley](https://raw.githubusercontent.com/Kometa-Team/People-Images-transparent/master/B/Images/Bruce%20Langley.png)\n"


class Response(BytesIO):
    def __init__(self, text=README, **headers):
        super().__init__(text.encode())
        self.headers = {"ETag": '"readme-v1"', **headers}


@pytest.fixture
def clock(monkeypatch):
    value = [1800000000.0]
    monkeypatch.setattr("logscan_web.people_readme.time.time", lambda: value[0])
    return value


def test_readme_cache_reuses_public_indexes_across_restart(tmp_path, clock):
    fetch = Mock(return_value=Response())
    first = PeopleReadmeCache(tmp_path).load(STYLE, open_url=fetch)
    restarted = PeopleReadmeCache(tmp_path).load(STYLE, open_url=fetch)
    assert first == restarted
    assert first.checked_at == restarted.checked_at
    assert first["bruce langley"].endswith(".png")
    assert not restarted.complete
    assert fetch.call_args.args[0].get_header("Authorization") is None
    fetch.assert_called_once()


def test_conditional_readme_refresh_reuses_304_body(tmp_path, clock):
    cache = PeopleReadmeCache(tmp_path)
    first = cache.load(STYLE, open_url=Mock(return_value=Response(**{"Last-Modified": "Thu, 29 Oct 2026 12:00:00 GMT"})))
    clock[0] += 3601
    fetch = Mock(side_effect=HTTPError(STYLE.readme_url, 304, "Not Modified", {}, None))
    refreshed = PeopleReadmeCache(tmp_path).load(STYLE, open_url=fetch)
    assert refreshed == first
    assert refreshed.checked_at > first.checked_at
    assert fetch.call_args.args[0].get_header("If-none-match") == '"readme-v1"'
    assert fetch.call_args.args[0].get_header("If-modified-since") == "Thu, 29 Oct 2026 12:00:00 GMT"
    PeopleReadmeCache(tmp_path).load(STYLE, open_url=fetch)
    fetch.assert_called_once()


def test_changed_readme_replaces_snapshot_and_unvalidated_text_does_not(tmp_path, clock):
    cache = PeopleReadmeCache(tmp_path)
    cache.load(STYLE, open_url=Mock(return_value=Response()))
    clock[0] += 3601
    with pytest.raises(ValueError, match="incomplete"):
        cache.load(STYLE, open_url=Mock(return_value=Response(README.replace("(1 Images)", "(2 Images)"))))
    saved = json.loads((tmp_path / "transparent.json").read_text())
    assert saved["text"] == README
    changed = README.replace("Bruce", "Other")
    refreshed = cache.load(STYLE, open_url=Mock(return_value=Response(changed)))
    assert "other langley" in refreshed
    assert "bruce langley" not in refreshed
    assert json.loads((tmp_path / "transparent.json").read_text())["text"] == changed


def test_expired_readme_is_not_reported_fresh_when_raw_host_is_unavailable(tmp_path, clock):
    cache = PeopleReadmeCache(tmp_path)
    first = cache.load(STYLE, open_url=Mock(return_value=Response()))
    clock[0] += 3601
    with pytest.raises(URLError):
        cache.load(STYLE, open_url=Mock(side_effect=URLError("offline")))
    fetch = Mock(side_effect=HTTPError(STYLE.readme_url, 304, "Not Modified", {}, None))
    refreshed = cache.load(STYLE, open_url=fetch)
    assert refreshed.checked_at > first.checked_at
    fetch.assert_called_once()


def test_expired_upstream_readme_is_not_saved_as_fresh(tmp_path, clock):
    with pytest.raises(ValueError, match="expired"):
        PeopleReadmeCache(tmp_path).load(STYLE, open_url=Mock(return_value=Response(Age="3601")))
    assert not (tmp_path / "transparent.json").exists()


def test_corrupt_readme_cache_is_refetched(tmp_path, clock):
    (tmp_path / "transparent.json").write_text('{"text":null,"checked_at":"bad"}')
    fetch = Mock(return_value=Response())
    assert "bruce langley" in PeopleReadmeCache(tmp_path).load(STYLE, open_url=fetch)
    fetch.assert_called_once()
