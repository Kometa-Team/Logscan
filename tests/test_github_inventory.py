import json
from io import BytesIO
from unittest.mock import Mock
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from logscan_web.github_inventory import GitHubInventoryCache

URL = "https://api.github.com/repos/Kometa-Team/People-Images/git/trees/master?recursive=1"
OTHER_URL = URL.replace("People-Images/", "People-Images-bw/")
TREE = {"sha": "branch-revision", "truncated": False, "tree": [{"type": "blob", "path": "G/Images/Gabee.jpg"}]}


class Response(BytesIO):
    def __init__(self, body=TREE, **headers):
        super().__init__(json.dumps(body).encode())
        self.headers = {"ETag": '"inventory-v1"', **headers}


@pytest.fixture
def clock(monkeypatch):
    value = [1800000000.0]
    monkeypatch.setattr("logscan_web.github_inventory.time.time", lambda: value[0])
    return value


def test_fresh_inventory_survives_restart_without_api_requests(tmp_path, clock):
    cache = GitHubInventoryCache(tmp_path)
    fetch = Mock(return_value=Response())
    request = Request(URL, headers={"Authorization": "Bearer not-a-real-token"})
    with cache.open(request, open_url=fetch) as response:
        assert json.load(response) == TREE
    restarted = GitHubInventoryCache(tmp_path)
    with restarted.open(request, open_url=fetch) as response:
        assert json.load(response) == TREE
    fetch.assert_called_once()
    assert all("not-a-real-token" not in path.read_text() for path in tmp_path.glob("*.json"))


def test_expired_inventory_uses_conditional_get_and_304_renews_verification(tmp_path, clock):
    cache = GitHubInventoryCache(tmp_path)
    cache.open(Request(URL), open_url=Mock(return_value=Response(**{"Last-Modified": "Thu, 29 Oct 2026 12:00:00 GMT"}))).close()
    clock[0] += 3601
    fetch = Mock(side_effect=HTTPError(URL, 304, "Not Modified", {}, None))
    restarted = GitHubInventoryCache(tmp_path)
    with restarted.open(Request(URL), open_url=fetch) as response:
        assert json.load(response) == TREE
        assert response.headers["Age"] == "0"
    request = fetch.call_args.args[0]
    assert request.get_header("If-none-match") == '"inventory-v1"'
    assert request.get_header("If-modified-since") == "Thu, 29 Oct 2026 12:00:00 GMT"
    assert request.get_header("Authorization") is None
    GitHubInventoryCache(tmp_path).open(Request(URL), open_url=fetch).close()
    fetch.assert_called_once()


def test_conditional_request_preserves_authentication(tmp_path, clock):
    cache = GitHubInventoryCache(tmp_path)
    cache.open(Request(URL), open_url=Mock(return_value=Response())).close()
    clock[0] += 3601
    fetch = Mock(return_value=Response())
    cache.open(Request(URL, headers={"Authorization": "Bearer test-token"}), open_url=fetch).close()
    assert fetch.call_args.args[0].get_header("Authorization") == "Bearer test-token"


def test_immutable_directory_tree_never_needs_another_api_request(tmp_path, clock):
    sha = "a" * 40
    url = URL.replace("master", sha)
    body = {**TREE, "sha": sha}
    fetch = Mock(return_value=Response(body))
    GitHubInventoryCache(tmp_path).open(Request(url), open_url=fetch).close()
    clock[0] += 30 * 86400
    with GitHubInventoryCache(tmp_path).open(Request(url), open_url=fetch) as response:
        assert json.load(response) == body
        assert response.headers["Age"] == "0"
    fetch.assert_called_once()


@pytest.mark.parametrize("status,headers", [(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1800000600"}), (429, {"Retry-After": "600"})])
def test_rate_limit_pauses_all_styles_and_survives_restart(tmp_path, clock, status, headers):
    fetch = Mock(side_effect=HTTPError(URL, status, "Rate limited", headers, None))
    with pytest.raises(HTTPError):
        GitHubInventoryCache(tmp_path).open(Request(URL), open_url=fetch)
    restarted = GitHubInventoryCache(tmp_path)
    clock[0] += 301
    with pytest.raises(HTTPError) as paused:
        restarted.open(Request(OTHER_URL), open_url=fetch)
    assert paused.value.code == 429
    fetch.assert_called_once()
    clock[0] += 301
    success = Mock(return_value=Response())
    restarted.open(Request(OTHER_URL), open_url=success).close()
    success.assert_called_once()


def test_secondary_rate_limit_without_headers_uses_exponential_backoff(tmp_path, clock):
    cache = GitHubInventoryCache(tmp_path)

    def fail(*_args, **_kwargs):
        raise HTTPError(URL, 403, "Forbidden", {"X-RateLimit-Remaining": "99"}, BytesIO(b'{"message":"You have exceeded a secondary rate limit."}'))

    fetch = Mock(side_effect=fail)
    with pytest.raises(HTTPError):
        cache.open(Request(URL), open_url=fetch)
    clock[0] += 61
    with pytest.raises(HTTPError):
        cache.open(Request(URL), open_url=fetch)
    clock[0] += 61
    with pytest.raises(HTTPError):
        cache.open(Request(OTHER_URL), open_url=fetch)
    assert fetch.call_count == 2


def test_last_successful_request_can_exhaust_quota_without_losing_its_inventory(tmp_path, clock):
    cache = GitHubInventoryCache(tmp_path)
    fetch = Mock(return_value=Response(**{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1800000600"}))
    with cache.open(Request(URL), open_url=fetch) as response:
        assert json.load(response) == TREE
    # Already verified inventories remain usable while API requests are paused.
    cache.open(Request(URL), open_url=fetch).close()
    with pytest.raises(HTTPError):
        cache.open(Request(OTHER_URL), open_url=fetch)
    fetch.assert_called_once()


def test_expired_inventory_is_not_reported_fresh_when_github_is_unavailable(tmp_path, clock):
    cache = GitHubInventoryCache(tmp_path)
    cache.open(Request(URL), open_url=Mock(return_value=Response())).close()
    clock[0] += 3601
    with pytest.raises(URLError):
        cache.open(Request(URL), open_url=Mock(side_effect=URLError("offline")))


def test_expired_upstream_response_keeps_its_age(tmp_path, clock):
    cache = GitHubInventoryCache(tmp_path)
    with cache.open(Request(URL), open_url=Mock(return_value=Response(Age="7200"))) as response:
        assert int(response.headers["Age"]) >= 7200


def test_corrupt_snapshot_is_refetched(tmp_path, clock):
    cache = GitHubInventoryCache(tmp_path)
    cache.open(Request(URL), open_url=Mock(return_value=Response())).close()
    for path in tmp_path.glob("*.json"):
        path.write_text('{"body": null, "checked_at": "invalid"}')
    fetch = Mock(return_value=Response())
    GitHubInventoryCache(tmp_path).open(Request(URL), open_url=fetch).close()
    fetch.assert_called_once()


def test_corrupt_backoff_metadata_does_not_block_requests(tmp_path, clock):
    (tmp_path / "rate-limit.json").write_text('{"retry_at":"invalid"}')
    fetch = Mock(return_value=Response())
    GitHubInventoryCache(tmp_path).open(Request(URL), open_url=fetch).close()
    fetch.assert_called_once()
