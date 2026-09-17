"""External-service recommendation rules."""

from .base import TextRule
from ..recommendations import RULES


def _rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULES.values() if rule.id == rule_id)
    return TextRule(definition, any_of=needles)


RULES = (
    _rule("anidb_connection", "No Anime Found for AniDB ID: 69"),
    _rule("anidb_auth", "Config Error: anidb sub-attribute", "AniDB Error: Login failed"),
    _rule("mdblist_api_key", "MdbList Error: Invalid API key"),
    _rule("mdblist_limit", "MDBList Error: API Limit Reached", "MDBList Error: API Rate Limit Reached"),
    _rule("omdb_api_key", "OMDb Error: Invalid API key"),
    _rule("omdb_limit", "OMDb Error: Request limit reached"),
    _rule("tmdb_key", "TMDb Error: Invalid API key"),
    _rule("tmdb_connection", "Failed to Connect to https://api.themoviedb.org/3"),
    _rule("tautulli_key", "Tautulli Error: Invalid apikey"),
    _rule("tautulli_url", "Tautulli Error: Invalid URL"),
    _rule("trakt_connection", "Trakt Connection Failed"),
    _rule("mal_connection", "My Anime List Connection Failed"),
    _rule("timeout", "timed out."),
)
