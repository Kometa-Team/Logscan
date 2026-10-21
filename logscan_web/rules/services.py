"""External-service recommendation rules."""

import re

from .base import EVIDENCE_LIMIT, TextRule, matching_line_spans
from ..models import Finding, ScanContext
from ..recommendations import RULES as RULE_DEFINITIONS


def _rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULE_DEFINITIONS.values() if rule.id == rule_id)
    return TextRule(definition, any_of=needles)


# Configuration section names, display names and documentation are controlled
# here; never copy arbitrary log contents or credentials into advice.
API_KEY_SERVICES = {
    "tmdb": "TMDb",
    "omdb": "OMDb",
    "mdblist": "MDBList",
    "tautulli": "Tautulli",
    "notifiarr": "Notifiarr",
    "radarr": "Radarr",
    "sonarr": "Sonarr",
    "tracearr": "Tracearr",
    "github": "GitHub",
    "yamtrack": "YamTrack",
    "floppy": "Floppy",
    "flicklist": "FlickList",
}


class MissingApiKeyRule:
    """Preserve service identity and exact evidence in normal and mmap scans."""

    id = "api_key_missing"

    def evaluate(self, context: ScanContext) -> list[Finding]:
        return self._evaluate(context.content)

    def evaluate_bytes(self, content) -> list[Finding]:
        return self._evaluate(content)

    def _evaluate(self, content) -> list[Finding]:
        expression = r"\bapi_?key[ \t]+(?:is[ \t]+(?:blank|missing)|(?:attribute[ \t]+)?not[ \t]+found)\b"
        pattern = re.compile(expression if isinstance(content, str) else expression.encode(), re.I)
        groups = {}
        for number, start, end in matching_line_spans(pattern, content):
            # Only read the short prefix immediately before the missing field,
            # even when a log line is unusually long.
            match = pattern.search(content, start, end)
            prefix = content[max(start, match.start() - 160) : match.start()]
            if not isinstance(prefix, str):
                prefix = prefix.decode("utf-8", errors="replace")
            source = re.search(r"\b([a-z][a-z0-9_]*)\s+(?:sub-attribute|Error:)\s*$", prefix, re.I)
            service = source[1].casefold() if source and source[1].casefold() in API_KEY_SERVICES else None
            evidence, count, fields = groups.setdefault(service, ([], 0, set()))
            field = match[0].split()[0]
            fields.add(field.lower() if isinstance(field, str) else field.decode().lower())
            if len(evidence) < EVIDENCE_LIMIT:
                evidence.append(number)
            groups[service] = (evidence, count + 1, fields)
        findings = []
        for service, (evidence, count, fields) in groups.items():
            if service:
                name = API_KEY_SERVICES[service]
                title = f"{name} API key is missing"
                description = f"The {name} API key is blank or missing. Features that depend on {name} cannot run."
                settings = ", ".join(f"`{service}.{field}`" for field in sorted(fields))
                solution = f"Add a valid {name} API key to {settings} in config.yml, then rerun Kometa. See https://kometa.wiki/en/latest/config/{service}/"
            else:
                title = "API key is missing"
                description = "An API key is blank or missing, but the affected service could not be identified from this log entry."
                solution = "Review the referenced log lines to identify the service, then set its API key in config.yml. See https://kometa.wiki/en/latest/config/overview/"
            findings.append(
                Finding(
                    f"{self.id}_{service}" if service else self.id,
                    "error",
                    title,
                    description,
                    solution,
                    tuple(evidence),
                    occurrence_count=count,
                    evidence_truncated=count > len(evidence),
                    service=service,
                )
            )
        return findings


RULES = (
    MissingApiKeyRule(),
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
    _rule("trakt_unsupported", "Trakt is no longer supported"),
    _rule("mal_connection", "My Anime List Connection Failed"),
    _rule("timeout", "timed out."),
)
