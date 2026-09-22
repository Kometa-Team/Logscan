"""Single-source recommendation catalogue."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml
from jsonschema import Draft7Validator


KOMETA_CONFIG_SCHEMA_URL = "https://raw.githubusercontent.com/Kometa-Team/Kometa/refs/heads/nightly/json-schema/config-schema.json"

@dataclass(frozen=True)
class RecommendationRule:
    id: str
    category: str
    title: str
    description: str
    solution: str
    detector: str | None = None
    captures: tuple[str, ...] = ()

    def capture_lines(self, content: str) -> list[int]:
        needles = tuple(value.lower() for value in self.captures)
        return [number for number, line in enumerate(content.splitlines(), start=1) if any(needle in line.lower() for needle in needles)] if needles else []


def extract_redacted_config(log_content: str) -> tuple[str, list[int]]:
    """Return Kometa's redacted config block and its source log-line numbers."""
    started = False
    extracted: list[tuple[str, int]] = []
    tagged_config = re.compile(r"\[config\.py:\d+\]\s+\[[A-Z]+\]\s*\|(.*)$")
    for line_number, line in enumerate(log_content.splitlines(), start=1):
        if not started:
            if "Redacted Config" in line:
                started = True
            continue
        if "Config Warning:" in line or "Initializing cache database at" in line:
            break
        match = tagged_config.search(line)
        if not match:
            break
        extracted.append((match.group(1).rstrip(" |"), line_number))
    if len(extracted) > 1:
        extracted.pop()
    return "\n".join(line[1:] if line.startswith(" ") else line for line, _number in extracted), [
        line_number for _line, line_number in extracted
    ]


def _node_at_path(node, path, unexpected_property: str | None = None):
    """Find the YAML node corresponding to a JSON Schema validation path."""
    for component in path:
        if isinstance(node, yaml.MappingNode):
            pair = next((pair for pair in node.value if pair[0].value == str(component)), None)
            if pair is None:
                break
            node = pair[1]
        elif isinstance(node, yaml.SequenceNode) and isinstance(component, int) and component < len(node.value):
            node = node.value[component]
        else:
            break
    if unexpected_property and isinstance(node, yaml.MappingNode):
        pair = next((pair for pair in node.value if pair[0].value == unexpected_property), None)
        if pair is not None:
            return pair[0]
    return node


def validate_redacted_config(log_content: str) -> list[dict[str, str | int]]:
    """Validate a log's extracted config against the latest Kometa nightly schema.

    The schema is deliberately downloaded for every call; it is not cached so the
    validation always reflects the current nightly branch.
    """
    config_text, log_lines = extract_redacted_config(log_content)
    if not config_text.strip():
        raise ValueError("No redacted configuration block was found in this log.")
    try:
        config = yaml.safe_load(config_text)
        config_node = yaml.compose(config_text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = log_lines[mark.line] if mark and mark.line < len(log_lines) else log_lines[0]
        return [{"line": line, "message": f"Invalid YAML: {getattr(exc, 'problem', str(exc))}", "path": ""}]
    try:
        schema_request = Request(
            KOMETA_CONFIG_SCHEMA_URL,
            headers={"Accept": "application/json", "Cache-Control": "no-cache", "User-Agent": "Kometa-Logscan/1.0"},
        )
        with urlopen(schema_request, timeout=15) as response:
            schema = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("The latest Kometa configuration schema could not be fetched.") from exc

    failures = []
    for error in sorted(Draft7Validator(schema).iter_errors(config), key=lambda item: list(item.absolute_path)):
        unexpected = None
        if error.validator == "additionalProperties":
            match = re.search(r"'([^']+)' was unexpected", error.message)
            unexpected = match.group(1) if match else None
        node = _node_at_path(config_node, error.absolute_path, unexpected)
        config_line = node.start_mark.line if node is not None else 0
        log_line = log_lines[config_line] if config_line < len(log_lines) else log_lines[0]
        path = ".".join(str(part) for part in error.absolute_path)
        failures.append({"line": log_line, "message": error.message, "path": path})
    return failures

# Each record contains its category, issue description, proposed solution, and capture text.
RULE_SPECS = (
    {'id': 'anidb_connection', 'category': 'error', 'title': 'AniDB connection test failed', 'description': 'Kometa uses AniDB ID 69 to test its AniDB connection. The test request failed and AniDB could not be reached.', 'solution': 'Check the AniDB configuration and connectivity. See https://kometa.wiki/en/latest/config/anidb', 'captures': ('No Anime Found for AniDB ID: 69',)},
    {'id': 'anidb_auth', 'category': 'error', 'title': 'AniDB authentication failed', 'description': 'Kometa uses the AniDB settings in config.yml to connect to AniDB. These settings are not configured correctly or AniDB rejected them.', 'solution': 'Correct the AniDB settings in config.yml. See https://kometa.wiki/en/latest/config/anidb', 'captures': ('Config Error: anidb sub-attribute', 'AniDB Error: Login failed')},
    {'id': 'api_key_missing', 'category': 'error', 'title': 'API key is missing', 'description': 'A third-party service API key is blank.', 'solution': 'Add the API key to the affected service configuration.', 'captures': ('apikey is blank',)},
    {'id': 'plex_version', 'category': 'critical', 'title': 'Incompatible Plex version detected', 'description': 'The detected Plex version is known to cause Kometa compatibility problems.', 'solution': 'Upgrade or downgrade Plex to a compatible release.', 'captures': ('1.32.7', 'Connected to server')},
    {'id': 'cache_disabled', 'category': 'advice', 'title': 'Kometa cache is disabled', 'description': 'Kometa caching is disabled, which can increase processing time and external API traffic.', 'solution': 'Enable the cache to improve performance and reduce API requests.', 'captures': ('cache: false',)},
    {'id': 'checkfiles', 'category': 'advice', 'title': 'Diagnostic file check enabled', 'description': 'Diagnostic file checking is enabled in this run.', 'solution': 'This diagnostic mode is intended for support investigation.', 'captures': ('checkFiles=1',)},
    {'id': 'legacy_other_award', 'category': 'schema', 'title': 'Legacy other_award setting detected', 'description': 'As of 1.20, `other_award` is no longer used and should be removed. Those awards now have their own individual files.', 'solution': 'Remove `other_award` and use the individual award files described at https://kometa.wiki/en/latest/kometa/faqs/?h=other_award#pmm-120-release-changes', 'captures': ('other_award',)},
    {'id': 'kometa_critical', 'category': 'critical', 'title': 'Critical Kometa messages detected', 'description': 'Critical log entries indicate that part or all of the run may have stopped early. Review each detailed issue and proposed solution below.', 'solution': 'Review the referenced critical log messages.', 'captures': ('[CRITICAL]',)},
    {'id': 'kometa_error', 'category': 'error', 'title': 'Kometa errors detected', 'description': 'Error log entries indicate that one or more requested operations may not have completed. Review each detailed issue and proposed solution below.', 'solution': 'Review the referenced error log messages.', 'captures': ('[ERROR]',)},
    {'id': 'kometa_warning', 'category': 'warning', 'title': 'Kometa warnings detected', 'description': 'Warning log entries were recorded; many are informational, but the referenced lines should be reviewed. Review each detailed issue and proposed solution below.', 'solution': 'Review the referenced warning log messages.', 'captures': ('[WARNING]',)},
    {'id': 'id_conversion', 'category': 'warning', 'title': 'Metadata ID conversion failed', 'description': 'A metadata provider record could not be cross-referenced to the requested identifier.', 'solution': 'Check the source item and identifier mapping.', 'captures': ('Convert Warning: No ', 'ID Found for')},
    {'id': 'image_unreadable', 'category': 'error', 'title': 'Unreadable image file detected', 'description': 'Kometa could not read an image file, commonly because it is corrupt or unsupported.', 'solution': 'Replace or repair the referenced image.', 'captures': ('PIL.UnidentifiedImageError',)},
    {'id': 'legacy_delete_unmanaged', 'category': 'schema', 'title': 'Legacy collection deletion setting detected', 'description': 'The configuration uses a legacy collection-deletion setting.', 'solution': 'Update this deprecated collection setting.', 'captures': ('delete_unmanaged_collections',)},
    {'id': 'flixpatrol_parse', 'category': 'warning', 'title': 'FlixPatrol data could not be parsed', 'description': 'Kometa could not parse data returned by FlixPatrol.', 'solution': 'Check the source data and service availability.', 'captures': ('FlixPatrol Error:', 'failed to parse')},
    {'id': 'flixpatrol_subscription', 'category': 'advice', 'title': 'FlixPatrol source requires a subscription', 'description': 'The configuration references a FlixPatrol source that is no longer supported by Kometa.', 'solution': 'Use a supported subscription or another data source.', 'captures': ('flixpatrol', '- pmm:')},
    {'id': 'legacy_git', 'category': 'schema', 'title': 'Legacy Kometa repository reference detected', 'description': 'The configuration contains a pre-1.18 Kometa metadata reference.', 'solution': 'Use the current Kometa repository reference.', 'captures': ('- git: PMM',)},
    {'id': 'legacy_pmm', 'category': 'schema', 'title': 'Pre-Kometa YAML detected', 'description': 'This config.yml references metadata files using syntax that predates Kometa.', 'solution': 'In config.yml, replace `- pmm:` with `- default:`. See https://kometa.wiki/en/latest/config/overview/?h=configuration', 'captures': ('- pmm:',)},
    {'id': 'image_size', 'category': 'warning', 'title': 'Image exceeds the permitted size', 'description': "Artwork exceeds Plex's supported upload size.", 'solution': 'Reduce the image dimensions or file size.', 'captures': ('in _upload_image',)},
    {'id': 'incomplete_log', 'category': 'warning', 'title': 'Log appears incomplete', 'description': 'The uploaded log does not contain a completed-run marker, limiting diagnostic accuracy.', 'solution': 'Upload a complete run log for accurate recommendations.', 'detector': 'LOG_INCOMPLETE'},
    {'id': 'internal_server', 'category': 'error', 'title': 'Remote service returned an internal error', 'description': 'An upstream service returned an internal-server error.', 'solution': 'Retry later and check the affected service status.', 'captures': ('internal_server_error',)},
    {'id': 'linuxserver', 'category': 'advice', 'title': 'LinuxServer container image detected', 'description': 'The log identifies a non-official LinuxServer container image.', 'solution': 'Review the container-specific Kometa guidance.', 'captures': ('(Linuxserver', 'Version:')},
    {'id': 'mal_connection', 'category': 'warning', 'title': 'MyAnimeList connection failed', 'description': 'Kometa could not connect to MyAnimeList.', 'solution': 'Check MyAnimeList credentials and connectivity.', 'captures': ('My Anime List Connection Failed',)},
    {'id': 'mass_update', 'category': 'error', 'title': 'Mass update prerequisite failed', 'description': 'A mass-update operation started without its required successful prerequisite.', 'solution': 'Resolve the failed prerequisite before running mass updates.', 'captures': ('Config Error: Operation mass_', 'without a successful')},
    {'id': 'mdblist_attribute', 'category': 'schema', 'title': 'MDBList attribute is invalid at this collection level', 'description': 'An MDBList attribute is being used at an unsupported collection level.', 'solution': 'Move or replace the attribute using the current schema.', 'captures': ('mdblist_list attribute not allowed',)},
    {'id': 'mdblist_api_key', 'category': 'critical', 'title': 'MDBList API key is invalid', 'description': 'MDBList rejected the configured API key.', 'solution': 'Replace the MDBList API key.', 'captures': ('MdbList Error: Invalid API key',)},
    {'id': 'mdblist_limit', 'category': 'warning', 'title': 'MDBList API limit reached', 'description': 'The MDBList API request limit has been reached.', 'solution': 'Wait for the limit reset or reduce requests.', 'captures': ('MDBList Error: API',)},
    {'id': 'metadata_attribute', 'category': 'schema', 'title': 'Required metadata attribute is missing', 'description': 'A required metadata-file attribute is missing.', 'solution': 'Add the required attribute to the metadata file.', 'captures': ('metadata attribute is required',)},
    {'id': 'metadata_load', 'category': 'error', 'title': 'Metadata file failed to load', 'description': 'A metadata file could not be loaded.', 'solution': 'Correct the referenced metadata file.', 'captures': ('Metadata File Failed To Load',)},
    {'id': 'overlay_load', 'category': 'error', 'title': 'Overlay file failed to load', 'description': 'An overlay file could not be loaded.', 'solution': 'Correct the referenced overlay file.', 'captures': ('Overlay File Failed To Load',)},
    {'id': 'playlist_load', 'category': 'error', 'title': 'Playlist file failed to load', 'description': 'A playlist file could not be loaded.', 'solution': 'Correct the referenced playlist file.', 'captures': ('Playlist File Failed To Load',)},
    {'id': 'legacy_missing', 'category': 'schema', 'title': 'Legacy missing-item setting detected', 'description': 'The configuration uses a deprecated missing-item setting.', 'solution': 'Update the deprecated missing-item setting.', 'captures': ('missing_path', 'save_missing')},
    {'id': 'plexapi_update', 'category': 'advice', 'title': 'Python dependency update required', 'description': 'The installed Plex API dependency is older than the version required by Kometa.', 'solution': 'Update the required Python dependency.', 'captures': ('requires an update to:',)},
    {'id': 'kometa_update', 'category': 'advice', 'title': 'Kometa update available', 'description': 'The log reports that a newer Kometa version was available at run time.', 'solution': 'Consider updating Kometa after reviewing the release notes.', 'captures': ('Newest Version:',)},
    {'id': 'plex_no_items', 'category': 'advice', 'title': 'No matching Plex items found', 'description': 'A Plex search or filter returned no items.', 'solution': 'Confirm the filter is expected and uses correct case.', 'captures': ('Plex Error: No Items found in Plex',)},
    {'id': 'omdb_api_key', 'category': 'critical', 'title': 'OMDb API key is invalid', 'description': 'OMDb rejected the configured API key.', 'solution': 'Replace the OMDb API key.', 'captures': ('OMDb Error: Invalid API key',)},
    {'id': 'omdb_limit', 'category': 'warning', 'title': 'OMDb request limit reached', 'description': 'The OMDb request limit has been reached.', 'solution': 'Wait for the limit reset or use a suitable plan.', 'captures': ('OMDb Error: Request limit',)},
    {'id': 'overlay_font', 'category': 'error', 'title': 'Overlay font file is missing', 'description': 'An overlay references a font file that Kometa cannot find.', 'solution': 'Install or correctly reference the font file.', 'captures': ('Overlay Error: font:',)},
    {'id': 'overlay_reset', 'category': 'warning', 'title': 'Overlay reapplication or reset detected', 'description': 'The run requests overlay reapplication or reset, which can create unnecessary artwork churn.', 'solution': 'Use reapply/reset only when a full overlay rebuild is intended.', 'captures': ('Reapply Overlays: True', 'Reset Overlays:')},
    {'id': 'overlay_existing', 'category': 'warning', 'title': 'Poster already contains an overlay', 'description': 'Kometa found artwork that already contains an overlay.', 'solution': 'Restore original artwork or follow the overlay reset process.', 'captures': ('Poster already has an Overlay',)},
    {'id': 'overlay_image', 'category': 'error', 'title': 'Overlay image file is missing', 'description': 'An overlay references an image file that cannot be found.', 'solution': 'Verify the image path, filename, case, and container access.', 'captures': ('Overlay Image not found',)},
    {'id': 'legacy_overlay_level', 'category': 'schema', 'title': 'Legacy overlay_level setting detected', 'description': 'The configuration uses the removed overlay_level setting.', 'solution': 'Replace overlay_level with builder_level.', 'captures': ('overlay_level:',)},
    {'id': 'playlist_library', 'category': 'error', 'title': 'Playlist references an unknown Plex library', 'description': 'A playlist references a Plex library that is not defined.', 'solution': 'Correct the library name or template variable.', 'captures': ('Playlist Error: Library:', 'not defined')},
    {'id': 'plex_regex', 'category': 'advice', 'title': 'Plex regular expression matched no items', 'description': 'A Plex regular-expression search returned no matches.', 'solution': 'Confirm the pattern and target field; an empty result may be expected.', 'captures': ('Plex Error: ', 'No matches found with regex pattern')},
    {'id': 'plex_library', 'category': 'critical', 'title': 'Plex library was not found', 'description': 'A configured Plex library name was not found.', 'solution': 'Verify spelling, case, and the configured Plex library.', 'captures': ('Plex Error: Plex Library', 'not found')},
    {'id': 'plex_url', 'category': 'critical', 'title': 'Plex URL is invalid', 'description': 'The configured Plex URL is invalid.', 'solution': 'Verify the scheme, hostname, port, and container networking.', 'captures': ('Plex Error: Plex url is invalid',)},
    {'id': 'rating_rounding', 'category': 'warning', 'title': 'Plex user-rating rounding issue detected', 'description': 'The detected Plex version can round user ratings written through the API.', 'solution': 'Upgrade Plex before applying the affected rating operations.', 'detector': 'RATING_ROUNDING'},
    {'id': 'yaml', 'category': 'schema', 'title': 'YAML parsing failed', 'description': 'Kometa encountered a YAML parsing error.', 'solution': 'Correct YAML indentation, quoting, spacing, or structure.', 'captures': ('ruamel.yaml.',)},
    {'id': 'run_order', 'category': 'schema', 'title': 'Recommended run order is not configured', 'description': "The configured run order does not follow Kometa's recommended processing sequence.", 'solution': 'Place operations before metadata and overlays unless your workflow requires otherwise.', 'detector': 'RUN_ORDER'},
    {'id': 'plex_security', 'category': 'critical', 'title': 'Vulnerable Plex Media Server version detected', 'description': 'A Plex Media Server version in a known vulnerable range was detected.', 'solution': 'Upgrade Plex Media Server to a secure release immediately.', 'detector': 'PMS_VULNERABLE'},
    {'id': 'traceback', 'category': 'error', 'title': 'Unhandled Kometa exception detected', 'description': 'Kometa raised an unhandled exception.', 'solution': 'Review the exception and its preceding context, then retry.', 'captures': ('Traceback (most recent call last):',)},
    {'id': 'tautulli_key', 'category': 'error', 'title': 'Tautulli API key is invalid', 'description': 'Tautulli rejected the configured API key.', 'solution': 'Replace the Tautulli API key.', 'captures': ('Tautulli Error: Invalid apikey',)},
    {'id': 'tautulli_url', 'category': 'error', 'title': 'Tautulli URL is invalid', 'description': 'The configured Tautulli URL is invalid.', 'solution': 'Verify the Tautulli URL and networking.', 'captures': ('Tautulli Error: Invalid URL',)},
    {'id': 'tmdb_key', 'category': 'critical', 'title': 'TMDb API key is invalid', 'description': 'TMDb rejected the configured API key.', 'solution': 'Replace the TMDb API key.', 'captures': ('TMDb Error: Invalid API key',)},
    {'id': 'timeout', 'category': 'error', 'title': 'Service connection timed out', 'description': 'A service request exceeded its configured timeout.', 'solution': 'Check service reachability or increase the relevant timeout.', 'captures': ('timed out.',)},
    {'id': 'tmdb_connection', 'category': 'critical', 'title': 'TMDb connection failed', 'description': 'Kometa could not establish a connection to TMDb.', 'solution': 'Check DNS, outbound access, firewall rules, and networking.', 'captures': ('Failed to Connect to https://api.themoviedb.org/3',)},
    {'id': 'service_config', 'category': 'schema', 'title': 'Required service is not configured', 'description': 'A required service has not been configured.', 'solution': 'Add the required configuration for the affected service.', 'captures': ('Error: ', ' requires ', ' to be configured')},
    {'id': 'trakt_connection', 'category': 'warning', 'title': 'Trakt connection failed', 'description': 'Kometa could not connect to Trakt.', 'solution': 'Check authorization, credentials, network access, and service availability.', 'captures': ('Trakt Connection Failed',)},
    {'id': 'wsl_memory', 'category': 'advice', 'title': 'WSL memory allocation', 'description': 'Kometa is running under WSL, which may constrain memory available to the process.', 'solution': 'Review the WSL memory allocation and increase it if the workload requires more memory.', 'captures': ('Platform:', '-WSL')},
    {'id': 'db_cache_exceeds_memory', 'category': 'error', 'title': 'Plex database cache exceeds available memory', 'description': 'The configured Plex database cache is at least as large as detected system memory.', 'solution': 'Reduce db_cache to a value safely below the available system memory.', 'captures': ('Plex DB cache setting:', 'Memory:')},
    {'id': 'db_cache_undersized', 'category': 'advice', 'title': 'Plex database cache may be undersized', 'description': 'The configured Plex database cache is below one gigabyte.', 'solution': 'Consider setting db_cache: 1024 (1 GB) in the Plex configuration, provided it remains safely below available memory and suits the workload.', 'captures': ('Plex DB cache setting:',)},
    {'id': 'memory_unavailable', 'category': 'advice', 'title': 'Memory information unavailable', 'description': 'The log does not include system-memory information.', 'solution': 'Upload a complete log that includes system-memory information.', 'captures': ()},
    {'id': 'memory_overlay_insufficient', 'category': 'warning', 'title': 'Insufficient memory for overlays', 'description': 'Detected memory is below the recommended minimum for an overlay workload.', 'solution': 'Increase available memory to at least 8 GB for overlay workloads.', 'captures': ('Memory:', 'overlay_path:', 'overlay_files:')},
    {'id': 'memory_low', 'category': 'warning', 'title': 'Low memory available', 'description': 'Detected memory is below the recommended minimum for a reliable Kometa run.', 'solution': 'Increase available memory to at least 4 GB for reliable operation.', 'captures': ('Memory:',)},
    {'id': 'memory_overlay_low', 'category': 'warning', 'title': 'Memory below the overlay recommendation', 'description': 'Detected memory is below the recommended level for an overlay workload.', 'solution': 'Increase available memory to at least 8 GB for overlay workloads.', 'captures': ('Memory:', 'overlay_path:', 'overlay_files:')},
    {'id': 'schedule_unavailable', 'category': 'advice', 'title': 'Kometa schedule information unavailable', 'description': 'The log does not include the configured Kometa schedule.', 'solution': 'Upload a log that includes the configured Kometa schedule.', 'captures': ()},
    {'id': 'schedule_over_24_hours', 'category': 'warning', 'title': 'Kometa run exceeds 24 hours', 'description': 'The recorded Kometa run duration exceeds 24 hours.', 'solution': 'Split the workload into shorter scheduled runs.', 'detector': 'SCHEDULE_ANALYSIS'},
    {'id': 'schedule_overlap', 'category': 'warning', 'title': 'Kometa run overlaps the next Plex maintenance window', 'description': 'The recorded run duration overlaps the next Plex maintenance window.', 'solution': 'Move the Kometa schedule, adjust maintenance, or divide the workload.', 'detector': 'SCHEDULE_ANALYSIS'},
    {'id': 'schedule_conflict', 'category': 'warning', 'title': 'Kometa schedule conflicts with Plex maintenance', 'description': 'The configured Kometa start time falls inside the Plex maintenance window.', 'solution': 'Schedule Kometa outside the Plex maintenance window.', 'detector': 'SCHEDULE_ANALYSIS'},
    {'id': 'schedule_maintenance_buffer', 'category': 'warning', 'title': 'Kometa may still be running when Plex maintenance begins', 'description': 'The recorded run duration may extend into Plex maintenance.', 'solution': 'Increase the gap between the Kometa schedule and maintenance.', 'detector': 'SCHEDULE_ANALYSIS'},
)

# Verified against the active Discord cog. Keeping these separate from prose makes
# documentation parity testable and prevents copy edits from dropping useful links.
DOCUMENTATION_URLS = {
    "anidb_connection": "https://kometa.wiki/en/latest/config/anidb",
    "anidb_auth": "https://kometa.wiki/en/latest/config/anidb",
    "api_key_missing": "https://kometa.wiki/en/latest/config/trakt/?q=api",
    "plex_version": "https://forums.plex.tv/t/refresh-endpoint-put-post-requests-started-throwing-404s-in-version-1-32-7-7484/853588",
    "cache_disabled": "https://kometa.wiki/en/latest/config/settings#cache",
    "legacy_other_award": "https://kometa.wiki/en/latest/kometa/faqs/?h=other_award#pmm-120-release-changes",
    "kometa_critical": "https://kometa.wiki/en/latest/kometa/logs/?h=%5Bcritical%5D#critical",
    "kometa_error": "https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error",
    "kometa_warning": "https://kometa.wiki/en/latest/kometa/logs/?h=%5Bwarning%5D#warning",
    "id_conversion": "https://kometa.wiki/en/latest/kometa/logs/#warning",
    "image_unreadable": "https://kometa.wiki/en/latest/kometa/logs/#error",
    "legacy_delete_unmanaged": "https://kometa.wiki/en/latest/config/operations/#delete-collections",
    "flixpatrol_parse": "https://kometa.wiki/en/latest/kometa/faqs/?h=flixpatrol#flixpatrol",
    "flixpatrol_subscription": "https://flixpatrol.com/about/premium/",
    "legacy_git": "https://kometa.wiki/en/latest/config/overview/?h=configuration",
    "legacy_pmm": "https://kometa.wiki/en/latest/config/overview/?h=configuration",
    "incomplete_log": "https://kometa.wiki/en/latest/kometa/logs/#providing-log-files-on-discord",
    "internal_server": "https://kometa.wiki/en/latest/kometa/faqs/?h=errors+issues#errors-issues",
    "linuxserver": "https://kometa.wiki/en/latest/kometa/install/images/?h=linuxserver#linuxserver",
    "mal_connection": "https://kometa.wiki/en/latest/config/myanimelist",
    "mass_update": "https://kometa.wiki/en/latest/config/operations",
    "mdblist_attribute": "https://kometa.wiki/en/latest/files/builders/mdblist/?h=mdblist+builders",
    "mdblist_api_key": "https://kometa.wiki/en/latest/config/mdblist/?h=mdblist+attributes#mdblist-attributes",
    "mdblist_limit": "https://kometa.wiki/en/latest/config/mdblist/?h=mdblist+attributes#mdblist-attributes",
    "metadata_attribute": "https://kometa.wiki/en/latest/config/files/#example",
    "metadata_load": "https://kometa.wiki/en/latest/config/overview/?h=configuration",
    "overlay_load": "https://kometa.wiki/en/latest/config/overview/?h=configuration",
    "playlist_load": "https://kometa.wiki/en/latest/config/overview/?h=configuration",
    "legacy_missing": "https://kometa.wiki/en/latest/config/libraries/?h=report_path#attributes",
    "plexapi_update": "https://kometa.wiki/en/latest/kometa/logs/#checking-kometa-version",
    "kometa_update": "https://kometa.wiki/en/latest/kometa/logs/#checking-kometa-version",
    "plex_no_items": "https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error",
    "omdb_api_key": "https://kometa.wiki/en/latest/config/omdb/#omdb-attributes",
    "omdb_limit": "https://kometa.wiki/en/latest/config/omdb/?h=omdb#omdb-attributes",
    "overlay_font": "https://kometa.wiki/en/latest/showcase/overlays/?h=font#example-2",
    "overlay_reset": "https://kometa.wiki/en/latest/kometa/scripts/imagemaid",
    "overlay_existing": "https://kometa.wiki/en/latest/defaults/overlays",
    "overlay_image": "https://kometa.wiki/en/latest/defaults/overlays",
    "legacy_overlay_level": "https://kometa.wiki/en/latest/files/settings/?h=builder_level",
    "playlist_library": "https://kometa.wiki/en/latest/defaults/playlist/?h=playlist",
    "plex_regex": "https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error",
    "plex_library": "https://kometa.wiki/en/latest/config/settings/?h=show_options#show-options",
    "plex_url": "https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/#getting-a-plex-url-and-token",
    "rating_rounding": "https://forums.plex.tv/t/plex-rounding-down-user-ratings-when-set-via-api/875806/8",
    "yaml": "https://kometa.wiki/en/latest/kometa/yaml/",
    "run_order": "https://kometa.wiki/en/latest/config/settings/?h=run_order#run-order",
    "plex_security": "https://forums.plex.tv/t/plex-media-server-security-update/928341",
    "tautulli_key": "https://kometa.wiki/en/latest/config/tautulli",
    "tautulli_url": "https://kometa.wiki/en/latest/config/tautulli#tautulli-attributes",
    "tmdb_key": "https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/#getting-a-tmdb-api-key",
    "timeout": "https://kometa.wiki/en/latest/kometa/install/overview/",
    "tmdb_connection": "https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/",
    "service_config": "https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error",
    "trakt_connection": "https://kometa.wiki/en/latest/config/trakt/#trakt-attributes",
}
DOCUMENTATION_URLS = {
    rule_id: url.replace("https://kometa.wiki/", "https://www.kometa.wiki/")
    for rule_id, url in DOCUMENTATION_URLS.items()
}

# Actionable prose retained from the Discord cog. Discord-only bot commands are
# intentionally omitted because they are not useful in a standalone web result.
DISCORD_GUIDANCE = {
    "api_key_missing": ("A required third-party API key is blank, so features using that service cannot run.", "Add a valid API key for the named service in config.yml."),
    "plex_version": ("Plex 1.32.7.x has a known refresh-endpoint compatibility problem with Kometa.", "Upgrade or downgrade Plex to a release outside the 1.32.7.x range."),
    "cache_disabled": ("Kometa has `cache: false`; this increases repeat processing and external API traffic.", "Set `cache: true` unless you are deliberately troubleshooting without cached data."),
    "checkfiles": ("The diagnostic `checkFiles=1` mode was detected in this run.", "Use this mode only when requested for a support investigation."),
    "kometa_critical": ("Critical messages strongly indicate that all or part of the Kometa run stopped early, so requested changes may not have been applied.", "Review each referenced critical line and resolve its underlying failure before rerunning Kometa."),
    "kometa_error": ("Error messages indicate that Kometa likely did not complete every requested action, although some individual errors may be non-fatal.", "Review each referenced error in context and correct the affected configuration or service."),
    "kometa_warning": ("Warnings are often informational and may not require immediate action, but each referenced line should be reviewed in context.", "Confirm whether each warning is expected before changing the configuration."),
    "id_conversion": ("Kometa could not cross-reference an item between metadata providers because the source record lacks the requested external ID.", "Check the referenced provider records and add or correct the missing cross-reference at the source when possible."),
    "image_unreadable": ("Kometa encountered an image it could not decode, commonly while processing overlays; the file may be corrupt or unsupported.", "Open the referenced image in an editor and replace or repair it before rerunning Kometa."),
    "legacy_delete_unmanaged": ("`delete_unmanaged_collections` is now a library operation and is in the wrong part of the configuration.", "Move the setting into the appropriate library operations configuration."),
    "flixpatrol_parse": ("Kometa could not process returned FlixPatrol data; this may be a service response problem or an obsolete Kometa integration.", "Update Kometa and verify FlixPatrol availability; if failures continue, contact FlixPatrol support."),
    "flixpatrol_subscription": ("FlixPatrol placed this data behind a paywall and Kometa no longer supports the old `- pmm: flixpatrol` source, even with a paid account.", "Remove the obsolete FlixPatrol source and replace it with a supported builder."),
    "legacy_git": ("This config.yml references pre-1.18 metadata files with the old `- git: PMM` syntax.", "Update the file reference to the current Kometa configuration syntax."),
    "image_size": ("Artwork being uploaded or applied exceeds Plex's 10 MB limit and may also produce HTTP 500 errors.", "Reduce the referenced image below 10 MB before rerunning Kometa."),
    "incomplete_log": ("The uploaded file appears incomplete, so important context needed for accurate troubleshooting may be missing.", "Upload the complete Kometa log from the beginning through the finished run summary."),
    "internal_server": ("A remote service returned an internal-server error; the failure may be temporary and outside Kometa's control.", "Identify the affected service from the referenced lines, retry later, and check that service's status if it continues."),
    "linuxserver": ("The log identifies the LinuxServer image rather than the official Kometa container image.", "Review the LinuxServer-specific limitations and migrate to the official Kometa image when supportability matters."),
    "mal_connection": ("Kometa could not connect to MyAnimeList, so features that depend on MAL data cannot complete.", "Correct the MyAnimeList credentials and verify network access to the service."),
    "mass_update": ("A `mass_*_update` operation was requested without configuring the corresponding service, so the operation cannot work.", "Review each referenced line and configure the service required by that mass-update operation."),
    "mdblist_attribute": ("The configured MDBList functionality is not supported for season-level collections.", "Move the builder to a supported collection level or choose a compatible builder."),
    "mdblist_api_key": ("MDBList rejected the configured API key, so all metadata operations depending on MDBList will fail.", "Replace the MDBList API key and verify the MDBList configuration."),
    "mdblist_limit": ("The MDBList daily API limit was reached; dependent metadata updates will fail until the limit resets.", "Wait for the reset and keep Kometa caching enabled so a later run can continue with fewer repeated requests."),
    "metadata_attribute": ("Legacy `metadata_path` or `overlay_path` file layouts can trigger the required metadata-attribute error under the current schema.", "Classify each referenced file under `collection_files`, `metadata_files`, `overlay_files`, or `playlist_files` according to its top-level YAML content."),
    "metadata_load": ("Kometa could not load a metadata file referenced by config.yml, usually because its path is wrong or its YAML is invalid.", "Inspect the referenced log lines, correct the path or YAML, and retry."),
    "overlay_load": ("Kometa could not load an overlay file referenced by config.yml, usually because its path is wrong or its YAML is invalid.", "Inspect the referenced log lines, correct the path or YAML, and retry."),
    "playlist_load": ("Kometa could not load a playlist file referenced by config.yml, usually because its path is wrong or its YAML is invalid.", "Inspect the referenced log lines, correct the path or YAML, and retry."),
    "legacy_missing": ("`missing_path` and `save_missing` are no longer used in current library configuration.", "Remove those settings and use `report_path` instead."),
    "plexapi_update": ("An installed Python module is older than the version required by Kometa.", "Update the installation requirements using the update procedure for your installation method."),
    "kometa_update": ("The log reports that a newer Kometa release was available when this run started.", "Review the release notes and update Kometa using the procedure for your installation method."),
    "plex_no_items": ("A Plex search or filter returned no matching items; searches and filters are case-sensitive.", "Check the requested value and its capitalization, such as `1080p` versus `1080P`, and confirm that an empty result was not expected."),
    "omdb_api_key": ("OMDb rejected the configured API key, so operations depending on OMDb will fail.", "Replace the OMDb API key and verify the OMDb configuration."),
    "omdb_limit": ("The OMDb daily API limit was reached; dependent metadata updates will fail until the limit resets.", "Wait for the reset and keep Kometa caching enabled so later runs avoid unnecessary repeated requests."),
    "overlay_font": ("An overlay references a font file that Kometa cannot find, preventing overlays that require it from being rendered.", "Correct the font path and confirm that the file is accessible inside the Kometa runtime."),
    "overlay_reset": ("`reapply_overlays` or `reset_overlays` is enabled; unnecessary use can create additional Plex posters and artwork bloat.", "Disable these options unless you have a specific rebuild reason; use ImageMaid guidance when cleaning accumulated artwork."),
    "overlay_existing": ("Kometa found artwork already carrying a Kometa overlay EXIF tag; this often happens when inherited or asset-pipeline art is already overlaid.", "Select clean source artwork in Plex or replace the corresponding asset with an image that has no overlay before reapplying."),
    "overlay_image": ("An overlay image file could not be found, so Kometa cannot apply that overlay.", "Correct the image path and filename, including letter case such as `4K.png` versus `4k.png`, and verify container access."),
    "legacy_overlay_level": ("The removed `overlay_level` setting is still present in the configuration.", "Replace `overlay_level` with `builder_level`."),
    "playlist_library": ("A playlist references a Plex library that does not exist; the default playlist expects `Movies` and `TV Shows` unless overridden.", "Correct the library name or use template variables to map the playlist to the actual Plex libraries."),
    "plex_regex": ("A Plex regular-expression search matched no items; this is often expected and can be ignored when an empty result is valid.", "If matches were expected, verify the expression, target field, and capitalization."),
    "plex_library": ("The configured Plex library name does not exist, so Kometa cannot update it.", "Check spelling and case, and enable `show_options: true` to review the library names Plex exposes."),
    "plex_url": ("The configured Plex URL is invalid, causing every feature that depends on that connection to fail.", "Correct the scheme, host, port, and container networking, then verify the Plex token and connection."),
    "rating_rounding": ("The detected Plex release can round values written by `mass_user_rating_update` or `mass_episode_user_ratings_update`.", "Downgrade Plex to 1.40.0.7998 or upgrade to 1.40.3.8555 or later before applying those operations."),
    "yaml": ("Kometa encountered a YAML parser error; YAML is sensitive to indentation, spacing, quoting, and structure.", "Use the referenced `ruamel.yaml` lines to locate the problem and validate the affected YAML in a suitable editor."),
    "run_order": ("The configured run order does not place operations before metadata and overlays, which is the recommended order for almost every workflow.", "Place `- operations` first in the `run_order` section of config.yml unless the workflow intentionally requires another order."),
    "plex_security": ("A Plex Media Server release in a known vulnerable range was detected and remote access may be restricted for protection.", "Upgrade Plex Media Server to a secure release immediately."),
    "traceback": ("The Kometa run contains an unhandled traceback and likely ended early or skipped tasks such as overlay processing.", "Review the traceback and the lines immediately before it, correct the underlying failure, and rerun Kometa."),
    "tautulli_key": ("Tautulli rejected the configured API key, so features depending on Tautulli will fail.", "Replace the Tautulli API key and verify the service configuration."),
    "tautulli_url": ("The configured Tautulli URL is invalid, so Kometa cannot use services that depend on it.", "Correct the Tautulli URL and verify that it is reachable from the Kometa runtime."),
    "tmdb_key": ("TMDb rejected the configured API key, so features depending on TMDb will fail.", "Replace the TMDb API key and verify the TMDb configuration."),
    "timeout": ("A connection to Plex or another service timed out; this is commonly a network or provider response problem rather than something Kometa can repair.", "Verify network access and increase the relevant `timeout` in config.yml when the service legitimately needs longer to respond."),
    "tmdb_connection": ("The host running Kometa could not connect to TMDb, commonly because outbound or container networking blocks the request.", "Verify DNS, firewall, proxy, and container network access to TMDb."),
    "service_config": ("A builder depends on a service that has not been configured, so related functionality cannot run.", "Review each referenced line and add the required service configuration."),
    "trakt_connection": ("Kometa could not connect to Trakt, so features relying on Trakt data cannot complete.", "Correct Trakt authorization and verify network access to the service."),
}


def _with_documentation(spec: dict) -> RecommendationRule:
    values = dict(spec)
    guidance = DISCORD_GUIDANCE.get(values["id"])
    if guidance:
        values["description"], values["solution"] = guidance
    values["solution"] = values["solution"].replace(
        "https://kometa.wiki/", "https://www.kometa.wiki/"
    )
    url = DOCUMENTATION_URLS.get(values["id"])
    if url and url not in values["solution"]:
        values["solution"] = f'{values["solution"]} See {url}'
    return RecommendationRule(**values)


RULES = {spec["title"]: _with_documentation(spec) for spec in RULE_SPECS}

def legacy_title(message: str) -> str:
    first_line = message.splitlines()[0] if message else ""
    first_line = re.sub(r"^[^\w]+", "", first_line)
    first_line = re.sub(r"[*`]+", "", first_line)
    return re.sub(r"\]+$", "", first_line).strip()

def rule_for_legacy_message(message: str) -> RecommendationRule | None:
    return RULES.get(legacy_title(message))
