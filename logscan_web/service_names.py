"""Shared service names and configuration documentation for findings."""

SERVICE_NAMES = {
    "anidb": "AniDB",
    "apprise": "Apprise",
    "flicklist": "FlickList",
    "floppy": "Floppy",
    "github": "GitHub",
    "gotify": "Gotify",
    "mal": "MyAnimeList",
    "mdblist": "MDBList",
    "notifiarr": "Notifiarr",
    "ntfy": "ntfy",
    "omdb": "OMDb",
    "plex": "Plex",
    "radarr": "Radarr",
    "serializd": "Serializd",
    "sonarr": "Sonarr",
    "tautulli": "Tautulli",
    "tmdb": "TMDb",
    "tracearr": "Tracearr",
    "trakt": "Trakt",
    "wetrakr": "WeTrakr",
    "yamtrack": "YamTrack",
}


def configuration_documentation(section: str) -> str:
    """Use known documentation routes; unknown sections keep the overview."""
    route = section if section in SERVICE_NAMES or section == "settings" else "overview"
    if route == "mal":
        route = "myanimelist"
    return f"https://kometa.wiki/en/latest/config/{route}/"


def service_key(value: str) -> str | None:
    """Accept a service's config key or its logged display name."""
    return next((key for key, name in SERVICE_NAMES.items() if value.casefold() in {key, name.casefold()}), None)
