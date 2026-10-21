"""Supported Kometa People Images styles and shared inventory assessment."""

import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from urllib.parse import quote, unquote, urlsplit


def person_name_key(value: str | None) -> str:
    decomposed = unicodedata.normalize("NFKD", value or "")
    return " ".join("".join(char for char in decomposed if not unicodedata.combining(char)).casefold().split())


@dataclass(frozen=True)
class PeopleImageStyle:
    key: str
    label: str
    repository: str
    branch: str = "master"
    # No supported style currently declares person-specific exclusions.
    excluded_names: frozenset[str] = frozenset()
    extensions: tuple[str, ...] = (".jpg", ".png")
    # Root filenames remain accepted for older Kometa log URLs.
    image_paths: tuple[str, ...] = (r"[^/]+/Images/[^/]+", r"[^/]+")

    @property
    def readme_url(self) -> str:
        branch = f"refs/heads/{self.branch}" if self.key == "primary" else self.branch
        return f"https://raw.githubusercontent.com/Kometa-Team/{self.repository}/{branch}/README.md"

    @property
    def inventory_url(self) -> str:
        return f"https://api.github.com/repos/Kometa-Team/{self.repository}/git/trees/{self.branch}?recursive=1"


PEOPLE_IMAGE_STYLES = (
    PeopleImageStyle("primary", "Kometa Repo Image", "People-Images"),
    PeopleImageStyle("bw", "Black & White", "People-Images-bw"),
    PeopleImageStyle("diiivoy", "DIIIVOY", "People-Images-diiivoy"),
    PeopleImageStyle("diiivoycolor", "DIIIVOY Color", "People-Images-diiivoycolor"),
    PeopleImageStyle("rainier", "Rainier", "People-Images-rainier"),
    PeopleImageStyle("signature", "Signature", "People-Images-signature"),
    PeopleImageStyle("transparent", "Transparent", "People-Images-transparent"),
)


class PeopleImageInventory(dict):
    """Name index with the Git revision and time successfully verified."""

    def __init__(self, images: dict[str, str], revision: str):
        super().__init__(images)
        self.revision = revision
        self.checked_at = datetime.now(UTC).isoformat()


def person_from_image_url(value: str) -> tuple[PeopleImageStyle, str] | None:
    """Accept only known raw GitHub repositories, branches and image paths."""
    try:
        url = urlsplit(value)
        if url.scheme.casefold() != "https" or url.netloc.casefold() != "raw.githubusercontent.com" or url.query or url.fragment:
            return None
        parts = url.path.lstrip("/").split("/")
        if len(parts) < 4 or parts[0].casefold() != "kometa-team":
            return None
        style = next((item for item in PEOPLE_IMAGE_STYLES if item.repository.casefold() == parts[1].casefold()), None)
        if style is None:
            return None
        rest = parts[2:]
        if rest[:2] == ["refs", "heads"]:
            rest = rest[2:]
        if rest[0] != style.branch:
            return None
        path = unquote("/".join(rest[1:]), errors="strict")
        if "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")) or any(ord(char) < 32 for char in path):
            return None
        if not any(re.fullmatch(pattern, path, re.IGNORECASE) for pattern in style.image_paths):
            return None
        filename = PurePosixPath(path)
        if filename.suffix.casefold() not in style.extensions or not filename.stem.strip():
            return None
        return style, filename.stem.strip()
    except (ValueError, UnicodeError, IndexError):
        return None


def parse_people_inventory(style: PeopleImageStyle, tree: dict) -> dict[str, str] | None:
    """Only a complete Git tree can confirm that an image is absent."""
    if not isinstance(tree, dict) or tree.get("truncated") is not False or not tree.get("sha") or not isinstance(tree.get("tree"), list):
        return None
    images = {}
    for entry in tree["tree"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or entry.get("type") not in {"tree", "blob", "commit"}:
            return None
        if entry["type"] != "blob":
            continue
        url = f"https://raw.githubusercontent.com/Kometa-Team/{style.repository}/{style.branch}/{quote(entry['path'], safe='/')}"
        person = person_from_image_url(url)
        if person is not None:
            images[person_name_key(person[1])] = url
    return PeopleImageInventory(images, tree["sha"])


def assess_people_images(candidate: dict, inventories: dict[str, dict[str, str]] | None) -> dict:
    """Attach all style statuses using one cached, normalized inventory snapshot."""
    names = {person_name_key(candidate.get(field)) for field in ("name", "original_name") if candidate.get(field)}
    availability = {}
    for style in PEOPLE_IMAGE_STYLES:
        inventory = (inventories or {}).get(style.label)
        if names & style.excluded_names:
            status = "not_applicable"
        elif inventory is None:
            status = "unknown"
        else:
            status = "present" if any(name in inventory for name in names) else "missing"
        availability[style.key] = {"label": style.label, "repository": style.repository, "status": status}
        if isinstance(inventory, PeopleImageInventory):
            availability[style.key].update(checked_at=inventory.checked_at, revision=inventory.revision)
    states = {item["status"] for item in availability.values()}
    overall = "incomplete" if "missing" in states else "pending_verification" if "unknown" in states else "complete"
    return {**candidate, "style_availability": availability, "people_image_status": overall}


def merge_people_candidate(people: dict[str, dict], candidate: dict) -> None:
    """Deduplicate repeated log events without retaining their original lines."""
    key = person_name_key(candidate["name"])
    existing = people.setdefault(key, {**candidate, "source_styles": [], "detection_reasons": []})
    existing["tmdb_image_found"] |= candidate.get("tmdb_image_found", False)
    for field in ("source_styles", "detection_reasons"):
        existing[field] = sorted(set(existing[field]) | set(candidate.get(field, [])))
