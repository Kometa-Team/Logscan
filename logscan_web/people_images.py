"""Supported Kometa People Images styles and shared inventory assessment."""

import re
import hashlib
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import HTTPException
from pathlib import PurePosixPath
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import Request


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
    PeopleImageStyle("transparent", "Transparent", "People-Images-transparent", extensions=(".png", ".jpg")),
)


class PeopleImageInventory(dict):
    """Name index with the Git revision and time successfully verified."""

    def __init__(self, images: dict[str, str], revision: str, *, complete: bool = True):
        super().__init__(images)
        self.revision = revision
        self.complete = complete
        self.checked_at = datetime.now(UTC).isoformat()


class PeopleImageInventories(dict):
    """Verified indexes and safe failure explanations for unavailable styles."""

    def __init__(self, images=(), *, errors=None):
        super().__init__(images)
        self.errors = errors or {}


def tmdb_image_path(value: object) -> str | None:
    """Accept only TMDb profile image URLs suitable for the existing image proxy."""
    if not isinstance(value, str):
        return None
    try:
        url = urlsplit(value)
        if url.scheme != "https" or url.netloc != "image.tmdb.org" or url.query or url.fragment:
            return None
        match = re.fullmatch(r"/t/p/(?:original|w\d+)(/[A-Za-z0-9_-]+\.jpe?g)", url.path, re.I)
        return match.group(1) if match else None
    except ValueError:
        return None


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


def parse_people_readme(style: PeopleImageStyle, readme: str) -> dict[str, str] | None:
    """Validate a repository's generated image index for the primary lookup.

    Every declared image must be listed and point into the expected repository.
    Even a valid index can lag behind poster syncs, so it cannot confirm absence.
    """
    header = re.search(r"^# Kometa People Images[^\n]*\(([\d,]+) Images\)\s*$", readme, re.M)
    if not header:
        return None
    try:
        expected_count = int(header.group(1).replace(",", ""))
    except ValueError:
        return None
    links = re.findall(r"^\* \[([^\n]+)\]\((https://[^\n]+)\)\s*$", readme, re.M)
    if len(links) != expected_count:
        return None
    images = {}
    for _name, url in links:
        parsed = person_from_image_url(url)
        if parsed is None or parsed[0] != style:
            return None
        images[person_name_key(parsed[1])] = url
    return PeopleImageInventory(images, "index:" + hashlib.sha256(readme.encode()).hexdigest(), complete=False)


def verify_people_image_urls(candidates: list[dict], inventories: dict, *, open_url, cache: dict, progress=None, max_seconds: float | None = None) -> PeopleImageInventories:
    """Recover present images omitted by unverified listings, without inferring absence.

    Raw image HEAD requests do not consume GitHub's inventory API quota. A 404
    cannot rule out another filename, so unsuccessful checks stay unknown.
    The caller serializes access to the short-lived probe cache.
    """
    now = time.monotonic()
    deadline = now + max_seconds if max_seconds is not None else None
    for url in list(cache):
        if cache[url]["expires_at"] <= now:
            del cache[url]
    tasks = {}
    for candidate in candidates:
        assessment = assess_people_images(candidate, inventories)
        for style in PEOPLE_IMAGE_STYLES:
            if assessment["style_availability"][style.key]["status"] != "unknown":
                continue
            names = tuple(dict.fromkeys(unicodedata.normalize("NFC", candidate.get(field) or "").strip() for field in ("name", "original_name")))
            tasks[(style.key, names)] = (style, names)

    def check_candidate(task):
        style, names = task
        for name in names:
            if not name:
                continue
            for prefix in (f"{name[0].upper()}/Images/", ""):
                for extension in style.extensions:
                    url = f"https://raw.githubusercontent.com/Kometa-Team/{style.repository}/{style.branch}/{quote(prefix + name + extension, safe='/')}"
                    parsed = person_from_image_url(url)
                    if parsed is None:
                        continue
                    result = cache.get(url)
                    if result is None:
                        if deadline is not None and time.monotonic() >= deadline:
                            return None
                        result = {"present": False, "try_next": False, "checked_at": datetime.now(UTC).isoformat()}
                        try:
                            with open_url(Request(url, method="HEAD", headers={"User-Agent": "Kometa-Logscan/1.0", "Accept": "image/*"}), timeout=5) as response:
                                result["present"] = getattr(response, "status", None) == 200 and response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() in {
                                    "image/jpeg",
                                    "image/png",
                                }
                        except HTTPError as exc:
                            result["try_next"] = exc.code == 404
                        except (OSError, ValueError, HTTPException):
                            pass
                        result["expires_at"] = time.monotonic() + (3600 if result["present"] else 300)
                        cache[url] = result
                    if result["present"]:
                        return style, person_name_key(parsed[1]), url, result["checked_at"]
                    if not result["try_next"]:
                        return None
        return None

    images = PeopleImageInventories(inventories, errors=dict(getattr(inventories, "errors", {})))
    copied = set()
    if progress:
        progress("images", "Checking Kometa poster images.", 0, len(tasks))
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="people-image-check") as executor:
        for completed, result in enumerate(executor.map(check_candidate, tasks.values()), start=1):
            if progress:
                progress("images", "Checking Kometa poster images.", completed, len(tasks))
            if result is None:
                continue
            style, name, url, checked_at = result
            if style.label not in copied:
                previous = images.get(style.label)
                inventory = PeopleImageInventory(dict(previous or {}), getattr(previous, "revision", "image-urls"), complete=False)
                inventory.checked_at = getattr(previous, "checked_at", checked_at)
                inventory.verified_images = {}
                images[style.label] = inventory
                copied.add(style.label)
            images[style.label][name] = url
            images[style.label].verified_images[name] = checked_at
    return images


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
            if status == "missing" and isinstance(inventory, PeopleImageInventory) and not inventory.complete:
                status = "unknown"
        availability[style.key] = {"label": style.label, "repository": style.repository, "status": status}
        if status == "present":
            url = next(inventory[name] for name in sorted(names) if name in inventory)
            parsed = person_from_image_url(url)
            if parsed and parsed[0] == style:
                availability[style.key]["image_url"] = url
        if status == "unknown":
            failure = getattr(inventories, "errors", {}).get(style.label, "")
            availability[style.key]["reason"] = (
                (failure + " " if failure else "") + "The repository inventory may be incomplete or outdated; absence has not been verified against the current files."
                if isinstance(inventory, PeopleImageInventory) and not inventory.complete
                else failure or "Repository inventory has not been verified."
            )
        if isinstance(inventory, PeopleImageInventory):
            availability[style.key].update(checked_at=inventory.checked_at, revision=inventory.revision)
            verified_at = next((getattr(inventory, "verified_images", {}).get(name) for name in names if name in getattr(inventory, "verified_images", {})), None)
            if verified_at:
                availability[style.key].update(checked_at=verified_at, verification_source="image_url")
    states = {item["status"] for item in availability.values()}
    overall = "incomplete" if "missing" in states else "pending_verification" if "unknown" in states else "complete"
    return {**candidate, "style_availability": availability, "people_image_status": overall}


def merge_people_candidate(people: dict[str, dict], candidate: dict) -> None:
    """Deduplicate repeated log events without retaining their original lines."""
    key = person_name_key(candidate["name"])
    existing = people.setdefault(key, {**candidate, "source_styles": [], "detection_reasons": [], "evidence_lines": [], "occurrence_count": 0})
    existing["tmdb_image_found"] |= candidate.get("tmdb_image_found", False)
    for field in ("source_styles", "detection_reasons"):
        existing[field] = sorted(set(existing[field]) | set(candidate.get(field, [])))
    existing["occurrence_count"] += candidate.get("occurrence_count", 1)
    for number in candidate.get("evidence_lines", []):
        evidence = existing["evidence_lines"]
        if len(evidence) < 10_000:
            if not evidence or number > evidence[-1]:
                evidence.append(number)
            elif number not in evidence:
                evidence.append(number)
                evidence.sort()
    if candidate.get("log_tmdb_image_path"):
        existing["log_tmdb_image_path"] = candidate["log_tmdb_image_path"]
        existing["log_tmdb_image_line"] = candidate.get("log_tmdb_image_line")
