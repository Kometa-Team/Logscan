"""Check export labels against the three fonts used by the poster renderer."""

import json
from pathlib import Path
import re
import unicodedata

_GLYPHS = json.loads(Path(__file__).with_name("poster_label_glyphs.json").read_text(encoding="utf-8"))
_FONTS = {name: frozenset(value["characters"]) for name, value in _GLYPHS["fonts"].items()}


def poster_label_supported(name: str) -> bool:
    if not isinstance(name, str) or any(char in name for char in "\r\n|"):
        return False
    # Match the downloader's filename cleanup and renderer.label_name, without
    # changing the exported identity or substituting an unverified name.
    label = re.sub(r'[\\/:*?"<>|]+', "_", name)
    label = re.sub(r"\(\d+\)$", "", label.strip()).strip()
    label = re.sub(r"\d+$", "", label).strip()
    label = unicodedata.normalize("NFC", label)
    if not label:
        return False
    return all(set(label if font == "Fuggles-Regular.ttf" else label.upper()) <= characters for font, characters in _FONTS.items())
