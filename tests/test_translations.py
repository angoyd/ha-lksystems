"""Guards against translations/en.json drifting from strings.json.

Home Assistant's runtime translation loader only ever reads
translations/<language>.json - strings.json is exclusively a hassfest
build-time source, never read by a running instance. Since this repo has
no build step that generates translations/en.json from strings.json, the
two are maintained as a manual duplicate; this test only catches the two
files going out of sync, not the broader question of whether that manual
duplication is worth automating away.
"""

from __future__ import annotations

import json
from pathlib import Path

_LKSYSTEMS_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "lksystems"


def test_translations_en_matches_strings_json():
    strings = json.loads((_LKSYSTEMS_DIR / "strings.json").read_text())
    translations_en = json.loads(
        (_LKSYSTEMS_DIR / "translations" / "en.json").read_text()
    )

    assert translations_en == strings
