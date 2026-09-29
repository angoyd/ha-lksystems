"""Guards against translations/en.json drifting from strings.json.

Home Assistant's runtime translation loader only ever reads
translations/<language>.json - strings.json is exclusively a hassfest
build-time source, never read by a running instance. This repo has no
build step that generates translations/en.json from strings.json, so any
entry present in the former is maintained as a manual duplicate of its
strings.json source; this test only catches that duplicate drifting, not
whether every strings.json entry has one (translations/en.json here is
intentionally partial - see its own file for which entries it covers).
"""

from __future__ import annotations

import json
from pathlib import Path

_LKSYSTEMS_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "lksystems"


def test_translations_en_entries_match_their_strings_json_source():
    strings = json.loads((_LKSYSTEMS_DIR / "strings.json").read_text())
    translations_en = json.loads(
        (_LKSYSTEMS_DIR / "translations" / "en.json").read_text()
    )

    for category, keys in translations_en.items():
        for key, translated_entry in keys.items():
            assert translated_entry == strings[category][key], (
                f"translations/en.json's {category}.{key} has drifted from "
                "its strings.json source"
            )
