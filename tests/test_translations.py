"""Guards against translations/en.json drifting from strings.json.

Home Assistant's runtime translation loader only ever reads
translations/<language>.json - strings.json is exclusively a hassfest
build-time source, never read by a running instance. This repo has no
build step that generates translations/en.json from strings.json, so it's
maintained as a manual duplicate - except where strings.json uses a
`[%key:...%]` cross-reference (a build-time-only feature custom
integrations can't use at all, per Home Assistant's own developer docs),
where translations/en.json instead carries the fully expanded literal
text that reference resolves to for core integrations.
"""

from __future__ import annotations

import json
from pathlib import Path

_LKSYSTEMS_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "lksystems"


def _flatten(tree: dict, prefix: str = "") -> dict[str, str]:
    """Flatten a nested strings.json-shaped dict to {"a.b.c": value}."""
    flattened = {}
    for key, value in tree.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flattened.update(_flatten(value, path))
        else:
            flattened[path] = value
    return flattened


def test_translations_en_has_no_leftover_key_placeholders():
    translations_en = json.loads(
        (_LKSYSTEMS_DIR / "translations" / "en.json").read_text()
    )

    for path, value in _flatten(translations_en).items():
        assert "[%key:" not in value, (
            f"translations/en.json's {path} still has an unresolved "
            "[%key:...%] reference - that syntax is build-time-only and "
            "never resolves for a custom integration"
        )


def test_translations_en_entries_match_their_strings_json_source():
    """Every translations/en.json entry must match strings.json, except
    where strings.json uses a %key reference - there, translations/en.json
    intentionally diverges by carrying the expanded literal text instead."""
    strings = _flatten(json.loads((_LKSYSTEMS_DIR / "strings.json").read_text()))
    translations_en = _flatten(
        json.loads((_LKSYSTEMS_DIR / "translations" / "en.json").read_text())
    )

    for path, translated_value in translations_en.items():
        strings_value = strings.get(path)
        if strings_value is not None and not strings_value.startswith("[%key:"):
            assert translated_value == strings_value, (
                f"translations/en.json's {path} has drifted from its "
                "strings.json source"
            )
