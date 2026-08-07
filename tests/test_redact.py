"""Unit tests for custom_components.lksystems.redact.

Loaded directly from its file path (like pylksystems in conftest.py) since
custom_components/lksystems/__init__.py pulls in `homeassistant`, which
isn't installed in this lightweight test environment - see conftest.py's
_load_pylksystems() for the same trick.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "lksystems"
    / "redact.py"
)


def _load_redact():
    spec = importlib.util.spec_from_file_location("lksystems_redact", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


redact = _load_redact()


class TestMaskUsername:
    def test_email_keeps_edges_and_dots_and_at_sign(self):
        assert redact.mask_username("john.doe@example.com") == "joh*.***@*******.com"

    def test_plain_username_with_no_dot_or_at(self):
        assert redact.mask_username("adminuser") == "adm***ser"

    def test_short_username_is_fully_within_edge_margins(self):
        # len <= 6: every index is within the first-3/last-3 margin, so
        # nothing gets masked. Documenting this boundary rather than hiding it.
        assert redact.mask_username("abcdef") == "abcdef"

    def test_none_and_empty_pass_through_unchanged(self):
        assert redact.mask_username(None) is None
        assert redact.mask_username("") == ""
