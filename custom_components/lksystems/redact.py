"""Pure helpers for keeping sensitive data out of logs.

No Home Assistant (or any other) imports here on purpose, so this module can
be exercised directly in the lightweight, HA-free test environment the same
way pylksystems is - see tests/conftest.py and tests/test_redact.py.
"""

from __future__ import annotations


def mask_username(username: str | None) -> str | None:
    """Mask a username/email for logging.

    Keeps the first and last 3 characters, plus any literal '.' or '@'
    character (so an email address's shape stays recognizable for
    troubleshooting), and replaces every other character with '*'.
    """
    if not username:
        return username

    length = len(username)
    masked_chars = [
        char if index < 3 or index >= length - 3 or char in ".@" else "*"
        for index, char in enumerate(username)
    ]
    return "".join(masked_chars)
