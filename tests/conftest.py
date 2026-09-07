"""Shared fixtures for the LK Systems test suite."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# The pylksystems client is a plain aiohttp-based module with no Home
# Assistant dependency, but it lives inside the `custom_components.lksystems`
# package. Importing that package the normal way (``import
# custom_components.lksystems.pylksystems``) runs the parent package's
# __init__.py first, which imports `homeassistant` — not installed in this
# lightweight test environment. Loading the module directly from its file
# path sidesteps that and keeps these tests fast and dependency-free.
_MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "lksystems"
    / "pylksystems"
    / "__init__.py"
)


def _load_pylksystems():
    spec = importlib.util.spec_from_file_location("pylksystems", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pylksystems = _load_pylksystems()


def _new_manager():
    return pylksystems.LKSystemsManager("user@example.com", "hunter2")


@pytest.fixture
def manager():
    """A fresh, unauthenticated LKSystemsManager instance."""
    return _new_manager()


@pytest.fixture
def other_manager():
    """A second, independent LKSystemsManager instance - for tests that
    exercise state meant to be shared *across* instances."""
    return _new_manager()


@pytest.fixture(autouse=True)
def rate_limit_cooldowns():
    """The shared per-endpoint 429 cooldown store, reset before each test
    so it doesn't leak between them."""
    pylksystems._rate_limited_until.clear()
    yield pylksystems._rate_limited_until
    pylksystems._rate_limited_until.clear()
