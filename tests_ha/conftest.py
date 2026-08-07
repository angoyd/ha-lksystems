"""Shared fixtures for the Home-Assistant-dependent LK Systems test suite.

Unlike tests/conftest.py (which sidesteps importing `homeassistant`
entirely), these tests run against the real thing via
pytest-homeassistant-custom-component, so they can exercise
custom_components/lksystems/__init__.py, climate.py, sensor.py,
config_flow.py and services.py directly.
"""

from __future__ import annotations

import pytest

pytest_plugins = "pytest_homeassistant_custom_component"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Make custom_components/lksystems loadable as a real integration.

    Without this, Home Assistant's test harness only ever sees its
    built-in integrations - `enable_custom_integrations` (provided by
    pytest-homeassistant-custom-component) tells the loader to also look
    in the repo's custom_components/ directory.
    """
    yield
