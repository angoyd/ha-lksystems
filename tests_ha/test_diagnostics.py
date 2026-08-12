"""Tests for diagnostics.py.

Exercises async_get_config_entry_diagnostics() directly against a real
config-entry setup (see test_integration_setup.py's _setup_entry pattern),
so the redaction runs over the same coordinator.data shape HA would.
"""

from __future__ import annotations

from unittest.mock import patch

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lksystems.const import DOMAIN
from custom_components.lksystems.diagnostics import (
    async_get_config_entry_diagnostics,
)

from .conftest import CUBIC_IDENTITY, THERMOSTAT_MAC


async def _setup_entry(hass, manager) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_USERNAME: "user@example.com", CONF_PASSWORD: "hunter2"},
    )
    entry.add_to_hass(hass)
    with patch("custom_components.lksystems.LKSystemsManager", return_value=manager):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    return entry


async def test_diagnostics_redacts_credentials(hass, fake_manager):
    entry = await _setup_entry(hass, fake_manager)

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    assert diagnostics["entry_data"][CONF_USERNAME] == "**REDACTED**"
    assert diagnostics["entry_data"][CONF_PASSWORD] == "**REDACTED**"


async def test_diagnostics_redacts_home_address(hass, fake_manager):
    entry = await _setup_entry(hass, fake_manager)

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    coordinator_data = diagnostics["coordinator_data"]
    assert coordinator_data["address"] == "**REDACTED**"
    assert coordinator_data["city"] == "**REDACTED**"
    assert coordinator_data["zip"] == "**REDACTED**"
    assert coordinator_data["ownerId"] == "**REDACTED**"
    assert coordinator_data["realestateId"] == "**REDACTED**"


async def test_diagnostics_redacts_device_mac_addresses(hass, fake_manager):
    entry = await _setup_entry(hass, fake_manager)

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    devices = diagnostics["coordinator_data"]["devices"]
    thermostat = next(d for d in devices if d.get("mac") == "**REDACTED**")
    assert thermostat is not None


async def test_diagnostics_keeps_device_identities_for_debugging(hass, fake_manager):
    """Device identities aren't redacted: unlike a MAC address they aren't
    a hardware fingerprint, and they're the only way to correlate devices
    across the nested structure when debugging (e.g. issue #29's multiple
    Cubic Secure devices)."""
    entry = await _setup_entry(hass, fake_manager)

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    assert CUBIC_IDENTITY in diagnostics["coordinator_data"]["cubic_devices"]
    assert diagnostics["coordinator_data"]["cubic_devices"][CUBIC_IDENTITY][
        "machine_info"
    ]["identity"] == CUBIC_IDENTITY
