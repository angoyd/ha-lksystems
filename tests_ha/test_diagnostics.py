"""Tests for diagnostics.py.

Exercises async_get_config_entry_diagnostics() directly against a real
config-entry setup, so the redaction runs over the same coordinator.data
shape HA would.
"""

from __future__ import annotations

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from custom_components.lksystems.diagnostics import (
    async_get_config_entry_diagnostics,
)

from .conftest import CUBIC_IDENTITY, THERMOSTAT_MAC, setup_entry as _setup_entry


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
    entry = await _setup_entry(hass, fake_manager)

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    cubic_device = diagnostics["coordinator_data"]["cubic_devices"][CUBIC_IDENTITY]
    assert cubic_device["machine_info"]["identity"] == CUBIC_IDENTITY
