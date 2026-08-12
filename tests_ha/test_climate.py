"""Tests for climate.py entity naming.

LKThermostat is the sole entity on its device, so it follows Home
Assistant's convention for a device's primary entity: has_entity_name=True
with name=None, so the entity's displayed name is just the device name
(issue #49).
"""

from __future__ import annotations

from unittest.mock import patch

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lksystems.const import DOMAIN

from .conftest import THERMOSTAT_MAC


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


def _entity_id(hass, unique_id: str) -> str:
    entity_id = er.async_get(hass).async_get_entity_id("climate", DOMAIN, unique_id)
    assert entity_id is not None, f"no climate entity registered for {unique_id!r}"
    return entity_id


class TestThermostatHasEntityName:
    async def test_has_entity_name_is_true(self, hass, fake_manager):
        await _setup_entry(hass, fake_manager)
        entity_id = _entity_id(hass, f"{DOMAIN}_{THERMOSTAT_MAC}_thermostat")

        entity = er.async_get(hass).async_get(entity_id)

        assert entity.has_entity_name is True

    async def test_entity_name_is_none(self, hass, fake_manager):
        """The thermostat is the only entity on its device, so its own
        name is unset - HA displays just the device name, per convention
        for a device's primary/sole entity."""
        await _setup_entry(hass, fake_manager)
        entity_id = _entity_id(hass, f"{DOMAIN}_{THERMOSTAT_MAC}_thermostat")

        entity = er.async_get(hass).async_get(entity_id)

        assert entity.original_name is None

    async def test_device_name_has_no_redundant_suffix(self, hass, fake_manager):
        await _setup_entry(hass, fake_manager)
        _entity_id(hass, f"{DOMAIN}_{THERMOSTAT_MAC}_thermostat")

        device = dr.async_get(hass).async_get_device(
            identifiers={(DOMAIN, THERMOSTAT_MAC)}
        )

        assert device.name == "LK Living Room"

    async def test_friendly_name_is_just_the_device_name(self, hass, fake_manager):
        await _setup_entry(hass, fake_manager)
        entity_id = _entity_id(hass, f"{DOMAIN}_{THERMOSTAT_MAC}_thermostat")

        state = hass.states.get(entity_id)

        assert state.attributes["friendly_name"] == "LK Living Room"
