"""Tests for climate.py entity naming.

LKThermostat is the sole entity on its device, so it follows Home
Assistant's convention for a device's primary entity: has_entity_name=True
with name=None, so the entity's displayed name is just the device name.
"""

from __future__ import annotations

from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from custom_components.lksystems.const import DOMAIN

from .conftest import THERMOSTAT_MAC, entity_id, setup_entry


class TestThermostatHasEntityName:
    async def test_has_entity_name_is_true(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)
        climate_entity_id = entity_id(
            hass, "climate", f"{DOMAIN}_{THERMOSTAT_MAC}_thermostat"
        )

        entity = er.async_get(hass).async_get(climate_entity_id)

        assert entity.has_entity_name is True

    async def test_entity_name_is_none(self, hass, fake_manager):
        """The thermostat is the only entity on its device, so its own
        name is unset - HA displays just the device name, per convention
        for a device's primary/sole entity."""
        await setup_entry(hass, fake_manager)
        climate_entity_id = entity_id(
            hass, "climate", f"{DOMAIN}_{THERMOSTAT_MAC}_thermostat"
        )

        entity = er.async_get(hass).async_get(climate_entity_id)

        assert entity.original_name is None

    async def test_device_name_has_no_redundant_suffix(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)
        entity_id(hass, "climate", f"{DOMAIN}_{THERMOSTAT_MAC}_thermostat")

        device = dr.async_get(hass).async_get_device(
            identifiers={(DOMAIN, THERMOSTAT_MAC)}
        )

        assert device.name == "LK Living Room"

    async def test_friendly_name_is_just_the_device_name(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)
        climate_entity_id = entity_id(
            hass, "climate", f"{DOMAIN}_{THERMOSTAT_MAC}_thermostat"
        )

        state = hass.states.get(climate_entity_id)

        assert state.attributes["friendly_name"] == "LK Living Room"
