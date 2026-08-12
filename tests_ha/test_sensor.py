"""Tests for sensor.py entity naming.

Exercises entity/device names against a real config-entry setup, looking
entities up by their unique_id via the entity registry rather than
guessing slugified entity_ids.
"""

from __future__ import annotations

from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from custom_components.lksystems.const import DOMAIN

from .conftest import HUB_IDENTITY, THERMOSTAT_MAC, entity_id, setup_entry


def _entity_entry(hass, unique_id: str):
    return er.async_get(hass).async_get(entity_id(hass, "sensor", unique_id))


def _device_name(hass, identity: str) -> str:
    device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, identity)})
    assert device is not None, f"no device registered for identity {identity!r}"
    return device.name


class TestArcSensorHasEntityName:
    """Only AbstractLkCubicSensor set has_entity_name - the Arc sensor/hub
    classes baked the device's own name into each entity's full name
    string instead."""

    async def test_temperature_sensor_has_entity_name(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)

        entity = _entity_entry(hass, f"{DOMAIN}_{THERMOSTAT_MAC}_temperature")

        assert entity.has_entity_name is True
        assert entity.original_name == "Temperature"

    async def test_device_name_excludes_the_entity_suffix(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)
        # Force the entity to be created before asserting on its device.
        _entity_entry(hass, f"{DOMAIN}_{THERMOSTAT_MAC}_temperature")

        assert _device_name(hass, THERMOSTAT_MAC) == "LK Living Room"

    async def test_friendly_name_is_unchanged_by_the_split(self, hass, fake_manager):
        """The visible name in the UI (device name + entity name) must stay
        the same as before has_entity_name was set - only the split
        between "device" and "entity" parts changes, not the text."""
        await setup_entry(hass, fake_manager)
        temperature_entity_id = entity_id(
            hass, "sensor", f"{DOMAIN}_{THERMOSTAT_MAC}_temperature"
        )

        state = hass.states.get(temperature_entity_id)

        assert state.attributes["friendly_name"] == "LK Living Room Temperature"


class TestArcHubHasEntityName:
    """The hub's own "Status" sensor has an explicit device_title["name"]
    ("Test Hub" - see conftest) rather than falling back to a zone name,
    exercising the other branch of the friendly_name lookup."""

    async def test_status_sensor_has_entity_name(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)

        entity = _entity_entry(hass, f"{DOMAIN}_{HUB_IDENTITY}_status")

        assert entity.has_entity_name is True
        assert entity.original_name == "Status"

    async def test_device_name_excludes_the_entity_suffix(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)
        _entity_entry(hass, f"{DOMAIN}_{HUB_IDENTITY}_status")

        assert _device_name(hass, HUB_IDENTITY) == "Test Hub"

    async def test_friendly_name_is_unchanged_by_the_split(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)
        status_entity_id = entity_id(hass, "sensor", f"{DOMAIN}_{HUB_IDENTITY}_status")

        state = hass.states.get(status_entity_id)

        assert state.attributes["friendly_name"] == "Test Hub Status"
