"""Tests for sensor.py: entity naming, and entity-registry defaults.

Exercises entity names against a real config-entry setup, looking entities
up by their unique_id via the entity registry rather than guessing
slugified entity_ids. Also drives a real config-entry setup (like
test_integration_setup.py) and inspects the entities the entity registry
actually ended up with for disabled-by-default/diagnostic-category
defaults, rather than the SensorEntityDescription objects in const.py
directly, so a bug in how sensor.py applies them would still show up.
"""

from __future__ import annotations

from homeassistant.const import EntityCategory
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_registry import RegistryEntryDisabler

from custom_components.lksystems.const import DOMAIN

from .conftest import (
    CUBIC_IDENTITY,
    HUB_IDENTITY,
    SENSOR_MAC,
    THERMOSTAT_MAC,
    entity_id,
    setup_entry,
)
from .conftest import CUBIC_IDENTITY, entity_id as _entity_id, setup_entry as _setup_entry


def _entity_entry(hass, unique_id: str):
    return er.async_get(hass).async_get(entity_id(hass, "sensor", unique_id))


def _registry_entry(hass, platform: str, unique_id: str) -> er.RegistryEntry:
    entry = er.async_get(hass).async_get(entity_id(hass, platform, unique_id))
    assert entry is not None
    return entry


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


async def test_last_status_sensor_name_says_what_it_represents(hass, fake_manager):
    """lastStatus is when the device itself last reported to LK's cloud,
    not a generic "status" and not something the integration sends -
    the entity name should say so without implying either of those."""
    await _setup_entry(hass, fake_manager)

    entity_id = _entity_id(hass, "sensor", f"LkUid_lastStatus_{CUBIC_IDENTITY}")
    state = hass.states.get(entity_id)

    assert state.attributes["friendly_name"] == "Cubic Secure Utility Room Last Device Report"


async def test_low_value_sensors_are_disabled_by_default(hass, fake_manager):
    await setup_entry(hass, fake_manager)

    rssi_entry = _registry_entry(hass, "sensor", f"{DOMAIN}_{SENSOR_MAC}_rssi")
    assert rssi_entry.disabled_by == RegistryEntryDisabler.INTEGRATION

    for key in (
        "tempWaterMin",
        "tempWaterMax",
        "cacheUpdated",
        "leak.meanFlow",
        "leak.dateStartedAt",
        "leak.dateUpdatedAt",
        "leak.acknowledged",
    ):
        entry = _registry_entry(hass, "sensor", f"LkUid_{key}_{CUBIC_IDENTITY}")
        assert entry.disabled_by == RegistryEntryDisabler.INTEGRATION, key


async def test_safety_and_primary_sensors_stay_enabled_by_default(
    hass, fake_manager
):
    """lastStatus ("Last Data Sent") is device-freshness information, not
    low-value: it's the only signal that the device itself has gone quiet,
    as distinct from last_successful_cloud_fetch (an attribute on every
    cubic sensor), which only says the integration's own poll of LK's cloud
    API succeeded - LK's cloud can keep serving a stale cached reading
    successfully long after the device itself stopped reporting to it."""
    await setup_entry(hass, fake_manager)

    temperature_entry = _registry_entry(
        hass, "sensor", f"{DOMAIN}_{SENSOR_MAC}_temperature"
    )
    assert temperature_entry.disabled_by is None

    for key in (
        "volumeTotal",
        "tempWaterAverage",
        "waterPressure",
        "leak.leakState",
        "lastStatus",
    ):
        entry = _registry_entry(hass, "sensor", f"LkUid_{key}_{CUBIC_IDENTITY}")
        assert entry.disabled_by is None, key


async def test_diagnostic_sensors_are_categorized_as_diagnostic(hass, fake_manager):
    await setup_entry(hass, fake_manager)

    hub_status_entry = _registry_entry(hass, "sensor", f"{DOMAIN}_{HUB_IDENTITY}_status")
    assert hub_status_entry.entity_category == EntityCategory.DIAGNOSTIC

    for key in ("firmwareVersion", "hardwareVersion"):
        entry = _registry_entry(hass, "sensor", f"LkUid_{key}_{CUBIC_IDENTITY}")
        assert entry.entity_category == EntityCategory.DIAGNOSTIC, key
