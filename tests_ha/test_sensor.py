"""Tests for sensor.py's entity-registry defaults.

Several sensors are diagnostic/low-value enough that they shouldn't clutter
the main device card by default - drives a real config-entry setup (like
test_integration_setup.py) and inspects the entities the entity registry
actually ended up with, rather than the SensorEntityDescription objects in
const.py directly, so a bug in how sensor.py applies them would still show up.
"""

from __future__ import annotations

from homeassistant.const import EntityCategory
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_registry import RegistryEntryDisabler

from custom_components.lksystems.const import DOMAIN

from .conftest import (
    CUBIC_IDENTITY,
    HUB_IDENTITY,
    SENSOR_MAC,
    entity_id,
    setup_entry,
)


def _registry_entry(hass, platform: str, unique_id: str) -> er.RegistryEntry:
    entry = er.async_get(hass).async_get(entity_id(hass, platform, unique_id))
    assert entry is not None
    return entry


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
