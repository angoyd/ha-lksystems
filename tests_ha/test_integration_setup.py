"""End-to-end config-entry setup tests.

These drive a real (test-mode) hass through hass.config_entries.async_setup,
so the coordinator's first refresh, and both the sensor.py and climate.py
platforms' async_setup_entry() + entity classes, all run for real against
FakeLKSystemsManager's canned data (see conftest.py). Entities are looked
up by their unique_id via the entity registry rather than by guessing
slugified entity_ids, so these don't depend on HA's naming/slugify rules.
"""

from __future__ import annotations

from unittest.mock import patch

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lksystems.const import DOMAIN

from .conftest import (
    CUBIC_IDENTITY,
    HUB_CHILD_MAC,
    HUB_IDENTITY,
    SENSOR_MAC,
    THERMOSTAT_MAC,
)


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


def _entity_id(hass, platform: str, unique_id: str) -> str:
    entity_id = er.async_get(hass).async_get_entity_id(platform, DOMAIN, unique_id)
    assert entity_id is not None, f"no {platform} entity registered for {unique_id!r}"
    return entity_id


async def test_thermostat_entity_reflects_client_data(hass, fake_manager):
    await _setup_entry(hass, fake_manager)

    entity_id = _entity_id(
        hass, "climate", f"{DOMAIN}_{THERMOSTAT_MAC}_thermostat"
    )
    state = hass.states.get(entity_id)

    assert state.attributes["current_temperature"] == 20.5
    assert state.attributes["temperature"] == 21.5


async def test_standalone_sensor_entities_reflect_client_data(hass, fake_manager):
    await _setup_entry(hass, fake_manager)

    temperature_id = _entity_id(
        hass, "sensor", f"{DOMAIN}_{SENSOR_MAC}_temperature"
    )
    humidity_id = _entity_id(hass, "sensor", f"{DOMAIN}_{SENSOR_MAC}_humidity")
    battery_id = _entity_id(hass, "sensor", f"{DOMAIN}_{SENSOR_MAC}_battery")
    rssi_id = _entity_id(hass, "sensor", f"{DOMAIN}_{SENSOR_MAC}_rssi")

    assert hass.states.get(temperature_id).state == "19.0"
    assert hass.states.get(humidity_id).state == "40.0"
    assert hass.states.get(battery_id).state == "75"
    assert hass.states.get(rssi_id).state == "-60"


async def test_hub_and_hub_child_entities_are_created(hass, fake_manager):
    """The hub entity itself is created, but its status is currently
    always unavailable: the coordinator never stores a "measurement" (and
    so no connectionState) for the arc-hub device itself, only for its
    children - LKArcHubEntity.native_value has no data source that ever
    matches. Asserting the entity exists at all, since that's the part
    this suite is meant to cover; the value gap is a separate bug (see
    TODO.local.md).
    """
    await _setup_entry(hass, fake_manager)

    hub_status_id = _entity_id(hass, "sensor", f"{DOMAIN}_{HUB_IDENTITY}_status")
    assert hass.states.get(hub_status_id).state == "unknown"

    child_temperature_id = _entity_id(
        hass, "sensor", f"{DOMAIN}_{HUB_CHILD_MAC}_temperature"
    )
    assert hass.states.get(child_temperature_id).state == "22.0"


async def test_cubic_secure_sensors_reflect_client_data(hass, fake_manager):
    await _setup_entry(hass, fake_manager)

    volume_id = _entity_id(hass, "sensor", f"LkUid_volumeTotal_{CUBIC_IDENTITY}")
    valve_id = _entity_id(hass, "sensor", f"LkUid_valveState_{CUBIC_IDENTITY}")

    assert hass.states.get(volume_id).state == "45000"
    assert hass.states.get(valve_id).state == "open"


async def test_set_temperature_service_calls_coordinator(hass, fake_manager):
    await _setup_entry(hass, fake_manager)
    entity_id = _entity_id(hass, "climate", f"{DOMAIN}_{THERMOSTAT_MAC}_thermostat")

    with patch(
        "custom_components.lksystems.LKSystemsManager", return_value=fake_manager
    ):
        await hass.services.async_call(
            "climate",
            "set_temperature",
            {"entity_id": entity_id, "temperature": 22.5},
            blocking=True,
        )

    assert (
        "set_thermostat_temperature",
        THERMOSTAT_MAC,
        225,
    ) in fake_manager.calls


async def test_refresh_device_service_forces_a_device_update(hass, fake_manager):
    await _setup_entry(hass, fake_manager)

    with patch(
        "custom_components.lksystems.LKSystemsManager", return_value=fake_manager
    ):
        await hass.services.async_call(
            DOMAIN,
            "refresh_device",
            {"device_id": THERMOSTAT_MAC},
            blocking=True,
        )

    assert (
        "get_device_measurement",
        THERMOSTAT_MAC,
        True,
    ) in fake_manager.calls


async def test_unload_entry_removes_coordinator(hass, fake_manager):
    entry = await _setup_entry(hass, fake_manager)

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.entry_id not in hass.data[DOMAIN]
