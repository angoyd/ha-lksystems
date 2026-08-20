"""Tests for climate.py entity naming.

LKThermostat is the sole entity on its device, so it follows Home
Assistant's convention for a device's primary entity: has_entity_name=True
with name=None, so the entity's displayed name is just the device name.
"""

from __future__ import annotations

from datetime import timedelta

from homeassistant.components.climate import ATTR_CURRENT_TEMPERATURE
from homeassistant.const import ATTR_TEMPERATURE
from homeassistant.core import State
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import mock_restore_cache

from custom_components.lksystems.climate import LKThermostat
from custom_components.lksystems.const import DOMAIN
from custom_components.lksystems.restore import ATTR_LAST_SUCCESSFUL_CLOUD_FETCH

from .conftest import THERMOSTAT_MAC, setup_entry as _setup_entry


def _seed_restore_cache(
    hass, entity_id: str, current_temperature: float, target_temperature: float, fetched_at
) -> None:
    mock_restore_cache(
        hass,
        [
            State(
                entity_id,
                "heat",
                {
                    ATTR_CURRENT_TEMPERATURE: current_temperature,
                    ATTR_TEMPERATURE: target_temperature,
                    ATTR_LAST_SUCCESSFUL_CLOUD_FETCH: fetched_at.isoformat(),
                },
            )
        ],
    )


def _thermostat_device(coordinator) -> dict:
    return next(
        d for d in coordinator.data["devices"] if d.get("mac") == THERMOSTAT_MAC
    )


def _clear_thermostat_live_measurement(coordinator) -> dict:
    """See test_sensor.py's identically-named helper - native_value/here
    current_temperature checks the devices list and hub_data; clearing the
    devices-list entry's measurement is enough for the thermostat since,
    unlike LKArcSensorEntity, it doesn't also consult device_details."""
    device = _thermostat_device(coordinator)
    device["measurement"] = {}
    return device


class TestThermostatRestore:
    async def test_restores_temperatures_when_live_fetch_failed_and_fresh(
        self, hass, fake_manager
    ):
        entity_id = "climate.test_restore_thermostat"
        _seed_restore_cache(hass, entity_id, 19.5, 21.0, dt_util.utcnow())

        entry = await _setup_entry(hass, fake_manager)
        coordinator = hass.data[DOMAIN][entry.entry_id]

        device = _clear_thermostat_live_measurement(coordinator)
        entity = LKThermostat(coordinator=coordinator, device=device)
        entity.hass = hass
        entity.entity_id = entity_id
        await entity.async_added_to_hass()

        assert entity.current_temperature == 19.5
        assert entity.target_temperature == 21.0

    async def test_ignores_a_stale_restored_value(self, hass, fake_manager):
        entity_id = "climate.test_restore_thermostat"
        stale = dt_util.utcnow() - timedelta(hours=1)
        _seed_restore_cache(hass, entity_id, 19.5, 21.0, stale)

        entry = await _setup_entry(hass, fake_manager)
        coordinator = hass.data[DOMAIN][entry.entry_id]

        device = _clear_thermostat_live_measurement(coordinator)
        entity = LKThermostat(coordinator=coordinator, device=device)
        entity.hass = hass
        entity.entity_id = entity_id
        await entity.async_added_to_hass()

        assert entity.current_temperature is None
        assert entity.target_temperature is None

    async def test_live_value_takes_priority_over_a_restored_one(
        self, hass, fake_manager
    ):
        entity_id = "climate.test_restore_thermostat"
        _seed_restore_cache(hass, entity_id, 1.1, 2.2, dt_util.utcnow())

        entry = await _setup_entry(hass, fake_manager)
        coordinator = hass.data[DOMAIN][entry.entry_id]

        # Live data is present this time - unlike the tests above.
        entity = LKThermostat(coordinator=coordinator, device=_thermostat_device(coordinator))
        entity.hass = hass
        entity.entity_id = entity_id
        await entity.async_added_to_hass()

        assert entity.current_temperature == 20.5  # conftest's live value
        assert entity.target_temperature == 21.5
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
