"""Tests for sensor.py's restore-last-known-state behavior.

Entities are exercised somewhat directly rather than through a full
config-entry setup + simulated process restart: a real coordinator is set
up once via _setup_entry() (so entity construction has real coordinator
data to work from), then the entity under test is instantiated on its own,
given a pre-seeded restore cache via mock_restore_cache_with_extra_data(),
and added to hass directly - the standard Home Assistant pattern for
testing a RestoreEntity/RestoreSensor mixin without simulating an actual
process restart.
"""

from __future__ import annotations

from datetime import timedelta

from homeassistant.core import State
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    mock_restore_cache_with_extra_data,
)

from custom_components.lksystems.const import (
    DOMAIN,
    LK_CUBICSECURE_CONFIG_SENSORS,
)
from custom_components.lksystems.restore import ATTR_LAST_SUCCESSFUL_FETCH
from custom_components.lksystems.sensor import (
    LKArcHubEntity,
    LKArcSensorEntity,
    LKCubicSensor,
)

from .conftest import HUB_IDENTITY, THERMOSTAT_MAC, setup_entry as _setup_entry


def _seed_restore_cache(hass, entity_id: str, native_value, fetched_at) -> None:
    """Seed a restore cache entry with a properly-typed native_value.

    RestoreSensor stores/restores native_value with its original type
    (float, datetime, ...) via extra_data, separate from the state
    machine's own string state - the State.state string is what an entity
    without RestoreSensor (e.g. climate) would fall back to instead.
    """
    mock_restore_cache_with_extra_data(
        hass,
        [
            (
                State(
                    entity_id,
                    str(native_value),
                    {ATTR_LAST_SUCCESSFUL_FETCH: fetched_at.isoformat()},
                ),
                {"native_value": native_value, "native_unit_of_measurement": None},
            )
        ],
    )


async def _restored_firmware_version_entity(hass, fake_manager, fetched_at):
    """A firmwareVersion sensor added fresh, as if right after an HA
    restart, with a restore cache seeded from before that restart and the
    live cubic_configuration payload missing (a fetch failure on the very
    first poll)."""
    entity_id = "sensor.test_restore_firmware_version"
    # Deliberately distinct from conftest's live firmwareVersion ("1.2.3")
    # so a pass unambiguously means the restored path, not a coincidence.
    # Seeded before setup, per mock_restore_cache_with_extra_data's own
    # convention - it replaces hass's RestoreStateData wholesale, which
    # would otherwise orphan the bookkeeping of any entity already added
    # by an earlier _setup_entry() call.
    _seed_restore_cache(hass, entity_id, "9.9.9-restored", fetched_at)

    entry = await _setup_entry(hass, fake_manager)
    coordinator = hass.data[DOMAIN][entry.entry_id]

    coordinator.data["cubic_configuration"] = None
    entity = LKCubicSensor(
        coordinator,
        LK_CUBICSECURE_CONFIG_SENSORS["firmwareVersion"],
        data_source="configuration",
    )
    entity.hass = hass
    entity.entity_id = entity_id
    await entity.async_added_to_hass()
    return entity


class TestCubicSensorRestore:
    async def test_restores_value_when_live_fetch_failed_and_restore_is_fresh(
        self, hass, fake_manager
    ):
        entity = await _restored_firmware_version_entity(
            hass, fake_manager, fetched_at=dt_util.utcnow()
        )

        assert entity.native_value == "9.9.9-restored"

    async def test_ignores_a_stale_restored_value(self, hass, fake_manager):
        stale = dt_util.utcnow() - timedelta(hours=1)
        entity = await _restored_firmware_version_entity(
            hass, fake_manager, fetched_at=stale
        )

        assert entity.native_value is None

    async def test_live_value_takes_priority_over_a_restored_one(
        self, hass, fake_manager
    ):
        entity_id = "sensor.test_restore_firmware_version"
        _seed_restore_cache(hass, entity_id, "old-version", dt_util.utcnow())

        entry = await _setup_entry(hass, fake_manager)
        coordinator = hass.data[DOMAIN][entry.entry_id]

        # Live data is present this time - unlike _restored_firmware_version_entity().
        entity = LKCubicSensor(
            coordinator,
            LK_CUBICSECURE_CONFIG_SENSORS["firmwareVersion"],
            data_source="configuration",
        )
        entity.hass = hass
        entity.entity_id = entity_id
        await entity.async_added_to_hass()

        assert entity.native_value == coordinator.data["cubic_configuration"][
            "firmwareVersion"
        ]
        assert entity.native_value != "old-version"


def _thermostat_device(coordinator) -> dict:
    return next(
        d for d in coordinator.data["devices"] if d.get("mac") == THERMOSTAT_MAC
    )


def _clear_thermostat_live_measurement(coordinator) -> dict:
    """Simulate a live fetch failure for the thermostat device: native_value
    checks device_details before the devices list (see LKArcSensorEntity's
    docstring-free comment "First check device_details..."), so both need
    clearing to make the live lookup actually return None."""
    device = _thermostat_device(coordinator)
    device["measurement"] = {}
    device_details = coordinator.data.get("device_details", {}).get(THERMOSTAT_MAC)
    if device_details:
        device_details["measurement"] = {}
    return device


class TestArcSensorRestore:
    async def test_restores_value_when_live_fetch_failed_and_restore_is_fresh(
        self, hass, fake_manager
    ):
        entity_id = "sensor.test_restore_temperature"
        _seed_restore_cache(hass, entity_id, 42.0, dt_util.utcnow())

        entry = await _setup_entry(hass, fake_manager)
        coordinator = hass.data[DOMAIN][entry.entry_id]

        device = _clear_thermostat_live_measurement(coordinator)
        entity = LKArcSensorEntity(
            coordinator,
            device,
            "temperature",
            "Temperature",
            "mdi:thermometer",
        )
        entity.hass = hass
        entity.entity_id = entity_id
        await entity.async_added_to_hass()

        assert entity.native_value == 42.0

    async def test_ignores_a_stale_restored_value(self, hass, fake_manager):
        entity_id = "sensor.test_restore_temperature"
        stale = dt_util.utcnow() - timedelta(hours=1)
        _seed_restore_cache(hass, entity_id, 42.0, stale)

        entry = await _setup_entry(hass, fake_manager)
        coordinator = hass.data[DOMAIN][entry.entry_id]

        device = _clear_thermostat_live_measurement(coordinator)
        entity = LKArcSensorEntity(
            coordinator,
            device,
            "temperature",
            "Temperature",
            "mdi:thermometer",
        )
        entity.hass = hass
        entity.entity_id = entity_id
        await entity.async_added_to_hass()

        assert entity.native_value is None


def _hub_device(coordinator) -> dict:
    return next(
        d for d in coordinator.data["devices"] if d.get("mac") == HUB_IDENTITY
    )


class TestArcHubRestore:
    """The hub's own "Status" sensor never actually gets live data - the
    coordinator never stores a measurement/connectionState for the arc-hub
    device itself, only its children - so unlike the other restore tests
    there's no live data to clear first - native_value is already
    unconditionally None going in."""

    async def test_restores_value_when_fresh(self, hass, fake_manager):
        entity_id = "sensor.test_restore_hub_status"
        _seed_restore_cache(hass, entity_id, "Connected", dt_util.utcnow())

        entry = await _setup_entry(hass, fake_manager)
        coordinator = hass.data[DOMAIN][entry.entry_id]

        entity = LKArcHubEntity(
            coordinator,
            _hub_device(coordinator),
            "status",
            "Status",
            "mdi:router-wireless",
        )
        entity.hass = hass
        entity.entity_id = entity_id
        await entity.async_added_to_hass()

        assert entity.native_value == "Connected"

    async def test_ignores_a_stale_restored_value(self, hass, fake_manager):
        entity_id = "sensor.test_restore_hub_status"
        stale = dt_util.utcnow() - timedelta(hours=1)
        _seed_restore_cache(hass, entity_id, "Connected", stale)

        entry = await _setup_entry(hass, fake_manager)
        coordinator = hass.data[DOMAIN][entry.entry_id]

        entity = LKArcHubEntity(
            coordinator,
            _hub_device(coordinator),
            "status",
            "Status",
            "mdi:router-wireless",
        )
        entity.hass = hass
        entity.entity_id = entity_id
        await entity.async_added_to_hass()

        assert entity.native_value is None
