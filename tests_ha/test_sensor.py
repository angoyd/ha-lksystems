"""Tests for sensor.py: entity naming, entity-registry defaults, and
restoring state across a restart.

Exercises entity names against a real config-entry setup, looking entities
up by their unique_id via the entity registry rather than guessing
slugified entity_ids. Also drives a real config-entry setup (like
test_integration_setup.py) and inspects the entities the entity registry
actually ended up with for disabled-by-default/diagnostic-category
defaults, rather than the SensorEntityDescription objects in const.py
directly, so a bug in how sensor.py applies them would still show up.
"""

from __future__ import annotations

from datetime import timedelta

from homeassistant.const import EntityCategory
from homeassistant.core import State
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_registry import RegistryEntryDisabler
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    mock_restore_cache_with_extra_data,
)

from custom_components.lksystems.const import DOMAIN, LK_CUBICSECURE_CONFIG_SENSORS
from custom_components.lksystems.restore import ATTR_LAST_SUCCESSFUL_CLOUD_FETCH
from custom_components.lksystems.sensor import (
    LKArcHubEntity,
    LKArcSensorEntity,
    LKCubicSensor,
)

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
                    {ATTR_LAST_SUCCESSFUL_CLOUD_FETCH: fetched_at.isoformat()},
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

    coordinator.data["cubic_devices"][CUBIC_IDENTITY]["configuration"] = None
    entity = LKCubicSensor(
        coordinator,
        LK_CUBICSECURE_CONFIG_SENSORS["firmwareVersion"],
        CUBIC_IDENTITY,
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
            CUBIC_IDENTITY,
            data_source="configuration",
        )
        entity.hass = hass
        entity.entity_id = entity_id
        await entity.async_added_to_hass()

        assert entity.native_value == coordinator.data["cubic_devices"][
            CUBIC_IDENTITY
        ]["configuration"]["firmwareVersion"]
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
