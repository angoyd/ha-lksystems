"""Shared fixtures for the Home-Assistant-dependent LK Systems test suite.

Unlike tests/conftest.py (which sidesteps importing `homeassistant`
entirely), these tests run against the real thing via
pytest-homeassistant-custom-component, so they can exercise
custom_components/lksystems/__init__.py, climate.py, sensor.py,
config_flow.py and services.py directly.

FakeLKSystemsManager below is a hand-written stand-in for
pylksystems.LKSystemsManager - it lets these tests exercise the HA-layer
logic that calls the API client without touching pylksystems itself
(that's covered separately by tests/test_pylksystems.py, with real HTTP
mocking via aioresponses).
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lksystems.const import DOMAIN

pytest_plugins = "pytest_homeassistant_custom_component"


@pytest.fixture(scope="session", autouse=True)
def _warm_up_aiohttp_shutdown_thread():
    """Work around a false-positive in the HA plugin's thread-leak check.

    aiohttp lazily spawns a one-time, global "_run_safe_shutdown_loop"
    background thread the first time any ClientSession/TCPConnector is
    created in the process. pytest-homeassistant-custom-component's
    autouse verify_cleanup fixture snapshots threads before/after every
    test and fails whichever test happens to trigger that first-ever
    creation, since there's no way to mark it as expected (unlike
    lingering tasks/timers, which do have opt-out fixtures). Triggering
    it once here, at session scope, means it always happens before any
    test's snapshot instead of inside a random one.
    """
    import aiohttp

    async def _touch() -> None:
        async with aiohttp.ClientSession():
            pass

    asyncio.run(_touch())
    yield


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Make custom_components/lksystems loadable as a real integration.

    Without this, Home Assistant's test harness only ever sees its
    built-in integrations - `enable_custom_integrations` (provided by
    pytest-homeassistant-custom-component) tells the loader to also look
    in the repo's custom_components/ directory.
    """
    yield


class FakeLKSystemsManager:
    """Stand-in for pylksystems.LKSystemsManager.

    Mirrors the real client's public surface (the async context manager,
    login(), the get_*() calls and the attributes they populate) with
    in-memory, test-controlled data instead of real HTTP calls.
    """

    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password

        self.jwt_token = None
        self.refresh_token = None
        self.userid = None

        self.user_structure: dict = {}
        self.device_measurements: dict = {}
        self.device_configurations: dict = {}
        self.hub_devices: dict = {}
        self.cubic_secure_messurement: dict | None = None
        self.cubic_secure_configuration: dict | None = None

        # Per-call canned data, keyed by device/hub identity. Tests set
        # these before triggering a coordinator update.
        self.measurements_by_device: dict[str, dict] = {}
        self.configurations_by_device: dict[str, dict] = {}
        self.hub_devices_by_hub: dict[str, dict] = {}
        self.cubic_measurement_data: dict | None = None
        self.cubic_configuration_data: dict | None = None
        # Per-cubic-device overrides, keyed by device identity - takes
        # precedence over the single cubic_measurement_data/
        # cubic_configuration_data above when set for that identity, so
        # single-device tests can keep using the simpler singular fields.
        self.cubic_measurements_by_device: dict[str, dict] = {}
        self.cubic_configurations_by_device: dict[str, dict] = {}

        # Configurable outcomes for each call, so tests can force failures.
        self.login_result = True
        self.get_user_structure_result = True
        self.get_device_measurement_result = True
        self.get_device_configuration_result = True
        self.get_hub_devices_result = True
        self.get_cubic_secure_measurement_result = True
        self.get_cubic_secure_configuration_result = True
        self.set_thermostat_temperature_result: dict = {
            "success": True,
            "data": {},
            "error": None,
        }

        # Call log, for tests that want to assert *what* was called.
        self.calls: list[tuple] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def login(self):
        self.calls.append(("login",))
        if self.login_result:
            self.jwt_token = "fake-jwt-token"
            self.refresh_token = "fake-refresh-token"
            self.userid = "fake-user-id"
        return self.login_result

    async def get_user_structure(self):
        self.calls.append(("get_user_structure",))
        return self.get_user_structure_result

    async def get_device_measurement(self, device_identity, force_update=False):
        self.calls.append(("get_device_measurement", device_identity, force_update))
        if self.get_device_measurement_result:
            self.device_measurements[device_identity] = self.measurements_by_device.get(
                device_identity, {}
            )
        return self.get_device_measurement_result

    async def get_device_configuration(self, device_identity, force_update=False):
        self.calls.append(
            ("get_device_configuration", device_identity, force_update)
        )
        if self.get_device_configuration_result:
            self.device_configurations[device_identity] = (
                self.configurations_by_device.get(device_identity, {})
            )
        return self.get_device_configuration_result

    async def get_hub_devices(self, hub_id):
        self.calls.append(("get_hub_devices", hub_id))
        if self.get_hub_devices_result:
            self.hub_devices = self.hub_devices_by_hub.get(hub_id, {"devices": []})
        return self.get_hub_devices_result

    async def get_cubic_secure_measurement(self, device_identity, force_update=False):
        self.calls.append(
            ("get_cubic_secure_measurement", device_identity, force_update)
        )
        if self.get_cubic_secure_measurement_result:
            self.cubic_secure_messurement = self.cubic_measurements_by_device.get(
                device_identity, self.cubic_measurement_data
            )
        return self.get_cubic_secure_measurement_result

    async def get_cubic_secure_configuration(
        self, device_identity, force_update=False
    ):
        self.calls.append(
            ("get_cubic_secure_configuration", device_identity, force_update)
        )
        if self.get_cubic_secure_configuration_result:
            self.cubic_secure_configuration = self.cubic_configurations_by_device.get(
                device_identity, self.cubic_configuration_data
            )
        return self.get_cubic_secure_configuration_result

    async def set_thermostat_temperature(self, device_id, temperature):
        self.calls.append(("set_thermostat_temperature", device_id, temperature))
        return self.set_thermostat_temperature_result

    async def cubic_secure_close_valve(self, cubic_identity):
        self.calls.append(("cubic_secure_close_valve", cubic_identity))

    async def cubic_secure_open_valve(self, cubic_identity):
        self.calls.append(("cubic_secure_open_valve", cubic_identity))

    async def cubic_secure_pause_leak_detection(self, cubic_identity, seconds):
        self.calls.append(
            ("cubic_secure_pause_leak_detection", cubic_identity, seconds)
        )

    async def cubic_secure_set_pressure_test_schedule(
        self, cubic_identity, hour, minute
    ):
        self.calls.append(
            ("cubic_secure_set_pressure_test_schedule", cubic_identity, hour, minute)
        )

    async def cubic_secure_set_thresholds(self, cubic_identity, thresholds):
        self.calls.append(("cubic_secure_set_thresholds", cubic_identity, thresholds))


# --- Sample device identities used across tests ---------------------------

CUBIC_IDENTITY = "cubic-secure-1"
CUBIC_IDENTITY_2 = "cubic-secure-2"
THERMOSTAT_MAC = "AA:BB:CC:DD:EE:01"
SENSOR_MAC = "AA:BB:CC:DD:EE:02"
HUB_IDENTITY = "arc-hub-1"
HUB_CHILD_MAC = "AA:BB:CC:DD:EE:03"


def build_user_structure() -> dict:
    """A realistic realestate structure: one cubicsecure, one standalone
    thermostat, one standalone plain sensor, and one hub with a child
    sensor - exercising every branch of the coordinator's device loop.
    """
    now = int(time.time())
    return {
        "realestateId": "realestate-1",
        "name": "Test House",
        "city": "Testville",
        "address": "1 Test Street",
        "zip": "12345",
        "country": "SE",
        "ownerId": "owner-1",
        "cacheUpdated": now,
        "realestateMachines": [
            {
                "identity": CUBIC_IDENTITY,
                "deviceGroup": "cubic",
                "deviceType": "cubicsecure",
                "deviceRole": "cubicsecure",
                "zone": {"zoneId": "zone-cubic", "zoneName": "Utility Room"},
            },
            {
                "identity": THERMOSTAT_MAC,
                "mac": THERMOSTAT_MAC,
                "deviceGroup": "arc",
                "deviceType": "arc-sense",
                "deviceRole": "arc-tune",
                "zone": {"zoneId": "zone-living", "zoneName": "Living Room"},
            },
            {
                "identity": SENSOR_MAC,
                "mac": SENSOR_MAC,
                "deviceGroup": "arc",
                "deviceType": "arc-sense",
                "deviceRole": "arc-node",
                "zone": {"zoneId": "zone-bed", "zoneName": "Bedroom"},
            },
            {
                "identity": HUB_IDENTITY,
                "mac": HUB_IDENTITY,
                "deviceGroup": "arc",
                "deviceType": "arc-hub",
                "deviceRole": "arc-hub",
                "name": "Test Hub",
            },
        ],
    }


def build_user_structure_with_two_cubic_devices() -> dict:
    """Same as build_user_structure(), but with a second Cubic Secure
    machine registered under the same property - two Cubic Secure devices
    (e.g. "Kitchen" and "Garage") registered under one realestate.
    """
    structure = build_user_structure()
    structure["realestateMachines"].append(
        {
            "identity": CUBIC_IDENTITY_2,
            "deviceGroup": "cubic",
            "deviceType": "cubicsecure",
            "deviceRole": "cubicsecure",
            "zone": {"zoneId": "zone-cubic-2", "zoneName": "Garage"},
        }
    )
    return structure


def build_measurements_by_device() -> dict:
    return {
        THERMOSTAT_MAC: {
            "currentTemperature": 205,  # 20.5°C
            "desiredTemperature": 215,  # 21.5°C
            "currentHumidity": 450,
            "currentBattery": 90,
            "currentRssi": -50,
            "connectionState": "Connected",
        },
        SENSOR_MAC: {
            "currentTemperature": 190,  # 19.0°C
            "currentHumidity": 400,
            "currentBattery": 75,
            "currentRssi": -60,
            "connectionState": "Connected",
        },
    }


def build_hub_devices_by_hub() -> dict:
    return {
        HUB_IDENTITY: {
            "devices": [
                {
                    "mac": HUB_CHILD_MAC,
                    "deviceTitle": {
                        "identity": HUB_CHILD_MAC,
                        "deviceGroup": "arc",
                        "deviceType": "arc-sense",
                        "deviceRole": "arc-node",
                        "parentIdentity": HUB_IDENTITY,
                        "zone": {"zoneId": "zone-kitchen", "zoneName": "Kitchen"},
                    },
                    "measurement": {
                        "currentTemperature": 220,
                        "currentHumidity": 500,
                        "currentBattery": 60,
                        "currentRssi": -70,
                        "connectionState": "Connected",
                    },
                }
            ]
        }
    }


def build_cubic_measurement(volume_total: int = 45000) -> dict:
    return {
        "cacheUpdated": int(time.time()),
        "volumeTotalDay": 120,
        "volumeTotal": volume_total,
        "tempWaterAverage": 185,
        "tempWaterMin": 170,
        "tempWaterMax": 210,
        "waterPressure": 3200,
        "tempAmbient": 210,
        "lastStatus": int(time.time()),
        "leak": {
            "leakState": "NoLeak",
            "meanFlow": 0.0,
            "dateStartedAt": int(time.time()),
            "dateUpdatedAt": int(time.time()),
            "acknowledged": False,
        },
    }


def build_cubic_configuration(valve_state: str = "open") -> dict:
    return {
        "cacheUpdated": int(time.time()),
        "valveState": valve_state,
        "firmwareVersion": "1.2.3",
        "hardwareVersion": 4,
    }


def configure_fake_manager_with_sample_data(manager: FakeLKSystemsManager) -> None:
    """Populate a FakeLKSystemsManager with the sample fixture data above."""
    manager.user_structure = build_user_structure()
    manager.measurements_by_device = build_measurements_by_device()
    manager.hub_devices_by_hub = build_hub_devices_by_hub()
    manager.cubic_measurement_data = build_cubic_measurement()
    manager.cubic_configuration_data = build_cubic_configuration()


def configure_fake_manager_with_two_cubic_devices(manager: FakeLKSystemsManager) -> None:
    """Populate a FakeLKSystemsManager with two Cubic Secure devices, each
    with distinct measurement/configuration data so tests can tell them
    apart (see build_user_structure_with_two_cubic_devices()).
    """
    manager.user_structure = build_user_structure_with_two_cubic_devices()
    manager.measurements_by_device = build_measurements_by_device()
    manager.hub_devices_by_hub = build_hub_devices_by_hub()
    manager.cubic_measurements_by_device = {
        CUBIC_IDENTITY: build_cubic_measurement(volume_total=45000),
        CUBIC_IDENTITY_2: build_cubic_measurement(volume_total=99000),
    }
    manager.cubic_configurations_by_device = {
        CUBIC_IDENTITY: build_cubic_configuration(valve_state="open"),
        CUBIC_IDENTITY_2: build_cubic_configuration(valve_state="closed"),
    }


@pytest.fixture
def fake_manager() -> FakeLKSystemsManager:
    """A FakeLKSystemsManager pre-populated with a realistic structure."""
    manager = FakeLKSystemsManager()
    configure_fake_manager_with_sample_data(manager)
    return manager


async def setup_entry(hass, manager: FakeLKSystemsManager) -> MockConfigEntry:
    """Drive a real config-entry setup against a FakeLKSystemsManager.

    Runs the coordinator's first refresh and both the sensor.py and
    climate.py platforms' async_setup_entry() for real, so tests can inspect
    the entities/entity registry they actually produce.
    """
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_USERNAME: "user@example.com", CONF_PASSWORD: "hunter2"},
    )
    entry.add_to_hass(hass)
    with patch("custom_components.lksystems.LKSystemsManager", return_value=manager):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    return entry


def entity_id(hass, platform: str, unique_id: str) -> str:
    """Look up an entity_id by platform/unique_id via the entity registry.

    Entities are looked up this way, rather than by guessing slugified
    entity_ids, so tests don't depend on HA's naming/slugify rules.
    """
    found = er.async_get(hass).async_get_entity_id(platform, DOMAIN, unique_id)
    assert found is not None, f"no {platform} entity registered for {unique_id!r}"
    return found
@pytest.fixture
def fake_manager_with_two_cubic_devices() -> FakeLKSystemsManager:
    """A FakeLKSystemsManager pre-populated with two Cubic Secure devices
    registered under the same property.
    """
    manager = FakeLKSystemsManager()
    configure_fake_manager_with_two_cubic_devices(manager)
    return manager
