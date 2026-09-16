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
from contextlib import contextmanager
from dataclasses import dataclass
from unittest.mock import patch

import pytest
from homeassistant.helpers import issue_registry as ir
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

        self.user_structure: list[dict] = []
        self.device_measurements: dict = {}
        self.device_configurations: dict = {}
        self.hub_devices: dict = {}
        self.cubic_secure_measurement: dict | None = None
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
        # Per-device override for what get_cubic_secure_configuration returns
        # when *not* force_update - distinct from cubic_configurations_by_device
        # above (used otherwise, and always when force_update=True) - lets
        # tests simulate the real API's own server-side cache (the bypass=0
        # path) serving a stale snapshot independently of the live value.
        self.cubic_configurations_cached_by_device: dict[str, dict] = {}

        # Configurable outcomes for each call, so tests can force failures.
        self.login_result = True
        self.get_user_structure_result = True
        self.get_device_measurement_result = True
        self.get_device_configuration_result = True
        self.get_hub_devices_result = True
        self.get_cubic_secure_measurement_result = True
        self.get_cubic_secure_configuration_result = True
        self.cubic_secure_set_thresholds_result = True
        # Simulates a real fetch taking a while - e.g. pylksystems
        # honoring a long Retry-After from LK's own rate limiter, which
        # can take tens of seconds on a real device (confirmed live).
        self.get_cubic_secure_configuration_delay: float = 0
        self.set_thermostat_temperature_result: dict = {
            "success": True,
            "data": {},
            "error": None,
        }

        # Call log, for tests that want to assert *what* was called.
        self.calls: list[tuple] = []

        # Simulates a real open/close write taking a while - the write
        # goes through the same unbounded Retry-After-honoring network
        # layer as any other request, so it can itself take a long time.
        self.valve_write_delay: float = 0

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
            self.cubic_secure_measurement = self.cubic_measurements_by_device.get(
                device_identity, self.cubic_measurement_data
            )
        return self.get_cubic_secure_measurement_result

    async def get_cubic_secure_configuration(
        self, device_identity, force_update=False
    ):
        if self.get_cubic_secure_configuration_delay:
            await asyncio.sleep(self.get_cubic_secure_configuration_delay)
        self.calls.append(
            ("get_cubic_secure_configuration", device_identity, force_update)
        )
        if self.get_cubic_secure_configuration_result:
            if (
                not force_update
                and device_identity in self.cubic_configurations_cached_by_device
            ):
                self.cubic_secure_configuration = (
                    self.cubic_configurations_cached_by_device[device_identity]
                )
            else:
                self.cubic_secure_configuration = (
                    self.cubic_configurations_by_device.get(
                        device_identity, self.cubic_configuration_data
                    )
                )
        return self.get_cubic_secure_configuration_result

    async def set_thermostat_temperature(self, device_id, temperature):
        self.calls.append(("set_thermostat_temperature", device_id, temperature))
        return self.set_thermostat_temperature_result

    async def cubic_secure_close_valve(self, cubic_identity):
        if self.valve_write_delay:
            await asyncio.sleep(self.valve_write_delay)
        self.calls.append(("cubic_secure_close_valve", cubic_identity))

    async def cubic_secure_open_valve(self, cubic_identity):
        if self.valve_write_delay:
            await asyncio.sleep(self.valve_write_delay)
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
        return self.cubic_secure_set_thresholds_result


# --- Sample device identities used across tests ---------------------------

CUBIC_IDENTITY = "cubic-secure-1"
CUBIC_IDENTITY_2 = "cubic-secure-2"
THERMOSTAT_MAC = "AA:BB:CC:DD:EE:01"
SENSOR_MAC = "AA:BB:CC:DD:EE:02"
HUB_IDENTITY = "arc-hub-1"
HUB_CHILD_MAC = "AA:BB:CC:DD:EE:03"

# A second realestate's devices - distinct identities from the ones above,
# used to model an account whose devices are split across two properties
# rather than doubled up on one (see build_user_structure_with_two_realestates()).
CUBIC_IDENTITY_3 = "cubic-secure-3"
THERMOSTAT_MAC_2 = "AA:BB:CC:DD:EE:11"
SENSOR_MAC_2 = "AA:BB:CC:DD:EE:12"
HUB_IDENTITY_2 = "arc-hub-2"
HUB_CHILD_MAC_2 = "AA:BB:CC:DD:EE:13"


@dataclass(frozen=True)
class _RealestateDevices:
    """One realestate's device identities/zone names - shared by
    build_user_structure() and build_second_realestate_structure() so the
    device mix itself (one cubicsecure, one standalone thermostat, one
    standalone plain sensor, one hub) isn't duplicated between them.
    """

    cubic_identity: str
    cubic_zone: str
    thermostat_mac: str
    thermostat_zone: str
    sensor_mac: str
    sensor_zone: str
    hub_identity: str
    hub_name: str


def _build_realestate_machines(devices: _RealestateDevices) -> list[dict]:
    """The realestateMachines shape exercising every branch of the
    coordinator's device loop: one cubicsecure, one standalone thermostat,
    one standalone plain sensor, and one hub."""
    return [
        {
            "identity": devices.cubic_identity,
            "deviceGroup": "cubic",
            "deviceType": "cubicsecure",
            "deviceRole": "cubicsecure",
            "zone": {
                "zoneId": f"zone-{devices.cubic_identity}",
                "zoneName": devices.cubic_zone,
            },
        },
        {
            "identity": devices.thermostat_mac,
            "mac": devices.thermostat_mac,
            "deviceGroup": "arc",
            "deviceType": "arc-sense",
            "deviceRole": "arc-tune",
            "zone": {
                "zoneId": f"zone-{devices.thermostat_mac}",
                "zoneName": devices.thermostat_zone,
            },
        },
        {
            "identity": devices.sensor_mac,
            "mac": devices.sensor_mac,
            "deviceGroup": "arc",
            "deviceType": "arc-sense",
            "deviceRole": "arc-node",
            "zone": {
                "zoneId": f"zone-{devices.sensor_mac}",
                "zoneName": devices.sensor_zone,
            },
        },
        {
            "identity": devices.hub_identity,
            "mac": devices.hub_identity,
            "deviceGroup": "arc",
            "deviceType": "arc-hub",
            "deviceRole": "arc-hub",
            "name": devices.hub_name,
        },
    ]


def build_user_structure() -> dict:
    """A realistic realestate structure: one cubicsecure, one standalone
    thermostat, one standalone plain sensor, and one hub with a child
    sensor - exercising every branch of the coordinator's device loop.
    """
    return {
        "realestateId": "realestate-1",
        "name": "Test House",
        "city": "Testville",
        "address": "1 Test Street",
        "zip": "12345",
        "country": "SE",
        "ownerId": "owner-1",
        "cacheUpdated": int(time.time()),
        "realestateMachines": _build_realestate_machines(
            _RealestateDevices(
                cubic_identity=CUBIC_IDENTITY,
                cubic_zone="Utility Room",
                thermostat_mac=THERMOSTAT_MAC,
                thermostat_zone="Living Room",
                sensor_mac=SENSOR_MAC,
                sensor_zone="Bedroom",
                hub_identity=HUB_IDENTITY,
                hub_name="Test Hub",
            )
        ),
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


def build_second_realestate_structure() -> dict:
    """A second realestate on the same account, with its own full mix of
    devices (cubic, thermostat, sensor, hub) under distinct identities from
    build_user_structure()'s - see build_user_structure_with_two_realestates().
    """
    return {
        "realestateId": "realestate-2",
        "name": "Second House",
        "city": "Otherville",
        "address": "2 Test Street",
        "zip": "54321",
        "country": "SE",
        "ownerId": "owner-1",
        "cacheUpdated": int(time.time()),
        "realestateMachines": _build_realestate_machines(
            _RealestateDevices(
                cubic_identity=CUBIC_IDENTITY_3,
                cubic_zone="Basement",
                thermostat_mac=THERMOSTAT_MAC_2,
                thermostat_zone="Second Living Room",
                sensor_mac=SENSOR_MAC_2,
                sensor_zone="Second Bedroom",
                hub_identity=HUB_IDENTITY_2,
                hub_name="Second Hub",
            )
        ),
    }


def build_user_structure_with_two_realestates() -> list[dict]:
    """The get_user_structure() response for an account whose devices are
    split across two realestates rather than doubled up on one - each
    realestate carries its own full device mix so merging has more than a
    single device per side to get wrong.
    """
    return [build_user_structure(), build_second_realestate_structure()]


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
        THERMOSTAT_MAC_2: {
            "currentTemperature": 175,  # 17.5°C
            "desiredTemperature": 190,  # 19.0°C
            "currentHumidity": 420,
            "currentBattery": 80,
            "currentRssi": -55,
            "connectionState": "Connected",
        },
        SENSOR_MAC_2: {
            "currentTemperature": 165,  # 16.5°C
            "currentHumidity": 380,
            "currentBattery": 70,
            "currentRssi": -65,
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
        },
        HUB_IDENTITY_2: {
            "devices": [
                {
                    "mac": HUB_CHILD_MAC_2,
                    "deviceTitle": {
                        "identity": HUB_CHILD_MAC_2,
                        "deviceGroup": "arc",
                        "deviceType": "arc-sense",
                        "deviceRole": "arc-node",
                        "parentIdentity": HUB_IDENTITY_2,
                        "zone": {"zoneId": "zone-attic", "zoneName": "Attic"},
                    },
                    "measurement": {
                        "currentTemperature": 230,
                        "currentHumidity": 480,
                        "currentBattery": 55,
                        "currentRssi": -75,
                        "connectionState": "Connected",
                    },
                }
            ]
        },
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


def build_thresholds(
    *,
    pressure_sensitivity: float = 0.3,
    pressure_duration: int = 45,
    pressure_close_delay: int = 255600,
    pressure_notification_delay: int = 169200,
    medium_leak_threshold: float = 10.0,
    medium_leak_close_delay: int = 1800,
    medium_leak_notification_delay: int = 1800,
    large_leak_threshold: float = 1500.0,
    large_leak_close_delay: int = 90,
    large_leak_notification_delay: int = 90,
) -> dict:
    """A realistic thresholds object - values confirmed against a real
    Cubic Secure account's diagnostics. Medium-leak deliberately doesn't
    match set_thresholds' old hardcoded literal defaults (5.0/2700/2700)
    - it's what the account actually had configured, most likely via the
    app, distinct from whatever a never-successfully-called service might
    have written.
    """
    return {
        "pressure": {
            "sensitivity": pressure_sensitivity,
            "duration": pressure_duration,
            "closeDelay": pressure_close_delay,
            "notificationDelay": pressure_notification_delay,
        },
        "leakMedium": {
            "threshold": medium_leak_threshold,
            "closeDelay": medium_leak_close_delay,
            "notificationDelay": medium_leak_notification_delay,
        },
        "leakLarge": {
            "threshold": large_leak_threshold,
            "closeDelay": large_leak_close_delay,
            "notificationDelay": large_leak_notification_delay,
        },
    }


def build_cubic_configuration(
    valve_state: str = "open", mute_leak: int = 0, thresholds: dict | None = None
) -> dict:
    return {
        "cacheUpdated": int(time.time()),
        "valveState": valve_state,
        "firmwareVersion": "1.2.3",
        "hardwareVersion": 4,
        "muteLeak": mute_leak,
        "thresholds": thresholds if thresholds is not None else build_thresholds(),
    }


def build_live_config_without_mute_leak(**kwargs) -> dict:
    """A cubic configuration as the real bypass/"live" endpoint returns it -
    it never carries muteLeak at all, unlike the cached endpoint."""
    config = build_cubic_configuration(**kwargs)
    del config["muteLeak"]
    return config


def configure_fake_manager_with_sample_data(manager: FakeLKSystemsManager) -> None:
    """Populate a FakeLKSystemsManager with the sample fixture data above."""
    manager.user_structure = [build_user_structure()]
    manager.measurements_by_device = build_measurements_by_device()
    manager.hub_devices_by_hub = build_hub_devices_by_hub()
    manager.cubic_measurement_data = build_cubic_measurement()
    manager.cubic_configuration_data = build_cubic_configuration()


def configure_fake_manager_with_two_cubic_devices(manager: FakeLKSystemsManager) -> None:
    """Populate a FakeLKSystemsManager with two Cubic Secure devices, each
    with distinct measurement/configuration data so tests can tell them
    apart (see build_user_structure_with_two_cubic_devices()).
    """
    manager.user_structure = [build_user_structure_with_two_cubic_devices()]
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


def configure_fake_manager_with_two_realestates(manager: FakeLKSystemsManager) -> None:
    """Populate a FakeLKSystemsManager with two realestates on one account,
    each with its own full set of devices (see
    build_user_structure_with_two_realestates()).
    """
    manager.user_structure = build_user_structure_with_two_realestates()
    manager.measurements_by_device = build_measurements_by_device()
    manager.hub_devices_by_hub = build_hub_devices_by_hub()
    manager.cubic_measurements_by_device = {
        CUBIC_IDENTITY: build_cubic_measurement(volume_total=45000),
        CUBIC_IDENTITY_3: build_cubic_measurement(volume_total=77000),
    }
    manager.cubic_configurations_by_device = {
        CUBIC_IDENTITY: build_cubic_configuration(valve_state="open"),
        CUBIC_IDENTITY_3: build_cubic_configuration(valve_state="closed"),
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


def patch_coordinator_manager(manager: FakeLKSystemsManager):
    """Patch the LKSystemsManager the coordinator itself constructs
    (setup, polling refresh)."""
    return patch("custom_components.lksystems.LKSystemsManager", return_value=manager)


def patch_services_manager(manager: FakeLKSystemsManager):
    """Patch the LKSystemsManager used by services.py's own handlers.

    Needed by anything that ends up going through a service call - either
    directly (hass.services.async_call) or indirectly (an entity whose
    action delegates to a service, e.g. button.py's pause-leak-detection
    button) - since each service handler opens its own LKSystemsManager
    rather than reusing the one patched for coordinator setup.
    """
    return patch(
        "custom_components.lksystems.services.LKSystemsManager", return_value=manager
    )


@contextmanager
def patch_all_managers(manager: FakeLKSystemsManager):
    """Patch every place LKSystemsManager gets constructed: the coordinator
    (its polling refresh) and services.py (service handlers).

    patch_services_manager() alone only covers a service call itself;
    needed on top of that by anything that also triggers a coordinator
    refresh in the same action (e.g. button.py's pause-leak-detection
    button, which refreshes the paused-until sensor after pausing),
    since that refresh would otherwise fall through to a real, unpatched
    LKSystemsManager and attempt a genuine network call.
    """
    with patch_coordinator_manager(manager), patch_services_manager(manager):
        yield


def tiny_valve_retry_timings():
    """The valve confirmation's give-up decision compares real
    dt_util.utcnow() reads (a single fetch's own real duration - e.g.
    honoring a long Retry-After - has to count, see
    LKSystemCoordinator._schedule_valve_state_confirmation's own comment
    on why), which HA's simulated-time test helpers
    (async_fire_time_changed) can't drive. Patches the retry timing
    constants down to a few milliseconds so give-up tests can use real
    waiting instead, without actually taking VALVE_ACTION_MAX_RETRY_SECONDS
    to run."""
    return (
        patch("custom_components.lksystems.VALVE_ACTION_MAX_RETRY_SECONDS", 0.05),
        patch("custom_components.lksystems.VALVE_ACTION_RETRY_INTERVAL_SECONDS", 0.01),
    )


@pytest.fixture
def fake_manager_with_two_cubic_devices() -> FakeLKSystemsManager:
    """A FakeLKSystemsManager pre-populated with two Cubic Secure devices
    registered under the same property.
    """
    manager = FakeLKSystemsManager()
    configure_fake_manager_with_two_cubic_devices(manager)
    return manager


@pytest.fixture
def fake_manager_with_two_realestates() -> FakeLKSystemsManager:
    """A FakeLKSystemsManager pre-populated with two realestates on one
    account, each with its own full set of devices.
    """
    manager = FakeLKSystemsManager()
    configure_fake_manager_with_two_realestates(manager)
    return manager



def get_issue(hass, issue_id: str):
    """Look up a repair issue by id via the issue registry."""
    return ir.async_get(hass).async_get_issue(DOMAIN, issue_id)
async def setup_entry(
    hass, manager: FakeLKSystemsManager, options: dict | None = None
) -> MockConfigEntry:
    """Drive a real config-entry setup against a FakeLKSystemsManager.

    Runs the coordinator's first refresh and every platform's
    async_setup_entry() for real (see __init__.py's PLATFORMS), so tests can
    inspect the entities/entity registry they actually produce.
    """
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_USERNAME: "user@example.com", CONF_PASSWORD: "hunter2"},
        options=options or {},
    )
    entry.add_to_hass(hass)
    with patch_coordinator_manager(manager):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    return entry


def pause_leak_detection_duration_unique_id(device_identity: str) -> str:
    """unique_id of a device's "Pause Duration" number entity.

    Shared by test_number.py (which owns the entity) and test_button.py
    (which needs to look it up to drive the paired button's tests).
    """
    return f"LkUid_pause_leak_detection_duration_{device_identity}"


def entity_id(hass, platform: str, unique_id: str) -> str:
    """Look up an entity_id by platform/unique_id via the entity registry.

    Entities are looked up this way, rather than by guessing slugified
    entity_ids, so tests don't depend on HA's naming/slugify rules.
    """
    found = er.async_get(hass).async_get_entity_id(platform, DOMAIN, unique_id)
    assert found is not None, f"no {platform} entity registered for {unique_id!r}"
    return found
