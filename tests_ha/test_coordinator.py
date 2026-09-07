"""Tests for is_token_valid() and LKSystemCoordinator in __init__.py.

The LK Systems API client itself (pylksystems) is mocked out via
FakeLKSystemsManager (see conftest.py) - these tests are only concerned
with the coordinator's own logic: building the response structure from
whatever the client returns, token caching, and error handling.
"""

from __future__ import annotations

import base64
import json
import logging
import time
import typing
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import UpdateFailed
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)

from custom_components.lksystems import (
    TOKEN_STORAGE,
    LkCubicDeviceData,
    LKSystemCoordinator,
    LkStructureMachine,
    is_token_valid,
)
from custom_components.lksystems.const import (
    CONF_UPDATE_INTERVAL,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    LEAK_DETECTION_EXPIRY_MAX_RETRY_SECONDS,
    LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS,
    LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS,
    PAUSE_LEAK_DETECTION_MIN_SECONDS,
)
from custom_components.lksystems.repairs import _issue_id

from .conftest import (
    CUBIC_IDENTITY,
    CUBIC_IDENTITY_2,
    HUB_CHILD_MAC,
    HUB_IDENTITY,
    SENSOR_MAC,
    THERMOSTAT_MAC,
    build_cubic_configuration,
    build_live_config_without_mute_leak,
    get_issue,
)


def _make_token(expires_in_seconds: float) -> str:
    """Build a JWT-shaped (but unsigned) token with a controllable exp claim.

    is_token_valid() never checks the signature, only the middle segment.
    """
    exp = dt_util.utcnow().timestamp() + expires_in_seconds
    payload = base64.b64encode(json.dumps({"exp": exp}).encode()).rstrip(b"=").decode()
    return f"header.{payload}.signature"


def _patch_manager(manager):
    return patch("custom_components.lksystems.LKSystemsManager", return_value=manager)


@pytest.fixture(autouse=True)
def _clear_token_storage():
    """TOKEN_STORAGE is a module-level global - keep tests isolated."""
    TOKEN_STORAGE.clear()
    yield
    TOKEN_STORAGE.clear()


class TestLkCubicDeviceDataTyping:
    def test_machine_info_field_uses_correctly_spelled_machine_type(self):
        assert (
            typing.get_type_hints(LkCubicDeviceData)["machine_info"]
            is LkStructureMachine
        )


class TestIsTokenValid:
    def test_none_and_empty_are_invalid(self):
        assert is_token_valid(None) is False
        assert is_token_valid("") is False

    def test_malformed_token_is_invalid(self):
        assert is_token_valid("not-a-jwt") is False

    def test_unparsable_payload_is_invalid(self):
        assert is_token_valid("a.b.c") is False

    def test_future_expiry_is_valid(self):
        assert is_token_valid(_make_token(3600)) is True

    def test_past_expiry_is_invalid(self):
        assert is_token_valid(_make_token(-3600)) is False

    def test_expiry_within_five_minute_margin_is_invalid(self):
        # is_token_valid requires more than 5 minutes of remaining validity.
        assert is_token_valid(_make_token(60)) is False


def _make_entry(hass, update_interval=None):
    data = {CONF_USERNAME: "user@example.com", CONF_PASSWORD: "hunter2"}
    if update_interval is not None:
        data[CONF_UPDATE_INTERVAL] = update_interval
    entry = MockConfigEntry(domain=DOMAIN, data=data)
    entry.add_to_hass(hass)
    return entry


class TestCoordinatorConstruction:
    async def test_uses_configured_update_interval(self, hass):
        entry = _make_entry(hass, update_interval=15)
        coordinator = LKSystemCoordinator(hass, entry)
        assert coordinator.update_interval == timedelta(minutes=15)

    async def test_defaults_to_default_update_interval(self, hass):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        assert coordinator.update_interval == timedelta(
            minutes=DEFAULT_UPDATE_INTERVAL
        )

    async def test_construction_does_not_log_above_debug(self, hass, caplog):
        # Setting up the coordinator's update interval is routine, expected
        # behaviour on every startup/reload - it shouldn't show up in a
        # user's log unless they've turned on debug logging.
        entry = _make_entry(hass)

        with caplog.at_level(
            logging.WARNING, logger="custom_components.lksystems"
        ):
            LKSystemCoordinator(hass, entry)

        assert caplog.records == []

    async def test_last_successful_cloud_fetch_starts_none(self, hass):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        assert coordinator.last_successful_cloud_fetch is None


class TestLastSuccessfulCloudFetch:
    """Restoring entity state across a restart needs a per-update
    timestamp to judge whether a restored value is still fresh enough to
    show."""

    async def test_successful_update_sets_the_timestamp(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        before = dt_util.utcnow()
        with _patch_manager(fake_manager):
            await coordinator._async_update_data()
        after = dt_util.utcnow()

        assert coordinator.last_successful_cloud_fetch is not None
        assert before <= coordinator.last_successful_cloud_fetch <= after

    async def test_failed_update_does_not_clear_a_prior_timestamp(
        self, hass, fake_manager
    ):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        with _patch_manager(fake_manager):
            await coordinator._async_update_data()
        first_fetch_time = coordinator.last_successful_cloud_fetch

        fake_manager.get_user_structure_result = False
        with _patch_manager(fake_manager):
            with pytest.raises(UpdateFailed):
                await coordinator._async_update_data()

        assert coordinator.last_successful_cloud_fetch == first_fetch_time


class TestAsyncUpdateData:
    async def test_missing_credentials_raises_auth_failed(self, hass):
        entry = MockConfigEntry(domain=DOMAIN, data={})
        entry.add_to_hass(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with pytest.raises(ConfigEntryAuthFailed):
            await coordinator._async_update_data()

    async def test_login_failure_raises_auth_failed(self, hass, fake_manager):
        fake_manager.login_result = False
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            with pytest.raises(ConfigEntryAuthFailed):
                await coordinator._async_update_data()

    async def test_get_user_structure_failure_raises_update_failed(
        self, hass, fake_manager
    ):
        fake_manager.get_user_structure_result = False
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            with pytest.raises(UpdateFailed):
                await coordinator._async_update_data()

    async def test_builds_full_structure_from_client_data(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            data = await coordinator._async_update_data()

        assert data["realestateId"] == "realestate-1"

        # Cubic Secure device
        cubic_device = data["cubic_devices"][CUBIC_IDENTITY]
        assert cubic_device["machine_info"]["identity"] == CUBIC_IDENTITY
        assert cubic_device["last_measurement"]["volumeTotal"] == 45000
        assert cubic_device["configuration"]["valveState"] == "open"

        # Standalone Arc devices (thermostat + plain sensor)
        macs = {d.get("mac") for d in data["devices"]}
        assert THERMOSTAT_MAC in macs
        assert SENSOR_MAC in macs
        thermostat_device = next(
            d for d in data["devices"] if d.get("mac") == THERMOSTAT_MAC
        )
        assert thermostat_device["measurement"]["desiredTemperature"] == 215

        # Hub + its child device
        assert HUB_IDENTITY in data["hub_data"]
        hub_macs = {
            d.get("mac") for d in data["hub_data"][HUB_IDENTITY]["devices"]
        }
        assert HUB_CHILD_MAC in hub_macs

    async def test_valid_stored_token_skips_login(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        TOKEN_STORAGE[entry.entry_id] = {
            "jwt": _make_token(3600),
            "refresh": "stored-refresh",
            "userid": "stored-user",
        }

        with _patch_manager(fake_manager):
            await coordinator._async_update_data()

        assert ("login",) not in fake_manager.calls

    async def test_expired_stored_token_triggers_login(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        TOKEN_STORAGE[entry.entry_id] = {
            "jwt": _make_token(-3600),
            "refresh": "stored-refresh",
            "userid": "stored-user",
        }

        with _patch_manager(fake_manager):
            await coordinator._async_update_data()

        assert ("login",) in fake_manager.calls
        assert TOKEN_STORAGE[entry.entry_id]["jwt"] == "fake-jwt-token"


class TestRepairIssues:
    """A failed update should surface as a repair issue instead of only a
    log line - auth failures immediately (HA's own reauth flow already
    treats them as non-transient), fetch failures only after
    CONSECUTIVE_FAILURE_THRESHOLD in a row (a single failure is routine and
    resolves on its own via the next scheduled poll)."""

    async def test_auth_failure_raises_a_repair_issue(self, hass):
        entry = MockConfigEntry(domain=DOMAIN, data={})
        entry.add_to_hass(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with pytest.raises(ConfigEntryAuthFailed):
            await coordinator._async_update_data()

        assert get_issue(hass, _issue_id("auth_failed", entry.entry_id)) is not None

    async def test_successful_update_clears_the_auth_failed_issue(
        self, hass, fake_manager
    ):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        ir.async_create_issue(
            hass,
            DOMAIN,
            _issue_id("auth_failed", entry.entry_id),
            is_fixable=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key="auth_failed",
        )

        with _patch_manager(fake_manager):
            await coordinator._async_update_data()

        assert get_issue(hass, _issue_id("auth_failed", entry.entry_id)) is None

    async def test_single_fetch_failure_does_not_raise_a_persistent_issue(
        self, hass, fake_manager
    ):
        fake_manager.get_user_structure_result = False
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            with pytest.raises(UpdateFailed):
                await coordinator._async_update_data()

        assert (
            get_issue(hass, _issue_id("persistent_update_failure", entry.entry_id))
            is None
        )

    async def test_consecutive_fetch_failures_raise_a_persistent_issue(
        self, hass, fake_manager
    ):
        fake_manager.get_user_structure_result = False
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            for _ in range(3):
                with pytest.raises(UpdateFailed):
                    await coordinator._async_update_data()

        assert (
            get_issue(hass, _issue_id("persistent_update_failure", entry.entry_id))
            is not None
        )

    async def test_successful_update_after_failures_clears_the_persistent_issue(
        self, hass, fake_manager
    ):
        fake_manager.get_user_structure_result = False
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            for _ in range(3):
                with pytest.raises(UpdateFailed):
                    await coordinator._async_update_data()

        fake_manager.get_user_structure_result = True
        with _patch_manager(fake_manager):
            await coordinator._async_update_data()

        assert (
            get_issue(hass, _issue_id("persistent_update_failure", entry.entry_id))
            is None
        )


class TestCubicFetchFailureFallback:
    """A failure partway through fetching the cubic measurement/configuration
    used to leave "cubic_last_measurement"/"cubic_configuration" out of the
    returned data entirely, since the keys are only assigned after the calls
    that can raise. sensor.py indexes both keys directly, so every cubic
    sensor crashed with a KeyError while Home Assistant was adding it.
    """

    async def test_configuration_fetch_failure_still_yields_both_keys(
        self, hass, fake_manager
    ):
        fake_manager.get_cubic_secure_configuration = AsyncMock(
            side_effect=RuntimeError("boom")
        )
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            data = await coordinator._async_update_data()

        cubic_device = data["cubic_devices"][CUBIC_IDENTITY]
        assert "last_measurement" in cubic_device
        assert "configuration" in cubic_device
        assert cubic_device["configuration"] is None

    async def test_configuration_fetch_failure_falls_back_to_previous_data(
        self, hass, fake_manager
    ):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            good_data = await coordinator._async_update_data()
        coordinator.async_set_updated_data(good_data)

        fake_manager.get_cubic_secure_configuration = AsyncMock(
            side_effect=RuntimeError("boom")
        )
        with _patch_manager(fake_manager):
            data = await coordinator._async_update_data()

        assert (
            data["cubic_devices"][CUBIC_IDENTITY]["configuration"]
            == good_data["cubic_devices"][CUBIC_IDENTITY]["configuration"]
        )


class TestCubicConfigurationStalenessForceFetch:

    async def test_preserves_mute_leak_across_a_staleness_triggered_force_fetch(
        self, hass, fake_manager
    ):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        stale_cache_updated = (
            int(time.time()) - int(coordinator.update_interval.total_seconds()) - 60
        )
        cached_config = build_cubic_configuration(mute_leak=1200)
        cached_config["cacheUpdated"] = stale_cache_updated
        fake_manager.cubic_configurations_cached_by_device[CUBIC_IDENTITY] = (
            cached_config
        )

        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_live_config_without_mute_leak()
        )

        with _patch_manager(fake_manager):
            data = await coordinator._async_update_data()

        assert (
            data["cubic_devices"][CUBIC_IDENTITY]["configuration"]["muteLeak"] == 1200
        )
        await coordinator.async_shutdown()  # cancel the expiry check this adopted


class TestMultipleCubicSecureDevices:
    """Two Cubic Secure devices registered under the same property used to
    stomp on each other, since the coordinator kept a single unkeyed slot
    for machine_info/last_measurement/configuration instead of one per
    device identity.
    """

    async def test_both_devices_keep_their_own_machine_info(
        self, hass, fake_manager_with_two_cubic_devices
    ):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager_with_two_cubic_devices):
            data = await coordinator._async_update_data()

        assert set(data["cubic_devices"]) == {CUBIC_IDENTITY, CUBIC_IDENTITY_2}
        assert (
            data["cubic_devices"][CUBIC_IDENTITY]["machine_info"]["zone"]["zoneName"]
            == "Utility Room"
        )
        assert (
            data["cubic_devices"][CUBIC_IDENTITY_2]["machine_info"]["zone"][
                "zoneName"
            ]
            == "Garage"
        )

    async def test_both_devices_keep_their_own_measurement_and_configuration(
        self, hass, fake_manager_with_two_cubic_devices
    ):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager_with_two_cubic_devices):
            data = await coordinator._async_update_data()

        first = data["cubic_devices"][CUBIC_IDENTITY]
        second = data["cubic_devices"][CUBIC_IDENTITY_2]

        assert first["last_measurement"]["volumeTotal"] == 45000
        assert second["last_measurement"]["volumeTotal"] == 99000
        assert first["configuration"]["valveState"] == "open"
        assert second["configuration"]["valveState"] == "closed"


class TestForceDeviceUpdate:
    async def test_success_updates_stored_data(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            data = await coordinator._async_update_data()
        coordinator.async_set_updated_data(data)

        fake_manager.measurements_by_device[THERMOSTAT_MAC] = {
            **fake_manager.measurements_by_device[THERMOSTAT_MAC],
            "currentTemperature": 250,
        }

        with _patch_manager(fake_manager):
            result = await coordinator.force_device_update(THERMOSTAT_MAC)

        assert result is True
        assert (
            coordinator.data["device_details"][THERMOSTAT_MAC]["measurement"][
                "currentTemperature"
            ]
            == 250
        )

    async def test_measurement_fetch_failure_returns_false(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        fake_manager.get_device_measurement_result = False

        with _patch_manager(fake_manager):
            result = await coordinator.force_device_update(THERMOSTAT_MAC)

        assert result is False

    async def test_login_failure_returns_false(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        fake_manager.login_result = False

        with _patch_manager(fake_manager):
            result = await coordinator.force_device_update(THERMOSTAT_MAC)

        assert result is False


class TestForceCubicSecureConfigurationUpdate:
    """_fetch_data()'s regular poll only force-bypasses the LK API's own
    backend cache for a Cubic Secure device's configuration (valveState,
    firmwareVersion, ...) once that cache looks older than the poll
    interval - decoupled from whether a write actually just happened. A
    write-triggered refresh (e.g. valve.py after open/close) needs its
    own, unconditionally-forced fetch instead, or it can keep serving the
    same stale cached snapshot.
    """

    async def test_success_updates_stored_configuration(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            data = await coordinator._async_update_data()
        coordinator.async_set_updated_data(data)

        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(valve_state="closed")
        )

        with _patch_manager(fake_manager):
            result = await coordinator.force_cubic_secure_configuration_update(
                CUBIC_IDENTITY
            )

        assert result is True
        assert (
            coordinator.data["cubic_devices"][CUBIC_IDENTITY]["configuration"][
                "valveState"
            ]
            == "closed"
        )

    async def test_configuration_fetch_failure_returns_false(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        fake_manager.get_cubic_secure_configuration_result = False

        with _patch_manager(fake_manager):
            result = await coordinator.force_cubic_secure_configuration_update(
                CUBIC_IDENTITY
            )

        assert result is False

    async def test_bypasses_the_backend_cache_unlike_a_regular_refresh(
        self, hass, fake_manager
    ):
        """Regression test for the actual bug this method exists to work
        around: a regular refresh only escalates to force_update=True once
        the cached response's own cacheUpdated timestamp looks older than
        the poll interval - so right after a write, it can keep serving
        the same pre-write cached snapshot.
        """
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            data = await coordinator._async_update_data()
        coordinator.async_set_updated_data(data)

        # The LK backend's own cache still serving a pre-write snapshot
        # (a fresh cacheUpdated, so _fetch_data()'s own staleness check
        # won't escalate to force_update=True on its own), while the
        # force_update=True/"live" value already reflects a fresh write.
        fake_manager.cubic_configurations_cached_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(valve_state="open")
        )
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(valve_state="closed")
        )

        with _patch_manager(fake_manager):
            await coordinator.async_request_refresh()

        assert (
            coordinator.data["cubic_devices"][CUBIC_IDENTITY]["configuration"][
                "valveState"
            ]
            == "open"
        ), "a regular refresh should still be serving the stale cached value"

        with _patch_manager(fake_manager):
            result = await coordinator.force_cubic_secure_configuration_update(
                CUBIC_IDENTITY
            )

        assert result is True
        assert (
            coordinator.data["cubic_devices"][CUBIC_IDENTITY]["configuration"][
                "valveState"
            ]
            == "closed"
        )

    async def test_login_failure_returns_false(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        fake_manager.login_result = False

        with _patch_manager(fake_manager):
            result = await coordinator.force_cubic_secure_configuration_update(
                CUBIC_IDENTITY
            )

        assert result is False


class TestRefreshCubicSecureConfiguration:
    """See refresh_cubic_secure_configuration()'s own docstring for why
    this reads the cached response rather than bypassing it."""

    async def test_success_updates_stored_configuration(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            data = await coordinator._async_update_data()
        coordinator.async_set_updated_data(data)

        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(valve_state="closed")
        )

        with _patch_manager(fake_manager):
            result = await coordinator.refresh_cubic_secure_configuration(
                CUBIC_IDENTITY
            )

        assert result is True
        assert (
            coordinator.data["cubic_devices"][CUBIC_IDENTITY]["configuration"][
                "valveState"
            ]
            == "closed"
        )

    async def test_reads_the_cached_value_unlike_a_forced_fetch(
        self, hass, fake_manager
    ):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            data = await coordinator._async_update_data()
        coordinator.async_set_updated_data(data)

        # The cached (force_update=False) response and the "live"
        # (force_update=True) one deliberately disagree here, so the two
        # coordinator methods are distinguishable by which one they read.
        fake_manager.cubic_configurations_cached_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(valve_state="open")
        )
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(valve_state="closed")
        )

        with _patch_manager(fake_manager):
            result = await coordinator.refresh_cubic_secure_configuration(
                CUBIC_IDENTITY
            )

        assert result is True
        assert (
            coordinator.data["cubic_devices"][CUBIC_IDENTITY]["configuration"][
                "valveState"
            ]
            == "open"
        )

    async def test_configuration_fetch_failure_returns_false(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        fake_manager.get_cubic_secure_configuration_result = False

        with _patch_manager(fake_manager):
            result = await coordinator.refresh_cubic_secure_configuration(
                CUBIC_IDENTITY
            )

        assert result is False

    async def test_login_failure_returns_false(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        fake_manager.login_result = False

        with _patch_manager(fake_manager):
            result = await coordinator.refresh_cubic_secure_configuration(
                CUBIC_IDENTITY
            )

        assert result is False


class TestLeakDetectionPausedUntilTracking:
    """See LKSystemCoordinator.leak_detection_paused_until's own docstring
    for why it's tracked locally instead of recomputed from muteLeak on
    every poll."""

    async def test_set_rounds_to_the_nearest_minute(self, hass):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        before = dt_util.utcnow()
        coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, 130)
        target = coordinator.leak_detection_paused_until[CUBIC_IDENTITY]

        assert target.second == 0 and target.microsecond == 0
        assert abs((target - (before + timedelta(seconds=130))).total_seconds()) <= 30
        await coordinator.async_shutdown()  # cancel the scheduled expiry check

    async def test_set_with_zero_seconds_clears_it(self, hass):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, 900)

        coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, 0)

        assert CUBIC_IDENTITY not in coordinator.leak_detection_paused_until

    async def test_regular_poll_adopts_a_pause_ha_did_not_itself_start(
        self, hass, fake_manager
    ):
        """E.g. one started from the LK app instead of an HA button/service."""
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=900)
        )

        with _patch_manager(fake_manager):
            await coordinator._async_update_data()

        assert CUBIC_IDENTITY in coordinator.leak_detection_paused_until
        await coordinator.async_shutdown()  # cancel the scheduled expiry check

    async def test_regular_poll_does_not_clear_a_pause_moments_after_it_was_set(
        self, hass, fake_manager
    ):
        """A regular poll isn't triggered by a write, but nothing stops
        its own independent timer from landing moments after one anyway.
        The cloud's cached response can still be serving a pre-write
        snapshot for tens of seconds after HA's own pause API call
        succeeded (confirmed empirically against the real API) - a poll
        that lands in that window must not let a stale muteLeak=0
        override the pause HA itself just set."""
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, 900)
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=0)
        )

        with _patch_manager(fake_manager):
            await coordinator._async_update_data()

        assert CUBIC_IDENTITY in coordinator.leak_detection_paused_until
        await coordinator.async_shutdown()  # cancel the scheduled expiry check

    async def test_regular_poll_clears_it_once_the_cloud_reports_inactive(
        self, hass, fake_manager
    ):
        """Covers both natural expiry and a cancel issued from elsewhere
        (e.g. the LK app's own "Stop" action) - either way, the cloud
        reporting muteLeak=0 is what HA learns it from, once enough time
        has passed since the last HA-issued write for that to be
        trustworthy rather than a stale pre-write snapshot."""
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, 900)
        coordinator._leak_detection_last_local_write[CUBIC_IDENTITY] -= timedelta(
            seconds=LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS
        )
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=0)
        )

        with _patch_manager(fake_manager):
            await coordinator._async_update_data()

        assert CUBIC_IDENTITY not in coordinator.leak_detection_paused_until

    async def test_regular_poll_does_not_override_an_already_tracked_target(
        self, hass, fake_manager
    ):
        """muteLeak is a static number, not a live countdown - re-deriving
        a target from it on every poll would make the displayed time drift
        later and later. Once a target is tracked, only an explicit
        set_leak_detection_paused_until() call (a fresh pause/resume HA
        itself issued) may change it - not the passive reconciliation a
        regular poll does."""
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, 900)
        original_target = coordinator.leak_detection_paused_until[CUBIC_IDENTITY]
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=1)
        )

        with _patch_manager(fake_manager):
            await coordinator._async_update_data()

        assert coordinator.leak_detection_paused_until[CUBIC_IDENTITY] == original_target
        await coordinator.async_shutdown()  # cancel the scheduled expiry check

    async def test_forced_live_fetch_does_not_touch_local_tracking(
        self, hass, fake_manager
    ):
        """The live/bypass fetch doesn't reliably carry muteLeak at all
        (see force_cubic_secure_configuration_update's own docstring) - a
        write-triggered forced fetch (e.g. valve.py after open/close) must
        not clear a genuinely active pause just because that response
        doesn't mention it."""
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            data = await coordinator._async_update_data()
        coordinator.async_set_updated_data(data)
        coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, 900)

        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_live_config_without_mute_leak()
        )

        with _patch_manager(fake_manager):
            await coordinator.force_cubic_secure_configuration_update(CUBIC_IDENTITY)

        assert CUBIC_IDENTITY in coordinator.leak_detection_paused_until
        await coordinator.async_shutdown()  # cancel the scheduled expiry check


async def _paused_coordinator(hass, fake_manager, seconds=300):
    """Build a coordinator with an already-completed initial refresh and
    an active local pause, for the retry-loop tests below - they all start
    from this same state and only differ in what happens next.

    Deliberately well clear of both PAUSE_LEAK_DETECTION_MIN_SECONDS and
    LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS (currently equal, at 60s) -
    these tests are about the retry loop's own timing, not about its
    interaction with the write-grace window right at a minimum-duration
    pause's target, which is covered separately."""
    entry = _make_entry(hass)
    coordinator = LKSystemCoordinator(hass, entry)
    with _patch_manager(fake_manager):
        data = await coordinator._async_update_data()
    coordinator.async_set_updated_data(data)

    coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, seconds)
    target = coordinator.leak_detection_paused_until[CUBIC_IDENTITY]
    return coordinator, target


class TestLeakDetectionExpiryRefresh:
    """A pause's target end time passing doesn't itself cause anything to
    happen - nothing watches the clock for it, so without this, "Leak
    Detection Paused Until" would just sit there showing a stale value
    until the next regular poll (up to a full update_interval later).
    These poll the cloud starting at the target, retrying at
    LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS until it confirms the
    pause is actually over - see that constant's docstring for why a
    single delayed check isn't used instead.
    """

    async def test_resolves_on_the_first_check_if_already_over(
        self, hass, fake_manager
    ):
        coordinator, target = await _paused_coordinator(hass, fake_manager)
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=0)
        )

        with _patch_manager(fake_manager):
            async_fire_time_changed(hass, target)
            await hass.async_block_till_done()

        assert CUBIC_IDENTITY not in coordinator.leak_detection_paused_until

    async def test_notifies_listeners_after_resolving_not_before(
        self, hass, fake_manager
    ):
        """A coordinator listener (standing in for the Resume button and
        the "Leak Detection Paused Until" sensor, both of which re-render
        off a listener notification) must see the pause actually cleared
        by the time it's called - not be notified while
        leak_detection_paused_until is still stale, with nothing telling
        it to re-render again once the clear happens a moment later."""
        coordinator, target = await _paused_coordinator(hass, fake_manager)
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=0)
        )

        paused_at_last_notify = []
        coordinator.async_add_listener(
            lambda: paused_at_last_notify.append(
                CUBIC_IDENTITY in coordinator.leak_detection_paused_until
            )
        )

        with _patch_manager(fake_manager):
            async_fire_time_changed(hass, target)
            await hass.async_block_till_done()

        assert CUBIC_IDENTITY not in coordinator.leak_detection_paused_until
        assert paused_at_last_notify[-1] is False
        await coordinator.async_shutdown()  # cancel the now-listened-for refresh interval

    async def test_does_not_check_before_the_target(self, hass, fake_manager):
        coordinator, target = await _paused_coordinator(hass, fake_manager)
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=0)
        )

        with _patch_manager(fake_manager):
            async_fire_time_changed(hass, target - timedelta(seconds=5))
            await hass.async_block_till_done()

        assert CUBIC_IDENTITY in coordinator.leak_detection_paused_until
        await coordinator.async_shutdown()  # cancel the still-pending check

    async def test_retries_until_the_cloud_confirms_it_is_over(
        self, hass, fake_manager
    ):
        """The cloud can still report a pause as active right at its
        target end time (confirmed empirically against the real API) -
        the first check seeing that must not be treated as final."""
        coordinator, target = await _paused_coordinator(hass, fake_manager)
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=60)
        )

        with _patch_manager(fake_manager):
            async_fire_time_changed(hass, target)
            await hass.async_block_till_done()

        assert CUBIC_IDENTITY in coordinator.leak_detection_paused_until

        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=0)
        )

        with _patch_manager(fake_manager):
            async_fire_time_changed(
                hass,
                target
                + timedelta(seconds=LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS),
            )
            await hass.async_block_till_done()

        assert CUBIC_IDENTITY not in coordinator.leak_detection_paused_until

    async def test_a_still_active_retry_check_never_touches_the_tracked_target(
        self, hass, fake_manager
    ):
        """Unlike a poll landing right after a write (which risks clobbering
        a fresher local value with a staler cloud one - see
        LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS), a retry check reading
        stale "still active" data has nothing to clobber: the device is
        already tracked for its own pause the whole time this loop runs,
        so _reconcile_leak_detection_paused_until()'s own
        never-overwrite-an-already-tracked-target rule applies regardless
        of what muteLeak says, not just when it happens to match. Proves
        that by using a muteLeak value a naive re-adopt would compute a
        different target from, and asserting the original is untouched."""
        coordinator, target = await _paused_coordinator(hass, fake_manager)
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=9999)
        )

        with _patch_manager(fake_manager):
            async_fire_time_changed(hass, target)
            await hass.async_block_till_done()

        assert coordinator.leak_detection_paused_until[CUBIC_IDENTITY] == target
        await coordinator.async_shutdown()  # cancel the still-pending retry

    async def test_minimum_duration_pause_self_heals_past_a_grace_window_no_op(
        self, hass, fake_manager
    ):
        """PAUSE_LEAK_DETECTION_MIN_SECONDS and
        LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS are currently equal (60s),
        so a minimum-duration pause's target can land inside its own
        write-grace window - the first check that lands there is a
        deliberate no-op (see _reconcile_leak_detection_paused_until), not
        a resolution. It isn't left stuck there: the loop's own next retry,
        LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS later, is always past
        the grace window and resolves it normally."""
        coordinator, target = await _paused_coordinator(
            hass, fake_manager, seconds=PAUSE_LEAK_DETECTION_MIN_SECONDS
        )
        coordinator._leak_detection_last_local_write[CUBIC_IDENTITY] = (
            target - timedelta(seconds=LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS - 10)
        )
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=0)
        )

        with _patch_manager(fake_manager):
            async_fire_time_changed(hass, target)
            await hass.async_block_till_done()

        assert CUBIC_IDENTITY in coordinator.leak_detection_paused_until

        with _patch_manager(fake_manager):
            async_fire_time_changed(
                hass,
                target
                + timedelta(seconds=LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS),
            )
            await hass.async_block_till_done()

        assert CUBIC_IDENTITY not in coordinator.leak_detection_paused_until

    async def test_gives_up_after_the_max_retry_window(self, hass, fake_manager):
        """A safety cap for if the cloud never resolves (e.g. the device
        has gone offline) - falls back to the regular poll rather than
        retrying forever."""
        coordinator, target = await _paused_coordinator(hass, fake_manager)
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=60)
        )

        # async_fire_time_changed only fires whatever's already scheduled
        # at the moment it's called - a follow-up retry scheduled
        # reactively during that firing needs its own separate jump to
        # fire in turn, so step through the retries one interval at a
        # time rather than jumping straight to a point past all of them.
        steps = LEAK_DETECTION_EXPIRY_MAX_RETRY_SECONDS // LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS + 2
        with _patch_manager(fake_manager):
            for step in range(1, steps + 1):
                async_fire_time_changed(
                    hass,
                    target
                    + timedelta(
                        seconds=step * LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS
                    ),
                )
                await hass.async_block_till_done()

        # Never confirmed resolved - still tracked under its original
        # target - but no retry left pending (the test's own teardown
        # would fail on a lingering timer if one were).
        assert CUBIC_IDENTITY in coordinator.leak_detection_paused_until

    async def test_resuming_cancels_the_pending_retries(self, hass, fake_manager):
        coordinator, target = await _paused_coordinator(hass, fake_manager)
        coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, 0)
        calls_before = len(fake_manager.calls)

        with _patch_manager(fake_manager):
            async_fire_time_changed(
                hass, target + timedelta(seconds=LEAK_DETECTION_EXPIRY_MAX_RETRY_SECONDS)
            )
            await hass.async_block_till_done()

        assert len(fake_manager.calls) == calls_before

    async def test_re_pausing_replaces_the_pending_retries(self, hass, fake_manager):
        """Re-pausing while already active resets the target (confirmed
        empirically against the real API) - the scheduled retries must
        move with it rather than firing early against the old target."""
        coordinator, original_target = await _paused_coordinator(hass, fake_manager)
        coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, 600)
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=0)
        )

        with _patch_manager(fake_manager):
            async_fire_time_changed(hass, original_target)
            await hass.async_block_till_done()

        # The old target's check must not have fired - the pause is still
        # tracked, under its new (later) target.
        assert CUBIC_IDENTITY in coordinator.leak_detection_paused_until
        assert coordinator.leak_detection_paused_until[CUBIC_IDENTITY] != original_target
        await coordinator.async_shutdown()  # cancel the still-pending new check

    async def test_shutdown_cancels_pending_retries(self, hass, fake_manager):
        """Otherwise a retry scheduled before unload would fire against a
        torn-down coordinator afterwards - including one scheduled by a
        previous retry iteration, not just the first check."""
        coordinator, target = await _paused_coordinator(hass, fake_manager)
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=60)
        )

        with _patch_manager(fake_manager):
            async_fire_time_changed(hass, target)  # still active - schedules a retry
            await hass.async_block_till_done()
        calls_before = len(fake_manager.calls)

        await coordinator.async_shutdown()

        with _patch_manager(fake_manager):
            async_fire_time_changed(
                hass,
                target
                + timedelta(seconds=LEAK_DETECTION_EXPIRY_MAX_RETRY_SECONDS + 30),
            )
            await hass.async_block_till_done()

        assert len(fake_manager.calls) == calls_before


class TestSetThermostatTemperature:
    async def test_success_returns_true_and_refreshes(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            result = await coordinator.set_thermostat_temperature(
                THERMOSTAT_MAC, 225
            )

        assert result is True
        assert ("set_thermostat_temperature", THERMOSTAT_MAC, 225) in fake_manager.calls
        # async_refresh() was called as a side effect
        assert coordinator.data is not None

    async def test_api_failure_returns_false(self, hass, fake_manager):
        fake_manager.set_thermostat_temperature_result = {
            "success": False,
            "data": None,
            "error": "boom",
        }
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            result = await coordinator.set_thermostat_temperature(
                THERMOSTAT_MAC, 225
            )

        assert result is False

    async def test_unexpected_exception_returns_false(self, hass, fake_manager):
        fake_manager.set_thermostat_temperature = AsyncMock(
            side_effect=RuntimeError("boom")
        )
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            result = await coordinator.set_thermostat_temperature(
                THERMOSTAT_MAC, 225
            )

        assert result is False

    async def test_logs_in_before_calling_the_api(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            result = await coordinator.set_thermostat_temperature(
                THERMOSTAT_MAC, 225
            )

        assert result is True
        call_names = [call[0] for call in fake_manager.calls]
        assert call_names.index("login") < call_names.index(
            "set_thermostat_temperature"
        )

    async def test_login_failure_returns_false(self, hass, fake_manager):
        fake_manager.login_result = False
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)

        with _patch_manager(fake_manager):
            result = await coordinator.set_thermostat_temperature(
                THERMOSTAT_MAC, 225
            )

        assert result is False

    async def test_reuses_stored_valid_token(self, hass, fake_manager):
        entry = _make_entry(hass)
        coordinator = LKSystemCoordinator(hass, entry)
        TOKEN_STORAGE[entry.entry_id] = {
            "jwt": _make_token(3600),
            "refresh": "stored-refresh-token",
            "expiry": dt_util.utcnow().timestamp() + 3600,
        }

        with _patch_manager(fake_manager):
            result = await coordinator.set_thermostat_temperature(
                THERMOSTAT_MAC, 225
            )

        assert result is True
        assert ("login",) not in fake_manager.calls
