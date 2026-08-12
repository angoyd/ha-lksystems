"""Tests for is_token_valid() and LKSystemCoordinator in __init__.py.

The LK Systems API client itself (pylksystems) is mocked out via
FakeLKSystemsManager (see conftest.py) - these tests are only concerned
with the coordinator's own logic: building the response structure from
whatever the client returns, token caching, and error handling.
"""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import UpdateFailed
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lksystems import (
    TOKEN_STORAGE,
    LKSystemCoordinator,
    is_token_valid,
)
from custom_components.lksystems.const import (
    CONF_UPDATE_INTERVAL,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
)
from custom_components.lksystems.repairs import _issue_id

from .conftest import (
    CUBIC_IDENTITY,
    HUB_CHILD_MAC,
    HUB_IDENTITY,
    SENSOR_MAC,
    THERMOSTAT_MAC,
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
        assert data["cubic_machine_info"]["identity"] == CUBIC_IDENTITY
        assert data["cubic_last_measurement"]["volumeTotal"] == 45000
        assert data["cubic_configuration"]["valveState"] == "open"

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
    """A failed update should surface as a repair issue (issue #50) instead
    of only a log line - auth failures immediately (HA's own reauth flow
    already treats them as non-transient), fetch failures only after
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

        assert "cubic_last_measurement" in data
        assert "cubic_configuration" in data
        assert data["cubic_configuration"] is None

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

        assert data["cubic_configuration"] == good_data["cubic_configuration"]


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
