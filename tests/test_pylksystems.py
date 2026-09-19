"""Unit tests for the pylksystems API client.

These tests mock the HTTP layer with aioresponses so they exercise the
client's parsing/branching logic (auth flow, device-list normalization,
merge/dedupe, error handling) without ever hitting the real LK Systems API.
"""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import ClientConnectionError
from aioresponses import aioresponses

import pylksystems

BASE_URL = "https://link2.lk.nu/"


@pytest.fixture
def mock_sleep():
    """Patch asyncio.sleep so a test never actually waits out a real delay."""
    with patch("asyncio.sleep", new=AsyncMock()) as mock:
        yield mock


class TestLogin:
    async def test_success_sets_tokens_and_userid(self, manager):
        with aioresponses() as m:
            m.post(
                BASE_URL + "auth/auth/login",
                payload={"accessToken": "tok-123", "refreshToken": "refresh-123"},
                status=200,
            )
            m.get(
                BASE_URL + "auth/auth/user",
                payload={"userId": "user-123"},
                status=200,
            )
            async with manager:
                result = await manager.login()

        assert result is True
        assert manager.jwt_token == "tok-123"
        assert manager.refresh_token == "refresh-123"
        assert manager.userid == "user-123"

    async def test_unauthorized_returns_false(self, manager):
        with aioresponses() as m:
            m.post(BASE_URL + "auth/auth/login", payload={}, status=401)
            async with manager:
                result = await manager.login()

        assert result is False
        assert manager.jwt_token is None

    async def test_userid_lookup_failure_returns_false(self, manager):
        with aioresponses() as m:
            m.post(
                BASE_URL + "auth/auth/login",
                payload={"accessToken": "tok-123", "refreshToken": "refresh-123"},
                status=200,
            )
            m.get(BASE_URL + "auth/auth/user", payload={}, status=500)
            async with manager:
                result = await manager.login()

        # Tokens are already set from the first call, only userid lookup failed.
        assert result is False
        assert manager.jwt_token == "tok-123"
        assert manager.userid is None

    @pytest.mark.parametrize(
        "userid_status",
        [
            401,  # raises ClientResponseError, caught by handle_client_error()
            204,  # 2xx but not 200 - doesn't raise, falls through to the inline error log
        ],
    )
    async def test_userid_lookup_failure_logs_the_userid_endpoint(
        self, manager, caplog, userid_status
    ):
        """The userid lookup is a separate request from login, on a
        different endpoint - an error from it should be logged against its
        own URL, not the login endpoint that already succeeded.
        """
        with aioresponses() as m:
            m.post(
                BASE_URL + "auth/auth/login",
                payload={"accessToken": "tok-123", "refreshToken": "refresh-123"},
                status=200,
            )
            m.get(BASE_URL + "auth/auth/user", payload={}, status=userid_status)
            async with manager:
                with caplog.at_level(logging.ERROR):
                    await manager.login()

        messages = [record.getMessage() for record in caplog.records]
        assert any(BASE_URL + "auth/auth/user" in msg for msg in messages)
        assert not any(BASE_URL + "auth/auth/login" in msg for msg in messages)

    async def test_connection_error_is_handled(self, manager):
        with aioresponses() as m:
            m.post(BASE_URL + "auth/auth/login", exception=ClientConnectionError())
            async with manager:
                result = await manager.login()

        assert result is False


class TestGetUserStructure:
    async def test_success_keeps_full_list_of_realestates(self, manager):
        manager.userid = "user-123"
        api_response = [{"realestateId": "re-1", "cacheUpdated": 111}]

        with aioresponses() as m:
            m.get(
                BASE_URL + "service/users/user/user-123/structure/1",
                payload=api_response,
                status=200,
            )
            async with manager:
                result = await manager.get_user_structure()

        assert result is True
        assert manager.user_structure == api_response

    async def test_second_realestate_is_not_dropped(self, manager):
        """An account whose devices are split across two properties used to
        lose the second realestate entirely - get_user_structure() indexed
        into the response with res[0] instead of keeping every entry.
        """
        manager.userid = "user-123"
        api_response = [
            {"realestateId": "re-1", "cacheUpdated": 111},
            {"realestateId": "re-2", "cacheUpdated": 222},
        ]

        with aioresponses() as m:
            m.get(
                BASE_URL + "service/users/user/user-123/structure/1",
                payload=api_response,
                status=200,
            )
            async with manager:
                result = await manager.get_user_structure()

        assert result is True
        assert manager.user_structure == api_response

    async def test_empty_list_response_does_not_raise(self, manager):
        """Account with no devices/realestates: API returns `[]`.

        This used to raise `IndexError: list index out of range`.
        """
        manager.userid = "user-123"

        with aioresponses() as m:
            m.get(
                BASE_URL + "service/users/user/user-123/structure/1",
                payload=[],
                status=200,
            )
            async with manager:
                result = await manager.get_user_structure()

        assert result is False
        assert manager.user_structure is None

    async def test_request_failure_returns_false(self, manager):
        manager.userid = "user-123"

        with aioresponses() as m:
            m.get(
                BASE_URL + "service/users/user/user-123/structure/1",
                status=500,
            )
            async with manager:
                result = await manager.get_user_structure()

        assert result is False
        assert manager.user_structure is None


class TestGetDevices:
    async def test_list_response_skips_cubic_and_extracts_arc_fields(self, manager):
        manager.userid = "user-123"
        api_response = [
            {
                "cacheUpdated": 111,
                "realestateMachines": [
                    {
                        "deviceType": "cubicsecure",
                        "deviceRole": "cubicsecure",
                        "identity": "cubic-1",
                    },
                    {
                        "deviceGroup": "arc",
                        "deviceType": "arc-sense",
                        "deviceRole": "sense",
                        "identity": "AA:BB:CC",
                        "zone": "Living Room",
                    },
                ],
            }
        ]

        with aioresponses() as m:
            m.get(
                BASE_URL + "service/users/user/user-123/structure/false",
                payload=api_response,
                status=200,
            )
            async with manager:
                result = await manager.get_devices()

        assert result is True
        devices = manager.devices["devices"]
        assert len(devices) == 1
        assert devices[0]["mac"] == "AA:BB:CC"
        assert devices[0]["deviceGroup"] == "arc"
        assert devices[0]["zone"] == "Living Room"
        assert devices[0]["cacheUpdated"] == 111

    async def test_dict_response_used_as_is(self, manager):
        manager.userid = "user-123"
        api_response = {
            "devices": [{"mac": "DD:EE:FF", "deviceGroup": "arc"}],
            "cacheUpdated": 222,
        }

        with aioresponses() as m:
            m.get(
                BASE_URL + "service/users/user/user-123/structure/false",
                payload=api_response,
                status=200,
            )
            async with manager:
                result = await manager.get_devices()

        assert result is True
        assert manager.devices == api_response

    async def test_merges_and_dedupes_against_existing_devices(self, manager):
        manager.userid = "user-123"
        manager._devices = {
            "devices": [{"mac": "AA", "existing": True}],
            "cacheUpdated": 1,
        }
        api_response = [
            {
                "cacheUpdated": 999,
                "realestateMachines": [
                    # Duplicate mac - must not be added a second time, and the
                    # existing entry must be preserved rather than overwritten.
                    {"deviceGroup": "arc", "deviceType": "x", "identity": "AA"},
                    {"deviceGroup": "arc", "deviceType": "x", "identity": "BB"},
                ],
            }
        ]

        with aioresponses() as m:
            m.get(
                BASE_URL + "service/users/user/user-123/structure/false",
                payload=api_response,
                status=200,
            )
            async with manager:
                result = await manager.get_devices()

        assert result is True
        macs = [d["mac"] for d in manager.devices["devices"]]
        assert macs.count("AA") == 1
        assert "BB" in macs
        assert manager.devices["devices"][0] == {"mac": "AA", "existing": True}

    async def test_request_failure_falls_back_to_existing_devices(self, manager):
        manager.userid = "user-123"
        manager._devices = {"devices": [{"mac": "AA"}], "cacheUpdated": 1}

        with aioresponses() as m:
            m.get(
                BASE_URL + "service/users/user/user-123/structure/false",
                status=500,
            )
            async with manager:
                result = await manager.get_devices()

        # Falls back to True because devices already exist locally.
        assert result is True
        assert manager.devices["devices"] == [{"mac": "AA"}]


class TestExtractDevicesFromStructure:
    """extract_devices_from_structure() and get_arc_hubs_from_structure()
    read manager._user_structure directly - the list of every realestate on
    the account, as get_user_structure() now stores it.
    """

    def test_extracts_devices_from_every_realestate(self, manager):
        manager._user_structure = [
            {
                "cacheUpdated": 111,
                "realestateMachines": [
                    {
                        "deviceType": "cubicsecure",
                        "deviceRole": "cubicsecure",
                        "identity": "cubic-1",
                    },
                    {
                        "deviceGroup": "arc",
                        "deviceType": "arc-sense",
                        "deviceRole": "sense",
                        "identity": "AA:BB:CC",
                        "zone": "Living Room",
                    },
                ],
            },
            {
                "cacheUpdated": 222,
                "realestateMachines": [
                    {
                        "deviceGroup": "arc",
                        "deviceType": "arc-sense",
                        "deviceRole": "sense",
                        "identity": "DD:EE:FF",
                        "zone": "Kitchen",
                    },
                ],
            },
        ]

        extracted = manager.extract_devices_from_structure()

        macs = {d["mac"] for d in extracted["devices"]}
        # Cubic Secure devices are skipped here - handled separately.
        assert macs == {"AA:BB:CC", "DD:EE:FF"}
        first_realestate_device = next(
            d for d in extracted["devices"] if d["mac"] == "AA:BB:CC"
        )
        second_realestate_device = next(
            d for d in extracted["devices"] if d["mac"] == "DD:EE:FF"
        )
        assert first_realestate_device["cacheUpdated"] == 111
        assert second_realestate_device["cacheUpdated"] == 222

    def test_get_arc_hubs_finds_hubs_across_every_realestate(self, manager):
        manager._user_structure = [
            {
                "realestateMachines": [
                    {
                        "deviceGroup": "arc",
                        "deviceType": "arc-hub",
                        "deviceRole": "arc-hub",
                        "identity": "hub-1",
                    },
                ],
            },
            {
                "realestateMachines": [
                    {
                        "deviceGroup": "arc",
                        "deviceType": "arc-hub",
                        "deviceRole": "arc-hub",
                        "identity": "hub-2",
                    },
                ],
            },
        ]

        arc_hubs = manager.get_arc_hubs_from_structure()

        assert {hub["identity"] for hub in arc_hubs} == {"hub-1", "hub-2"}


class TestCubicSecureMeasurement:
    async def test_force_update_selects_endpoint(self, manager):
        with aioresponses() as m:
            m.get(
                BASE_URL + "service/cubic/secure/cubic-1/measurement/1",
                payload={"flow": 1.5},
                status=200,
            )
            async with manager:
                result = await manager.get_cubic_secure_measurement(
                    "cubic-1", force_update=True
                )

        assert result is True
        assert manager.cubic_secure_measurement == {"flow": 1.5}

    async def test_without_force_update_selects_endpoint(self, manager):
        with aioresponses() as m:
            m.get(
                BASE_URL + "service/cubic/secure/cubic-1/measurement/0",
                payload={"flow": 0.0},
                status=200,
            )
            async with manager:
                result = await manager.get_cubic_secure_measurement("cubic-1")

        assert result is True
        assert manager.cubic_secure_measurement == {"flow": 0.0}

    async def test_error_status_returns_false_and_keeps_state(self, manager):
        with aioresponses() as m:
            m.get(
                BASE_URL + "service/cubic/secure/cubic-1/measurement/0",
                status=404,
            )
            async with manager:
                result = await manager.get_cubic_secure_measurement("cubic-1")

        assert result is False
        assert manager.cubic_secure_measurement is None


class TestCubicSecureSetThresholds:
    async def test_posts_to_the_real_plural_endpoint(self, manager):
        """The real API endpoint is /thresholds (plural) - confirmed
        against the actual OpenAPI spec and, live, with a real device
        (a singular /threshold URL 404s every time)."""
        thresholds = {
            "pressure": {
                "sensitivity": 0.3,
                "duration": 45,
                "closeDelay": 255600,
                "notificationDelay": 169200,
            },
            "leakMedium": {
                "threshold": 10.0,
                "closeDelay": 1800,
                "notificationDelay": 1800,
            },
            "leakLarge": {
                "threshold": 1500.0,
                "closeDelay": 90,
                "notificationDelay": 90,
            },
        }

        with aioresponses() as m:
            m.post(
                BASE_URL + "control/cubic/secure/cubic-1/thresholds",
                payload=thresholds,
                status=200,
            )
            async with manager:
                result = await manager.cubic_secure_set_thresholds(
                    "cubic-1", thresholds
                )

        assert result is True

    async def test_error_status_returns_false(self, manager):
        with aioresponses() as m:
            m.post(
                BASE_URL + "control/cubic/secure/cubic-1/thresholds",
                status=404,
            )
            async with manager:
                result = await manager.cubic_secure_set_thresholds("cubic-1", {})

        assert result is False


class TestThresholdsWithOverrides:
    """cubic_secure_set_thresholds() only accepts the full object at
    once - this is the one place that carry-forward logic lives, shared
    by both the leak-detection threshold number entities and the
    set_thresholds service.
    """

    def _sample_thresholds(self):
        return {
            "pressure": {"sensitivity": 0.3, "duration": 45},
            "leakMedium": {"threshold": 10.0, "closeDelay": 1800},
            "leakLarge": {"threshold": 1500.0, "closeDelay": 90},
        }

    def test_overrides_only_the_given_category_and_fields(self):
        current = self._sample_thresholds()

        updated = pylksystems.thresholds_with_overrides(
            current, "leakLarge", {"threshold": 2000.0}
        )

        assert updated["leakLarge"] == {"threshold": 2000.0, "closeDelay": 90}
        assert updated["pressure"] == current["pressure"]
        assert updated["leakMedium"] == current["leakMedium"]

    def test_can_override_multiple_fields_in_one_category(self):
        current = self._sample_thresholds()

        updated = pylksystems.thresholds_with_overrides(
            current, "leakLarge", {"closeDelay": 60, "notificationDelay": 60}
        )

        assert updated["leakLarge"] == {
            "threshold": 1500.0,
            "closeDelay": 60,
            "notificationDelay": 60,
        }

    def test_does_not_mutate_the_input(self):
        current = self._sample_thresholds()

        pylksystems.thresholds_with_overrides(current, "leakLarge", {"threshold": 2000.0})

        assert current["leakLarge"]["threshold"] == 1500.0


class TestSetDeviceTemperature:
    async def test_success_converts_and_sends_tenths_of_degree(self, manager):
        with aioresponses() as m:
            m.get(
                BASE_URL + "service/arc/sense/AA:BB:CC/measurement/true",
                payload={"currentTemperature": 210, "desiredTemperature": 200},
                status=200,
            )
            m.post(
                BASE_URL + "service/arc/sense/AA:BB:CC/measurement/true",
                payload={"currentTemperature": 210, "desiredTemperature": 215},
                status=200,
            )
            async with manager:
                result = await manager.set_device_temperature("AA:BB:CC", 21.5)

        assert result is True
        assert manager.device_measurements["AA:BB:CC"]["desiredTemperature"] == 215

    async def test_non_arc_device_identity_is_rejected(self, manager):
        async with manager:
            result = await manager.set_device_temperature("not-a-mac", 21.5)

        assert result is False

    async def test_empty_device_identity_is_rejected(self, manager):
        async with manager:
            result = await manager.set_device_temperature("", 21.5)

        assert result is False

    async def test_measurement_fetch_failure_aborts_before_posting(self, manager):
        with aioresponses() as m:
            m.get(
                BASE_URL + "service/arc/sense/AA:BB:CC/measurement/true",
                status=500,
            )
            async with manager:
                result = await manager.set_device_temperature("AA:BB:CC", 21.5)

        assert result is False
        assert "AA:BB:CC" not in manager.device_measurements

    async def test_timeout_during_post_is_handled(self, manager):
        with aioresponses() as m:
            m.get(
                BASE_URL + "service/arc/sense/AA:BB:CC/measurement/true",
                payload={"currentTemperature": 210, "desiredTemperature": 200},
                status=200,
            )
            m.post(
                BASE_URL + "service/arc/sense/AA:BB:CC/measurement/true",
                exception=asyncio.TimeoutError(),
            )
            async with manager:
                result = await manager.set_device_temperature("AA:BB:CC", 21.5)

        assert result is False


class TestSensitiveDataNotLogged:
    """Regression tests: request failures and debug logs must never leak
    the bearer token, the API subscription key, or any part of a JWT.
    """

    async def test_handle_client_error_redacts_headers(self, manager, caplog):
        headers = {
            "content-type": "application/json",
            "authorization": "Bearer super-secret-jwt",
            "ocp-apim-subscription-key": "super-secret-key",
        }

        await manager.handle_client_error("some/endpoint", headers, ValueError("boom"))

        log_text = caplog.text
        assert "super-secret-jwt" not in log_text
        assert "super-secret-key" not in log_text
        # Non-sensitive headers are still useful for debugging.
        assert "application/json" in log_text

    async def test_set_thermostat_temperature_logs_token_presence_not_value(
        self, manager, caplog
    ):
        manager.jwt_token = "super-secret-jwt"
        caplog.set_level(logging.DEBUG)

        with aioresponses() as m:
            m.post(
                "https://lk-arc-structure-mapper.azurewebsites.net/api/measurement/sense",
                payload={"currentTemperature": 210},
                status=200,
            )
            async with manager:
                await manager.set_thermostat_temperature("AA:BB:CC", 215)

        assert "super-secret-jwt" not in caplog.text
class TestClientSessionTimeout:
    async def test_session_has_a_bounded_timeout(self, manager):
        """Regression test: aiohttp defaults to a 300s total timeout when
        none is configured on the ClientSession. That lets one slow or
        unresponsive LK API call stall an entire coordinator update cycle
        for up to 5 minutes before it even fails. The session must set an
        explicit, short timeout instead of relying on that default.
        """
        async with manager:
            timeout = manager.session.timeout

        assert timeout.total is not None
        assert timeout.total <= 30


class TestUnguardedRequestTimeout:
    """A slow/unresponsive LK API response (aiohttp's ClientTimeout firing)
    must be handled the same way any other request failure is, not escape
    uncaught up to the coordinator - which logs it as a bare, endpoint-less
    "Timeout fetching lksystems data" and fails the whole update.

    _get()/_post() already guarantee this (see TestClientSessionTimeout's
    sibling coverage via _request_with_retry's own timeout handling), but
    these methods build their own request directly instead of going
    through that shared, hardened path.
    """

    @pytest.mark.parametrize(
        ("http_method", "endpoint", "call"),
        [
            ("post", "auth/auth/login", lambda m: m.login()),
            (
                "get",
                "service/users/user/user-123/structure/false",
                lambda m: m.get_devices(),
            ),
            (
                "get",
                "service/arc/hub/hub-1/structure/false",
                lambda m: m.get_hub_devices("hub-1"),
            ),
            (
                "get",
                "service/arc/sense/AA:BB:CC/measurement/false",
                lambda m: m.get_arc_sense_measurement("AA:BB:CC"),
            ),
            (
                "get",
                "service/arc/sense/AA:BB:CC/configuration/false",
                lambda m: m.get_arc_sense_configuration("AA:BB:CC"),
            ),
            (
                "get",
                "service/arc/sense/AA:BB:CC/measurement/false",
                lambda m: m.get_device_measurement("AA:BB:CC"),
            ),
            (
                "get",
                "service/arc/sense/AA:BB:CC/configuration/false",
                lambda m: m.get_device_configuration("AA:BB:CC"),
            ),
            (
                "get",
                "service/devices/device/AA:BB:CC/title/false",
                lambda m: m.get_device_title("AA:BB:CC"),
            ),
        ],
    )
    async def test_timeout_is_handled_not_raised(
        self, manager, http_method, endpoint, call
    ):
        manager.userid = "user-123"
        with aioresponses() as m:
            getattr(m, http_method)(BASE_URL + endpoint, exception=asyncio.TimeoutError())
            async with manager:
                result = await call(manager)

        assert result is False


@pytest.mark.usefixtures("mock_sleep")
class TestRateLimitBackoff:
    """LK's cloud API rate-limits (429) during bursts of activity - this is
    an expected, routine condition on LK's end, not a genuine error. The
    client should retry with backoff (honoring Retry-After when present)
    instead of failing immediately, and log at warning rather than error.
    """

    async def test_429_is_retried_and_eventually_succeeds(self, manager, mock_sleep):
        url = BASE_URL + "service/cubic/secure/cubic-1/measurement/0"

        with aioresponses() as m:
            m.get(url, status=429, headers={"Retry-After": "1"})
            m.get(url, payload={"flow": 0.0}, status=200)
            async with manager:
                result = await manager.get_cubic_secure_measurement("cubic-1")

        assert result is True
        assert manager.cubic_secure_measurement == {"flow": 0.0}

    async def test_429_honors_retry_after_header(self, manager, mock_sleep):
        url = BASE_URL + "service/cubic/secure/cubic-1/measurement/0"

        with aioresponses() as m:
            m.get(url, status=429, headers={"Retry-After": "7"})
            m.get(url, payload={"flow": 0.0}, status=200)
            async with manager:
                await manager.get_cubic_secure_measurement("cubic-1")

        mock_sleep.assert_awaited_once_with(7.0)

    async def test_429_without_retry_after_uses_a_default_backoff(
        self, manager, mock_sleep
    ):
        url = BASE_URL + "service/cubic/secure/cubic-1/measurement/0"

        with aioresponses() as m:
            m.get(url, status=429)
            m.get(url, payload={"flow": 0.0}, status=200)
            async with manager:
                await manager.get_cubic_secure_measurement("cubic-1")

        mock_sleep.assert_awaited_once()
        assert mock_sleep.await_args.args[0] > 0

    async def test_429_with_a_zero_retry_after_still_backs_off(
        self, manager, mock_sleep
    ):
        """A Retry-After of 0 (or anything below the floor) shouldn't
        collapse the backoff to an immediate retry - that's indistinguishable
        from not backing off at all, defeating the point of retrying."""
        url = BASE_URL + "service/cubic/secure/cubic-1/measurement/0"

        with aioresponses() as m:
            m.get(url, status=429, headers={"Retry-After": "0"})
            m.get(url, payload={"flow": 0.0}, status=200)
            async with manager:
                await manager.get_cubic_secure_measurement("cubic-1")

        mock_sleep.assert_awaited_once()
        assert mock_sleep.await_args.args[0] > 0

    async def test_429_exhausting_retries_returns_false(self, manager, mock_sleep):
        manager.userid = "user-123"
        url = BASE_URL + "service/users/user/user-123/structure/1"

        with aioresponses() as m:
            m.get(url, status=429, repeat=True)
            async with manager:
                result = await manager.get_user_structure()

        assert result is False
        assert manager.user_structure is None

    async def test_429_exhausting_retries_logs_warning_not_error(
        self, manager, mock_sleep, caplog
    ):
        manager.userid = "user-123"
        url = BASE_URL + "service/users/user/user-123/structure/1"

        with aioresponses() as m:
            m.get(url, status=429, repeat=True)
            with caplog.at_level(logging.WARNING):
                async with manager:
                    await manager.get_user_structure()

        assert not any(record.levelno >= logging.ERROR for record in caplog.records)
        assert "429" in caplog.text

    async def test_post_429_is_retried_and_eventually_succeeds(
        self, manager, mock_sleep
    ):
        url = BASE_URL + "control/cubic/secure/cubic-1/valve/close"

        with aioresponses() as m:
            m.post(url, status=429, headers={"Retry-After": "1"})
            m.post(url, payload={}, status=200)
            async with manager:
                result = await manager.cubic_secure_close_valve("cubic-1")

        assert result is True

    async def test_other_error_statuses_still_log_at_error(self, manager, caplog):
        """Non-429 failures aren't rate-limiting - they keep the existing
        error-level logging, unaffected by the 429 backoff path."""
        manager.userid = "user-123"
        url = BASE_URL + "service/users/user/user-123/structure/1"

        with aioresponses() as m:
            m.get(url, status=500)
            with caplog.at_level(logging.ERROR):
                async with manager:
                    result = await manager.get_user_structure()

        assert result is False
        assert any(record.levelno >= logging.ERROR for record in caplog.records)


class TestLastRateLimitRetryAfter:
    """last_rate_limit_retry_after lets a caller tell "this failed because
    of rate limiting, retry after N seconds" apart from any other kind of
    failure, without changing what any existing call returns.
    """

    async def test_none_before_any_call(self, manager):
        assert manager.last_rate_limit_retry_after is None

    async def test_set_when_a_429_is_observed_even_if_eventually_retried_successfully(
        self, manager, mock_sleep
    ):
        url = BASE_URL + "service/cubic/secure/cubic-1/measurement/0"

        with aioresponses() as m:
            m.get(url, status=429, headers={"Retry-After": "7"})
            m.get(url, payload={"flow": 0.0}, status=200)
            async with manager:
                result = await manager.get_cubic_secure_measurement("cubic-1")

        assert result is True
        assert manager.last_rate_limit_retry_after == 7.0

    async def test_set_when_retries_are_exhausted(self, manager, mock_sleep):
        manager.userid = "user-123"
        url = BASE_URL + "service/users/user/user-123/structure/1"

        with aioresponses() as m:
            m.get(url, status=429, headers={"Retry-After": "42"}, repeat=True)
            async with manager:
                await manager.get_user_structure()

        assert manager.last_rate_limit_retry_after == 42.0

    async def test_none_after_a_non_429_failure(self, manager):
        manager.userid = "user-123"
        url = BASE_URL + "service/users/user/user-123/structure/1"

        with aioresponses() as m:
            m.get(url, status=500)
            async with manager:
                await manager.get_user_structure()

        assert manager.last_rate_limit_retry_after is None

    async def test_reset_to_none_at_the_start_of_the_next_call(self, manager, mock_sleep):
        """A stale value from a previous failed call must not look like
        it describes the current one."""
        manager.userid = "user-123"
        url = BASE_URL + "service/users/user/user-123/structure/1"

        with aioresponses() as m:
            m.get(url, status=429, headers={"Retry-After": "5"}, repeat=True)
            async with manager:
                await manager.get_user_structure()
        assert manager.last_rate_limit_retry_after == 5.0

        with aioresponses() as m:
            m.get(url, payload=[], status=200)
            async with manager:
                await manager.get_user_structure()

        assert manager.last_rate_limit_retry_after is None


class TestSharedRateLimitCooldown:
    """A 429's Retry-After becomes a cooldown deadline for its endpoint,
    visible to every LKSystemsManager instance in the process - not just
    the one call that happened to observe it.
    """

    FORCED_ENDPOINT = "service/cubic/secure/cubic-1/configuration/1"
    CACHED_ENDPOINT = "service/cubic/secure/cubic-1/configuration/0"

    async def test_429_exhausting_one_instances_retries_still_delays_another(
        self, manager, other_manager, mock_sleep
    ):
        """A caller that exhausts its own retries and gives up must still
        leave the cooldown it observed for the next caller to see - giving
        up is not the same as the rate limit having lifted."""
        url = BASE_URL + self.FORCED_ENDPOINT

        with aioresponses() as m:
            m.get(url, status=429, headers={"Retry-After": "50"}, repeat=True)
            async with manager:
                result = await manager.get_cubic_secure_configuration(
                    "cubic-1", force_update=True
                )

        assert result is False
        mock_sleep.reset_mock()

        with aioresponses() as m:
            m.get(url, payload={"flow": 2.0}, status=200)
            async with other_manager:
                result = await other_manager.get_cubic_secure_configuration(
                    "cubic-1", force_update=True
                )

        assert result is True
        mock_sleep.assert_awaited_once()
        assert mock_sleep.await_args.args[0] == pytest.approx(50.0, abs=1.0)

    async def test_cooldown_is_scoped_per_endpoint_path(
        self, manager, other_manager, mock_sleep
    ):
        """The cached and force-update variants of the same resource are
        different paths - a 429 on one must not delay the other."""
        forced_url = BASE_URL + self.FORCED_ENDPOINT
        cached_url = BASE_URL + self.CACHED_ENDPOINT

        with aioresponses() as m:
            m.get(forced_url, status=429, headers={"Retry-After": "50"})
            m.get(forced_url, payload={"flow": 1.0}, status=200)
            async with manager:
                await manager.get_cubic_secure_configuration(
                    "cubic-1", force_update=True
                )

        mock_sleep.reset_mock()

        with aioresponses() as m:
            m.get(cached_url, payload={"flow": 2.0}, status=200)
            async with other_manager:
                result = await other_manager.get_cubic_secure_configuration(
                    "cubic-1", force_update=False
                )

        assert result is True
        mock_sleep.assert_not_awaited()

    async def test_success_clears_the_cooldown_for_that_endpoint(
        self, manager, other_manager, mock_sleep
    ):
        url = BASE_URL + self.FORCED_ENDPOINT

        with aioresponses() as m:
            m.get(url, status=429, headers={"Retry-After": "1"})
            m.get(url, payload={"flow": 1.0}, status=200)
            async with manager:
                await manager.get_cubic_secure_configuration(
                    "cubic-1", force_update=True
                )

        mock_sleep.reset_mock()

        with aioresponses() as m:
            m.get(url, payload={"flow": 2.0}, status=200)
            async with other_manager:
                await other_manager.get_cubic_secure_configuration(
                    "cubic-1", force_update=True
                )

        mock_sleep.assert_not_awaited()


class TestPerCallMaxWait:
    """`_get`/`_post` accept an optional per-call `max_wait` budget - how
    long *this* caller is willing to wait, independent of the shared
    cooldown. Giving up on that budget must never touch the shared
    deadline: the remaining cooldown is still real server-side state that
    applies to whoever asks next.
    """

    ENDPOINT = "service/cubic/secure/cubic-1/configuration/1"

    async def test_gives_up_once_its_own_budget_is_exhausted(
        self, manager, rate_limit_cooldowns
    ):
        pylksystems._record_rate_limited(self.ENDPOINT, 0.4)

        with aioresponses():
            async with manager:
                success, data = await manager._get(self.ENDPOINT, max_wait=0.05)

        assert success is False
        assert data is None

    async def test_giving_up_does_not_shorten_the_shared_cooldown(
        self, manager, rate_limit_cooldowns
    ):
        pylksystems._record_rate_limited(self.ENDPOINT, 0.4)
        deadline = rate_limit_cooldowns[self.ENDPOINT]

        with aioresponses():
            async with manager:
                await manager._get(self.ENDPOINT, max_wait=0.05)

        assert rate_limit_cooldowns[self.ENDPOINT] == deadline

    async def test_without_max_wait_keeps_waiting_out_the_full_cooldown(
        self, manager, rate_limit_cooldowns, mock_sleep
    ):
        pylksystems._record_rate_limited(self.ENDPOINT, 50)

        with aioresponses() as m:
            m.get(BASE_URL + self.ENDPOINT, payload={"flow": 1.0}, status=200)
            async with manager:
                success, data = await manager._get(self.ENDPOINT)

        assert success is True
        assert data == {"flow": 1.0}
        mock_sleep.assert_awaited_once()
        assert mock_sleep.await_args.args[0] == pytest.approx(50.0, abs=1.0)
