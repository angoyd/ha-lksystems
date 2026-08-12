"""Unit tests for the pylksystems API client.

These tests mock the HTTP layer with aioresponses so they exercise the
client's parsing/branching logic (auth flow, device-list normalization,
merge/dedupe, error handling) without ever hitting the real LK Systems API.
"""

from __future__ import annotations

import logging

from aiohttp import ClientConnectionError
from aioresponses import aioresponses

BASE_URL = "https://link2.lk.nu/"


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

    async def test_connection_error_is_handled(self, manager):
        with aioresponses() as m:
            m.post(BASE_URL + "auth/auth/login", exception=ClientConnectionError())
            async with manager:
                result = await manager.login()

        assert result is False


class TestGetUserStructure:
    async def test_success_uses_first_element_of_list(self, manager):
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
        assert manager.user_structure == {"realestateId": "re-1", "cacheUpdated": 111}

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
        assert manager.cubic_secure_messurement == {"flow": 1.5}

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
        assert manager.cubic_secure_messurement == {"flow": 0.0}

    async def test_error_status_returns_false_and_keeps_state(self, manager):
        with aioresponses() as m:
            m.get(
                BASE_URL + "service/cubic/secure/cubic-1/measurement/0",
                status=404,
            )
            async with manager:
                result = await manager.get_cubic_secure_measurement("cubic-1")

        assert result is False
        assert manager.cubic_secure_messurement is None


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
