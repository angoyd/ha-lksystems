"""Tests for system_health.py.

Exercises system_health_info() directly against a real config-entry setup
(see test_integration_setup.py's _setup_entry pattern), and async_register()
against a fake SystemHealthRegistration to check it wires up the callback.
"""

from __future__ import annotations

from unittest.mock import patch

import aiohttp
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lksystems.const import CONF_UPDATE_INTERVAL, DOMAIN
from custom_components.lksystems.pylksystems import LKSystemsManager
from custom_components.lksystems.system_health import (
    async_register,
    system_health_info,
)


async def _setup_entry(hass, manager, options: dict | None = None) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_USERNAME: "user@example.com", CONF_PASSWORD: "hunter2"},
        options=options or {},
    )
    entry.add_to_hass(hass)
    with patch("custom_components.lksystems.LKSystemsManager", return_value=manager):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    return entry


async def test_system_health_reports_last_update_success(hass, fake_manager, aioclient_mock):
    aioclient_mock.get(LKSystemsManager.BASE_URL)
    await _setup_entry(hass, fake_manager)

    info = await system_health_info(hass)

    assert info["last_update_success"] is True


async def test_system_health_reports_update_interval(hass, fake_manager, aioclient_mock):
    aioclient_mock.get(LKSystemsManager.BASE_URL)
    await _setup_entry(hass, fake_manager, options={CONF_UPDATE_INTERVAL: 15})

    info = await system_health_info(hass)

    assert info["update_interval"] == "0:15:00"


async def test_system_health_reports_last_update_failure(hass, fake_manager, aioclient_mock):
    aioclient_mock.get(LKSystemsManager.BASE_URL)
    entry = await _setup_entry(hass, fake_manager)
    coordinator = hass.data[DOMAIN][entry.entry_id]

    fake_manager.get_user_structure_result = False
    await coordinator.async_refresh()

    info = await system_health_info(hass)

    assert info["last_update_success"] is False


async def test_system_health_reports_reachable_server(hass, fake_manager, aioclient_mock):
    aioclient_mock.get(LKSystemsManager.BASE_URL)
    await _setup_entry(hass, fake_manager)

    info = await system_health_info(hass)

    assert info["can_reach_server"] == "ok"


async def test_system_health_reports_unreachable_server(hass, fake_manager, aioclient_mock):
    aioclient_mock.get(LKSystemsManager.BASE_URL, exc=aiohttp.ClientError("boom"))
    await _setup_entry(hass, fake_manager)

    info = await system_health_info(hass)

    assert info["can_reach_server"]["type"] == "failed"


async def test_async_register_registers_info_callback():
    registered = {}

    class FakeRegistration:
        def async_register_info(self, info_callback, info_url=None):
            registered["callback"] = info_callback
            registered["info_url"] = info_url

    async_register(hass=None, register=FakeRegistration())

    assert registered["callback"] is system_health_info
