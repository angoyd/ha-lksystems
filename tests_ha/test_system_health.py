"""Tests for system_health.py.

Exercises system_health_info() directly against a real config-entry setup,
and async_register() against a fake SystemHealthRegistration to check it
wires up the callback.
"""

from __future__ import annotations

import aiohttp

from custom_components.lksystems.const import CONF_UPDATE_INTERVAL, DOMAIN
from custom_components.lksystems.pylksystems import LKSystemsManager
from custom_components.lksystems.system_health import (
    async_register,
    system_health_info,
)

from .conftest import setup_entry as _setup_entry


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

    async_register(hass=None, register=FakeRegistration())

    assert registered["callback"] is system_health_info
