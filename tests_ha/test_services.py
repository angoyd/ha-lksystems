"""Tests for the service call handlers registered by services.py.

The valve/threshold/schedule services operate on Cubic Secure devices, so
each test sets up a full config entry (giving us a real HA device created
from AbstractLkCubicSensor.device_info, which is the only device_info in
this integration that carries a serial_number - see close_valve() et al.
reading device_entry.serial_number) and drives the services through
hass.services.async_call().
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lksystems.const import DOMAIN

from .conftest import CUBIC_IDENTITY


def _patch_services_manager(manager):
    return patch(
        "custom_components.lksystems.services.LKSystemsManager", return_value=manager
    )


async def _setup_entry_and_get_cubic_device(hass, manager):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_USERNAME: "user@example.com", CONF_PASSWORD: "hunter2"},
    )
    entry.add_to_hass(hass)
    with patch("custom_components.lksystems.LKSystemsManager", return_value=manager):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    device_entry = dr.async_get(hass).async_get_device(
        identifiers={(DOMAIN, CUBIC_IDENTITY)}
    )
    assert device_entry is not None
    assert device_entry.serial_number == CUBIC_IDENTITY
    return entry, device_entry


async def test_close_valve_calls_client(hass, fake_manager):
    _, device_entry = await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with _patch_services_manager(fake_manager):
        await hass.services.async_call(
            DOMAIN, "close_valve", {"device_id": device_entry.id}, blocking=True
        )

    assert ("cubic_secure_close_valve", CUBIC_IDENTITY) in fake_manager.calls


async def test_open_valve_calls_client(hass, fake_manager):
    _, device_entry = await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with _patch_services_manager(fake_manager):
        await hass.services.async_call(
            DOMAIN, "open_valve", {"device_id": device_entry.id}, blocking=True
        )

    assert ("cubic_secure_open_valve", CUBIC_IDENTITY) in fake_manager.calls


async def test_pause_leak_detection_calls_client(hass, fake_manager):
    _, device_entry = await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with _patch_services_manager(fake_manager):
        await hass.services.async_call(
            DOMAIN,
            "pause_leak_detection",
            {"device_id": device_entry.id, "seconds": 1800},
            blocking=True,
        )

    assert (
        "cubic_secure_pause_leak_detection",
        CUBIC_IDENTITY,
        1800,
    ) in fake_manager.calls


async def test_set_pressure_test_schedule_calls_client(hass, fake_manager):
    _, device_entry = await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with _patch_services_manager(fake_manager):
        await hass.services.async_call(
            DOMAIN,
            "set_pressure_test_schedule",
            {"device_id": device_entry.id, "hour": 3, "minute": 30},
            blocking=True,
        )

    assert (
        "cubic_secure_set_pressure_test_schedule",
        CUBIC_IDENTITY,
        3,
        30,
    ) in fake_manager.calls


async def test_set_thresholds_calls_client_with_defaults(hass, fake_manager):
    _, device_entry = await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with _patch_services_manager(fake_manager):
        await hass.services.async_call(
            DOMAIN,
            "set_thresholds",
            {"device_id": device_entry.id},
            blocking=True,
        )

    threshold_calls = [
        c for c in fake_manager.calls if c[0] == "cubic_secure_set_thresholds"
    ]
    assert len(threshold_calls) == 1
    assert threshold_calls[0][1] == CUBIC_IDENTITY
    thresholds = threshold_calls[0][2]
    assert thresholds["pressure"]["sensitivity"] == 0.3
    assert thresholds["leakLarge"]["threshold"] == 1500.0


async def test_close_valve_login_failure_does_not_raise(hass, fake_manager):
    """Handler catches the login failure inside its try/except and just logs."""
    _, device_entry = await _setup_entry_and_get_cubic_device(hass, fake_manager)
    fake_manager.login_result = False

    with _patch_services_manager(fake_manager):
        await hass.services.async_call(
            DOMAIN, "close_valve", {"device_id": device_entry.id}, blocking=True
        )

    assert not any(c[0] == "cubic_secure_close_valve" for c in fake_manager.calls)


async def test_close_valve_unknown_device_raises(hass, fake_manager):
    """Documents current (buggy) behavior: device_entry.serial_number is
    read before the handler's own try/except, so an unrecognized
    device_id crashes with an AttributeError instead of being handled
    gracefully. Not fixed here - see TODO.local.md.
    """
    await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with _patch_services_manager(fake_manager):
        with pytest.raises(Exception):
            await hass.services.async_call(
                DOMAIN,
                "close_valve",
                {"device_id": "not-a-real-device-id"},
                blocking=True,
            )
