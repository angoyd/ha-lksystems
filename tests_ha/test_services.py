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
from custom_components.lksystems.services import pause_leak_detection_for_serial

from .conftest import (
    CUBIC_IDENTITY,
    build_cubic_configuration,
    entity_id,
    patch_all_managers,
    patch_services_manager,
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

    with patch_services_manager(fake_manager):
        await hass.services.async_call(
            DOMAIN, "close_valve", {"device_id": device_entry.id}, blocking=True
        )

    assert ("cubic_secure_close_valve", CUBIC_IDENTITY) in fake_manager.calls


async def test_open_valve_calls_client(hass, fake_manager):
    _, device_entry = await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with patch_services_manager(fake_manager):
        await hass.services.async_call(
            DOMAIN, "open_valve", {"device_id": device_entry.id}, blocking=True
        )

    assert ("cubic_secure_open_valve", CUBIC_IDENTITY) in fake_manager.calls


async def test_pause_leak_detection_calls_client(hass, fake_manager):
    _, device_entry = await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with patch_services_manager(fake_manager):
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


async def test_pause_leak_detection_logs_its_own_action(hass, fake_manager, caplog):
    """Regression test: the handler used to log "Closing valve %s",
    copy-pasted from close_valve and never updated."""
    _, device_entry = await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with patch_services_manager(fake_manager), caplog.at_level("INFO"):
        await hass.services.async_call(
            DOMAIN,
            "pause_leak_detection",
            {"device_id": device_entry.id, "seconds": 1800},
            blocking=True,
        )

    assert "closing valve" not in caplog.text.lower()
    assert "pausing leak detection" in caplog.text.lower()


class TestPauseLeakDetectionForSerial:
    """Direct tests for pause_leak_detection_for_serial (see its own
    docstring for why it's called directly rather than only through the
    service)."""

    async def test_calls_the_client(self, hass, fake_manager):
        entry, _ = await _setup_entry_and_get_cubic_device(hass, fake_manager)

        with patch_all_managers(fake_manager):
            await pause_leak_detection_for_serial(hass, entry, CUBIC_IDENTITY, 1800)

        assert (
            "cubic_secure_pause_leak_detection",
            CUBIC_IDENTITY,
            1800,
        ) in fake_manager.calls

    async def test_login_failure_does_not_raise(self, hass, fake_manager):
        entry, _ = await _setup_entry_and_get_cubic_device(hass, fake_manager)
        fake_manager.login_result = False

        with patch_all_managers(fake_manager):
            await pause_leak_detection_for_serial(hass, entry, CUBIC_IDENTITY, 1800)

        assert not any(c[0] == "cubic_secure_pause_leak_detection" for c in fake_manager.calls)

    async def test_refreshes_the_paused_until_sensor(self, hass, fake_manager):
        """Regression test: the refresh used to live only in button.py,
        so calling this function any other way (e.g. the raw HA service)
        never updated the "Leak Detection Paused Until" sensor."""
        entry, _ = await _setup_entry_and_get_cubic_device(hass, fake_manager)
        paused_until_entity_id = entity_id(
            hass, "sensor", f"LkUid_leakDetectionPausedUntil_{CUBIC_IDENTITY}"
        )
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(mute_leak=1800)
        )

        with patch_all_managers(fake_manager):
            await pause_leak_detection_for_serial(hass, entry, CUBIC_IDENTITY, 1800)

        assert hass.states.get(paused_until_entity_id).state != "unknown"

    async def test_sets_the_local_paused_until_target_immediately(
        self, hass, fake_manager
    ):
        """Doesn't wait on the cloud to confirm the pause - muteLeak is
        static and can lag by up to a poll interval, so the coordinator's
        own target is set right away rather than left to reconciliation."""
        entry, _ = await _setup_entry_and_get_cubic_device(hass, fake_manager)
        coordinator = hass.data[DOMAIN][entry.entry_id]

        with patch_all_managers(fake_manager):
            await pause_leak_detection_for_serial(hass, entry, CUBIC_IDENTITY, 1800)

        assert CUBIC_IDENTITY in coordinator.leak_detection_paused_until

    async def test_zero_seconds_clears_the_local_paused_until_target(
        self, hass, fake_manager
    ):
        entry, _ = await _setup_entry_and_get_cubic_device(hass, fake_manager)
        coordinator = hass.data[DOMAIN][entry.entry_id]
        coordinator.set_leak_detection_paused_until(CUBIC_IDENTITY, 1800)

        with patch_all_managers(fake_manager):
            await pause_leak_detection_for_serial(hass, entry, CUBIC_IDENTITY, 0)

        assert CUBIC_IDENTITY not in coordinator.leak_detection_paused_until

    async def test_reuses_one_session_for_the_write_and_its_confirmation_read(
        self, hass, fake_manager
    ):
        """The write (cubic_secure_pause_leak_detection) and its immediate
        confirmation read (refresh_cubic_secure_configuration) used to each
        open their own session - two logins for one logical action."""
        entry, _ = await _setup_entry_and_get_cubic_device(hass, fake_manager)
        fake_manager.calls.clear()

        with patch_all_managers(fake_manager):
            await pause_leak_detection_for_serial(hass, entry, CUBIC_IDENTITY, 1800)

        assert fake_manager.calls.count(("login",)) == 1


async def test_set_pressure_test_schedule_calls_client(hass, fake_manager):
    _, device_entry = await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with patch_services_manager(fake_manager):
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

    with patch_services_manager(fake_manager):
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

    with patch_services_manager(fake_manager):
        await hass.services.async_call(
            DOMAIN, "close_valve", {"device_id": device_entry.id}, blocking=True
        )

    assert not any(c[0] == "cubic_secure_close_valve" for c in fake_manager.calls)


@pytest.mark.parametrize(
    "service,extra_data,client_call",
    [
        ("close_valve", {}, "cubic_secure_close_valve"),
        ("open_valve", {}, "cubic_secure_open_valve"),
        ("pause_leak_detection", {"seconds": 1800}, "cubic_secure_pause_leak_detection"),
        (
            "set_pressure_test_schedule",
            {"hour": 3, "minute": 30},
            "cubic_secure_set_pressure_test_schedule",
        ),
        ("set_thresholds", {}, "cubic_secure_set_thresholds"),
    ],
)
async def test_unknown_device_does_not_raise(
    hass, fake_manager, service, extra_data, client_call
):
    """An unrecognized device_id used to crash with an AttributeError:
    device_entry.serial_number was read before the handler's own
    try/except. It should instead be handled the same way as a missing
    serial number - log and return without calling the client.
    """
    await _setup_entry_and_get_cubic_device(hass, fake_manager)

    with patch_services_manager(fake_manager):
        await hass.services.async_call(
            DOMAIN,
            service,
            {"device_id": "not-a-real-device-id", **extra_data},
            blocking=True,
        )

    assert not any(c[0] == client_call for c in fake_manager.calls)
