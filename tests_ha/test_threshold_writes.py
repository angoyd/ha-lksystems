"""Tests for threshold_writes.py's LKThresholdWriteCoordinator.

DEBOUNCE_SECONDS/FALLBACK_RETRY_SECONDS are patched down to a few
milliseconds throughout so these tests can wait out a real timer instead
of taking the production 5s/30s - see tiny_valve_retry_timings() in
conftest.py for the established reason simulated-time helpers
(async_fire_time_changed) can't drive this kind of test.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from homeassistant.components.persistent_notification import (
    _async_get_or_create_notifications,
)

from custom_components.lksystems.const import DOMAIN
from custom_components.lksystems.threshold_writes import LKThresholdWriteCoordinator

from .conftest import CUBIC_IDENTITY, build_thresholds, patch_all_managers, setup_entry

TINY_TIMING = patch.multiple(
    LKThresholdWriteCoordinator,
    DEBOUNCE_SECONDS=0.01,
    FALLBACK_RETRY_SECONDS=0.01,
)


async def _get_write_coordinator(hass, fake_manager) -> LKThresholdWriteCoordinator:
    coordinator, write_coordinator = await _get_coordinator_and_write_coordinator(
        hass, fake_manager
    )
    return write_coordinator


async def _get_coordinator_and_write_coordinator(hass, fake_manager):
    entry = await setup_entry(hass, fake_manager)
    coordinator = hass.data[DOMAIN][entry.entry_id]
    return coordinator, coordinator.get_threshold_write_coordinator(CUBIC_IDENTITY)


async def test_stage_does_not_write_immediately(hass, fake_manager):
    write_coordinator = await _get_write_coordinator(hass, fake_manager)

    with patch_all_managers(fake_manager):
        write_coordinator.stage("leakLarge", {"threshold": 2000.0})

    assert not any(c[0] == "cubic_secure_set_thresholds" for c in fake_manager.calls)


async def test_debounce_collapses_multiple_edits_into_one_write(hass, fake_manager):
    with TINY_TIMING:
        write_coordinator = await _get_write_coordinator(hass, fake_manager)

        with patch_all_managers(fake_manager):
            write_coordinator.stage("leakLarge", {"threshold": 2000.0})
            await asyncio.sleep(0.005)
            write_coordinator.stage("pressure", {"sensitivity": 0.5})
            await asyncio.sleep(0.05)

    threshold_calls = [
        c for c in fake_manager.calls if c[0] == "cubic_secure_set_thresholds"
    ]
    assert len(threshold_calls) == 1
    sent = threshold_calls[0][2]
    assert sent == build_thresholds(large_leak_threshold=2000.0, pressure_sensitivity=0.5)


async def test_successful_write_is_not_blocked(hass, fake_manager):
    with TINY_TIMING:
        write_coordinator = await _get_write_coordinator(hass, fake_manager)

        with patch_all_managers(fake_manager):
            write_coordinator.stage("leakLarge", {"threshold": 2000.0})
            await asyncio.sleep(0.05)

    assert write_coordinator.is_blocked is False


async def test_failed_write_blocks_then_retries_and_recovers(hass, fake_manager):
    with TINY_TIMING:
        write_coordinator = await _get_write_coordinator(hass, fake_manager)
        fake_manager.cubic_secure_set_thresholds_result = False

        with patch_all_managers(fake_manager):
            write_coordinator.stage("leakLarge", {"threshold": 2000.0})
            await asyncio.sleep(0.02)
            assert write_coordinator.is_blocked is True

            fake_manager.cubic_secure_set_thresholds_result = True
            await asyncio.sleep(0.05)

    assert write_coordinator.is_blocked is False
    threshold_calls = [
        c for c in fake_manager.calls if c[0] == "cubic_secure_set_thresholds"
    ]
    assert len(threshold_calls) >= 2


async def test_gives_up_after_max_attempts_and_discards_the_edit(hass, fake_manager):
    with TINY_TIMING:
        write_coordinator = await _get_write_coordinator(hass, fake_manager)
        fake_manager.cubic_secure_set_thresholds_result = False

        with patch_all_managers(fake_manager):
            write_coordinator.stage("leakLarge", {"threshold": 2000.0})
            await asyncio.sleep(0.2)

    assert write_coordinator.is_blocked is False
    threshold_calls = [
        c for c in fake_manager.calls if c[0] == "cubic_secure_set_thresholds"
    ]
    assert len(threshold_calls) == LKThresholdWriteCoordinator.MAX_RETRY_ATTEMPTS


async def test_never_flickers_back_to_unblocked_mid_retry(hass, fake_manager):
    """is_blocked must go True once and stay True through every retry -
    never toggle back to False until final resolution."""
    with TINY_TIMING:
        coordinator, write_coordinator = await _get_coordinator_and_write_coordinator(
            hass, fake_manager
        )
        fake_manager.cubic_secure_set_thresholds_result = False
        observed = []
        coordinator.async_add_listener(lambda: observed.append(write_coordinator.is_blocked))

        with patch_all_managers(fake_manager):
            write_coordinator.stage("leakLarge", {"threshold": 2000.0})
            await asyncio.sleep(0.2)

    # First update is when it becomes blocked (True); nothing in between
    # should ever have gone back to False before the final give-up.
    assert observed[0] is True
    assert all(observed[:-1]) or len(observed) == 1


async def test_coordinator_listeners_are_updated_on_block_and_resolve(
    hass, fake_manager
):
    """Entities learn about a block/resolve through the device's own
    coordinator listeners - the same mechanism every CoordinatorEntity on
    that device already listens through, not a bespoke registration."""
    with TINY_TIMING:
        coordinator, write_coordinator = await _get_coordinator_and_write_coordinator(
            hass, fake_manager
        )
        fake_manager.cubic_secure_set_thresholds_result = False
        update_count = 0

        def _count_update():
            nonlocal update_count
            update_count += 1

        coordinator.async_add_listener(_count_update)

        with patch_all_managers(fake_manager):
            write_coordinator.stage("leakLarge", {"threshold": 2000.0})
            await asyncio.sleep(0.02)
            assert update_count == 1  # the transition into blocked

            fake_manager.cubic_secure_set_thresholds_result = True
            await asyncio.sleep(0.05)

    # At least one more update for the transition back out of blocked - the
    # successful write's own configuration refresh also notifies listeners,
    # so this may be more than one.
    assert update_count > 1


async def test_persistent_notification_created_on_block_and_dismissed_on_recovery(
    hass, fake_manager
):
    with TINY_TIMING:
        write_coordinator = await _get_write_coordinator(hass, fake_manager)
        fake_manager.cubic_secure_set_thresholds_result = False

        with patch_all_managers(fake_manager):
            write_coordinator.stage("leakLarge", {"threshold": 2000.0})
            await asyncio.sleep(0.02)

        notification_id = write_coordinator._notification_id
        assert notification_id in _async_get_or_create_notifications(hass)

        with patch_all_managers(fake_manager):
            fake_manager.cubic_secure_set_thresholds_result = True
            await asyncio.sleep(0.05)

    assert notification_id not in _async_get_or_create_notifications(hass)


async def test_async_shutdown_cancels_a_pending_timer(hass, fake_manager):
    with TINY_TIMING:
        write_coordinator = await _get_write_coordinator(hass, fake_manager)

        with patch_all_managers(fake_manager):
            write_coordinator.stage("leakLarge", {"threshold": 2000.0})
            write_coordinator.async_shutdown()
            await asyncio.sleep(0.05)

    assert not any(c[0] == "cubic_secure_set_thresholds" for c in fake_manager.calls)
