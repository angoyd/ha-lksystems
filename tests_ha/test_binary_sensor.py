"""Tests for binary_sensor.py: the "Rate Limited" flag.

A glanceable, always-available companion to the threshold entities going
unavailable while blocked - so a user can tell "this is a temporary
rate-limit cooldown" apart from any other reason an entity might be
unavailable, without having to check the notification drawer or Logbook.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from homeassistant.const import EntityCategory
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from custom_components.lksystems.const import DOMAIN
from custom_components.lksystems.threshold_writes import LKThresholdWriteCoordinator

from .conftest import CUBIC_IDENTITY, entity_id, patch_all_managers, setup_entry

TINY_TIMING = patch.multiple(
    LKThresholdWriteCoordinator, DEBOUNCE_SECONDS=0.01, FALLBACK_RETRY_SECONDS=0.01
)


def _rate_limited_unique_id(device_identity: str) -> str:
    return f"LkUid_rateLimited_{device_identity}"


async def test_belongs_to_the_cubic_secure_device(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    rate_limited_entity_id = entity_id(
        hass, "binary_sensor", _rate_limited_unique_id(CUBIC_IDENTITY)
    )

    device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, CUBIC_IDENTITY)})
    registry_entry = er.async_get(hass).async_get(rate_limited_entity_id)

    assert registry_entry.device_id == device.id


async def test_is_a_diagnostic_entity(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    registry_entry = er.async_get(hass).async_get(
        entity_id(hass, "binary_sensor", _rate_limited_unique_id(CUBIC_IDENTITY))
    )

    assert registry_entry.entity_category is EntityCategory.DIAGNOSTIC


async def test_is_off_by_default(hass, fake_manager):
    await setup_entry(hass, fake_manager)

    state = hass.states.get(
        entity_id(hass, "binary_sensor", _rate_limited_unique_id(CUBIC_IDENTITY))
    )

    assert state.state == "off"


async def test_turns_on_while_blocked_and_off_on_recovery(hass, fake_manager):
    entry = await setup_entry(hass, fake_manager)
    coordinator = hass.data[DOMAIN][entry.entry_id]
    write_coordinator = coordinator.get_threshold_write_coordinator(CUBIC_IDENTITY)
    rate_limited_entity_id = entity_id(
        hass, "binary_sensor", _rate_limited_unique_id(CUBIC_IDENTITY)
    )
    fake_manager.cubic_secure_set_thresholds_result = False

    with TINY_TIMING, patch_all_managers(fake_manager):
        write_coordinator.stage("leakLarge", {"threshold": 2000.0})
        await asyncio.sleep(0.02)
        assert hass.states.get(rate_limited_entity_id).state == "on"

        fake_manager.cubic_secure_set_thresholds_result = True
        await asyncio.sleep(0.05)

    assert hass.states.get(rate_limited_entity_id).state == "off"


async def test_stays_available_while_blocked(hass, fake_manager):
    """Unlike the writable entities, this flag must stay available even
    while they're all unavailable - it's the one place a user can see
    *why*."""
    entry = await setup_entry(hass, fake_manager)
    coordinator = hass.data[DOMAIN][entry.entry_id]
    write_coordinator = coordinator.get_threshold_write_coordinator(CUBIC_IDENTITY)
    rate_limited_entity_id = entity_id(
        hass, "binary_sensor", _rate_limited_unique_id(CUBIC_IDENTITY)
    )
    fake_manager.cubic_secure_set_thresholds_result = False

    with TINY_TIMING, patch_all_managers(fake_manager):
        write_coordinator.stage("leakLarge", {"threshold": 2000.0})
        await asyncio.sleep(0.02)

        assert hass.states.get(rate_limited_entity_id).state not in (
            "unavailable",
            "unknown",
        )
