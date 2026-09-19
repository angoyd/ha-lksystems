"""Tests for switch.py: the "Micro Leak Valve Prevention" switch.

Confirmed empirically against a real device (a before/after diagnostics
diff around toggling the app's own "prevent valve closing" control): it
isn't a separate API field, it overloads thresholds.pressure.closeDelay -
see PREVENT_VALVE_CLOSING_SENTINEL's own comment in const.py for why.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from homeassistant.const import EntityCategory
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from custom_components.lksystems.const import (
    DOMAIN,
    PREVENT_VALVE_CLOSING_SENTINEL,
    PRESSURE_CLOSE_DELAY_DEFAULT,
)
from custom_components.lksystems.threshold_writes import LKThresholdWriteCoordinator

from .conftest import (
    CUBIC_IDENTITY,
    build_cubic_configuration,
    build_thresholds,
    entity_id,
    patch_all_managers,
    setup_entry,
)

TINY_TIMING = patch.multiple(
    LKThresholdWriteCoordinator, DEBOUNCE_SECONDS=0.01, FALLBACK_RETRY_SECONDS=0.01
)


def _switch_unique_id(device_identity: str) -> str:
    return f"LkUid_preventValveClosing_{device_identity}"


async def test_belongs_to_the_cubic_secure_device(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    switch_entity_id = entity_id(hass, "switch", _switch_unique_id(CUBIC_IDENTITY))

    device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, CUBIC_IDENTITY)})
    registry_entry = er.async_get(hass).async_get(switch_entity_id)

    assert registry_entry.device_id == device.id


async def test_is_a_configuration_entity(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    registry_entry = er.async_get(hass).async_get(
        entity_id(hass, "switch", _switch_unique_id(CUBIC_IDENTITY))
    )

    assert registry_entry.entity_category is EntityCategory.CONFIG


async def test_is_off_when_close_delay_is_the_default(hass, fake_manager):
    fake_manager.cubic_configuration_data = build_cubic_configuration(
        thresholds=build_thresholds(pressure_close_delay=PRESSURE_CLOSE_DELAY_DEFAULT)
    )
    await setup_entry(hass, fake_manager)

    state = hass.states.get(entity_id(hass, "switch", _switch_unique_id(CUBIC_IDENTITY)))

    assert state.state == "off"


async def test_is_on_when_the_sentinel_is_set(hass, fake_manager):
    fake_manager.cubic_configuration_data = build_cubic_configuration(
        thresholds=build_thresholds(pressure_close_delay=PREVENT_VALVE_CLOSING_SENTINEL)
    )
    await setup_entry(hass, fake_manager)

    state = hass.states.get(entity_id(hass, "switch", _switch_unique_id(CUBIC_IDENTITY)))

    assert state.state == "on"


async def test_turning_on_writes_the_sentinel_and_carries_over_other_fields(
    hass, fake_manager
):
    await setup_entry(hass, fake_manager)
    switch_entity_id = entity_id(hass, "switch", _switch_unique_id(CUBIC_IDENTITY))

    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "switch", "turn_on", {"entity_id": switch_entity_id}, blocking=True
        )

    sent = next(
        c[2] for c in fake_manager.calls if c[0] == "cubic_secure_set_thresholds"
    )
    assert sent == build_thresholds(pressure_close_delay=PREVENT_VALVE_CLOSING_SENTINEL)


async def test_turning_off_restores_the_default_and_carries_over_other_fields(
    hass, fake_manager
):
    fake_manager.cubic_configuration_data = build_cubic_configuration(
        thresholds=build_thresholds(pressure_close_delay=PREVENT_VALVE_CLOSING_SENTINEL)
    )
    await setup_entry(hass, fake_manager)
    switch_entity_id = entity_id(hass, "switch", _switch_unique_id(CUBIC_IDENTITY))

    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "switch", "turn_off", {"entity_id": switch_entity_id}, blocking=True
        )

    sent = next(
        c[2] for c in fake_manager.calls if c[0] == "cubic_secure_set_thresholds"
    )
    assert sent == build_thresholds(pressure_close_delay=PRESSURE_CLOSE_DELAY_DEFAULT)


async def test_becomes_unavailable_while_a_write_is_blocked_and_recovers(
    hass, fake_manager
):
    """A one-shot control still shares the device's thresholds endpoint,
    so a failed write blocks it (and every other entity on that
    endpoint) exactly like a debounced number edit would."""
    await setup_entry(hass, fake_manager)
    switch_entity_id = entity_id(hass, "switch", _switch_unique_id(CUBIC_IDENTITY))
    fake_manager.cubic_secure_set_thresholds_result = False

    with TINY_TIMING, patch_all_managers(fake_manager):
        await hass.services.async_call(
            "switch", "turn_on", {"entity_id": switch_entity_id}, blocking=True
        )
        assert hass.states.get(switch_entity_id).state == "unavailable"

        fake_manager.cubic_secure_set_thresholds_result = True
        await asyncio.sleep(0.05)

    assert hass.states.get(switch_entity_id).state != "unavailable"
