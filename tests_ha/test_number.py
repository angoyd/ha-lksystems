"""Tests for number.py: the per-device "Pause Leak Detection Duration" entity.

This entity holds a local preference only - the API has no "get configured
pause duration" endpoint, just "pause for N seconds" on each call - so its
value is read/written straight to the coordinator and persisted via HA's
restore-state mechanism rather than fetched from the coordinator's polled
data.
"""

from __future__ import annotations

from homeassistant.core import State
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import mock_restore_cache_with_extra_data

from custom_components.lksystems.const import (
    DEFAULT_PAUSE_LEAK_DETECTION_SECONDS,
    DOMAIN,
    PAUSE_LEAK_DETECTION_MAX_SECONDS,
    PAUSE_LEAK_DETECTION_MIN_SECONDS,
)

from .conftest import (
    CUBIC_IDENTITY,
    CUBIC_IDENTITY_2,
    entity_id,
    pause_leak_detection_duration_unique_id as _number_unique_id,
    setup_entry,
)


async def test_defaults_to_the_service_default(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    number_entity_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY))

    state = hass.states.get(number_entity_id)

    assert float(state.state) == DEFAULT_PAUSE_LEAK_DETECTION_SECONDS


async def test_bounds_match_pause_leak_detection_limits(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    number_entity_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY))

    state = hass.states.get(number_entity_id)

    assert float(state.attributes["min"]) == PAUSE_LEAK_DETECTION_MIN_SECONDS
    assert float(state.attributes["max"]) == PAUSE_LEAK_DETECTION_MAX_SECONDS


async def test_belongs_to_the_cubic_secure_device(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    number_entity_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY))

    device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, CUBIC_IDENTITY)})
    entry = er.async_get(hass).async_get(number_entity_id)

    assert entry.device_id == device.id


async def test_setting_a_value_updates_the_coordinator(hass, fake_manager):
    entry = await setup_entry(hass, fake_manager)
    number_entity_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY))
    coordinator = hass.data[DOMAIN][entry.entry_id]

    await hass.services.async_call(
        "number", "set_value", {"entity_id": number_entity_id, "value": 900}, blocking=True
    )

    assert coordinator.pause_leak_detection_seconds[CUBIC_IDENTITY] == 900
    assert float(hass.states.get(number_entity_id).state) == 900


async def test_two_cubic_secure_devices_get_independent_durations(
    hass, fake_manager_with_two_cubic_devices
):
    entry = await setup_entry(hass, fake_manager_with_two_cubic_devices)
    first_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY))
    second_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY_2))
    coordinator = hass.data[DOMAIN][entry.entry_id]

    await hass.services.async_call(
        "number", "set_value", {"entity_id": first_id, "value": 300}, blocking=True
    )

    assert coordinator.pause_leak_detection_seconds[CUBIC_IDENTITY] == 300
    assert CUBIC_IDENTITY_2 not in coordinator.pause_leak_detection_seconds
    assert float(hass.states.get(second_id).state) == DEFAULT_PAUSE_LEAK_DETECTION_SECONDS


async def test_restores_last_value_on_startup(hass, fake_manager):
    """Seed the restore cache before the entity is ever created, the way
    HA repopulates it from disk on a real restart - a live entity has no
    prior instance to hand data to, so there's nothing to reload here.
    """
    # Predictable from has_entity_name=True: "<device slug>_<entity slug>".
    number_entity_id = "number.cubic_secure_utility_room_pause_leak_detection_duration"
    mock_restore_cache_with_extra_data(
        hass,
        [
            (
                State(number_entity_id, "1800"),
                {
                    "native_max_value": PAUSE_LEAK_DETECTION_MAX_SECONDS,
                    "native_min_value": PAUSE_LEAK_DETECTION_MIN_SECONDS,
                    "native_step": 60,
                    "native_unit_of_measurement": "s",
                    "native_value": 1800,
                },
            )
        ],
    )

    entry = await setup_entry(hass, fake_manager)

    # Confirms the guessed entity_id above actually matches what HA
    # assigned - if slugify rules ever changed, this fails loudly instead
    # of the restore silently not applying.
    assert entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY)) == number_entity_id

    coordinator = hass.data[DOMAIN][entry.entry_id]
    assert coordinator.pause_leak_detection_seconds[CUBIC_IDENTITY] == 1800
    assert float(hass.states.get(number_entity_id).state) == 1800
