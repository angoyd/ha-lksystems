"""Tests for number.py: the per-device "Pause Duration" entity.

This entity holds a local preference only - the API has no "get configured
pause duration" endpoint, just "pause for N seconds" on each call - so its
value is read/written straight to the coordinator and persisted via HA's
restore-state mechanism rather than fetched from the coordinator's polled
data. Displayed (and stored) in minutes for readability; the coordinator's
pause_leak_detection_seconds - and everything downstream of it - stays in
seconds, matching the API's own "pause for N seconds" contract.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from homeassistant.const import EntityCategory
from homeassistant.core import State
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import mock_restore_cache_with_extra_data

from custom_components.lksystems.const import (
    DEFAULT_PAUSE_LEAK_DETECTION_SECONDS,
    DOMAIN,
    LK_CUBICSECURE_THRESHOLD_NUMBERS,
    PAUSE_LEAK_DETECTION_MAX_SECONDS,
    PAUSE_LEAK_DETECTION_MIN_SECONDS,
)
from custom_components.lksystems.threshold_writes import LKThresholdWriteCoordinator

from .conftest import (
    CUBIC_IDENTITY,
    CUBIC_IDENTITY_2,
    build_thresholds,
    entity_id,
    pause_leak_detection_duration_unique_id as _number_unique_id,
    patch_all_managers,
    setup_entry,
)

SECONDS_PER_MINUTE = 60
TINY_DEBOUNCE = patch.object(LKThresholdWriteCoordinator, "DEBOUNCE_SECONDS", 0.01)
TINY_TIMING = patch.multiple(
    LKThresholdWriteCoordinator, DEBOUNCE_SECONDS=0.01, FALLBACK_RETRY_SECONDS=0.01
)


async def test_defaults_to_the_service_default(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    number_entity_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY))

    state = hass.states.get(number_entity_id)

    assert (
        float(state.state)
        == DEFAULT_PAUSE_LEAK_DETECTION_SECONDS / SECONDS_PER_MINUTE
    )


async def test_bounds_match_pause_leak_detection_limits(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    number_entity_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY))

    state = hass.states.get(number_entity_id)

    assert (
        float(state.attributes["min"])
        == PAUSE_LEAK_DETECTION_MIN_SECONDS / SECONDS_PER_MINUTE
    )
    assert (
        float(state.attributes["max"])
        == PAUSE_LEAK_DETECTION_MAX_SECONDS / SECONDS_PER_MINUTE
    )


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
        "number", "set_value", {"entity_id": number_entity_id, "value": 15}, blocking=True
    )

    assert coordinator.pause_leak_detection_seconds[CUBIC_IDENTITY] == 900
    assert float(hass.states.get(number_entity_id).state) == 15


async def test_two_cubic_secure_devices_get_independent_durations(
    hass, fake_manager_with_two_cubic_devices
):
    entry = await setup_entry(hass, fake_manager_with_two_cubic_devices)
    first_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY))
    second_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY_2))
    coordinator = hass.data[DOMAIN][entry.entry_id]

    await hass.services.async_call(
        "number", "set_value", {"entity_id": first_id, "value": 5}, blocking=True
    )

    assert coordinator.pause_leak_detection_seconds[CUBIC_IDENTITY] == 300
    assert CUBIC_IDENTITY_2 not in coordinator.pause_leak_detection_seconds
    assert float(hass.states.get(second_id).state) == (
        DEFAULT_PAUSE_LEAK_DETECTION_SECONDS / SECONDS_PER_MINUTE
    )


async def test_restores_last_value_on_startup(hass, fake_manager):
    """Seed the restore cache before the entity is ever created, the way
    HA repopulates it from disk on a real restart - a live entity has no
    prior instance to hand data to, so there's nothing to reload here.
    """
    # Predictable from has_entity_name=True: "<device slug>_<entity slug>".
    number_entity_id = "number.cubic_secure_utility_room_pause_duration"
    mock_restore_cache_with_extra_data(
        hass,
        [
            (
                State(number_entity_id, "30"),
                {
                    "native_max_value": PAUSE_LEAK_DETECTION_MAX_SECONDS
                    / SECONDS_PER_MINUTE,
                    "native_min_value": PAUSE_LEAK_DETECTION_MIN_SECONDS
                    / SECONDS_PER_MINUTE,
                    "native_step": 1,
                    "native_unit_of_measurement": "min",
                    "native_value": 30,
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
    assert float(hass.states.get(number_entity_id).state) == 30


async def test_restores_seconds_data_from_before_the_unit_changed_to_minutes(
    hass, fake_manager
):
    """Regression test: an installation that already had a value restored
    while this entity's native unit was still seconds must not reinterpret
    that raw number as minutes after the change - 300 (seconds) restoring
    as "300 min" would be a 60x jump, not the equivalent ~5 min.
    """
    number_entity_id = "number.cubic_secure_utility_room_pause_duration"
    mock_restore_cache_with_extra_data(
        hass,
        [
            (
                State(number_entity_id, "300"),
                {
                    "native_max_value": PAUSE_LEAK_DETECTION_MAX_SECONDS,
                    "native_min_value": PAUSE_LEAK_DETECTION_MIN_SECONDS,
                    "native_step": 60,
                    "native_unit_of_measurement": "s",
                    "native_value": 300,
                },
            )
        ],
    )

    entry = await setup_entry(hass, fake_manager)

    coordinator = hass.data[DOMAIN][entry.entry_id]
    assert coordinator.pause_leak_detection_seconds[CUBIC_IDENTITY] == 300
    assert float(hass.states.get(number_entity_id).state) == 5


class TestLeakDetectionThresholdNumbers:
    """The six leak-detection threshold entities - see
    LKThresholdNumberDescription's own docstring for the field
    scope/units, chosen to match what the LK app itself exposes.
    """

    async def test_reads_current_values_from_the_coordinator(
        self, hass, fake_manager
    ):
        await setup_entry(hass, fake_manager)

        assert (
            float(
                hass.states.get(
                    entity_id(hass, "number", f"LkUid_large_leak_threshold_{CUBIC_IDENTITY}")
                ).state
            )
            == 1500.0
        )
        assert (
            float(
                hass.states.get(
                    entity_id(hass, "number", f"LkUid_medium_leak_threshold_{CUBIC_IDENTITY}")
                ).state
            )
            == 10.0
        )
        assert (
            float(
                hass.states.get(
                    entity_id(hass, "number", f"LkUid_pressure_sensitivity_{CUBIC_IDENTITY}")
                ).state
            )
            == 0.3
        )

    async def test_medium_leak_delay_is_converted_to_minutes(self, hass, fake_manager):
        """build_thresholds()'s medium-leak delay is 1800s (30 min) - the
        one field this platform displays in minutes rather than the raw
        API seconds, the same seconds-to-minutes boundary Pause Duration
        already uses."""
        await setup_entry(hass, fake_manager)

        state = hass.states.get(
            entity_id(hass, "number", f"LkUid_medium_leak_delay_{CUBIC_IDENTITY}")
        )

        assert float(state.state) == 30
        assert state.attributes["unit_of_measurement"] == "min"

    async def test_belongs_to_the_cubic_secure_device(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)

        device = dr.async_get(hass).async_get_device(
            identifiers={(DOMAIN, CUBIC_IDENTITY)}
        )
        entry = er.async_get(hass).async_get(
            entity_id(hass, "number", f"LkUid_large_leak_threshold_{CUBIC_IDENTITY}")
        )

        assert entry.device_id == device.id

    async def test_is_a_configuration_entity(self, hass, fake_manager):
        """These are set-once tuning values, not something you operate
        moment-to-moment - entity_category=CONFIG puts them in the device
        page's separate Configuration section instead of mixed in with
        Controls (the valve, Pause Duration/buttons), matching how the LK
        app itself keeps "Advanced alarm settings" on its own screen,
        apart from the main dashboard.
        """
        await setup_entry(hass, fake_manager)

        entry = er.async_get(hass).async_get(
            entity_id(hass, "number", f"LkUid_large_leak_threshold_{CUBIC_IDENTITY}")
        )

        assert entry.entity_category is EntityCategory.CONFIG

    async def test_setting_a_value_carries_over_every_other_current_value(
        self, hass, fake_manager
    ):
        """The write is a full-object POST, not a per-field patch -
        changing one control must not silently reset any other currently
        configured value. This is the exact bug the old set_thresholds
        service had (see its own test coverage in test_services.py)."""
        await setup_entry(hass, fake_manager)
        large_leak_threshold_id = entity_id(
            hass, "number", f"LkUid_large_leak_threshold_{CUBIC_IDENTITY}"
        )

        with TINY_DEBOUNCE, patch_all_managers(fake_manager):
            await hass.services.async_call(
                "number",
                "set_value",
                {"entity_id": large_leak_threshold_id, "value": 2000},
                blocking=True,
            )
            await asyncio.sleep(0.05)

        threshold_calls = [
            c for c in fake_manager.calls if c[0] == "cubic_secure_set_thresholds"
        ]
        assert len(threshold_calls) == 1
        sent = threshold_calls[0][2]
        assert sent == build_thresholds(large_leak_threshold=2000.0)

    async def test_delay_entity_writes_both_close_and_notification_delay(
        self, hass, fake_manager
    ):
        """One displayed "delay" control maps to two API fields at once -
        confirmed against a real account that the app's single delay
        slider per leak category writes the same value to both."""
        await setup_entry(hass, fake_manager)
        large_leak_delay_id = entity_id(
            hass, "number", f"LkUid_large_leak_delay_{CUBIC_IDENTITY}"
        )

        with TINY_DEBOUNCE, patch_all_managers(fake_manager):
            await hass.services.async_call(
                "number",
                "set_value",
                {"entity_id": large_leak_delay_id, "value": 60},
                blocking=True,
            )
            await asyncio.sleep(0.05)

        sent = next(
            c[2] for c in fake_manager.calls if c[0] == "cubic_secure_set_thresholds"
        )
        assert sent["leakLarge"]["closeDelay"] == 60
        assert sent["leakLarge"]["notificationDelay"] == 60
        assert sent == build_thresholds(
            large_leak_close_delay=60, large_leak_notification_delay=60
        )

    async def test_edit_displays_immediately_before_the_debounced_write(
        self, hass, fake_manager
    ):
        """Typing a new value should show up right away - the point of
        staging on the shared write coordinator rather than writing (and
        waiting on the API) on every keystroke."""
        await setup_entry(hass, fake_manager)
        large_leak_threshold_id = entity_id(
            hass, "number", f"LkUid_large_leak_threshold_{CUBIC_IDENTITY}"
        )

        with patch_all_managers(fake_manager):
            await hass.services.async_call(
                "number",
                "set_value",
                {"entity_id": large_leak_threshold_id, "value": 2000},
                blocking=True,
            )

        assert float(hass.states.get(large_leak_threshold_id).state) == 2000.0
        assert not any(
            c[0] == "cubic_secure_set_thresholds" for c in fake_manager.calls
        )

    async def test_becomes_unavailable_while_a_write_is_blocked_and_recovers(
        self, hass, fake_manager
    ):
        """A failure on the shared thresholds endpoint should be visible
        on every entity that writes to it, not just the one that
        triggered it - confirmed here for a second, unrelated field."""
        await setup_entry(hass, fake_manager)
        large_leak_threshold_id = entity_id(
            hass, "number", f"LkUid_large_leak_threshold_{CUBIC_IDENTITY}"
        )
        medium_leak_threshold_id = entity_id(
            hass, "number", f"LkUid_medium_leak_threshold_{CUBIC_IDENTITY}"
        )
        fake_manager.cubic_secure_set_thresholds_result = False

        with TINY_TIMING, patch_all_managers(fake_manager):
            await hass.services.async_call(
                "number",
                "set_value",
                {"entity_id": large_leak_threshold_id, "value": 2000},
                blocking=True,
            )
            await asyncio.sleep(0.02)

            assert hass.states.get(large_leak_threshold_id).state == "unavailable"
            assert hass.states.get(medium_leak_threshold_id).state == "unavailable"

            fake_manager.cubic_secure_set_thresholds_result = True
            await asyncio.sleep(0.05)

        assert hass.states.get(large_leak_threshold_id).state != "unavailable"
        assert hass.states.get(medium_leak_threshold_id).state != "unavailable"

    @pytest.mark.parametrize(
        ("key", "native_min_value", "native_max_value", "native_step"),
        [
            ("large_leak_threshold", 500, 2500, 50),
            ("large_leak_delay", 30, 120, 10),
            ("medium_leak_threshold", 2, 30, 1),
            ("medium_leak_delay", 5, 120, 5),
            ("pressure_sensitivity", 0.2, 0.8, 0.1),
            ("pressure_duration", 45, 150, 1),
        ],
    )
    def test_field_scope_matches_the_app(
        self, key, native_min_value, native_max_value, native_step
    ):
        """Min/max/step come from the LK app's own Advanced alarm settings
        screen (dragging every slider to both extremes on a real account),
        not just the raw API schema."""
        description = LK_CUBICSECURE_THRESHOLD_NUMBERS[key]

        assert description.native_min_value == native_min_value
        assert description.native_max_value == native_max_value
        assert description.native_step == native_step
