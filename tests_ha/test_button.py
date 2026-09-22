"""Tests for button.py: the per-device "Pause Leak Detection" button.

A one-tap dashboard alternative to calling the pause_leak_detection service
by hand - it uses whichever duration is currently set on the device's
"Pause Duration" number entity (see test_number.py).
"""

from __future__ import annotations

from homeassistant.const import EntityCategory
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from custom_components.lksystems.const import (
    DEFAULT_PAUSE_LEAK_DETECTION_SECONDS,
    DOMAIN,
    LK_CUBICSECURE_THRESHOLD_FACTORY_DEFAULTS,
)

from .conftest import (
    CUBIC_IDENTITY,
    CUBIC_IDENTITY_2,
    build_cubic_configuration,
    entity_id,
    patch_all_managers,
    pause_leak_detection_duration_unique_id as _number_unique_id,
    setup_entry,
)


def _button_unique_id(device_identity: str) -> str:
    return f"LkUid_pause_leak_detection_{device_identity}"


def _resume_button_unique_id(device_identity: str) -> str:
    return f"LkUid_resume_leak_detection_{device_identity}"


def _reset_thresholds_button_unique_id(device_identity: str) -> str:
    return f"LkUid_reset_thresholds_to_defaults_{device_identity}"


async def test_belongs_to_the_cubic_secure_device(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    button_entity_id = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY))

    device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, CUBIC_IDENTITY)})
    entry = er.async_get(hass).async_get(button_entity_id)

    assert entry.device_id == device.id


async def test_press_pauses_leak_detection_for_the_default_duration(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    button_entity_id = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY))

    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "button", "press", {"entity_id": button_entity_id}, blocking=True
        )

    assert (
        "cubic_secure_pause_leak_detection",
        CUBIC_IDENTITY,
        DEFAULT_PAUSE_LEAK_DETECTION_SECONDS,
    ) in fake_manager.calls


async def test_press_uses_the_configured_duration(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    number_entity_id = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY))
    button_entity_id = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY))

    await hass.services.async_call(
        "number", "set_value", {"entity_id": number_entity_id, "value": 15}, blocking=True
    )

    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "button", "press", {"entity_id": button_entity_id}, blocking=True
        )

    assert (
        "cubic_secure_pause_leak_detection",
        CUBIC_IDENTITY,
        900,
    ) in fake_manager.calls


async def test_two_cubic_secure_devices_have_independent_buttons(
    hass, fake_manager_with_two_cubic_devices
):
    await setup_entry(hass, fake_manager_with_two_cubic_devices)
    first_number = entity_id(hass, "number", _number_unique_id(CUBIC_IDENTITY))
    first_button = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY))
    second_button = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY_2))

    await hass.services.async_call(
        "number", "set_value", {"entity_id": first_number, "value": 2}, blocking=True
    )

    with patch_all_managers(fake_manager_with_two_cubic_devices):
        await hass.services.async_call(
            "button", "press", {"entity_id": first_button}, blocking=True
        )
        await hass.services.async_call(
            "button", "press", {"entity_id": second_button}, blocking=True
        )

    calls = fake_manager_with_two_cubic_devices.calls
    assert ("cubic_secure_pause_leak_detection", CUBIC_IDENTITY, 120) in calls
    assert (
        "cubic_secure_pause_leak_detection",
        CUBIC_IDENTITY_2,
        DEFAULT_PAUSE_LEAK_DETECTION_SECONDS,
    ) in calls


async def test_press_refreshes_the_paused_until_sensor(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    button_entity_id = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY))
    paused_until_entity_id = entity_id(
        hass, "sensor", f"LkUid_leakDetectionPausedUntil_{CUBIC_IDENTITY}"
    )
    assert hass.states.get(paused_until_entity_id).state == "unknown"

    # The fake client only reflects the paused state once refreshed -
    # confirms the post-press coordinator refresh actually happened.
    fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
        build_cubic_configuration(mute_leak=900)
    )

    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "button", "press", {"entity_id": button_entity_id}, blocking=True
        )

    assert hass.states.get(paused_until_entity_id).state != "unknown"


async def test_resume_belongs_to_the_cubic_secure_device(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    button_entity_id = entity_id(hass, "button", _resume_button_unique_id(CUBIC_IDENTITY))

    device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, CUBIC_IDENTITY)})
    entry = er.async_get(hass).async_get(button_entity_id)

    assert entry.device_id == device.id


async def test_resume_press_calls_client_with_zero_seconds(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    pause_button_entity_id = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY))
    resume_button_entity_id = entity_id(
        hass, "button", _resume_button_unique_id(CUBIC_IDENTITY)
    )
    # The resume button is only available once a pause is actually active.
    fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
        build_cubic_configuration(mute_leak=900)
    )
    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "button", "press", {"entity_id": pause_button_entity_id}, blocking=True
        )

        await hass.services.async_call(
            "button", "press", {"entity_id": resume_button_entity_id}, blocking=True
        )

    assert ("cubic_secure_pause_leak_detection", CUBIC_IDENTITY, 0) in fake_manager.calls


async def test_resume_press_refreshes_the_paused_until_sensor(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    pause_button_entity_id = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY))
    resume_button_entity_id = entity_id(
        hass, "button", _resume_button_unique_id(CUBIC_IDENTITY)
    )
    paused_until_entity_id = entity_id(
        hass, "sensor", f"LkUid_leakDetectionPausedUntil_{CUBIC_IDENTITY}"
    )
    fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
        build_cubic_configuration(mute_leak=900)
    )
    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "button", "press", {"entity_id": pause_button_entity_id}, blocking=True
        )
    assert hass.states.get(paused_until_entity_id).state != "unknown"

    fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
        build_cubic_configuration(mute_leak=0)
    )
    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "button", "press", {"entity_id": resume_button_entity_id}, blocking=True
        )

    assert hass.states.get(paused_until_entity_id).state == "unknown"


async def test_resume_button_unavailable_when_not_paused(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    button_entity_id = entity_id(hass, "button", _resume_button_unique_id(CUBIC_IDENTITY))

    assert hass.states.get(button_entity_id).state == "unavailable"


async def test_resume_button_available_once_a_pause_is_active(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    pause_button_entity_id = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY))
    resume_button_entity_id = entity_id(
        hass, "button", _resume_button_unique_id(CUBIC_IDENTITY)
    )
    fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
        build_cubic_configuration(mute_leak=900)
    )

    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "button", "press", {"entity_id": pause_button_entity_id}, blocking=True
        )

    assert hass.states.get(resume_button_entity_id).state != "unavailable"


class TestResetThresholdsToDefaultsButton:
    """Resets every leak-detection/pressure-test threshold to its factory
    default - see LK_CUBICSECURE_THRESHOLD_FACTORY_DEFAULTS's own comment
    in const.py for how those values were confirmed against a real
    device's own "reset to factory defaults" action.
    """

    async def test_belongs_to_the_cubic_secure_device(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)
        button_entity_id = entity_id(
            hass, "button", _reset_thresholds_button_unique_id(CUBIC_IDENTITY)
        )

        device = dr.async_get(hass).async_get_device(
            identifiers={(DOMAIN, CUBIC_IDENTITY)}
        )
        entry = er.async_get(hass).async_get(button_entity_id)

        assert entry.device_id == device.id

    async def test_is_a_configuration_entity(self, hass, fake_manager):
        await setup_entry(hass, fake_manager)
        entry = er.async_get(hass).async_get(
            entity_id(hass, "button", _reset_thresholds_button_unique_id(CUBIC_IDENTITY))
        )

        assert entry.entity_category is EntityCategory.CONFIG

    async def test_press_writes_every_field_to_its_factory_default(
        self, hass, fake_manager
    ):
        await setup_entry(hass, fake_manager)
        button_entity_id = entity_id(
            hass, "button", _reset_thresholds_button_unique_id(CUBIC_IDENTITY)
        )

        with patch_all_managers(fake_manager):
            await hass.services.async_call(
                "button", "press", {"entity_id": button_entity_id}, blocking=True
            )

        sent = next(
            c[2] for c in fake_manager.calls if c[0] == "cubic_secure_set_thresholds"
        )
        assert sent == LK_CUBICSECURE_THRESHOLD_FACTORY_DEFAULTS

    async def test_press_updates_other_threshold_entities_immediately(
        self, hass, fake_manager
    ):
        """Regression test: this button changes six fields at once, none
        of which is "the entity HA just serviced" - unlike a single
        number's own set_value, nothing here relies on HA's post-service
        auto-refresh of the button itself to make the change visible.
        The other five threshold entities need an explicit coordinator
        listener notification after the confirmation read, or they'd only
        pick this up on the next regular poll.
        """
        await setup_entry(hass, fake_manager)
        button_entity_id = entity_id(
            hass, "button", _reset_thresholds_button_unique_id(CUBIC_IDENTITY)
        )
        # The fixture's default (10.0) deliberately differs from the
        # factory default (15.0), so a stale read would be caught.
        medium_threshold_entity_id = entity_id(
            hass, "number", f"LkUid_medium_leak_threshold_{CUBIC_IDENTITY}"
        )

        with patch_all_managers(fake_manager):
            await hass.services.async_call(
                "button", "press", {"entity_id": button_entity_id}, blocking=True
            )

        assert float(hass.states.get(medium_threshold_entity_id).state) == 15.0
