"""Tests for button.py: the per-device "Pause Leak Detection" button.

A one-tap dashboard alternative to calling the pause_leak_detection service
by hand - it uses whichever duration is currently set on the device's
"Pause Leak Detection Duration" number entity (see test_number.py).
"""

from __future__ import annotations

from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from custom_components.lksystems.const import DEFAULT_PAUSE_LEAK_DETECTION_SECONDS, DOMAIN

from .conftest import (
    CUBIC_IDENTITY,
    CUBIC_IDENTITY_2,
    entity_id,
    pause_leak_detection_duration_unique_id as _number_unique_id,
    patch_services_manager,
    setup_entry,
)


def _button_unique_id(device_identity: str) -> str:
    return f"LkUid_pause_leak_detection_{device_identity}"


async def test_belongs_to_the_cubic_secure_device(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    button_entity_id = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY))

    device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, CUBIC_IDENTITY)})
    entry = er.async_get(hass).async_get(button_entity_id)

    assert entry.device_id == device.id


async def test_press_pauses_leak_detection_for_the_default_duration(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    button_entity_id = entity_id(hass, "button", _button_unique_id(CUBIC_IDENTITY))

    with patch_services_manager(fake_manager):
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
        "number", "set_value", {"entity_id": number_entity_id, "value": 900}, blocking=True
    )

    with patch_services_manager(fake_manager):
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
        "number", "set_value", {"entity_id": first_number, "value": 120}, blocking=True
    )

    with patch_services_manager(fake_manager_with_two_cubic_devices):
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
