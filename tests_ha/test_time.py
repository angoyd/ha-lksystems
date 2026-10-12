"""Tests for time.py: the "Micro Leak Test Time" entity.

Reads/writes the device's automatic pressure-test schedule
(configuration.pressureTestSchedule) - confirmed empirically against a real
device that a write lands in this same cached field within the write's own
confirmation read, so no separate live/cached distinction is needed here
(see cubic_secure_pressure_test_schedule()'s own docstring in __init__.py).
"""

from __future__ import annotations

from homeassistant.const import EntityCategory
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from custom_components.lksystems.const import DOMAIN

from .conftest import (
    CUBIC_IDENTITY,
    build_cubic_configuration,
    entity_id,
    patch_all_managers,
    setup_entry,
)


def _time_unique_id(device_identity: str) -> str:
    return f"LkUid_pressureTestSchedule_{device_identity}"


async def test_belongs_to_the_cubic_secure_device(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    time_entity_id = entity_id(hass, "time", _time_unique_id(CUBIC_IDENTITY))

    registry_entry = er.async_get(hass).async_get(time_entity_id)
    device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, CUBIC_IDENTITY)})
    assert registry_entry.device_id == device.id


async def test_is_a_configuration_entity(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    time_entity_id = entity_id(hass, "time", _time_unique_id(CUBIC_IDENTITY))

    registry_entry = er.async_get(hass).async_get(time_entity_id)
    assert registry_entry.entity_category is EntityCategory.CONFIG


async def test_state_reflects_the_configured_schedule(hass, fake_manager):
    fake_manager.cubic_configuration_data = build_cubic_configuration(
        pressure_test_schedule={"hour": 3, "minute": 30}
    )
    await setup_entry(hass, fake_manager)
    time_entity_id = entity_id(hass, "time", _time_unique_id(CUBIC_IDENTITY))

    assert hass.states.get(time_entity_id).state == "03:30:00"


async def test_setting_the_value_writes_the_new_schedule(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    time_entity_id = entity_id(hass, "time", _time_unique_id(CUBIC_IDENTITY))

    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "time",
            "set_value",
            {"entity_id": time_entity_id, "time": "05:15:00"},
            blocking=True,
        )

    assert (
        "cubic_secure_set_pressure_test_schedule",
        CUBIC_IDENTITY,
        5,
        15,
    ) in fake_manager.calls


async def test_setting_the_value_confirms_the_write_and_updates_state(
    hass, fake_manager
):
    await setup_entry(hass, fake_manager)
    time_entity_id = entity_id(hass, "time", _time_unique_id(CUBIC_IDENTITY))

    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "time",
            "set_value",
            {"entity_id": time_entity_id, "time": "05:15:00"},
            blocking=True,
        )

    assert hass.states.get(time_entity_id).state == "05:15:00"
