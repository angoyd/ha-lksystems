"""Tests for valve.py: the Cubic Secure's main shutoff valve as a native
`valve.*` entity, rather than only the pre-existing read-only
`sensor.*_valve_state` and the open_valve/close_valve services.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import async_fire_time_changed

from custom_components.lksystems.const import DOMAIN, VALVE_ACTION_RETRY_INTERVAL_SECONDS

from .conftest import (
    CUBIC_IDENTITY,
    CUBIC_IDENTITY_2,
    build_cubic_configuration,
    entity_id,
    patch_all_managers,
    setup_entry,
    tiny_valve_retry_timings,
)


def _valve_unique_id(device_identity: str) -> str:
    return f"LkUid_valve_{device_identity}"


async def test_belongs_to_the_cubic_secure_device(hass, fake_manager):
    await setup_entry(hass, fake_manager)
    valve_entity_id = entity_id(hass, "valve", _valve_unique_id(CUBIC_IDENTITY))

    device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, CUBIC_IDENTITY)})
    entry = er.async_get(hass).async_get(valve_entity_id)

    assert entry.device_id == device.id


@pytest.mark.parametrize("valve_state", ["open", "closed"])
async def test_reflects_state_from_client_data(hass, fake_manager, valve_state):
    fake_manager.cubic_configuration_data = build_cubic_configuration(valve_state=valve_state)
    await setup_entry(hass, fake_manager)
    valve_entity_id = entity_id(hass, "valve", _valve_unique_id(CUBIC_IDENTITY))

    state = hass.states.get(valve_entity_id)

    assert state.state == valve_state


async def test_unknown_when_configuration_data_is_missing(hass, fake_manager):
    fake_manager.get_cubic_secure_configuration_result = False
    await setup_entry(hass, fake_manager)
    valve_entity_id = entity_id(hass, "valve", _valve_unique_id(CUBIC_IDENTITY))

    state = hass.states.get(valve_entity_id)

    assert state.state == "unknown"


@pytest.mark.parametrize(
    ("ha_service", "client_call", "starting_state", "resulting_state"),
    [
        ("close_valve", "cubic_secure_close_valve", "open", "closed"),
        ("open_valve", "cubic_secure_open_valve", "closed", "open"),
    ],
)
async def test_action_calls_the_client_and_refreshes(
    hass, fake_manager, ha_service, client_call, starting_state, resulting_state
):
    fake_manager.cubic_configuration_data = build_cubic_configuration(
        valve_state=starting_state
    )
    await setup_entry(hass, fake_manager)
    valve_entity_id = entity_id(hass, "valve", _valve_unique_id(CUBIC_IDENTITY))
    # A fresh cached (force_update=False) response still showing the
    # pre-action state - proves the entity forces a fresh fetch rather
    # than relying on a regular refresh, which would keep serving this.
    fake_manager.cubic_configurations_cached_by_device[CUBIC_IDENTITY] = (
        build_cubic_configuration(valve_state=starting_state)
    )
    fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = build_cubic_configuration(
        valve_state=resulting_state
    )

    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "valve", ha_service, {"entity_id": valve_entity_id}, blocking=True
        )
        # The confirmation that the valve actually reached the requested
        # state is scheduled to check a few seconds later, not
        # immediately - see LKSystemCoordinator._schedule_valve_state_confirmation.
        async_fire_time_changed(
            hass, dt_util.utcnow() + timedelta(seconds=VALVE_ACTION_RETRY_INTERVAL_SECONDS)
        )
        await hass.async_block_till_done()

    assert (client_call, CUBIC_IDENTITY) in fake_manager.calls
    assert hass.states.get(valve_entity_id).state == resulting_state


@pytest.mark.parametrize(
    ("ha_service", "starting_state", "transitional_state", "resulting_state"),
    [
        ("close_valve", "open", "closing", "closed"),
        ("open_valve", "closed", "opening", "open"),
    ],
)
async def test_shows_a_transitional_state_until_the_motor_finishes_moving(
    hass, fake_manager, ha_service, starting_state, transitional_state, resulting_state
):
    """The physical motor takes real time to move - the entity must show
    a steady "closing"/"opening" throughout, not flash through whatever
    stale intermediate reads the confirmation retries publish along the
    way (see LKSystemCoordinator.valve_action_pending)."""
    fake_manager.cubic_configuration_data = build_cubic_configuration(
        valve_state=starting_state
    )
    await setup_entry(hass, fake_manager)
    valve_entity_id = entity_id(hass, "valve", _valve_unique_id(CUBIC_IDENTITY))
    # Still mid-travel on the first retry check.
    fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
        build_cubic_configuration(valve_state=starting_state)
    )

    with patch_all_managers(fake_manager):
        await hass.services.async_call(
            "valve", ha_service, {"entity_id": valve_entity_id}, blocking=True
        )

        assert hass.states.get(valve_entity_id).state == transitional_state

        async_fire_time_changed(
            hass, dt_util.utcnow() + timedelta(seconds=VALVE_ACTION_RETRY_INTERVAL_SECONDS)
        )
        await hass.async_block_till_done()

        assert (
            hass.states.get(valve_entity_id).state == transitional_state
        ), "still mid-travel - must not flash to the stale pre-action reading"

        # The motor has now finished moving.
        fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
            build_cubic_configuration(valve_state=resulting_state)
        )
        async_fire_time_changed(
            hass,
            dt_util.utcnow() + timedelta(seconds=2 * VALVE_ACTION_RETRY_INTERVAL_SECONDS),
        )
        await hass.async_block_till_done()

    assert hass.states.get(valve_entity_id).state == resulting_state


async def test_two_cubic_secure_devices_get_independent_valves(
    hass, fake_manager_with_two_cubic_devices
):
    await setup_entry(hass, fake_manager_with_two_cubic_devices)
    first_id = entity_id(hass, "valve", _valve_unique_id(CUBIC_IDENTITY))
    second_id = entity_id(hass, "valve", _valve_unique_id(CUBIC_IDENTITY_2))

    # configure_fake_manager_with_two_cubic_devices() sets the first device
    # open and the second closed - see conftest.py.
    assert hass.states.get(first_id).state == "open"
    assert hass.states.get(second_id).state == "closed"


async def test_assumes_success_if_never_confirmed_within_the_max_retry_window(
    hass, fake_manager
):
    """HA already issued the write - if the cloud never confirms it within
    VALVE_ACTION_MAX_RETRY_SECONDS, the entity shows the requested state
    rather than getting stuck on "closing"/"opening" or reverting to the
    stale pre-action reading."""
    fake_manager.cubic_configuration_data = build_cubic_configuration(valve_state="open")
    await setup_entry(hass, fake_manager)
    valve_entity_id = entity_id(hass, "valve", _valve_unique_id(CUBIC_IDENTITY))
    fake_manager.cubic_configurations_by_device[CUBIC_IDENTITY] = (
        build_cubic_configuration(valve_state="open")
    )

    max_retry, retry_interval = tiny_valve_retry_timings()
    with max_retry, retry_interval, patch_all_managers(fake_manager):
        await hass.services.async_call(
            "valve", "close_valve", {"entity_id": valve_entity_id}, blocking=True
        )
        await asyncio.sleep(0.3)  # comfortably past the (patched) tiny window

    assert hass.states.get(valve_entity_id).state == "closed"


async def test_shows_opening_immediately_even_if_the_write_itself_is_slow(
    hass, fake_manager
):
    """The write (login, then the API call) goes through the same
    unbounded Retry-After-honoring network layer as any other request -
    it can itself take a long time, confirmed missing live: a slow write
    left the entity showing nothing until the frontend's own optimistic
    toggle reverted. The entity must show "opening" the instant the user
    acts, not only once that write finishes."""
    fake_manager.cubic_configuration_data = build_cubic_configuration(valve_state="closed")
    await setup_entry(hass, fake_manager)
    valve_entity_id = entity_id(hass, "valve", _valve_unique_id(CUBIC_IDENTITY))
    fake_manager.valve_write_delay = 0.2  # far longer than this test waits below

    with patch_all_managers(fake_manager):
        call_task = hass.async_create_task(
            hass.services.async_call(
                "valve", "open_valve", {"entity_id": valve_entity_id}, blocking=True
            )
        )
        await asyncio.sleep(0.02)  # well before the write itself would finish
        assert hass.states.get(valve_entity_id).state == "opening"
        await call_task
