"""Tests for sensor.py entity naming.

Exercises entity names against a real config-entry setup (see
test_integration_setup.py's _setup_entry pattern), looking entities up by
their unique_id via the entity registry rather than guessing slugified
entity_ids.
"""

from __future__ import annotations

from unittest.mock import patch

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lksystems.const import DOMAIN

from .conftest import CUBIC_IDENTITY


async def _setup_entry(hass, manager) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_USERNAME: "user@example.com", CONF_PASSWORD: "hunter2"},
    )
    entry.add_to_hass(hass)
    with patch("custom_components.lksystems.LKSystemsManager", return_value=manager):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    return entry


def _entity_id(hass, unique_id: str) -> str:
    entity_id = er.async_get(hass).async_get_entity_id("sensor", DOMAIN, unique_id)
    assert entity_id is not None, f"no sensor entity registered for {unique_id!r}"
    return entity_id


async def test_last_status_sensor_name_says_what_it_represents(hass, fake_manager):
    """lastStatus is the device's last data transmission to LK's cloud
    (confirmed against the LK app's own "Last data sent" wording - see
    issue #55), not a generic "status" - the entity name should say so."""
    await _setup_entry(hass, fake_manager)

    entity_id = _entity_id(hass, f"LkUid_lastStatus_{CUBIC_IDENTITY}")
    state = hass.states.get(entity_id)

    assert state.attributes["friendly_name"] == "Cubic Secure Utility Room Last Data Sent"
