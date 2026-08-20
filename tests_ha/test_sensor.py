"""Tests for sensor.py entity naming.

Exercises entity names against a real config-entry setup, looking entities
up by their unique_id via the entity registry rather than guessing
slugified entity_ids.
"""

from __future__ import annotations

from .conftest import CUBIC_IDENTITY, entity_id as _entity_id, setup_entry as _setup_entry


async def test_last_status_sensor_name_says_what_it_represents(hass, fake_manager):
    """lastStatus is when the device itself last reported to LK's cloud,
    not a generic "status" and not something the integration sends -
    the entity name should say so without implying either of those."""
    await _setup_entry(hass, fake_manager)

    entity_id = _entity_id(hass, "sensor", f"LkUid_lastStatus_{CUBIC_IDENTITY}")
    state = hass.states.get(entity_id)

    assert state.attributes["friendly_name"] == "Cubic Secure Utility Room Last Device Report"
