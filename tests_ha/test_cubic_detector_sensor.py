"""Tests for the Cubic Detector sensors added in sensor.py.

A Cubic Detector is a battery-powered, valve-less leak/humidity sensor -
distinct from a Cubic Secure, which has its own tests in test_sensor.py.
These tests exist mainly to pin down two API quirks confirmed against a
real device (see const.py's LK_CUBICDETECTOR_SENSORS and
LKCubicDetectorSensor._live_native_value): currentBattery is raw
millivolts, not a 0-100 percentage, and currentHumidity is in tenths of a
percent.
"""

from __future__ import annotations

from homeassistant.const import EntityCategory
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from custom_components.lksystems.const import DOMAIN

from .conftest import CUBIC_DETECTOR_IDENTITY, CUBIC_IDENTITY, entity_id, setup_entry


def _registry_entry(hass, unique_id: str) -> er.RegistryEntry:
    found = entity_id(hass, "sensor", unique_id)
    entry = er.async_get(hass).async_get(found)
    assert entry is not None
    return entry


class TestCubicDetectorSensors:
    async def test_sensors_are_created_for_a_cubic_detector_device(
        self, hass, fake_manager_with_cubic_detector
    ):
        await setup_entry(hass, fake_manager_with_cubic_detector)

        for key in (
            "currentBattery",
            "currentHumidity",
            "tempAmbient",
            "lastStatus",
            "leak.leakState",
            "firmwareVersion",
            "hardwareVersion",
        ):
            # Raises if the entity doesn't exist.
            entity_id(hass, "sensor", f"LkUid_{key}_{CUBIC_DETECTOR_IDENTITY}")

    async def test_battery_sensor_reports_raw_millivolts_not_a_percentage(
        self, hass, fake_manager_with_cubic_detector
    ):
        """currentBattery looks like a 0-100 percentage from its field
        name, but a real device reports its raw battery voltage in
        millivolts (e.g. 2976) - confirmed live, not inferred from the
        name. Exposed as a voltage sensor, so this must never be silently
        treated as a percentage again."""
        await setup_entry(hass, fake_manager_with_cubic_detector)
        battery_entity_id = entity_id(
            hass, "sensor", f"LkUid_currentBattery_{CUBIC_DETECTOR_IDENTITY}"
        )

        state = hass.states.get(battery_entity_id)

        assert state.state == "2976"
        assert state.attributes["unit_of_measurement"] == "mV"
        assert state.attributes["device_class"] == "voltage"

    async def test_humidity_sensor_is_scaled_from_tenths_of_a_percent(
        self, hass, fake_manager_with_cubic_detector
    ):
        """currentHumidity is in tenths of a percent (431 == 43.1%),
        confirmed live - the same scaling this codebase already applies
        to Arc's identically-named field."""
        await setup_entry(hass, fake_manager_with_cubic_detector)
        humidity_entity_id = entity_id(
            hass, "sensor", f"LkUid_currentHumidity_{CUBIC_DETECTOR_IDENTITY}"
        )

        state = hass.states.get(humidity_entity_id)

        assert float(state.state) == 43.1

    async def test_belongs_to_its_own_cubic_detector_device(
        self, hass, fake_manager_with_cubic_detector
    ):
        await setup_entry(hass, fake_manager_with_cubic_detector)
        battery_entity_id = entity_id(
            hass, "sensor", f"LkUid_currentBattery_{CUBIC_DETECTOR_IDENTITY}"
        )

        device = dr.async_get(hass).async_get_device(
            identifiers={(DOMAIN, CUBIC_DETECTOR_IDENTITY)}
        )
        secure_device = dr.async_get(hass).async_get_device(
            identifiers={(DOMAIN, CUBIC_IDENTITY)}
        )
        registry_entry = er.async_get(hass).async_get(battery_entity_id)

        assert device is not None
        assert device.model == "Cubic Detector"
        # A distinct HA device from the Cubic Secure also on this account -
        # never the same one.
        assert device.id != secure_device.id
        assert registry_entry.device_id == device.id

    async def test_has_entity_name(self, hass, fake_manager_with_cubic_detector):
        await setup_entry(hass, fake_manager_with_cubic_detector)

        entry = _registry_entry(
            hass, f"LkUid_currentBattery_{CUBIC_DETECTOR_IDENTITY}"
        )

        assert entry.has_entity_name is True

    async def test_diagnostic_sensors_are_categorized_as_diagnostic(
        self, hass, fake_manager_with_cubic_detector
    ):
        await setup_entry(hass, fake_manager_with_cubic_detector)

        for key in ("currentBattery", "firmwareVersion", "hardwareVersion"):
            entry = _registry_entry(hass, f"LkUid_{key}_{CUBIC_DETECTOR_IDENTITY}")
            assert entry.entity_category == EntityCategory.DIAGNOSTIC, key
