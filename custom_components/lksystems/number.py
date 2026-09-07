"""Number platform for LK Systems integration."""

from __future__ import annotations

import logging

from homeassistant.components.number import NumberDeviceClass, NumberMode, RestoreNumber
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util.unit_conversion import DurationConverter

from . import CubicSecureEntityMixin, LKSystemCoordinator, cubic_secure_device_identities
from .const import (
    DEFAULT_PAUSE_LEAK_DETECTION_SECONDS,
    DOMAIN,
    PAUSE_LEAK_DETECTION_MAX_SECONDS,
    PAUSE_LEAK_DETECTION_MIN_SECONDS,
)

_LOGGER = logging.getLogger(__name__)


def _minutes(seconds: float) -> float:
    """Convert a seconds duration to minutes."""
    return DurationConverter.convert(seconds, UnitOfTime.SECONDS, UnitOfTime.MINUTES)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems number entities based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities(
        LKPauseLeakDetectionDurationNumber(coordinator, device_identity)
        for device_identity in cubic_secure_device_identities(coordinator)
    )


class LKPauseLeakDetectionDurationNumber(CubicSecureEntityMixin, RestoreNumber):
    """How long the device's "Pause Leak Detection" button should pause for.

    A local preference, not fetched from the API - the API only takes a
    duration on each pause-leak-detection call, it doesn't expose a
    "currently configured duration" of its own. The coordinator holds the
    live value (shared with button.py); this entity is a persisted view
    onto it, restoring the last value across HA restarts. It doesn't
    subclass CoordinatorEntity: its value has nothing to do with
    coordinator polls, so it stays available even when the last poll
    failed.

    Displayed (and stored/restored) in minutes for readability - a pause
    is realistically minutes-to-a-day long, and NumberEntity has no
    suggested-unit mechanism like SensorEntity's to convert that from a
    seconds-native value automatically. The coordinator's
    pause_leak_detection_seconds - and everything downstream of it
    (button.py, services.py) - keeps working in seconds, matching the
    API's own "pause for N seconds" contract; this entity converts at its
    own boundary instead, via DurationConverter.
    """

    _attr_name = "Pause Duration"
    _attr_icon = "mdi:timer-outline"
    _attr_device_class = NumberDeviceClass.DURATION
    _attr_native_unit_of_measurement = UnitOfTime.MINUTES
    _attr_native_min_value = _minutes(PAUSE_LEAK_DETECTION_MIN_SECONDS)
    _attr_native_max_value = _minutes(PAUSE_LEAK_DETECTION_MAX_SECONDS)
    _attr_native_step = 1
    _attr_mode = NumberMode.BOX

    def __init__(self, coordinator: LKSystemCoordinator, device_identity: str) -> None:
        """Initialize the number entity."""
        self.coordinator = coordinator
        self._device_identity = device_identity
        self._attr_unique_id = f"LkUid_pause_leak_detection_duration_{device_identity}"
        self._attr_native_value = _minutes(DEFAULT_PAUSE_LEAK_DETECTION_SECONDS)

    def _store_duration_minutes(self, minutes: float) -> None:
        """Set the displayed value and push the equivalent seconds
        duration to the coordinator, where button.py/services.py read it."""
        self._attr_native_value = minutes
        self.coordinator.pause_leak_detection_seconds[self._device_identity] = int(
            DurationConverter.convert(minutes, UnitOfTime.MINUTES, UnitOfTime.SECONDS)
        )

    async def async_added_to_hass(self) -> None:
        """Restore the last configured duration, if any, on startup/reload."""
        await super().async_added_to_hass()
        last_number_data = await self.async_get_last_number_data()
        if (
            last_number_data is None
            or last_number_data.native_value is None
            or last_number_data.native_unit_of_measurement is None
        ):
            return
        # DurationConverter is a no-op when the restored unit already
        # matches (the common case); it only does real work for data
        # restored while this entity's native unit was still seconds.
        self._store_duration_minutes(
            DurationConverter.convert(
                last_number_data.native_value,
                last_number_data.native_unit_of_measurement,
                UnitOfTime.MINUTES,
            )
        )

    async def async_set_native_value(self, value: float) -> None:
        """Update the configured duration."""
        self._store_duration_minutes(value)
        self.async_write_ha_state()
