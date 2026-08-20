"""Number platform for LK Systems integration."""

from __future__ import annotations

import logging

from homeassistant.components.number import NumberDeviceClass, NumberMode, RestoreNumber
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import LKSystemCoordinator, cubic_secure_device_identities, cubic_secure_device_info
from .const import (
    ATTRIBUTION,
    DEFAULT_PAUSE_LEAK_DETECTION_SECONDS,
    DOMAIN,
    PAUSE_LEAK_DETECTION_MAX_SECONDS,
    PAUSE_LEAK_DETECTION_MIN_SECONDS,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems number entities based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities(
        LKPauseLeakDetectionDurationNumber(coordinator, device_identity)
        for device_identity in cubic_secure_device_identities(coordinator)
    )


class LKPauseLeakDetectionDurationNumber(RestoreNumber):
    """How long the device's "Pause Leak Detection" button should pause for.

    A local preference, not fetched from the API - the API only takes a
    duration on each pause-leak-detection call, it doesn't expose a
    "currently configured duration" of its own. The coordinator holds the
    live value (shared with button.py); this entity is a persisted view
    onto it, restoring the last value across HA restarts. It doesn't
    subclass CoordinatorEntity: its value has nothing to do with
    coordinator polls, so it stays available even when the last poll
    failed.
    """

    _attr_attribution = ATTRIBUTION
    _attr_has_entity_name = True
    _attr_name = "Pause Leak Detection Duration"
    _attr_icon = "mdi:timer-outline"
    _attr_device_class = NumberDeviceClass.DURATION
    _attr_native_unit_of_measurement = UnitOfTime.SECONDS
    _attr_native_min_value = PAUSE_LEAK_DETECTION_MIN_SECONDS
    _attr_native_max_value = PAUSE_LEAK_DETECTION_MAX_SECONDS
    _attr_native_step = 60
    _attr_mode = NumberMode.BOX

    def __init__(self, coordinator: LKSystemCoordinator, device_identity: str) -> None:
        """Initialize the number entity."""
        self.coordinator = coordinator
        self._device_identity = device_identity
        self._attr_unique_id = f"LkUid_pause_leak_detection_duration_{device_identity}"
        self._attr_native_value = DEFAULT_PAUSE_LEAK_DETECTION_SECONDS

    @property
    def device_info(self) -> DeviceInfo:
        """Return the device_info of the device."""
        return cubic_secure_device_info(self.coordinator, self._device_identity)

    async def async_added_to_hass(self) -> None:
        """Restore the last configured duration, if any, on startup/reload."""
        await super().async_added_to_hass()
        last_number_data = await self.async_get_last_number_data()
        if last_number_data is None or last_number_data.native_value is None:
            return
        self._attr_native_value = last_number_data.native_value
        self.coordinator.pause_leak_detection_seconds[self._device_identity] = int(
            last_number_data.native_value
        )

    async def async_set_native_value(self, value: float) -> None:
        """Update the configured duration."""
        self._attr_native_value = value
        self.coordinator.pause_leak_detection_seconds[self._device_identity] = int(value)
        self.async_write_ha_state()
