"""Button platform for LK Systems integration."""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import LKSystemCoordinator, cubic_secure_device_identities, cubic_secure_device_info
from .const import ATTRIBUTION, DEFAULT_PAUSE_LEAK_DETECTION_SECONDS, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems button entities based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities(
        LKPauseLeakDetectionButton(coordinator, device_identity)
        for device_identity in cubic_secure_device_identities(coordinator)
    )


class LKPauseLeakDetectionButton(ButtonEntity):
    """Pauses leak detection for the device's configured duration.

    A one-tap dashboard alternative to calling the pause_leak_detection
    service by hand - e.g. before starting a manual watering session, or
    wired into an irrigation automation. Delegates to that same service
    (rather than duplicating its login/error-handling) using whichever
    duration is currently set on the device's "Pause Leak Detection
    Duration" number entity. Doesn't subclass CoordinatorEntity: pressing
    it has nothing to do with coordinator polls.
    """

    _attr_attribution = ATTRIBUTION
    _attr_has_entity_name = True
    _attr_name = "Pause Leak Detection"
    _attr_icon = "mdi:pause-circle-outline"

    def __init__(self, coordinator: LKSystemCoordinator, device_identity: str) -> None:
        """Initialize the button entity."""
        self.coordinator = coordinator
        self._device_identity = device_identity
        self._attr_unique_id = f"LkUid_pause_leak_detection_{device_identity}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return the device_info of the device."""
        return cubic_secure_device_info(self.coordinator, self._device_identity)

    async def async_press(self) -> None:
        """Pause leak detection for this device's configured duration."""
        device_entry = dr.async_get(self.hass).async_get_device(
            identifiers={(DOMAIN, self._device_identity)}
        )
        if device_entry is None:
            _LOGGER.error(
                "No registered device found for %s, cannot pause leak detection",
                self._device_identity,
            )
            return

        seconds = self.coordinator.pause_leak_detection_seconds.get(
            self._device_identity, DEFAULT_PAUSE_LEAK_DETECTION_SECONDS
        )
        await self.hass.services.async_call(
            DOMAIN,
            "pause_leak_detection",
            {"device_id": device_entry.id, "seconds": seconds},
            blocking=True,
        )
