"""Binary sensor platform for LK Systems integration."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import CubicSecureEntityMixin, LKSystemCoordinator, cubic_secure_device_identities
from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems binary sensor entities based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        LKRateLimitedBinarySensor(coordinator, device_identity)
        for device_identity in cubic_secure_device_identities(coordinator)
    )


class LKRateLimitedBinarySensor(
    CubicSecureEntityMixin, CoordinatorEntity[LKSystemCoordinator], BinarySensorEntity
):
    """Whether a threshold write to this device is currently blocked,
    retrying after a failure - see LKThresholdWriteCoordinator.

    Deliberately stays available even while every entity sharing that
    endpoint goes unavailable - it's the one place a user can tell "this
    is a temporary rate-limit cooldown" apart from any other reason an
    entity might be unavailable, without checking the notification
    drawer or Logbook.
    """

    _attr_name = "Rate Limited"
    _attr_icon = "mdi:timer-lock-outline"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: LKSystemCoordinator, device_identity: str) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self._device_identity = device_identity
        self._attr_unique_id = f"LkUid_rateLimited_{device_identity}"
        self._write_coordinator = coordinator.get_threshold_write_coordinator(
            device_identity
        )

    @property
    def is_on(self) -> bool:
        """Return whether a threshold write is currently blocked."""
        return self._write_coordinator.is_blocked
