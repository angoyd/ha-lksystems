"""Binary sensor platform for LK Systems integration."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
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
    async_add_entities(
        LKActuatorBinarySensor(coordinator, device, actuator["n"])
        for device in _arc_devices_with_actuators(coordinator)
        for actuator in device["measurement"]["actuators"]
    )


def _arc_devices_with_actuators(coordinator: LKSystemCoordinator) -> list[dict]:
    """Return each Arc sense device that reports actuators, once."""
    devices_by_mac: dict[str, dict] = {}
    for device in coordinator.data.get("devices", []):
        mac = device.get("mac")
        if mac and (device.get("measurement") or {}).get("actuators"):
            devices_by_mac.setdefault(mac, device)
    return list(devices_by_mac.values())


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


class LKActuatorBinarySensor(CoordinatorEntity[LKSystemCoordinator], BinarySensorEntity):
    """Whether one actuator (valve) behind a room's thermostat is open.

    The API reports each actuator as {"n": <number>, "s": <state>} without
    documenting the state values; 1 meaning open and 0 closed was confirmed
    by comparing against the LK app.
    """

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.OPENING

    def __init__(
        self, coordinator: LKSystemCoordinator, device: dict, actuator_number: int
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        device_title = device.get("deviceTitle", {})
        self._mac = device["mac"]
        self._actuator_number = actuator_number
        device_identity = device_title.get("identity") or self._mac
        zone_name = device_title.get("zone", {}).get("zoneName", "Unknown Zone")
        self._attr_unique_id = f"LkUid_actuator_{device_identity}_{actuator_number}"
        self._attr_name = f"Actuator {actuator_number}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_identity)},
            name=f"LK {zone_name}",
            manufacturer="LK Systems",
            model=device_title.get("deviceType", "unknown"),
        )

    def _actuator_state(self) -> int | None:
        """Return this actuator's reported state, or None if it isn't reported."""
        for device in self.coordinator.data.get("devices", []):
            if device.get("mac") != self._mac:
                continue
            for actuator in (device.get("measurement") or {}).get("actuators") or []:
                if actuator.get("n") == self._actuator_number:
                    return actuator.get("s")
        return None

    @property
    def available(self) -> bool:
        """Return whether the actuator's state is currently reported."""
        return super().available and self._actuator_state() is not None

    @property
    def is_on(self) -> bool | None:
        """Return whether the actuator is open."""
        state = self._actuator_state()
        return None if state is None else state == 1
