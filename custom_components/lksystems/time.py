"""Time platform for LK Systems integration."""

from __future__ import annotations

from datetime import time

from homeassistant.components.time import TimeEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import (
    CubicSecureEntityMixin,
    LKSystemCoordinator,
    cubic_secure_device_identities,
    cubic_secure_pressure_test_schedule,
)
from .const import DOMAIN
from .services import set_pressure_test_schedule_for_serial


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems time entities based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        LKPressureTestScheduleTime(coordinator, device_identity)
        for device_identity in cubic_secure_device_identities(coordinator)
    )


class LKPressureTestScheduleTime(
    CubicSecureEntityMixin, CoordinatorEntity[LKSystemCoordinator], TimeEntity
):
    """When the device's own automatic pressure test runs each day.

    Read off the regular configuration poll, not a separate fetch - see
    cubic_secure_pressure_test_schedule()'s own docstring for why. The API
    has no seconds field, so this always reads/writes :00.
    """

    _attr_name = "Micro Leak Test Time"
    _attr_icon = "mdi:clock-outline"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: LKSystemCoordinator, device_identity: str) -> None:
        """Initialize the time entity."""
        super().__init__(coordinator)
        self._device_identity = device_identity
        self._attr_unique_id = f"LkUid_pressureTestSchedule_{device_identity}"

    @property
    def native_value(self) -> time | None:
        """Return the currently configured hour:minute, or None until fetched."""
        schedule = cubic_secure_pressure_test_schedule(
            self.coordinator, self._device_identity
        )
        if schedule is None:
            return None
        return time(schedule["hour"], schedule["minute"])

    async def async_set_value(self, value: time) -> None:
        """Change the pressure-test schedule to the given hour:minute."""
        await set_pressure_test_schedule_for_serial(
            self.hass,
            self.coordinator.entry,
            self._device_identity,
            value.hour,
            value.minute,
        )
