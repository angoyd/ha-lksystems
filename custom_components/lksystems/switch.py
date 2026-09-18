"""Switch platform for LK Systems integration."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import (
    CubicSecureEntityMixin,
    LKSystemCoordinator,
    cubic_secure_device_identities,
)
from .const import DOMAIN, PREVENT_VALVE_CLOSING_SENTINEL, PRESSURE_CLOSE_DELAY_DEFAULT
from .pylksystems import thresholds_with_overrides
from .services import set_thresholds_for_serial


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems switch entities based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        LKPreventValveClosingSwitch(coordinator, device_identity)
        for device_identity in cubic_secure_device_identities(coordinator)
    )


class LKPreventValveClosingSwitch(
    CubicSecureEntityMixin, CoordinatorEntity[LKSystemCoordinator], SwitchEntity
):
    """Whether a pressure-test failure is prevented from ever closing the valve.

    Confirmed empirically against a real device: the app's own "prevent
    valve closing" control isn't a separate API field - it overloads
    thresholds.pressure.closeDelay, writing PREVENT_VALVE_CLOSING_SENTINEL
    so that delay effectively never elapses. Turning it back off restores
    PRESSURE_CLOSE_DELAY_DEFAULT - see that constant's own comment for how
    it was confirmed to be the device's factory default, not just
    whatever value happened to be configured before.
    """

    _attr_name = "Prevent Valve Closing"
    _attr_icon = "mdi:valve-open"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: LKSystemCoordinator, device_identity: str) -> None:
        """Initialize the switch."""
        super().__init__(coordinator)
        self._device_identity = device_identity
        self._attr_unique_id = f"LkUid_preventValveClosing_{device_identity}"

    @property
    def is_on(self) -> bool | None:
        """Return whether the sentinel close delay is currently set."""
        pressure = self._current_thresholds().get("pressure")
        if pressure is None:
            return None
        return pressure.get("closeDelay") == PREVENT_VALVE_CLOSING_SENTINEL

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Set the sentinel so a pressure-test failure never closes the valve."""
        await self._write_close_delay(PREVENT_VALVE_CLOSING_SENTINEL)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Restore the factory-default close delay."""
        await self._write_close_delay(PRESSURE_CLOSE_DELAY_DEFAULT)

    async def _write_close_delay(self, close_delay: int) -> None:
        """Write close_delay, carrying over every other current value."""
        updated = thresholds_with_overrides(
            self._current_thresholds(), "pressure", {"closeDelay": close_delay}
        )
        await set_thresholds_for_serial(
            self.hass, self.coordinator.entry, self._device_identity, updated
        )
