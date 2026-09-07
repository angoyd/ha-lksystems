"""Valve platform for LK Systems integration."""

from __future__ import annotations

from homeassistant.components.valve import ValveDeviceClass, ValveEntity, ValveEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import (
    LKSystemCoordinator,
    async_call_cubic_secure_service,
    cubic_secure_configuration,
    cubic_secure_device_identities,
    cubic_secure_device_info,
)
from .const import ATTRIBUTION, CUBIC_SECURE_VALVE_STATE_CLOSED, DOMAIN


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems valve entities based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities(
        LKCubicSecureValve(coordinator, device_identity)
        for device_identity in cubic_secure_device_identities(coordinator)
    )


class LKCubicSecureValve(CoordinatorEntity[LKSystemCoordinator], ValveEntity):
    """The Cubic Secure's main shutoff valve.

    Reflects live coordinator data (like the sibling sensors), so it
    picks up a state change from any source - a scheduled poll, or the
    valve being toggled from the vendor app - not just its own actions.
    Open/close delegate to the existing open_valve/close_valve services
    (rather than duplicating their login/error-handling), then confirm
    the valve actually reached that state via
    _schedule_valve_state_confirmation() - the physical motor takes on
    the order of 10-30s to finish moving (confirmed against a real
    device), so a single immediate refresh right after the write would
    just read a stale pre-action snapshot (see that method's own
    docstring). Doesn't report a position: the API only exposes
    open/closed, not a percentage.
    """

    _attr_attribution = ATTRIBUTION
    _attr_has_entity_name = True
    _attr_name = "Valve"
    _attr_device_class = ValveDeviceClass.WATER
    _attr_supported_features = ValveEntityFeature.OPEN | ValveEntityFeature.CLOSE
    _attr_reports_position = False

    def __init__(self, coordinator: LKSystemCoordinator, device_identity: str) -> None:
        """Initialize the valve entity."""
        super().__init__(coordinator)
        self._device_identity = device_identity
        self._attr_unique_id = f"LkUid_valve_{device_identity}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return the device_info of the device."""
        return cubic_secure_device_info(self.coordinator, self._device_identity)

    @property
    def is_closed(self) -> bool | None:
        """Return True if the valve is closed, None if not yet known.

        Not consulted while is_opening/is_closing is set - ValveEntity's
        own state property checks those first - so this doesn't need to
        guard against showing a stale mid-action reading itself.
        """
        valve_state = cubic_secure_configuration(self.coordinator, self._device_identity).get(
            "valveState"
        )
        if valve_state is None:
            return None
        return valve_state == CUBIC_SECURE_VALVE_STATE_CLOSED

    @property
    def is_opening(self) -> bool:
        """Return True while an open write is pending confirmation.

        Takes priority over is_closed in ValveEntity's own state property,
        so the entity shows a steady "opening" for the real time the
        motor takes, instead of flashing through whatever intermediate
        (possibly stale) reads the confirmation retries publish along the
        way - see LKSystemCoordinator.valve_action_pending.
        """
        return self.coordinator.valve_action_pending.get(self._device_identity) is False

    @property
    def is_closing(self) -> bool:
        """Return True while a close write is pending confirmation - see
        is_opening above."""
        return self.coordinator.valve_action_pending.get(self._device_identity) is True

    async def async_open_valve(self) -> None:
        """Open the valve."""
        await self._async_call_valve_service("open_valve")

    async def async_close_valve(self) -> None:
        """Close the valve."""
        await self._async_call_valve_service("close_valve")

    async def _async_call_valve_service(self, service: str) -> None:
        expect_closed = service == "close_valve"
        # Marked pending before the write below, not just once its
        # confirmation retries start - the write itself (login, then the
        # API call) can take a while too (see
        # coordinator.mark_valve_action_pending's own docstring).
        self.coordinator.mark_valve_action_pending(self._device_identity, expect_closed)
        called = await async_call_cubic_secure_service(self.hass, self._device_identity, service)
        if called:
            self.coordinator._schedule_valve_state_confirmation(
                self._device_identity, expect_closed
            )
        else:
            self.coordinator.clear_valve_action_pending(self._device_identity)
