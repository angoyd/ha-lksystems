"""Button platform for LK Systems integration."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import CubicSecureEntityMixin, LKSystemCoordinator, cubic_secure_device_identities
from .const import DEFAULT_PAUSE_LEAK_DETECTION_SECONDS, DOMAIN
from .services import pause_leak_detection_for_serial


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems button entities based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities(
        button_class(coordinator, device_identity)
        for device_identity in cubic_secure_device_identities(coordinator)
        for button_class in (LKPauseLeakDetectionButton, LKResumeLeakDetectionButton)
    )


class _LKCubicSecureButton(CubicSecureEntityMixin, ButtonEntity):
    """Shared plumbing for the per-Cubic-Secure-device buttons below."""

    _unique_id_suffix: str

    def __init__(self, coordinator: LKSystemCoordinator, device_identity: str) -> None:
        """Initialize the button entity."""
        self.coordinator = coordinator
        self._device_identity = device_identity
        self._attr_unique_id = f"LkUid_{self._unique_id_suffix}_{device_identity}"


class LKPauseLeakDetectionButton(_LKCubicSecureButton):
    """Pauses leak detection for the device's configured duration.

    A one-tap dashboard alternative to calling the pause_leak_detection
    service by hand - e.g. before starting a manual watering session, or
    wired into an irrigation automation - using whichever duration is
    currently set on the device's "Pause Duration" number entity. Doesn't
    subclass CoordinatorEntity: pressing it has nothing to do with
    coordinator polls.
    """

    _attr_name = "Pause Leak Detection"
    _attr_icon = "mdi:pause-circle-outline"
    _unique_id_suffix = "pause_leak_detection"

    async def async_press(self) -> None:
        """Pause leak detection for this device's configured duration."""
        seconds = self.coordinator.pause_leak_detection_seconds.get(
            self._device_identity, DEFAULT_PAUSE_LEAK_DETECTION_SECONDS
        )
        await pause_leak_detection_for_serial(
            self.hass, self.coordinator.entry, self._device_identity, seconds
        )


class LKResumeLeakDetectionButton(CoordinatorEntity[LKSystemCoordinator], _LKCubicSecureButton):
    """Cancels an in-progress leak detection pause, resuming it early.

    Confirmed empirically against the real API: there's no separate
    "resume"/"cancel" endpoint - calling the same pause endpoint with
    seconds=0 cancels an active pause rather than starting a zero-length
    one, so this reuses pause_leak_detection_for_serial with seconds=0
    instead of needing its own API call.

    Unlike the Pause button, this one does subclass CoordinatorEntity:
    its availability depends on the coordinator's data (there being
    nothing to resume otherwise), so it needs to re-render whenever a
    coordinator refresh changes that.
    """

    _attr_name = "Resume Leak Detection"
    _attr_icon = "mdi:play-circle-outline"
    _unique_id_suffix = "resume_leak_detection"

    def __init__(self, coordinator: LKSystemCoordinator, device_identity: str) -> None:
        """Initialize the button entity."""
        CoordinatorEntity.__init__(self, coordinator)
        _LKCubicSecureButton.__init__(self, coordinator, device_identity)

    @property
    def available(self) -> bool:
        """Only pressable while a pause is actually active for this device."""
        return (
            super().available
            and self._device_identity in self.coordinator.leak_detection_paused_until
        )

    async def async_press(self) -> None:
        """Cancel this device's in-progress leak detection pause."""
        await pause_leak_detection_for_serial(
            self.hass, self.coordinator.entry, self._device_identity, 0
        )
