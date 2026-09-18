"""Button platform for LK Systems integration."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import CubicSecureEntityMixin, LKSystemCoordinator, cubic_secure_device_identities
from .const import (
    DEFAULT_PAUSE_LEAK_DETECTION_SECONDS,
    DOMAIN,
    LK_CUBICSECURE_THRESHOLD_FACTORY_DEFAULTS,
)
from .services import pause_leak_detection_for_serial


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems button entities based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities(
        button_class(coordinator, device_identity)
        for device_identity in cubic_secure_device_identities(coordinator)
        for button_class in (
            LKPauseLeakDetectionButton,
            LKResumeLeakDetectionButton,
            LKResetThresholdsToDefaultsButton,
        )
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


class LKResetThresholdsToDefaultsButton(
    CoordinatorEntity[LKSystemCoordinator], _LKCubicSecureButton
):
    """Resets every leak-detection/pressure-test threshold to its factory default.

    See LK_CUBICSECURE_THRESHOLD_FACTORY_DEFAULTS's own comment in
    const.py for how those values were confirmed against a real device.
    LK_CUBICSECURE_THRESHOLD_FACTORY_DEFAULTS already gives every field of
    every category, so writing it via this device's shared
    LKThresholdWriteCoordinator overwrites everything in one call rather
    than carrying anything forward - the point of a reset.

    A one-shot action rather than a continuously-editable field, so it
    writes immediately (write_now(), not stage()) instead of waiting out
    the numbers' debounce - but still shares that coordinator's
    blocked/retry state, since it writes to the same thresholds endpoint.
    Subclasses CoordinatorEntity (unlike the sibling buttons above) so its
    availability re-renders when that state changes.
    """

    _attr_name = "Reset Thresholds To Defaults"
    _attr_icon = "mdi:restore"
    _attr_entity_category = EntityCategory.CONFIG
    _unique_id_suffix = "reset_thresholds_to_defaults"

    def __init__(self, coordinator: LKSystemCoordinator, device_identity: str) -> None:
        """Initialize the button entity."""
        CoordinatorEntity.__init__(self, coordinator)
        _LKCubicSecureButton.__init__(self, coordinator, device_identity)
        self._write_coordinator = coordinator.get_threshold_write_coordinator(
            device_identity
        )

    @property
    def available(self) -> bool:
        """Unavailable while this device's shared endpoint is blocked
        retrying a failed write - see LKThresholdWriteCoordinator."""
        return super().available and not self._write_coordinator.is_blocked

    async def async_press(self) -> None:
        """Write every threshold back to its factory default."""
        await self._write_coordinator.write_now(LK_CUBICSECURE_THRESHOLD_FACTORY_DEFAULTS)
