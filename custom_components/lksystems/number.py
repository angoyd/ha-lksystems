"""Number platform for LK Systems integration."""

from __future__ import annotations

from homeassistant.components.number import (
    NumberDeviceClass,
    NumberEntity,
    NumberMode,
    RestoreNumber,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util.unit_conversion import DurationConverter

from . import (
    CubicSecureEntityMixin,
    LKSystemCoordinator,
    cubic_secure_device_identities,
)
from .const import (
    DEFAULT_PAUSE_LEAK_DETECTION_SECONDS,
    DOMAIN,
    LK_CUBICSECURE_THRESHOLD_NUMBERS,
    PAUSE_LEAK_DETECTION_MAX_SECONDS,
    PAUSE_LEAK_DETECTION_MIN_SECONDS,
    LKThresholdNumberDescription,
)


def _minutes(seconds: float) -> float:
    """Convert a seconds duration to minutes."""
    return DurationConverter.convert(seconds, UnitOfTime.SECONDS, UnitOfTime.MINUTES)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems number entities based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    device_identities = list(cubic_secure_device_identities(coordinator))

    entities: list[NumberEntity] = [
        LKPauseLeakDetectionDurationNumber(coordinator, device_identity)
        for device_identity in device_identities
    ]
    entities.extend(
        LKThresholdNumber(coordinator, device_identity, description)
        for device_identity in device_identities
        for description in LK_CUBICSECURE_THRESHOLD_NUMBERS.values()
    )
    async_add_entities(entities)


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


class LKThresholdNumber(CubicSecureEntityMixin, CoordinatorEntity[LKSystemCoordinator], NumberEntity):
    """One leak-detection threshold - see LKThresholdNumberDescription's
    own docstring for the category/fields/unit-conversion it carries.

    Reflects the live coordinator value (like the sibling sensors and the
    valve), so it picks up a change from any source - a scheduled poll,
    or the threshold being changed from the vendor app - not just its own
    writes. An edit doesn't write immediately: it's staged on this
    device's shared LKThresholdWriteCoordinator, which debounces several
    edits into one write and holds/retries a failed one - see that
    class's own docstring. native_value reads through
    effective_thresholds() rather than the coordinator's own cached
    value, so a pending or held edit displays immediately instead of
    waiting for (or reverting to) the real API state.
    """

    _attr_mode = NumberMode.BOX
    entity_description: LKThresholdNumberDescription

    def __init__(
        self,
        coordinator: LKSystemCoordinator,
        device_identity: str,
        description: LKThresholdNumberDescription,
    ) -> None:
        """Initialize the number entity."""
        super().__init__(coordinator)
        self._device_identity = device_identity
        self.entity_description = description
        self._attr_unique_id = f"LkUid_{description.key}_{device_identity}"
        self._write_coordinator = coordinator.get_threshold_write_coordinator(
            device_identity
        )

    @property
    def available(self) -> bool:
        """Unavailable while this device's shared endpoint is blocked
        retrying a failed write - see LKThresholdWriteCoordinator."""
        return super().available and not self._write_coordinator.is_blocked

    def _to_native_unit(self, api_value: float) -> float:
        """Convert one value from the API's own unit to this entity's
        displayed unit - a no-op unless the description names a
        different api_unit_of_measurement (see its own docstring)."""
        api_unit = self.entity_description.api_unit_of_measurement
        if api_unit is None:
            return api_value
        return DurationConverter.convert(
            api_value, api_unit, self.entity_description.native_unit_of_measurement
        )

    def _to_api_unit(self, native_value: float) -> float:
        """The inverse of _to_native_unit - see its own docstring."""
        api_unit = self.entity_description.api_unit_of_measurement
        if api_unit is None:
            return native_value
        return DurationConverter.convert(
            native_value, self.entity_description.native_unit_of_measurement, api_unit
        )

    @property
    def native_value(self) -> float | None:
        """Return the currently configured (or pending/held) value."""
        raw_value = self._current_category().get(self.entity_description.fields[0])
        if raw_value is None:
            return None
        return self._to_native_unit(raw_value)

    async def async_set_native_value(self, value: float) -> None:
        """Stage this threshold change, carrying over every other current
        value once it's actually written."""
        raw_value = self._to_api_unit(value)
        overrides = {field: raw_value for field in self.entity_description.fields}
        self._write_coordinator.stage(self.entity_description.category, overrides)
        self.async_write_ha_state()

    def _current_category(self) -> dict:
        category = self.entity_description.category
        return self._write_coordinator.effective_thresholds().get(category) or {}
