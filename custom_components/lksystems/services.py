from .pylksystems import LKSystemsManager, LKThresholds, thresholds_with_overrides
from contextlib import asynccontextmanager
import logging
from typing import NamedTuple

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.helpers import (
    device_registry as dr,
)

from .const import (
    DEFAULT_PAUSE_LEAK_DETECTION_SECONDS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class _ServiceLoginFailed(Exception):
    """Raised by _service_write_session() when login fails."""


@asynccontextmanager
async def _service_write_session(entry: ConfigEntry):
    """Open one logged-in LKSystemsManager session for a service-layer
    write - the shared shape every write below needs (extract
    credentials, open a session, log in), instead of each
    re-implementing its own copy.

    Deliberately always logs in fresh rather than reusing a cached token
    the way LKSystemCoordinator._authenticated_client() does for the
    regular poll - these are one-off, user-initiated writes (open/close
    the valve, change a threshold, ...), where a token that's stale by
    even a few seconds (e.g. right after a password change) is worth the
    cost of a fresh login to avoid, unlike a poll that just runs again in
    a few minutes regardless.

    Raises _ServiceLoginFailed if login fails - the caller decides what
    that means for its own return value/error message.
    """
    username = entry.data.get(CONF_USERNAME)
    password = entry.data.get(CONF_PASSWORD)

    async with LKSystemsManager(username, password) as lk_inst:
        if not await lk_inst.login():
            _LOGGER.error("Failed to login, abort update")
            raise _ServiceLoginFailed("Failed to login")
        yield lk_inst


def _overrides_from_call_data(
    call_data: dict, field_keys: dict[str, str]
) -> dict:
    """Extract just the fields a set_thresholds call actually specified -
    field_keys maps each API field name to its service call-data key.
    Passed to thresholds_with_overrides(), which carries every other
    current value forward unchanged."""
    return {
        field: call_data[call_key]
        for field, call_key in field_keys.items()
        if call_key in call_data
    }


def _get_serial_number(hass: HomeAssistant, device_id: str) -> str | None:
    """Look up a device's serial number, logging and returning None if
    device_id doesn't match a registered device or the device has none.
    """
    device_entry = dr.async_get(hass).async_get(device_id)
    if device_entry is None:
        _LOGGER.error("Unknown device_id: %s", device_id)
        return None
    if not device_entry.serial_number:
        _LOGGER.error("No serial number found for device %s", device_id)
        return None
    return device_entry.serial_number


async def pause_leak_detection_for_serial(
    hass: HomeAssistant, entry: ConfigEntry, serial_number: str, seconds: int
) -> None:
    """Log in and pause leak detection for one device.

    Shared by the pause_leak_detection service handler below (which
    resolves a device_id to a serial number first) and button.py's "Pause
    Leak Detection"/"Resume Leak Detection" buttons, which already have
    the serial number and would otherwise have to round-trip it through
    the device registry into a device_id just to go through the service
    call layer. Updates the coordinator's locally tracked pause end time
    and refreshes the "Leak Detection Paused Until" sensor immediately on
    success, rather than leaving either to the next scheduled poll -
    living here means every caller gets that, not just whichever one
    remembers to ask for it.

    Confirms the write by reusing the same session for the follow-up read
    (coordinator.refresh_cubic_secure_configuration_with_client()) rather
    than opening a second one just for that.
    """
    _LOGGER.info("Pausing leak detection for %s for %s seconds", serial_number, seconds)
    try:
        coordinator = hass.data[DOMAIN][entry.entry_id]

        async with _service_write_session(entry) as lk_inst:
            await lk_inst.cubic_secure_pause_leak_detection(serial_number, seconds)

            coordinator.set_leak_detection_paused_until(serial_number, seconds)
            await coordinator.refresh_cubic_secure_configuration_with_client(
                lk_inst, serial_number
            )
    except Exception as e:
        _LOGGER.error("Error pausing leak detection: %s", e)


async def _set_valve_state_for_serial(
    hass: HomeAssistant,
    entry: ConfigEntry,
    serial_number: str,
    action: str,
    write_method_name: str,
) -> bool:
    """Log in, write the valve's requested state (by calling
    `write_method_name` on the session's client), and confirm it by
    reusing the same session for one immediate read - shared body for
    close_valve_for_serial/open_valve_for_serial below.

    Takes the write's method name rather than a bound/unbound method
    reference: the LKSystemsManager class itself gets replaced with a
    mock in tests, so resolving the method against the real *instance*
    each call (via getattr) is what keeps this working under test rather
    than silently calling through to the wrong object.

    Returns whether the write itself was issued (a real login and API
    call happened), not whether the valve has already reached the
    requested state - that's for the caller to check against the
    coordinator data this also just refreshed.
    """
    _LOGGER.info("%s valve %s", action, serial_number)
    try:
        coordinator = hass.data[DOMAIN][entry.entry_id]

        async with _service_write_session(entry) as lk_inst:
            await getattr(lk_inst, write_method_name)(serial_number)
            await coordinator.force_cubic_secure_configuration_update_with_client(
                lk_inst, serial_number
            )
        return True
    except _ServiceLoginFailed:
        return False
    except Exception as e:
        _LOGGER.error("Error %s valve: %s", action.lower(), e)
        return False


async def close_valve_for_serial(
    hass: HomeAssistant, entry: ConfigEntry, serial_number: str
) -> bool:
    """Close one device's valve.

    Shared by the close_valve service handler below and callers that
    already have a serial number and would otherwise have to round-trip
    it through the device registry into a device_id just to go through
    the service call layer.
    """
    return await _set_valve_state_for_serial(
        hass, entry, serial_number, "Closing", "cubic_secure_close_valve"
    )


async def open_valve_for_serial(
    hass: HomeAssistant, entry: ConfigEntry, serial_number: str
) -> bool:
    """Open one device's valve - see close_valve_for_serial's own docstring."""
    return await _set_valve_state_for_serial(
        hass, entry, serial_number, "Opening", "cubic_secure_open_valve"
    )


class ThresholdWriteResult(NamedTuple):
    """Outcome of a threshold write - whether it succeeded, and if not,
    whether it's specifically known to be rate-limited (with the delay
    the API reported) as opposed to some other kind of failure."""

    success: bool
    retry_after: float | None = None


async def set_thresholds_for_serial(
    hass: HomeAssistant,
    entry: ConfigEntry,
    serial_number: str,
    thresholds: LKThresholds,
) -> ThresholdWriteResult:
    """Log in, write one device's full thresholds object, and confirm the
    write by refreshing configuration with the same session.

    Takes the complete thresholds object to send - the API only accepts a
    full-object write, not a per-field patch (see
    cubic_secure_set_thresholds's own docstring) - so a caller changing
    just one field must build it via pylksystems.thresholds_with_overrides()
    from the device's current thresholds (e.g.
    cubic_secure_configuration(coordinator, serial_number)), not pass a
    partial object here - every field not included would revert to
    whatever's passed.

    Uses the cached confirmation read (force_update=False), not the
    bypass one valve writes use: thresholds are server-side-tracked like
    muteLeak, not a physical device property, so the cache already
    reflects a write immediately - see
    refresh_cubic_secure_configuration()'s own docstring.
    """
    _LOGGER.info("Setting thresholds for %s", serial_number)
    try:
        coordinator = hass.data[DOMAIN][entry.entry_id]

        async with _service_write_session(entry) as lk_inst:
            success = await lk_inst.cubic_secure_set_thresholds(
                serial_number, thresholds
            )
            if success:
                await coordinator.refresh_cubic_secure_configuration_with_client(
                    lk_inst, serial_number
                )
                return ThresholdWriteResult(True)
            return ThresholdWriteResult(False, lk_inst.last_rate_limit_retry_after)
    except _ServiceLoginFailed:
        return ThresholdWriteResult(False)
    except Exception as e:
        _LOGGER.error("Error setting thresholds: %s", e)
        return ThresholdWriteResult(False)


async def set_pressure_test_schedule_for_serial(
    hass: HomeAssistant,
    entry: ConfigEntry,
    serial_number: str,
    hour: int,
    minute: int,
) -> bool:
    """Log in, write one device's pressure-test schedule, and confirm the
    write by refreshing configuration with the same session.

    Uses the cached confirmation read (force_update=False), not the
    bypass one valve writes use: confirmed empirically against a real
    device that pressureTestSchedule is server-side-tracked like
    muteLeak or thresholds, so the cache already reflects a write
    immediately - see refresh_cubic_secure_configuration()'s own
    docstring.
    """
    _LOGGER.info("Setting pressure test schedule for %s to %d:%02d", serial_number, hour, minute)
    try:
        coordinator = hass.data[DOMAIN][entry.entry_id]

        async with _service_write_session(entry) as lk_inst:
            success = await lk_inst.cubic_secure_set_pressure_test_schedule(
                serial_number, hour, minute
            )
            if success:
                await coordinator.refresh_cubic_secure_configuration_with_client(
                    lk_inst, serial_number
                )
            return success
    except _ServiceLoginFailed:
        return False
    except Exception as e:
        _LOGGER.error("Error setting pressure test schedule: %s", e)
        return False


async def async_setup_services(hass: HomeAssistant, entry: ConfigEntry) -> None:
    @callback
    async def pause_leak_detection(call: ServiceCall) -> None:
        """Handle the service action call."""
        device_id = call.data.get("device_id")
        seconds = int(call.data.get("seconds", DEFAULT_PAUSE_LEAK_DETECTION_SECONDS))
        sn = _get_serial_number(hass, device_id)
        if not sn:
            return
        await pause_leak_detection_for_serial(hass, entry, sn, seconds)

    @callback
    async def close_valve(call: ServiceCall) -> None:
        """Handle the service action call."""
        device_id = call.data.get("device_id")
        sn = _get_serial_number(hass, device_id)
        if not sn:
            return
        await close_valve_for_serial(hass, entry, sn)

    @callback
    async def open_valve(call: ServiceCall) -> None:
        """Handle the service action call."""
        device_id = call.data.get("device_id")
        sn = _get_serial_number(hass, device_id)
        if not sn:
            return
        await open_valve_for_serial(hass, entry, sn)

    @callback
    async def set_pressure_test_schedule(call: ServiceCall) -> None:
        """Handle the service action call."""
        device_id = call.data.get("device_id")
        hour = call.data.get("hour", 2)
        minute = call.data.get("minute", 0)
        sn = _get_serial_number(hass, device_id)
        if not sn:
            return
        await set_pressure_test_schedule_for_serial(hass, entry, sn, hour, minute)

    @callback
    async def set_thresholds(call: ServiceCall) -> None:
        """Handle the service action call.

        A field not explicitly given falls back to the device's current
        value, not a hardcoded literal - the API only accepts the whole
        thresholds object at once (see cubic_secure_set_thresholds's own
        docstring), so a literal default here would silently reset every
        omitted field instead of leaving it alone.
        """
        device_id = call.data.get("device_id")
        sn = _get_serial_number(hass, device_id)
        if not sn:
            return

        # Deferred to avoid a circular import: __init__.py imports
        # async_setup_services from this module at module load time, so a
        # top-level "from . import cubic_secure_thresholds" here would try
        # to read it off __init__.py before that module has finished
        # executing.
        from . import cubic_secure_thresholds

        coordinator = hass.data[DOMAIN][entry.entry_id]
        current = cubic_secure_thresholds(coordinator, sn)

        thresholds = thresholds_with_overrides(
            current,
            "pressure",
            _overrides_from_call_data(
                call.data,
                {
                    "sensitivity": "pressure_sensitivity",
                    "duration": "pressure_test_duration",
                    "closeDelay": "pressure_close_delay",
                    "notificationDelay": "pressure_notification_delay",
                },
            ),
        )
        thresholds = thresholds_with_overrides(
            thresholds,
            "leakMedium",
            _overrides_from_call_data(
                call.data,
                {
                    "threshold": "medium_leak_threshold",
                    "closeDelay": "medium_leak_close_delay",
                    "notificationDelay": "medium_leak_notification_delay",
                },
            ),
        )
        thresholds = thresholds_with_overrides(
            thresholds,
            "leakLarge",
            _overrides_from_call_data(
                call.data,
                {
                    "threshold": "large_leak_threshold",
                    "closeDelay": "large_leak_close_delay",
                    "notificationDelay": "large_leak_notification_delay",
                },
            ),
        )
        await set_thresholds_for_serial(hass, entry, sn, thresholds)

    # Register our service with Home Assistant.
    hass.services.async_register(DOMAIN, "pause_leak_detection", pause_leak_detection)
    hass.services.async_register(DOMAIN, "close_valve", close_valve)
    hass.services.async_register(DOMAIN, "open_valve", open_valve)
    hass.services.async_register(
        DOMAIN, "set_pressure_test_schedule", set_pressure_test_schedule
    )
    hass.services.async_register(DOMAIN, "set_thresholds", set_thresholds)
