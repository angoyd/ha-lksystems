from .pylksystems import LKSystemsManager, LKThresholds, LKPressureThresholds
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.helpers import (
    device_registry as dr,
)

from .const import (
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_services(hass: HomeAssistant, entry: ConfigEntry) -> None:
    @callback
    async def pause_leak_detection(call: ServiceCall) -> None:
        """Handle the service action call."""
        device_id = call.data.get("device_id")
        seconds = int(call.data.get("seconds", 3600))
        device_reg = dr.async_get(hass)
        device_entry = device_reg.async_get(device_id)
        sn = device_entry.serial_number
        _LOGGER.info(f"Closing valve {sn}")
        if not sn:
            _LOGGER.error("No serial number found for device %s", device_id)
            return
        try:
            username = entry.data.get(CONF_USERNAME)
            password = entry.data.get(CONF_PASSWORD)

            async with LKSystemsManager(username, password) as lk_inst:
                if not await lk_inst.login():
                    _LOGGER.error("Failed to login, abort update")
                    raise Exception("Failed to login")
                await lk_inst.cubic_secure_pause_leak_detection(sn, seconds)
        except Exception as e:
            _LOGGER.error("Error closing valve: %s", e)

    @callback
    async def close_valve(call: ServiceCall) -> None:
        """Handle the service action call."""
        device_id = call.data.get("device_id")
        device_reg = dr.async_get(hass)
        device_entry = device_reg.async_get(device_id)
        sn = device_entry.serial_number
        _LOGGER.info(f"Closing valve {sn}")
        if not sn:
            _LOGGER.error("No serial number found for device %s", device_id)
            return
        try:
            username = entry.data.get(CONF_USERNAME)
            password = entry.data.get(CONF_PASSWORD)

            async with LKSystemsManager(username, password) as lk_inst:
                if not await lk_inst.login():
                    _LOGGER.error("Failed to login, abort update")
                    raise Exception("Failed to login")
                await lk_inst.cubic_secure_close_valve(sn)
        except Exception as e:
            _LOGGER.error("Error closing valve: %s", e)

    @callback
    async def open_valve(call: ServiceCall) -> None:
        """Handle the service action call."""
        device_id = call.data.get("device_id")
        device_reg = dr.async_get(hass)
        device_entry = device_reg.async_get(device_id)
        sn = device_entry.serial_number
        _LOGGER.info(f"Open valve {sn}")
        if not sn:
            _LOGGER.error("No serial number found for device %s", device_id)
            return
        try:
            username = entry.data.get(CONF_USERNAME)
            password = entry.data.get(CONF_PASSWORD)

            async with LKSystemsManager(username, password) as lk_inst:
                if not await lk_inst.login():
                    _LOGGER.error("Failed to login, abort update")
                    raise Exception("Failed to login")
                await lk_inst.cubic_secure_open_valve(sn)
        except Exception as e:
            _LOGGER.error("Error open valve: %s", e)

    @callback
    async def set_pressure_test_schedule(call: ServiceCall) -> None:
        """Handle the service action call."""
        device_id = call.data.get("device_id")
        hour = call.data.get("hour", 2)
        minute = call.data.get("minute", 0)
        device_reg = dr.async_get(hass)
        device_entry = device_reg.async_get(device_id)
        sn = device_entry.serial_number
        _LOGGER.info(f"Setting pressure test schedule {sn} to {hour}:{minute}")
        if not sn:
            _LOGGER.error("No serial number found for device %s", device_id)
            return
        try:
            username = entry.data.get(CONF_USERNAME)
            password = entry.data.get(CONF_PASSWORD)

            async with LKSystemsManager(username, password) as lk_inst:
                if not await lk_inst.login():
                    _LOGGER.error("Failed to login, abort update")
                    raise Exception("Failed to login")
                await lk_inst.cubic_secure_set_pressure_test_schedule(sn, hour, minute)
        except Exception as e:
            _LOGGER.error("Error setting pressure test schedule: %s", e)

    @callback
    async def set_thresholds(call: ServiceCall) -> None:
        """Handle the service action call."""
        device_id = call.data.get("device_id")
        device_reg = dr.async_get(hass)
        device_entry = device_reg.async_get(device_id)
        sn = device_entry.serial_number
        pressure_sensitivity = call.data.get("pressure_sensitivity", 0.3)
        pressure_test_duration = call.data.get("pressure_test_duration", 45)
        pressure_close_delay = call.data.get("pressure_close_delay", 255600)
        pressure_notification_delay = call.data.get(
            "pressure_notification_delay", 169200
        )
        medium_leak_threshold = call.data.get("medium_leak_threshold", 5.0)
        medium_leak_close_delay = call.data.get("medium_leak_close_delay", 2700)
        medium_leak_notification_delay = call.data.get(
            "medium_leak_notification_delay", 2700
        )
        large_leak_threshold = call.data.get("large_leak_threshold", 1500.0)
        large_leak_close_delay = call.data.get("large_leak_close_delay", 90)
        large_leak_notification_delay = call.data.get(
            "large_leak_notification_delay", 90
        )
        thresholds = LKThresholds(
            pressure=LKPressureThresholds(
                sensitivity=pressure_sensitivity,
                duration=pressure_test_duration,
                closeDelay=pressure_close_delay,
                notificationDelay=pressure_notification_delay,
            ),
            leakMedium={
                "threshold": medium_leak_threshold,
                "closeDelay": medium_leak_close_delay,
                "notificationDelay": medium_leak_notification_delay,
            },
            leakLarge={
                "threshold": large_leak_threshold,
                "closeDelay": large_leak_close_delay,
                "notificationDelay": large_leak_notification_delay,
            },
        )
        _LOGGER.info(f"Setting thresholds {sn} to {thresholds}")
        if not sn:
            _LOGGER.error("No serial number found for device %s", device_id)
            return
        try:
            username = entry.data.get(CONF_USERNAME)
            password = entry.data.get(CONF_PASSWORD)

            async with LKSystemsManager(username, password) as lk_inst:
                if not await lk_inst.login():
                    _LOGGER.error("Failed to login, abort update")
                    raise Exception("Failed to login")
                await lk_inst.cubic_secure_set_thresholds(sn, thresholds)
        except Exception as e:
            _LOGGER.error("Error setting thresholds: %s", e)

    # Register our service with Home Assistant.
    hass.services.async_register(DOMAIN, "pause_leak_detection", pause_leak_detection)
    hass.services.async_register(DOMAIN, "close_valve", close_valve)
    hass.services.async_register(DOMAIN, "open_valve", open_valve)
    hass.services.async_register(
        DOMAIN, "set_pressure_test_schedule", set_pressure_test_schedule
    )
    hass.services.async_register(DOMAIN, "set_thresholds", set_thresholds)
