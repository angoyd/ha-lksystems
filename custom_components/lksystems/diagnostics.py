"""Diagnostics support for LK Systems."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import DOMAIN

# Device "identity"/serial_number fields are deliberately not redacted:
# unlike a MAC address they're not a hardware fingerprint, and they're the
# only way to correlate devices across the nested coordinator data when
# debugging a report from an account with multiple Cubic Secure devices.
TO_REDACT = {
    CONF_USERNAME,
    CONF_PASSWORD,
    "realestateId",
    "ownerId",
    "name",
    "address",
    "city",
    "zip",
    "country",
    "mac",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    return {
        "entry_data": async_redact_data(dict(entry.data), TO_REDACT),
        "coordinator_data": async_redact_data(coordinator.data, TO_REDACT),
    }
