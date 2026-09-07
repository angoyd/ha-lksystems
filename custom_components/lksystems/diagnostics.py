"""Diagnostics support for LK Systems."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import DOMAIN

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
    "identity",
}

# device_details/hub_data are dicts keyed *by* the device's raw MAC/identity
# itself. async_redact_data only ever redacts values under known key names,
# never a dict's own keys, so these need rekeying to anonymous placeholders
# instead of (or in addition to) the value-based redaction above. Each field
# gets its own placeholder prefix so a "device_1" from one field is never
# mistaken for referring to the same device as a "device_1" from the other.
MAC_KEYED_COORDINATOR_FIELDS = {
    "device_details": "device",
    "hub_data": "hub",
}


def _anonymize_keys(mapping: dict[str, Any], placeholder: str) -> dict[str, Any]:
    """Replace a dict's keys with anonymous, stably ordered placeholders."""
    return {
        f"{placeholder}_{index}": value
        for index, value in enumerate(mapping.values(), start=1)
    }


def _redact_coordinator_data(coordinator_data: dict[str, Any]) -> dict[str, Any]:
    data = dict(coordinator_data)
    for field, placeholder in MAC_KEYED_COORDINATOR_FIELDS.items():
        if field in data:
            data[field] = _anonymize_keys(data[field], placeholder)

    redacted = async_redact_data(data, TO_REDACT)

    # Cubic Secure's own identity is deliberately exempted from the blanket
    # "identity" redaction above: unlike a MAC it's not a hardware
    # fingerprint, and it's the only way to correlate a report's nested data
    # across multiple Cubic Secure devices on the same account.
    for cubic_identity, device in redacted.get("cubic_devices", {}).items():
        machine_info = device.get("machine_info")
        if isinstance(machine_info, dict):
            machine_info["identity"] = cubic_identity

    return redacted


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    return {
        "entry_data": async_redact_data(dict(entry.data), TO_REDACT),
        "coordinator_data": _redact_coordinator_data(coordinator.data),
    }
