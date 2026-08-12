"""Provide info to system health for the LK Systems integration."""

from __future__ import annotations

from typing import Any

from homeassistant.components import system_health
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN
from .pylksystems import LKSystemsManager


@callback
def async_register(
    hass: HomeAssistant, register: system_health.SystemHealthRegistration
) -> None:
    """Register system health callbacks."""
    register.async_register_info(system_health_info)


async def system_health_info(hass: HomeAssistant) -> dict[str, Any]:
    """Get info for the system health info page."""
    coordinator = next(iter(hass.data[DOMAIN].values()))

    return {
        "can_reach_server": await system_health.async_check_can_reach_url(
            hass, LKSystemsManager.BASE_URL
        ),
        "last_update_success": coordinator.last_update_success,
        "update_interval": str(coordinator.update_interval),
    }
