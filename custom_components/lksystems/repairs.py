"""Repair/issue-registry integration for the LK Systems integration.

Surfaces persistent failures in Settings -> System -> Repairs instead of
only as log warnings or an entity silently going stale/unavailable (issue
#50). Each issue is keyed per config entry so multiple accounts don't
collide, and is cleared automatically once the condition that raised it
resolves - see coordinator.py's _async_update_data().
"""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN


def _auth_failed_issue_id(entry_id: str) -> str:
    return f"auth_failed_{entry_id}"


def _persistent_update_failure_issue_id(entry_id: str) -> str:
    return f"persistent_update_failure_{entry_id}"


def async_create_auth_failed_issue(hass: HomeAssistant, entry_id: str) -> None:
    """Raise a repair issue for an authentication failure."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        _auth_failed_issue_id(entry_id),
        is_fixable=False,
        severity=ir.IssueSeverity.ERROR,
        translation_key="auth_failed",
    )


def async_clear_auth_failed_issue(hass: HomeAssistant, entry_id: str) -> None:
    """Clear the authentication-failure repair issue, if any."""
    ir.async_delete_issue(hass, DOMAIN, _auth_failed_issue_id(entry_id))


def async_create_persistent_update_failure_issue(
    hass: HomeAssistant, entry_id: str
) -> None:
    """Raise a repair issue for a run of consecutive failed updates."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        _persistent_update_failure_issue_id(entry_id),
        is_fixable=False,
        severity=ir.IssueSeverity.WARNING,
        translation_key="persistent_update_failure",
    )


def async_clear_persistent_update_failure_issue(
    hass: HomeAssistant, entry_id: str
) -> None:
    """Clear the persistent-update-failure repair issue, if any."""
    ir.async_delete_issue(hass, DOMAIN, _persistent_update_failure_issue_id(entry_id))
