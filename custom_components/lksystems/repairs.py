"""Repair/issue-registry integration for the LK Systems integration.

Surfaces persistent failures in Settings -> System -> Repairs instead of
only as log warnings or an entity silently going stale/unavailable (issue
#50). Each issue is keyed per config entry so multiple accounts don't
collide, and is cleared automatically once the condition that raised it
resolves.
"""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN


def _issue_id(kind: str, entry_id: str) -> str:
    return f"{kind}_{entry_id}"


def _create_issue(
    hass: HomeAssistant, entry_id: str, kind: str, severity: ir.IssueSeverity
) -> None:
    ir.async_create_issue(
        hass,
        DOMAIN,
        _issue_id(kind, entry_id),
        is_fixable=False,
        severity=severity,
        translation_key=kind,
    )


def _clear_issue(hass: HomeAssistant, entry_id: str, kind: str) -> None:
    ir.async_delete_issue(hass, DOMAIN, _issue_id(kind, entry_id))


def async_create_auth_failed_issue(hass: HomeAssistant, entry_id: str) -> None:
    """Raise a repair issue for an authentication failure."""
    _create_issue(hass, entry_id, "auth_failed", ir.IssueSeverity.ERROR)


def async_clear_auth_failed_issue(hass: HomeAssistant, entry_id: str) -> None:
    """Clear the authentication-failure repair issue, if any."""
    _clear_issue(hass, entry_id, "auth_failed")


def async_create_persistent_update_failure_issue(
    hass: HomeAssistant, entry_id: str
) -> None:
    """Raise a repair issue for a run of consecutive failed updates."""
    _create_issue(
        hass, entry_id, "persistent_update_failure", ir.IssueSeverity.WARNING
    )


def async_clear_persistent_update_failure_issue(
    hass: HomeAssistant, entry_id: str
) -> None:
    """Clear the persistent-update-failure repair issue, if any."""
    _clear_issue(hass, entry_id, "persistent_update_failure")


def async_clear_all_issues(hass: HomeAssistant, entry_id: str) -> None:
    """Clear every repair issue this integration can raise for entry_id."""
    async_clear_auth_failed_issue(hass, entry_id)
    async_clear_persistent_update_failure_issue(hass, entry_id)
