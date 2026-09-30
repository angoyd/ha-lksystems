"""Repair/issue-registry integration for the LK Systems integration.

Surfaces persistent failures in Settings -> System -> Repairs instead of
only as log warnings or an entity silently going stale/unavailable. Each
issue is keyed per config entry so multiple accounts don't collide, and is
cleared automatically once the condition that raised it resolves.
"""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN


def _issue_id(kind: str, entry_id: str) -> str:
    return f"{kind}_{entry_id}"


def _create_issue(
    hass: HomeAssistant,
    entry_id: str,
    kind: str,
    severity: ir.IssueSeverity,
    translation_key: str | None = None,
) -> None:
    ir.async_create_issue(
        hass,
        DOMAIN,
        _issue_id(kind, entry_id),
        is_fixable=False,
        severity=severity,
        translation_key=translation_key or kind,
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


def async_create_threshold_write_failed_issue(
    hass: HomeAssistant, entry_id: str, device_identity: str
) -> None:
    """Raise a repair issue for a threshold/schedule write that kept
    failing until its retries were exhausted and the edit was discarded.

    Scoped per device (not just per entry_id, unlike the other issue
    kinds here) since an account can have more than one Cubic Secure
    device, each writing independently.
    """
    _create_issue(
        hass,
        entry_id,
        f"threshold_write_failed_{device_identity}",
        ir.IssueSeverity.WARNING,
        translation_key="threshold_write_failed",
    )


def async_clear_threshold_write_failed_issue(
    hass: HomeAssistant, entry_id: str, device_identity: str
) -> None:
    """Clear the threshold-write-failed repair issue for one device, if any."""
    _clear_issue(hass, entry_id, f"threshold_write_failed_{device_identity}")


def async_create_historical_unavailable_noise_issue(
    hass: HomeAssistant, entry_id: str
) -> None:
    """Raise a one-time, informational notice about pre-fix history noise.

    Entities used to flap `unavailable` on any single transient poll
    failure, before `CubicSecureEntityMixin.available` started gating on
    a consecutive-failure streak instead - accounts that were set up
    before that fix may have that noise recorded in their history. This
    tells the user where it came from and how to optionally clean it up.

    Raised unconditionally on every setup rather than tied to a live
    condition: `_create_issue()` is a no-op once the issue already
    exists, so this only ever surfaces once and stays dismissed once the
    user dismisses it - there's nothing here to detect or clear.
    """
    _create_issue(
        hass, entry_id, "historical_unavailable_noise", ir.IssueSeverity.WARNING
    )


def async_clear_all_issues(hass: HomeAssistant, entry_id: str) -> None:
    """Clear every repair issue this integration can raise for entry_id."""
    async_clear_auth_failed_issue(hass, entry_id)
    async_clear_persistent_update_failure_issue(hass, entry_id)
