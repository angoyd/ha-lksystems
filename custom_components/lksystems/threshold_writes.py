"""Debounced, retry-aware writes shared by every entity that writes to
one Cubic Secure device's thresholds endpoint.

The six threshold numbers, the Prevent Valve Closing switch, and the
Reset Thresholds To Defaults button all write to the same underlying
object at the same endpoint, so editing several of them in a burst
should produce one write, not several - and a failure on that endpoint
(most often rate-limiting) affects all of them, not just whichever one
triggered it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components import logbook, persistent_notification
from homeassistant.core import HomeAssistant
from homeassistant.helpers.event import async_call_later

from .const import DOMAIN
from .repairs import (
    async_clear_threshold_write_failed_issue,
    async_create_threshold_write_failed_issue,
)
from .services import set_thresholds_for_serial

if TYPE_CHECKING:
    from . import LKSystemCoordinator


class LKThresholdWriteCoordinator:
    """Coalesces threshold edits to one device into a single debounced
    write, and holds/retries a failed one instead of just dropping it.

    - stage() merges a new edit into whatever's already pending and
      (re)starts one shared debounce timer for the whole device -
      editing several fields within DEBOUNCE_SECONDS of each other
      produces one write covering all of them, not one write each.
      write_now() does the same merge but writes immediately instead of
      waiting out the debounce - for one-shot controls (a switch, a
      reset button) rather than a continuously-editable field.
    - effective_thresholds() is what an editable entity should display -
      the real coordinator value with every currently pending/held edit
      applied on top, so an edit shows immediately and a held retry
      doesn't revert to the pre-edit value until it's actually given up
      on.
    - A failed write is retried automatically - after the rate limit's
      own Retry-After when known, FALLBACK_RETRY_SECONDS otherwise - up
      to MAX_RETRY_ATTEMPTS times, holding the edit rather than
      discarding it on the first failure.
    - is_blocked stays continuously True across every attempt in that
      retry sequence (never toggled back and forth in between, even if
      a retry itself fails again) - entities read it for their own
      availability. A blocked/unblocked transition is pushed out via the
      device's own LKSystemCoordinator.async_update_listeners(), the
      same mechanism every CoordinatorEntity on that device already
      listens through, so no separate registration is needed here.
    """

    DEBOUNCE_SECONDS = 8
    FALLBACK_RETRY_SECONDS = 30
    MAX_RETRY_ATTEMPTS = 3

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: "LKSystemCoordinator",
        device_identity: str,
    ) -> None:
        """Initialize the write coordinator."""
        self.hass = hass
        self._coordinator = coordinator
        self._device_identity = device_identity
        self._pending_overrides: dict[str, dict] = {}
        self._unsub_timer = None
        self._retry_attempt = 0

    @property
    def is_blocked(self) -> bool:
        """Whether a write is currently being retried after a failure."""
        return self._retry_attempt > 0

    def effective_thresholds(self) -> dict:
        """Return this device's thresholds with every pending/held edit
        applied on top of the coordinator's own cached value."""
        updated = {
            category: dict(fields)
            for category, fields in self._coordinator_thresholds().items()
        }
        for category, fields in self._pending_overrides.items():
            updated.setdefault(category, {}).update(fields)
        return updated

    def stage(self, category: str, overrides: dict) -> None:
        """Merge overrides for one category into the pending write,
        (re)starting the shared debounce timer for this device."""
        self._merge_pending({category: overrides})
        self._unsub_timer = async_call_later(
            self.hass, self.DEBOUNCE_SECONDS, self._attempt_write
        )

    async def write_now(self, overrides_by_category: dict[str, dict]) -> None:
        """Merge overrides for one or more categories and write them
        immediately, skipping the debounce - for a one-shot control that
        isn't a continuously-editable field."""
        self._merge_pending(overrides_by_category)
        await self._attempt_write()

    def _merge_pending(self, overrides_by_category: dict[str, dict]) -> None:
        for category, overrides in overrides_by_category.items():
            self._pending_overrides.setdefault(category, {}).update(overrides)
        if self._unsub_timer is not None:
            self._unsub_timer()
            self._unsub_timer = None

    async def _attempt_write(self, _now=None) -> None:
        """Write every pending override in one call, retrying on failure."""
        self._unsub_timer = None
        updated = self.effective_thresholds()

        result = await set_thresholds_for_serial(
            self.hass, self._coordinator.entry, self._device_identity, updated
        )

        if result.success:
            self._pending_overrides = {}
            self._resolve(success=True)
            return

        delay = (
            result.retry_after
            if result.retry_after is not None
            else self.FALLBACK_RETRY_SECONDS
        )
        self._retry_attempt += 1
        if self._retry_attempt == 1:
            self._notify_blocked(delay)
            self._coordinator.async_update_listeners()

        if self._retry_attempt >= self.MAX_RETRY_ATTEMPTS:
            self._pending_overrides = {}
            self._resolve(success=False)
            return

        self._unsub_timer = async_call_later(self.hass, delay, self._attempt_write)

    def _coordinator_thresholds(self) -> dict:
        # Deferred to avoid a circular import: __init__.py imports
        # async_setup_services (services.py) at module load time, which
        # this module also imports from, so a top-level import of
        # cubic_secure_thresholds here would try to read it off __init__.py
        # before that module has finished executing.
        from . import cubic_secure_thresholds

        return cubic_secure_thresholds(self._coordinator, self._device_identity)

    def _resolve(self, *, success: bool) -> None:
        """Stop retrying - either the write succeeded, or MAX_RETRY_ATTEMPTS
        was reached and it's being given up on."""
        was_blocked = self.is_blocked
        self._retry_attempt = 0
        persistent_notification.async_dismiss(self.hass, self._notification_id)
        entry_id = self._coordinator.entry.entry_id
        if success:
            async_clear_threshold_write_failed_issue(
                self.hass, entry_id, self._device_identity
            )
        else:
            logbook.async_log_entry(
                self.hass,
                "LK Systems",
                "gave up writing a threshold change after repeated failures - "
                "the edit was discarded",
                domain=DOMAIN,
            )
            async_create_threshold_write_failed_issue(
                self.hass, entry_id, self._device_identity
            )
        if was_blocked:
            self._coordinator.async_update_listeners()

    @property
    def _notification_id(self) -> str:
        return f"{DOMAIN}_threshold_write_{self._device_identity}"

    def _notify_blocked(self, delay: float) -> None:
        message = (
            f"LK Systems: a setting change is rate-limited by the cloud API, "
            f"retrying in {delay:.0f}s."
        )
        persistent_notification.async_create(
            self.hass, message, title="LK Systems", notification_id=self._notification_id
        )
        logbook.async_log_entry(self.hass, "LK Systems", message, domain=DOMAIN)

    def async_shutdown(self) -> None:
        """Cancel any pending debounce/retry timer - it would otherwise
        fire against a torn-down coordinator after unload."""
        if self._unsub_timer is not None:
            self._unsub_timer()
            self._unsub_timer = None
