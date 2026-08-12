"""Restore-last-known-state helpers shared by every entity (issue #54).

Every entity restores its last value uniformly across a Home Assistant
restart. The coordinator's own in-memory fallback (see __init__.py's
per-cubic-device fetch/fallback) only survives within a running process -
coordinator.data starts as None on a fresh start, so the very first poll
after a restart has nothing to fall back to on its own, and every affected
entity shows unknown even though HA knew a perfectly good value seconds
before the restart.

A restored value is only shown while "fresh enough" - see
is_restored_value_fresh(). During normal steady-state polling a value can
already be up to one update_interval stale before the next poll catches
up, and it's shown with full confidence the whole time; a typical restart
produces a younger value than that (DataUpdateCoordinator's first refresh
fires immediately on setup). The real risk is the tail: a value restored
from disk has no ceiling on its age the way live polling does, so a real
outage (HA/the network down for an hour, a day) must not be presented
looking exactly as fresh as one from moments ago. STALE_THRESHOLD_MULTIPLIER
draws that line at a small multiple of update_interval - beyond it, the
restored value is discarded rather than shown.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from homeassistant.util import dt as dt_util

ATTR_LAST_SUCCESSFUL_FETCH = "last_successful_fetch"

STALE_THRESHOLD_MULTIPLIER = 3


def is_restored_value_fresh(
    restored_last_fetch: datetime | None, update_interval: timedelta | None
) -> bool:
    """Return whether a value restored from disk is still fresh enough to show."""
    if restored_last_fetch is None or update_interval is None:
        return False
    return dt_util.utcnow() - restored_last_fetch <= update_interval * STALE_THRESHOLD_MULTIPLIER
