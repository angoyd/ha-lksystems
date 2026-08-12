"""Restore-last-known-state helpers shared by every entity.

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
from typing import Any

from homeassistant.util import dt as dt_util

# "Cloud" distinguishes this from lastStatus/"Last Data Sent" (when the
# *device* last sent LK's cloud data - a value we only relay) and from the
# coordinator's own last_update_attempt_time (every poll attempt, whether
# or not it succeeded) - this is specifically when *our own* last
# successful fetch from LK's cloud API happened.
ATTR_LAST_SUCCESSFUL_CLOUD_FETCH = "last_successful_cloud_fetch"

STALE_THRESHOLD_MULTIPLIER = 3


def is_restored_value_fresh(
    restored_last_cloud_fetch: datetime | None, update_interval: timedelta | None
) -> bool:
    """Return whether a value restored from disk is still fresh enough to show."""
    if restored_last_cloud_fetch is None or update_interval is None:
        return False
    return (
        dt_util.utcnow() - restored_last_cloud_fetch
        <= update_interval * STALE_THRESHOLD_MULTIPLIER
    )


def parse_restored_last_cloud_fetch(last_state) -> datetime | None:
    """Parse ATTR_LAST_SUCCESSFUL_CLOUD_FETCH from a restored state's attributes."""
    last_fetch = last_state.attributes.get(ATTR_LAST_SUCCESSFUL_CLOUD_FETCH)
    if not last_fetch:
        return None
    return dt_util.parse_datetime(last_fetch)


def last_successful_cloud_fetch_attributes(
    last_successful_cloud_fetch: datetime | None,
) -> dict[str, str]:
    """Return the extra_state_attributes payload exposing last_successful_cloud_fetch."""
    if last_successful_cloud_fetch is None:
        return {}
    return {
        ATTR_LAST_SUCCESSFUL_CLOUD_FETCH: last_successful_cloud_fetch.isoformat()
    }


class RestoredNativeValueMixin:
    """Restore a sensor's last-known native value uniformly across an HA restart.

    Mixed in ahead of CoordinatorEntity and RestoreSensor, whose
    self.coordinator and async_get_last_sensor_data()/async_get_last_state()
    this relies on. Subclasses supply the live lookup via _live_native_value();
    this then owns the fallback to the restored value once that comes back
    empty.
    """

    _restored_native_value: Any = None
    _restored_last_cloud_fetch: datetime | None = None

    async def async_added_to_hass(self) -> None:
        """Restore the last-known value across an HA restart."""
        await super().async_added_to_hass()

        last_sensor_data = await self.async_get_last_sensor_data()
        if last_sensor_data is not None:
            self._restored_native_value = last_sensor_data.native_value

        last_state = await self.async_get_last_state()
        if last_state is not None:
            self._restored_last_cloud_fetch = parse_restored_last_cloud_fetch(
                last_state
            )

    @property
    def native_value(self) -> Any:
        """Return the live value, falling back to the last-restored value
        if the coordinator doesn't currently have one."""
        value = self._live_native_value()
        if value is not None:
            return value
        if is_restored_value_fresh(
            self._restored_last_cloud_fetch, self.coordinator.update_interval
        ):
            return self._restored_native_value
        return None
