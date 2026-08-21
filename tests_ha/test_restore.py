"""Tests for restore.py's freshness-check helper.

Entity-level restore behavior (an entity actually showing a restored value,
or not) is covered separately in test_sensor.py/test_climate.py - this is
only concerned with is_restored_value_fresh()'s own age-vs-threshold logic.
"""

from __future__ import annotations

from datetime import timedelta

from homeassistant.util import dt as dt_util

from custom_components.lksystems.restore import (
    STALE_THRESHOLD_MULTIPLIER,
    is_restored_value_fresh,
)


class TestIsRestoredValueFresh:
    def test_none_last_fetch_is_not_fresh(self):
        assert is_restored_value_fresh(None, timedelta(minutes=5)) is False

    def test_none_update_interval_is_not_fresh(self):
        assert is_restored_value_fresh(dt_util.utcnow(), None) is False

    def test_just_fetched_is_fresh(self):
        assert is_restored_value_fresh(dt_util.utcnow(), timedelta(minutes=5)) is True

    def test_within_threshold_is_fresh(self):
        update_interval = timedelta(minutes=5)
        age = update_interval * STALE_THRESHOLD_MULTIPLIER - timedelta(seconds=1)
        last_fetch = dt_util.utcnow() - age

        assert is_restored_value_fresh(last_fetch, update_interval) is True

    def test_beyond_threshold_is_not_fresh(self):
        update_interval = timedelta(minutes=5)
        age = update_interval * STALE_THRESHOLD_MULTIPLIER + timedelta(seconds=1)
        last_fetch = dt_util.utcnow() - age

        assert is_restored_value_fresh(last_fetch, update_interval) is False
