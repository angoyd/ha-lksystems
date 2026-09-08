"""LK Systems integration."""

from __future__ import annotations

import logging
from typing import TypedDict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import asyncio
import base64
import json
from typing import Any, Dict
import time

# Make sure jwt is installed using: pip install pyjwt
try:
    import jwt
except ImportError:
    jwt = None

from homeassistant.exceptions import HomeAssistantError, ConfigEntryAuthFailed
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import CALLBACK_TYPE, HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.event import async_track_point_in_time
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)
from homeassistant.util import dt as dt_util
import voluptuous as vol
from homeassistant.helpers import config_validation as cv

from .const import (
    ATTRIBUTION,
    CONF_UPDATE_INTERVAL,
    CUBIC_SECURE_MODEL,
    CUBIC_SECURE_VALVE_STATE_CLOSED,
    CUBIC_SECURE_VALVE_STATE_OPEN,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    LEAK_DETECTION_EXPIRY_MAX_RETRY_SECONDS,
    LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS,
    LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS,
    MANUFACTURER,
    VALVE_ACTION_MAX_RETRY_SECONDS,
    VALVE_ACTION_RETRY_INTERVAL_SECONDS,
)
from .pylksystems import (
    LKSystemsManager,
    LKSystemsError,
    LKThresholds,
    LKPressureThresholds,
)
from .redact import mask_username
from . import repairs

from .services import async_setup_services

_LOGGER = logging.getLogger(__name__)

# Number of consecutive failed updates before a persistent-failure repair
# issue is raised - a single failed update is routine (network blip, a 429
# that exhausted its retries) and resolves on its own via the next
# scheduled poll, so only a run of failures is worth surfacing.
CONSECUTIVE_FAILURE_THRESHOLD = 3

# Define the platforms we support
PLATFORMS = [
    Platform.SENSOR,
    Platform.CLIMATE,
    Platform.NUMBER,
    Platform.BUTTON,
    Platform.VALVE,
]


class LkStructureResp(TypedDict):
    """API response structure"""

    realestateId: str
    name: str
    city: str
    address: str
    zip: str
    country: str
    ownerId: str
    cubic_devices: Dict[str, "LkCubicDeviceData"]
    cacheUpdated: int
    update_time: str
    next_update_time: str


class LkCubicDeviceData(TypedDict):
    """Per-Cubic-Secure-device data, keyed by device identity in
    LkStructureResp.cubic_devices so multiple devices on one account
    don't share a single overwritable slot."""

    machine_info: LkStructureMachine
    last_measurement: LkCubicSecureResp
    configuration: LKCubicSecureConfigResp


class LKCubicSecureConfigResp(TypedDict):
    """Cubic secure configuration structure"""

    firmwareVersion: str
    hardwareVersion: int
    timeZonePosix: str
    pressureTestSchedule: LKPressureTestSchedule
    valveState: str
    thresholds: LKThresholds
    links: list
    paired: dict
    muteLeak: int
    cacheTimer: int
    cacheUpdated: int


class LKPressureTestSchedule(TypedDict):
    """Pressure test schedule structure"""

    hour: int
    minute: int


class LKLeakInfo(TypedDict):
    """Leak info structure"""

    leakState: str
    meanFlow: float
    dateStartedAt: int
    dateUpdatedAt: int
    acknowledged: bool


class LkCubicSecureResp(TypedDict):
    """API response structure"""

    serialNumber: str
    connectionState: str
    rssi: int
    currentRssi: int
    valveState: str
    lastStatus: int
    type: float
    subType: float
    tempAmbient: float
    tempWaterAverage: float
    tempWaterMin: float
    tempWaterMax: float
    volumeTotal: int
    waterPressure: int
    leak: LKLeakInfo
    cacheUpdated: int


class LkStructureMachine(TypedDict):
    """Machines API Resp structure"""

    identity: str
    deviceGroup: str
    deviceType: str
    deviceRole: str
    realestateId: str
    realestateMachineId: str
    zone: LkZoneInfo


class LkZoneInfo(TypedDict):
    """Zone API Resp"""

    zoneId: str
    zoneName: str
    cacheUpdated: int


# Global token storage (persists between coordinator updates)
TOKEN_STORAGE = {
    # Structure: entry_id -> {"jwt": jwt_token, "refresh": refresh_token, "expiry": timestamp}
}


def is_token_valid(token: str) -> bool:
    """Check if JWT token is valid and not expired."""
    if not token:
        return False

    try:
        # JWT tokens have 3 parts separated by dots
        parts = token.split(".")
        if len(parts) != 3:
            return False

        # The second part (payload) contains the expiration time
        payload = parts[1]
        # Add padding for base64 decoding
        payload += "=" * ((4 - len(payload) % 4) % 4)
        decoded = base64.b64decode(payload)
        payload_data = json.loads(decoded)

        # Check expiration
        exp_time = payload_data.get("exp", 0)
        current_time = dt_util.utcnow().timestamp()

        # Token is valid if expiration is in the future (with 5 min margin)
        is_valid = exp_time > current_time + 300
        _LOGGER.debug(
            "Token validity check: exp=%s, now=%s, valid=%s",
            exp_time,
            current_time,
            is_valid,
        )
        return is_valid
    except Exception as ex:
        _LOGGER.warning("Error validating token: %s", ex)
        return False


# Type definitions for better type checking
# LkStructureResp = Dict[str, Any]


class _LoginFailed(Exception):
    """Raised by LKSystemCoordinator._authenticated_client() when there's
    no valid cached token and a fresh login attempt fails."""


def _round_to_nearest_minute(moment: datetime) -> datetime:
    """Round a datetime to the nearest whole minute.

    LK's own API has slop of up to ~90 seconds around when a pause
    actually starts or ends - confirmed empirically against the real API -
    so a second-precision "paused until" value would claim an accuracy the
    underlying system doesn't have.
    """
    return (moment + timedelta(seconds=30)).replace(second=0, microsecond=0)


def _fill_missing_keys(target: dict, fallback: dict) -> None:
    """Copy every key `fallback` has that `target` doesn't, into `target`.

    For a live/bypass API response whose schema is narrower than the
    cached one it's replacing - so a cache-only field doesn't just vanish
    because a caller bypassed the cache.
    """
    for key, value in fallback.items():
        target.setdefault(key, value)


class LKSystemCoordinator(DataUpdateCoordinator[LkStructureResp]):
    """Data update coordinator for LK Systems."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the coordinator."""
        # Always convert to integer in case it comes as string from config.
        # Options (set via the Configure dialog after initial setup) take
        # precedence over data (set on the original setup form) - this
        # mirrors async_update_options()'s lookup below, which is what
        # actually detects changes and triggers a reload.
        update_interval_minutes = int(
            entry.options.get(
                CONF_UPDATE_INTERVAL,
                entry.data.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL),
            )
        )

        _LOGGER.debug(
            "Initializing LK Systems coordinator with update interval: %d minutes",
            update_interval_minutes,
        )

        # Store for later reference
        self._update_interval_minutes = update_interval_minutes
        self._entry = entry
        self._last_cloud_fetch_attempt = dt_util.now()
        self._entry_id = entry.entry_id
        self.last_successful_cloud_fetch: datetime | None = None
        self._consecutive_failures = 0

        # How long the next "Pause Leak Detection" button press should pause
        # for, per Cubic Secure device serial number. A local preference
        # (not fetched from the API), set by number.py and read by
        # button.py.
        self.pause_leak_detection_seconds: dict[str, int] = {}

        # When leak detection will resume for a paused Cubic Secure device,
        # per device serial number - absent when not currently paused. The
        # API's own muteLeak field doesn't decrement between polls and
        # isn't a live countdown - confirmed empirically against the real
        # API - so this is computed and tracked locally instead: set
        # explicitly by set_leak_detection_paused_until() right after HA
        # itself issues a pause/resume, and kept in sync with pauses/
        # cancellations from elsewhere (e.g. the LK app) by
        # _reconcile_leak_detection_paused_until() on every cached
        # configuration fetch.
        self.leak_detection_paused_until: dict[str, datetime] = {}

        # When set_leak_detection_paused_until() last landed for a
        # device - guards _reconcile_leak_detection_paused_until() against
        # a poll that coincidentally lands moments after that write, while
        # the cloud's cached response may still be serving a pre-write
        # snapshot (see LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS).
        self._leak_detection_last_local_write: dict[str, datetime] = {}

        # Cancel handle for each device's pending
        # _schedule_leak_detection_expiry_refresh() call, if any - reaching
        # a target end time isn't itself an event anything reacts to, so
        # without this, leak_detection_paused_until would just sit on a
        # stale value until the next regular poll (up to a full
        # update_interval later) picked up the change.
        self._leak_detection_refresh_unsub: dict[str, CALLBACK_TYPE] = {}

        # Cancel handle for each device's pending
        # _schedule_valve_state_confirmation() call, if any - see that
        # method's own docstring.
        self._valve_action_unsub: dict[str, CALLBACK_TYPE] = {}

        # Whether a device is currently mid-open/close, per device
        # identity - True while closing, False while opening, absent once
        # confirmed (or given up on). valve.py's is_closing/is_opening
        # read this directly, so the entity shows a transitional state
        # for the real time the physical motor takes to move instead of
        # flashing through whatever intermediate (possibly stale) reads
        # _schedule_valve_state_confirmation()'s retries publish along
        # the way.
        self.valve_action_pending: dict[str, bool] = {}

        # Device identities queued for a cache-bypassing fetch on the
        # coordinator's next update, via async_request_forced_refresh()
        # below. A set rather than a single overwritable value, so two
        # callers requesting a bypass for two different devices before that
        # update actually runs both get honored by it, instead of the
        # second overwriting the first. _fetch_data() snapshots and clears
        # this in one statement with no `await` in between, so a request
        # already queued by the time it does that is never lost, and one
        # that arrives after simply waits for the next update - the same
        # way a plain async_request_refresh() call arriving mid-update
        # already behaves.
        self._force_bypass_device_ids: set[str] = set()

        # Initialize coordinator with update interval
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(minutes=update_interval_minutes),
        )

    @property
    def entry(self) -> ConfigEntry:
        """Return the config entry this coordinator was set up from.

        Lets entities that need it (to call an API function directly,
        outside the coordinator's own methods) reach it through the
        coordinator they already hold, rather than each entity taking and
        storing its own separate copy.
        """
        return self._entry

    async def set_thermostat_temperature(self, device_id, temperature):
        """Set thermostat temperature through the API.

        Args:
            device_id: The device identity (MAC or unique ID)
            temperature: The temperature value in tenths of a degree (e.g. 215 = 21.5°C)

        Returns:
            True if the temperature was set successfully, False otherwise.
        """
        _LOGGER.debug("Setting temperature for device %s to %s", device_id, temperature)

        try:
            async with self._authenticated_client() as lk_inst:
                result = await lk_inst.set_thermostat_temperature(
                    device_id, temperature
                )

                if not result["success"]:
                    _LOGGER.error("Failed to set temperature: %s", result["error"])
                    return False

                _LOGGER.debug("Temperature set successfully: %s", result["data"])

                # Update the coordinator data to reflect the change
                await self.async_refresh()

                return True

        except _LoginFailed:
            _LOGGER.error("Login failed when setting temperature")
            return False
        except Exception as ex:
            _LOGGER.error("Failed to set temperature: %s", ex)
            return False

    def _apply_device_measurement(self, device_id: str, measurement_data: dict) -> None:
        """Write a fresh measurement for one Arc device into every place
        self.data stores it: device_details, the flat devices list, and
        any hub_data the device belongs to."""
        device_details = self.data.setdefault("device_details", {})
        device_details.setdefault(device_id, {})["measurement"] = measurement_data

        for device in self.data.get("devices", []):
            device_title = device.get("deviceTitle", {})
            if device.get("mac") == device_id or device_title.get("identity") == device_id:
                device["measurement"] = measurement_data.copy()
                break

        for hub_data in self.data.get("hub_data", {}).values():
            if not isinstance(hub_data, dict):
                continue
            for device in hub_data.get("devices", []):
                if device.get("mac") == device_id:
                    device["measurement"] = measurement_data.copy()

    async def force_device_update(self, device_id: str) -> bool:
        """Force a fresh, cache-bypassing measurement fetch for one Arc
        device, publishing it immediately rather than waiting for the next
        regular poll.
        """
        _LOGGER.debug("Forcing measurement update for device %s", device_id)

        try:
            async with self._authenticated_client() as lk_inst:
                success = await lk_inst.get_device_measurement(
                    device_id, force_update=True
                )

                if success and device_id in lk_inst.device_measurements and self.data:
                    self._apply_device_measurement(
                        device_id, lk_inst.device_measurements[device_id]
                    )
                    self.async_set_updated_data(self.data)

                return success

        except _LoginFailed:
            _LOGGER.error("Login failed when forcing device update")
            return False
        except Exception as ex:
            _LOGGER.error("Error during forced device update: %s", ex)
            return False

    @asynccontextmanager
    async def _authenticated_client(self):
        """Yield a logged-in LKSystemsManager for a one-off API call,
        reusing a still-valid stored token instead of always logging in
        fresh. Raises _LoginFailed if there's no valid cached token and a
        fresh login attempt fails.
        """
        username = self._entry.data.get(CONF_USERNAME)
        password = self._entry.data.get(CONF_PASSWORD)

        async with LKSystemsManager(username, password) as lk_inst:
            stored_tokens = TOKEN_STORAGE.get(self._entry_id, {})
            stored_jwt = stored_tokens.get("jwt")

            if stored_jwt and is_token_valid(stored_jwt):
                lk_inst.jwt_token = stored_jwt
                lk_inst.refresh_token = stored_tokens.get("refresh")
            else:
                if not await lk_inst.login():
                    raise _LoginFailed()

                TOKEN_STORAGE[self._entry_id] = {
                    "jwt": lk_inst.jwt_token,
                    "refresh": lk_inst.refresh_token,
                    "expiry": dt_util.utcnow().timestamp() + 3600,
                }

            yield lk_inst

    async def async_request_forced_refresh(self, device_id: str) -> None:
        """Request a cache-bypassing fetch for one device on the
        coordinator's next update, then trigger that update.

        Covers data types that have no other bypass entry point - a Cubic
        Secure device's own measurement (which carries its leak state) and
        an Arc-sense device's configuration (used for thermostat-role
        devices). Cubic Secure configuration already has its own dedicated
        force_cubic_secure_configuration_update(); this is the general
        primitive behind that gap that one doesn't cover.
        """
        self._force_bypass_device_ids.add(device_id)
        await self.async_request_refresh()

    def _pause_end_time(self, seconds: int) -> datetime:
        """Return the (rounded) wall-clock time `seconds` from now."""
        return _round_to_nearest_minute(dt_util.utcnow() + timedelta(seconds=seconds))

    def _clear_leak_detection_paused_until(self, device_identity: str) -> None:
        """Stop tracking a device as paused, and cancel any pending expiry
        check for it - shared by an explicit resume and by reconciliation
        learning the cloud considers it over."""
        self.leak_detection_paused_until.pop(device_identity, None)
        self._cancel_leak_detection_expiry_refresh(device_identity)

    def _adopt_leak_detection_target(self, device_identity: str, seconds: int) -> None:
        """Start tracking a device as paused for `seconds` from now, and
        schedule its expiry check - shared by an explicit pause and by
        reconciliation adopting one HA didn't itself start."""
        target = self._pause_end_time(seconds)
        self.leak_detection_paused_until[device_identity] = target
        self._schedule_leak_detection_expiry_refresh(device_identity, target)

    def set_leak_detection_paused_until(
        self, device_identity: str, seconds: int
    ) -> None:
        """Set (or, for seconds=0, clear) a device's locally tracked pause
        end time, right after HA itself issues a pause/resume that the API
        call confirmed succeeded.

        Takes effect immediately rather than waiting for
        _reconcile_leak_detection_paused_until() to pick it up off the next
        poll, and - for a re-pause while already active - overwrites the
        previous target rather than leaving it in place, matching the real
        API's reset-not-stack behavior (confirmed empirically).
        """
        self._leak_detection_last_local_write[device_identity] = dt_util.utcnow()
        if not seconds:
            self._clear_leak_detection_paused_until(device_identity)
            return
        self._adopt_leak_detection_target(device_identity, seconds)

    def _reconcile_leak_detection_paused_until(
        self, device_identity: str, configuration: dict, now: datetime
    ) -> None:
        """Keep the locally tracked pause end time in sync with a pause
        HA didn't itself just set - one started or cancelled from
        elsewhere (e.g. the LK app), or one that expired naturally.

        Only ever clears an untracked device or adopts a fresh target for
        one that isn't tracked yet; never overwrites an already-tracked
        target, since muteLeak can't tell a still-ongoing pause apart from
        a brand new one started for a different duration - only
        set_leak_detection_paused_until() (an explicit request HA itself
        just made) may do that.

        Also does nothing within LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS
        of such a write: the caller triggering this (a regular poll or
        the expiry retry-loop) isn't caused by the write, but nothing
        stops it landing moments after one anyway, and `configuration`
        can still be a pre-write cached snapshot at that point. Takes
        `now` from the caller rather than reading dt_util.utcnow() itself,
        so it judges the grace window against whatever moment the caller
        is actually acting on - the expiry retry-loop already has its own
        `now` (the point in time HA's scheduler woke it for), and reusing
        it here keeps this check consistent with that, rather than a
        second, independent clock read a moment later.
        """
        last_write = self._leak_detection_last_local_write.get(device_identity)
        if last_write is not None and now - last_write < timedelta(
            seconds=LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS
        ):
            return
        mute_leak_seconds = configuration.get("muteLeak")
        if not mute_leak_seconds:
            self._clear_leak_detection_paused_until(device_identity)
            return
        if device_identity not in self.leak_detection_paused_until:
            self._adopt_leak_detection_target(device_identity, mute_leak_seconds)

    def _schedule_leak_detection_expiry_refresh(
        self, device_identity: str, target: datetime
    ) -> None:
        """Poll the cloud starting at a pause's target end time, retrying
        every LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS until it
        confirms the pause is actually over, so leak_detection_paused_until
        clears promptly instead of sitting on a stale value until the next
        regular poll. Gives up after LEAK_DETECTION_EXPIRY_MAX_RETRY_SECONDS
        and leaves it to that regular poll instead.
        """
        self._cancel_leak_detection_expiry_refresh(device_identity)
        retry_deadline = target + timedelta(
            seconds=LEAK_DETECTION_EXPIRY_MAX_RETRY_SECONDS
        )

        def _track_at(when: datetime) -> None:
            self._leak_detection_refresh_unsub[device_identity] = (
                async_track_point_in_time(self.hass, _check_if_expired, when)
            )

        async def _check_if_expired(now: datetime) -> None:
            self._leak_detection_refresh_unsub.pop(device_identity, None)
            if not await self.refresh_cubic_secure_configuration(device_identity):
                return
            configuration = self.data["cubic_devices"][device_identity][
                "configuration"
            ]
            self._reconcile_leak_detection_paused_until(
                device_identity, configuration, now
            )
            # refresh_cubic_secure_configuration() above already notified
            # listeners once, before this reconcile ran - entities reading
            # leak_detection_paused_until (the Resume button, the "Leak
            # Detection Paused Until" sensor) need a second notification to
            # pick up what it just changed, or they're stuck showing the
            # pre-reconcile state until the next regular poll.
            self.async_update_listeners()

            if device_identity not in self.leak_detection_paused_until:
                # Logged at debug rather than left silent so how long the
                # cloud actually lags past a pause's nominal end is
                # observable from real usage over time, not just the one
                # sample this was originally tuned from.
                _LOGGER.debug(
                    "Leak detection expiry for %s confirmed %s past its target",
                    device_identity,
                    now - target,
                )
                return
            if now >= retry_deadline:
                _LOGGER.debug(
                    "Giving up on leak detection expiry checks for %s after %s - "
                    "leaving it to the regular poll",
                    device_identity,
                    now - target,
                )
                return  # give up - the regular poll will pick it up eventually

            _track_at(now + timedelta(seconds=LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS))

        _track_at(target)

    def _cancel_leak_detection_expiry_refresh(self, device_identity: str) -> None:
        """Cancel a device's pending expiry check, if one is scheduled."""
        if unsub := self._leak_detection_refresh_unsub.pop(device_identity, None):
            unsub()

    def mark_valve_action_pending(
        self, device_identity: str, expect_closed: bool
    ) -> None:
        """Show a device as opening/closing straight away.

        Called by valve.py right before it even issues the open/close
        write, not just once _schedule_valve_state_confirmation()'s
        confirmation retries start - the write itself (login and the API
        call) goes through the same unbounded Retry-After-honoring
        network layer as any other request, so it can itself take a long
        time (confirmed missing live: a slow write left the entity
        showing nothing until the frontend's own optimistic toggle
        reverted). See valve_action_pending's own comment for why
        tracking this at all matters.
        """
        self._cancel_valve_action_confirmation(device_identity)
        self.valve_action_pending[device_identity] = expect_closed
        self.async_update_listeners()

    def clear_valve_action_pending(self, device_identity: str) -> None:
        """Abort a pending open/close confirmation without assuming
        anything about the outcome - for when the write itself never
        got attempted (e.g. the device wasn't found), so there's nothing
        to confirm and nothing will otherwise resolve the pending state
        mark_valve_action_pending() just set.
        """
        self._cancel_valve_action_confirmation(device_identity)
        self.valve_action_pending.pop(device_identity, None)
        self.async_update_listeners()

    def _valve_reached_expected_state(
        self, device_identity: str, expect_closed: bool
    ) -> bool:
        """Whether the coordinator's current data already shows the valve
        in the state an open/close write was asked to reach."""
        valve_state = self.data["cubic_devices"][device_identity]["configuration"].get(
            "valveState"
        )
        return (valve_state == CUBIC_SECURE_VALVE_STATE_CLOSED) == expect_closed

    def _resolve_valve_action(self, device_identity: str) -> None:
        """Mark a device's pending open/close write as confirmed.

        A confirming fetch already notified listeners once with its raw
        data; entities reading valve_action_pending (is_closing/
        is_opening) need a second notification to pick up that it just
        cleared, or they're stuck showing the transitional state until
        the next regular poll.
        """
        self.valve_action_pending.pop(device_identity, None)
        self.async_update_listeners()

    def handle_valve_write_result(
        self, device_identity: str, expect_closed: bool, write_succeeded: bool
    ) -> None:
        """Decide what a just-finished open/close write means for the
        pending confirmation mark_valve_action_pending() set before it.

        The write is expected to have already reused its own session for
        one confirmation read, so coordinator data may already reflect
        the new state - resolve immediately rather than waiting out a
        retry interval for news that already arrived. If it doesn't yet
        (the physical motor is still moving), fall back to the regular
        confirmation retry loop. If the write was never actually issued
        (e.g. login failed), there's nothing to confirm.
        """
        if not write_succeeded:
            self.clear_valve_action_pending(device_identity)
        elif self._valve_reached_expected_state(device_identity, expect_closed):
            self._resolve_valve_action(device_identity)
        else:
            self._schedule_valve_state_confirmation(device_identity, expect_closed)

    def _schedule_valve_state_confirmation(
        self, device_identity: str, expect_closed: bool
    ) -> None:
        """Poll the cloud every VALVE_ACTION_RETRY_INTERVAL_SECONDS until
        it confirms the valve actually reached the requested state, giving
        up after VALVE_ACTION_MAX_RETRY_SECONDS - see that constant's own
        comment for what happens then.
        """
        self.mark_valve_action_pending(device_identity, expect_closed)
        retry_deadline = dt_util.utcnow() + timedelta(
            seconds=VALVE_ACTION_MAX_RETRY_SECONDS
        )

        def _track_at(when: datetime) -> None:
            self._valve_action_unsub[device_identity] = async_track_point_in_time(
                self.hass, _check_valve_state, when
            )

        def _give_up() -> None:
            # HA already issued the write - assume it succeeded rather
            # than leave the entity showing a stale pre-action reading
            # for longer than VALVE_ACTION_MAX_RETRY_SECONDS. Wrong only
            # if the write itself failed downstream of a successful API
            # call, in which case the next regular poll corrects it.
            self.data["cubic_devices"][device_identity]["configuration"][
                "valveState"
            ] = (
                CUBIC_SECURE_VALVE_STATE_CLOSED
                if expect_closed
                else CUBIC_SECURE_VALVE_STATE_OPEN
            )
            self._resolve_valve_action(device_identity)
            _LOGGER.debug(
                "Giving up on confirming valve %s reached the requested "
                "state after %ss - assuming it did, the regular poll "
                "will correct this if not",
                device_identity,
                VALVE_ACTION_MAX_RETRY_SECONDS,
            )

        async def _check_valve_state(_scheduled_for: datetime) -> None:
            self._valve_action_unsub.pop(device_identity, None)
            remaining = (retry_deadline - dt_util.utcnow()).total_seconds()
            if remaining <= 0:
                _give_up()
                return
            try:
                # A bounded wait, not an open-ended await: LK rate-limits
                # this specific endpoint (confirmed empirically, up to a
                # 93s Retry-After observed on a real attempt) and
                # pylksystems correctly honors it - meaning a single fetch
                # can, on its own, take longer than the entire retry
                # window. Passively waiting for it to finish before
                # checking the deadline would let one slow attempt block
                # the entity on a transitional state well past
                # VALVE_ACTION_MAX_RETRY_SECONDS, the opposite of what
                # that cap is for. Abandoning it here, rather than only
                # ignoring its result afterwards, is what actually bounds
                # the wait.
                fetched = await asyncio.wait_for(
                    self.force_cubic_secure_configuration_update(device_identity),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                _give_up()
                return
            if not fetched:
                return

            now = dt_util.utcnow()
            if self._valve_reached_expected_state(device_identity, expect_closed):
                self._resolve_valve_action(device_identity)
                _LOGGER.debug(
                    "Valve %s confirmed %s",
                    device_identity,
                    "closed" if expect_closed else "open",
                )
                return
            if now >= retry_deadline:
                _give_up()
                return

            _track_at(now + timedelta(seconds=VALVE_ACTION_RETRY_INTERVAL_SECONDS))

        _track_at(dt_util.utcnow() + timedelta(seconds=VALVE_ACTION_RETRY_INTERVAL_SECONDS))

    def _cancel_valve_action_confirmation(self, device_identity: str) -> None:
        """Cancel a device's pending valve-state check, if one is scheduled."""
        if unsub := self._valve_action_unsub.pop(device_identity, None):
            unsub()

    async def async_shutdown(self) -> None:
        """Cancel any scheduled call, and ignore new runs.

        Also cancels every pending leak-detection expiry check and
        valve-state confirmation - they'd otherwise fire against a
        torn-down coordinator after unload.
        """
        await super().async_shutdown()
        for device_identity in list(self._leak_detection_refresh_unsub):
            self._cancel_leak_detection_expiry_refresh(device_identity)
        for device_identity in list(self._valve_action_unsub):
            self._cancel_valve_action_confirmation(device_identity)

    async def _apply_cubic_secure_configuration(
        self, lk_inst: LKSystemsManager, device_identity: str, *, force_update: bool
    ) -> bool:
        """Fetch one Cubic Secure device's configuration via `lk_inst` (an
        already-authenticated client) and publish it.

        Shared by every variant below - see their own docstrings for which
        to use when.
        """
        success = await lk_inst.get_cubic_secure_configuration(
            device_identity, force_update=force_update
        )

        if success and self.data:
            self.data["cubic_devices"][device_identity]["configuration"] = (
                lk_inst.cubic_secure_configuration
            )
            # Deliberately doesn't call
            # _reconcile_leak_detection_paused_until() here: some callers
            # of this method (a pause/resume, an open/close) reach it
            # right after HA itself just wrote something, and the cached
            # response can still be serving a pre-write snapshot for tens
            # of seconds - confirmed empirically against the real API -
            # reconciling off it there would race the explicit
            # set_leak_detection_paused_until() call the caller already
            # made and undo it. Reconciliation instead happens at each
            # call site once it's independently established that enough
            # time has passed for the cached read to be trustworthy: the
            # regular poll (_fetch_data) isn't tied to a just-made write,
            # and the leak-detection expiry check
            # (_schedule_leak_detection_expiry_refresh) only ever calls
            # this at or after a pause's own target end time.
            self.async_set_updated_data(self.data)

        return success

    async def _update_cubic_secure_configuration(
        self, device_identity: str, *, force_update: bool
    ) -> bool:
        """Fetch one Cubic Secure device's configuration, opening its own
        authenticated session first."""
        try:
            async with self._authenticated_client() as lk_inst:
                return await self._apply_cubic_secure_configuration(
                    lk_inst, device_identity, force_update=force_update
                )
        except _LoginFailed:
            _LOGGER.error("Login failed when updating Cubic Secure configuration")
            return False
        except Exception as ex:
            _LOGGER.error("Error updating Cubic Secure configuration: %s", ex)
            return False

    async def force_cubic_secure_configuration_update(self, device_identity: str) -> bool:
        """Force-fetch one Cubic Secure device's configuration, bypassing
        the LK API's own backend cache.

        The regular poll (_fetch_data) only bypasses that cache once its
        own cacheUpdated timestamp looks older than the poll interval -
        decoupled from whether a write just happened, so it can't be
        relied on to reflect a write promptly. Callers that just wrote a
        physical device property (e.g. opening/closing the valve) need
        this instead. Don't use this for server-side-tracked fields like
        muteLeak - see refresh_cubic_secure_configuration().
        """
        _LOGGER.debug(
            "Forcing configuration update for Cubic Secure device %s", device_identity
        )
        return await self._update_cubic_secure_configuration(
            device_identity, force_update=True
        )

    async def refresh_cubic_secure_configuration(self, device_identity: str) -> bool:
        """Fetch one Cubic Secure device's configuration via the LK API's
        own cache (not bypassed).

        Confirmed empirically against the real API: for server-side-
        tracked fields like muteLeak, this cached read is the fresher
        one - force_cubic_secure_configuration_update()'s bypass polls
        the physical device live and doesn't carry server-managed timers
        like muteLeak at all, while this cached snapshot updates
        immediately on a write (e.g. button.py after pausing leak
        detection).
        """
        _LOGGER.debug(
            "Refreshing configuration for Cubic Secure device %s", device_identity
        )
        return await self._update_cubic_secure_configuration(
            device_identity, force_update=False
        )

    async def refresh_cubic_secure_configuration_with_client(
        self, lk_inst: LKSystemsManager, device_identity: str
    ) -> bool:
        """Like refresh_cubic_secure_configuration(), but reusing an
        already-authenticated `lk_inst` instead of opening a new session -
        for a caller that just used it for a write and wants to confirm
        that write with a read, at the cost of one login rather than two.
        """
        _LOGGER.debug(
            "Refreshing configuration for Cubic Secure device %s", device_identity
        )
        return await self._apply_cubic_secure_configuration(
            lk_inst, device_identity, force_update=False
        )

    async def force_cubic_secure_configuration_update_with_client(
        self, lk_inst: LKSystemsManager, device_identity: str
    ) -> bool:
        """Like force_cubic_secure_configuration_update(), but reusing an
        already-authenticated `lk_inst` instead of opening a new session -
        see refresh_cubic_secure_configuration_with_client()'s own
        docstring for why.
        """
        _LOGGER.debug(
            "Forcing configuration update for Cubic Secure device %s", device_identity
        )
        return await self._apply_cubic_secure_configuration(
            lk_inst, device_identity, force_update=True
        )

    async def _async_update_data(self) -> LkStructureResp:
        """Fetch the latest data, surfacing persistent failures as repair issues.

        Auth failures raise a repair issue immediately - HA's own reauth
        flow already treats them as non-transient. A fetch failure only
        raises one after CONSECUTIVE_FAILURE_THRESHOLD in a row (see that
        constant's own comment for why).
        """
        try:
            resp = await self._fetch_data()
        except ConfigEntryAuthFailed:
            repairs.async_create_auth_failed_issue(self.hass, self._entry_id)
            raise
        except UpdateFailed:
            self._consecutive_failures += 1
            if self._consecutive_failures >= CONSECUTIVE_FAILURE_THRESHOLD:
                repairs.async_create_persistent_update_failure_issue(
                    self.hass, self._entry_id
                )
            raise
        else:
            self._consecutive_failures = 0
            repairs.async_clear_all_issues(self.hass, self._entry_id)
            return resp

    def _should_bypass_cache(
        self, device_identity: str, forced_device_ids: set[str], cache_updated: int
    ) -> bool:
        """Whether a cached response for device_identity is stale enough to
        warrant a fresh, cache-bypassing fetch instead - or a bypass was
        explicitly requested for it via async_request_forced_refresh()."""
        if device_identity in forced_device_ids:
            return True
        return int(time.time()) - cache_updated > self.update_interval.total_seconds()

    async def _fetch_data(self) -> LkStructureResp:  # noqa: C901
        """Fetch the latest data from the source."""
        # Record update time at the beginning of update
        self._last_cloud_fetch_attempt = dt_util.now()
        _LOGGER.info(
            "Starting LK Systems data update at %s",
            self._last_cloud_fetch_attempt.isoformat(),
        )

        # Snapshot and clear in one statement (no `await` in between) so a
        # request queued by async_request_forced_refresh() is either fully
        # reflected in this fetch or left untouched for the next one - see
        # _force_bypass_device_ids' own comment for why.
        forced_device_ids = self._force_bypass_device_ids
        self._force_bypass_device_ids = set()

        try:
            # Get credentials from config entry
            username = self._entry.data.get(CONF_USERNAME)
            password = self._entry.data.get(CONF_PASSWORD)

            # Add validation to ensure credentials are present
            if not username or not password:
                _LOGGER.error(
                    "Missing credentials for LK Systems API. Check your configuration."
                )
                raise ConfigEntryAuthFailed("Missing username or password")

            _LOGGER.debug("Using credentials for user: %s", mask_username(username))

            # Check if we have stored tokens for this entry
            stored_tokens = TOKEN_STORAGE.get(self._entry_id, {})
            stored_jwt = stored_tokens.get("jwt")

            async with LKSystemsManager(username, password) as lk_inst:
                # Set the token if we have it and it's valid
                if stored_jwt and is_token_valid(stored_jwt):
                    _LOGGER.info("Using existing JWT token - skipping login")
                    lk_inst.jwt_token = stored_jwt
                    lk_inst.refresh_token = stored_tokens.get("refresh")
                    lk_inst.userid = stored_tokens.get("userid")
                else:
                    _LOGGER.info("No valid token, performing full login")
                    if not await lk_inst.login():
                        _LOGGER.error("Login failed")
                        raise ConfigEntryAuthFailed("Authentication failed")

                    # Store the new tokens
                    TOKEN_STORAGE[self._entry_id] = {
                        "jwt": lk_inst.jwt_token,
                        "refresh": lk_inst.refresh_token,
                        "expiry": dt_util.utcnow().timestamp()
                        + 3600,  # Assume 1 hour validity
                        "userid": lk_inst.userid,
                    }
                    _LOGGER.info("New tokens obtained and stored")

                # Step 2: Get user structure with device information
                if not await lk_inst.get_user_structure():
                    _LOGGER.error("Failed to get user structure, abort update")
                    raise UpdateFailed("Unknown error get_user_structure")

                # Initialize response structure
                resp: LkStructureResp = {
                    "realestateId": lk_inst.user_structure["realestateId"],
                    "name": lk_inst.user_structure["name"],
                    "city": lk_inst.user_structure["city"],
                    "address": lk_inst.user_structure["address"],
                    "zip": lk_inst.user_structure["zip"],
                    "country": lk_inst.user_structure["country"],
                    "ownerId": lk_inst.user_structure["ownerId"],
                    "cacheUpdated": lk_inst.user_structure["cacheUpdated"],
                    "cubic_devices": {},
                    "devices": [],
                    "device_details": {},  # Will store detailed information about each device
                    "update_time": self._last_cloud_fetch_attempt.isoformat(),
                    "next_update_time": (
                        self._last_cloud_fetch_attempt + self.update_interval
                    ).isoformat(),
                }

                # Extract devices from user structure
                devices = []
                device_identities = []
                arc_sense_devices = []  # Track Arc sense devices for direct updates

                # Process all devices from structure
                if "realestateMachines" in lk_inst.user_structure:
                    for machine in lk_inst.user_structure["realestateMachines"]:
                        # Skip if no identity
                        if not machine.get("identity"):
                            continue

                        device_identity = machine.get("identity")
                        device_identities.append(device_identity)

                        device_data = {
                            "deviceTitle": machine,
                            "mac": machine.get("identity"),
                            "cacheUpdated": lk_inst.user_structure.get(
                                "cacheUpdated", 0
                            ),
                        }
                        devices.append(device_data)

                        # Track Arc sense devices for direct measurements
                        if (
                            machine.get("deviceGroup") == "arc"
                            and machine.get("deviceType") == "arc-sense"
                        ):
                            arc_sense_devices.append(device_identity)

                        # Step 3: Get detailed information for each device
                        if machine.get("deviceGroup") == "arc":
                            if machine.get("deviceType") == "arc-sense":
                                # Fetch measurement data - always force update to get latest values
                                if await lk_inst.get_device_measurement(
                                    device_identity, force_update=True
                                ):
                                    resp["device_details"][device_identity] = {
                                        "measurement": lk_inst.device_measurements.get(
                                            device_identity
                                        )
                                    }
                                    # Also add to the device in the devices list
                                    device_data["measurement"] = (
                                        lk_inst.device_measurements.get(device_identity)
                                    )

                                # Fetch configuration data (used for
                                # thermostat-role devices by climate.py)
                                if await lk_inst.get_device_configuration(
                                    device_identity,
                                    force_update=device_identity in forced_device_ids,
                                ):
                                    if device_identity not in resp["device_details"]:
                                        resp["device_details"][device_identity] = {}
                                    resp["device_details"][device_identity][
                                        "configuration"
                                    ] = lk_inst.device_configurations.get(
                                        device_identity
                                    )
                                    # Also add to the device in the devices list
                                    device_data["configuration"] = (
                                        lk_inst.device_configurations.get(
                                            device_identity
                                        )
                                    )

                            elif machine.get("deviceType") == "arc-hub":
                                # Fetch hub data if available
                                hub_id = device_identity
                                if await lk_inst.get_hub_devices(hub_id):
                                    if "hub_data" not in resp:
                                        resp["hub_data"] = {}
                                    resp["hub_data"][hub_id] = lk_inst.hub_devices

                                    # Process devices from this hub
                                    if (
                                        isinstance(lk_inst.hub_devices, dict)
                                        and "devices" in lk_inst.hub_devices
                                    ):
                                        for hub_device in lk_inst.hub_devices[
                                            "devices"
                                        ]:
                                            if (
                                                hub_device.get("mac")
                                                and hub_device.get("mac")
                                                not in device_identities
                                            ):
                                                device_identities.append(
                                                    hub_device.get("mac")
                                                )
                                                devices.append(hub_device)

                                                # Also fetch detailed data for hub devices
                                                device_mac = hub_device.get("mac")
                                                if device_mac:
                                                    # Measurement data should already be in the hub devices
                                                    if "measurement" in hub_device:
                                                        if (
                                                            device_mac
                                                            not in resp[
                                                                "device_details"
                                                            ]
                                                        ):
                                                            resp["device_details"][
                                                                device_mac
                                                            ] = {}
                                                        resp["device_details"][
                                                            device_mac
                                                        ]["measurement"] = hub_device[
                                                            "measurement"
                                                        ]

                        # For cubic devices (if they exist)
                        elif (
                            machine.get("deviceType") == "cubicsecure"
                            and machine.get("deviceRole") == "cubicsecure"
                        ):
                            resp["cubic_devices"][device_identity] = {
                                "machine_info": machine
                            }

                            # Try to get cubic measurements but don't fail if not available
                            try:
                                await lk_inst.get_cubic_secure_measurement(
                                    device_identity
                                )

                                if lk_inst.cubic_secure_measurement is not None:
                                    if self._should_bypass_cache(
                                        device_identity,
                                        forced_device_ids,
                                        lk_inst.cubic_secure_measurement[
                                            "cacheUpdated"
                                        ],
                                    ):
                                        _LOGGER.debug(
                                            "Cubic secure measurement is stale or a fresh fetch was requested, force update"
                                        )
                                        if not await lk_inst.get_cubic_secure_measurement(
                                            device_identity, force_update=True
                                        ):
                                            _LOGGER.error(
                                                "Failed to get cubic secure measurement, abort update"
                                            )
                                            raise UpdateFailed(
                                                "Unknown error get_cubic_secure_measurement"
                                            )

                                resp["cubic_devices"][device_identity][
                                    "last_measurement"
                                ] = lk_inst.cubic_secure_measurement
                                if not await lk_inst.get_cubic_secure_configuration(
                                    device_identity
                                ):
                                    _LOGGER.error(
                                        "Failed to get cubic secure configuration, abort update"
                                    )
                                    raise UpdateFailed(
                                        "Unknown error get_cubic_secure_measurement"
                                    )
                                if lk_inst.cubic_secure_configuration is not None:
                                    if self._should_bypass_cache(
                                        device_identity,
                                        forced_device_ids,
                                        lk_inst.cubic_secure_configuration[
                                            "cacheUpdated"
                                        ],
                                    ):
                                        _LOGGER.debug(
                                            "Cubic secure configuration is stale or a fresh fetch was requested, force update"
                                        )
                                        cached_configuration = (
                                            lk_inst.cubic_secure_configuration
                                        )
                                        if not await lk_inst.get_cubic_secure_configuration(
                                            device_identity, force_update=True
                                        ):
                                            _LOGGER.error(
                                                "Failed to get cubic secure configuration, abort update"
                                            )
                                            raise UpdateFailed(
                                                "Unknown error get_cubic_secure_configuration"
                                            )
                                        # The bypass fetch above polls the
                                        # physical device live rather than
                                        # LK's backend cache, and that
                                        # response has a narrower schema
                                        # (confirmed empirically: it never
                                        # carries muteLeak) - carry over
                                        # whatever the cached response has
                                        # that the live one doesn't, so a
                                        # cache-only field doesn't just
                                        # vanish because this device was
                                        # bypassed.
                                        _fill_missing_keys(
                                            lk_inst.cubic_secure_configuration,
                                            cached_configuration,
                                        )

                                resp["cubic_devices"][device_identity][
                                    "configuration"
                                ] = lk_inst.cubic_secure_configuration
                                self._reconcile_leak_detection_paused_until(
                                    device_identity,
                                    lk_inst.cubic_secure_configuration,
                                    dt_util.utcnow(),
                                )
                            except Exception as err:
                                # Sensors index these keys directly, so they
                                # must exist even on failure; reuse this
                                # device's last known values if we have them.
                                previous_device_data = (
                                    (self.data or {})
                                    .get("cubic_devices", {})
                                    .get(device_identity, {})
                                )
                                device_entry = resp["cubic_devices"][device_identity]
                                device_entry.setdefault(
                                    "last_measurement",
                                    previous_device_data.get("last_measurement"),
                                )
                                device_entry.setdefault(
                                    "configuration",
                                    previous_device_data.get("configuration"),
                                )
                                _LOGGER.warning(
                                    "Error fetching cubic measurements: %s", str(err)
                                )

                # Now directly fetch fresh measurement data for each Arc sense device
                _LOGGER.info(
                    "Fetching direct measurements for %d Arc sense devices",
                    len(arc_sense_devices),
                )
                for device_id in arc_sense_devices:
                    _LOGGER.debug(
                        "Fetching fresh measurement data for Arc device: %s", device_id
                    )

                    # Always get the latest data with force_update=True
                    if await lk_inst.get_device_measurement(
                        device_id, force_update=True
                    ):
                        measurement_data = lk_inst.device_measurements.get(device_id)

                        if measurement_data:
                            # Store in device_details for easy access by sensors
                            if device_id not in resp["device_details"]:
                                resp["device_details"][device_id] = {}

                            resp["device_details"][device_id]["measurement"] = (
                                measurement_data
                            )

                            # Log the fetched values
                            _LOGGER.debug(
                                "Got measurement for %s: Temp=%.1f°C, Humidity=%.1f%%, Battery=%s%%, RSSI=%sdBm",
                                device_id,
                                float(measurement_data.get("currentTemperature", 0))
                                / 10,
                                float(measurement_data.get("currentHumidity", 0)) / 10,
                                measurement_data.get("currentBattery", 0),
                                measurement_data.get("currentRssi", 0),
                            )

                            # Also update the device in the devices list
                            for device in devices:
                                device_title = device.get("deviceTitle", {})
                                if (
                                    device.get("mac") == device_id
                                    or device_title.get("identity") == device_id
                                ):
                                    device["measurement"] = measurement_data.copy()
                                    break
                    else:
                        _LOGGER.warning(
                            "Failed to get measurement data for device %s", device_id
                        )

                # Also get measurements for devices listed in hub data if not already fetched
                if "hub_data" in resp:
                    for hub_id, hub_data in resp["hub_data"].items():
                        if isinstance(hub_data, dict) and "devices" in hub_data:
                            for device in hub_data["devices"]:
                                device_id = device.get("mac")

                                # Skip if already processed or not an Arc sense device
                                if not device_id or device_id in arc_sense_devices:
                                    continue

                                device_title = device.get("deviceTitle", {})
                                if (
                                    device_title.get("deviceGroup") == "arc"
                                    and device_title.get("deviceType") == "arc-sense"
                                ):
                                    _LOGGER.debug(
                                        "Fetching fresh measurement for hub device: %s",
                                        device_id,
                                    )

                                    # Direct measurement fetch
                                    if await lk_inst.get_device_measurement(
                                        device_id, force_update=True
                                    ):
                                        measurement_data = (
                                            lk_inst.device_measurements.get(device_id)
                                        )

                                        if measurement_data:
                                            # Store in device_details
                                            if device_id not in resp["device_details"]:
                                                resp["device_details"][device_id] = {}

                                            resp["device_details"][device_id][
                                                "measurement"
                                            ] = measurement_data

                                            # Also update the device in hub_data
                                            device["measurement"] = (
                                                measurement_data.copy()
                                            )
                                    else:
                                        _LOGGER.warning(
                                            "Failed to get measurement for hub device %s",
                                            device_id,
                                        )

                # Store all devices in the response
                resp["devices"] = devices

                _LOGGER.info(
                    "LK Systems update completed. Found %s devices. Next update in %s minutes at %s",
                    len(resp.get("devices", [])),
                    self.update_interval.total_seconds() / 60,
                    resp["next_update_time"],
                )

                self.last_successful_cloud_fetch = dt_util.utcnow()
                return resp

        except InvalidAuth as err:
            _LOGGER.error("Authentication error during update: %s", str(err))
            raise ConfigEntryAuthFailed from err
        except LKSystemsError as err:
            _LOGGER.error("LK Systems error during update: %s", str(err))
            raise UpdateFailed(str(err)) from err


def cubic_secure_device_identities(coordinator: LKSystemCoordinator) -> list[str]:
    """Return the device identities of every Cubic Secure device on the account."""
    return list(coordinator.data.get("cubic_devices", {}))


def cubic_secure_configuration(
    coordinator: LKSystemCoordinator, device_identity: str
) -> dict[str, Any]:
    """Return a Cubic Secure device's last-fetched configuration dict.

    Configuration (valveState, firmwareVersion, ...) is fetched
    separately from measurement data and can fail independently, so this
    is always defensive about it being missing.
    """
    cubic_device = coordinator.data["cubic_devices"][device_identity]
    return cubic_device.get("configuration") or {}


def cubic_secure_device_info(
    coordinator: LKSystemCoordinator, device_identity: str
) -> DeviceInfo:
    """Build the shared DeviceInfo for a Cubic Secure device.

    Every platform with an entity on a Cubic Secure device (sensor,
    number, button, ...) calls this, so they all resolve to the same HA
    device instead of each building their own copy.
    """
    machine_info = coordinator.data["cubic_devices"][device_identity]["machine_info"]
    return DeviceInfo(
        identifiers={(DOMAIN, device_identity)},
        manufacturer=MANUFACTURER,
        model=CUBIC_SECURE_MODEL,
        name=f"Cubic Secure {machine_info['zone']['zoneName']}",
        serial_number=device_identity,
    )


class CubicSecureEntityMixin:
    """Shared identity plumbing for every entity on a Cubic Secure device.

    Mixed in by sensor.py, number.py, and button.py's per-platform base
    classes, whose self.coordinator and self._device_identity this relies
    on, so a future change to a Cubic Secure device's attribution/naming/
    device_info only needs editing here instead of at each platform
    separately.
    """

    _attr_attribution = ATTRIBUTION
    _attr_has_entity_name = True

    @property
    def device_info(self) -> DeviceInfo:
        """Return the device_info of the device."""
        return cubic_secure_device_info(self.coordinator, self._device_identity)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the LK Systems component."""
    hass.data[DOMAIN] = {}
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up LK Systems from a config entry."""
    coordinator = LKSystemCoordinator(hass, entry)

    # Fetch initial data so we have data when entities subscribe
    try:
        await coordinator.async_config_entry_first_refresh()
    except ConfigEntryAuthFailed:
        # entry.async_start_reauth() (rather than hand-rolling
        # hass.config_entries.flow.async_init()) is what actually links the
        # started flow back to this entry - without that link, HA has
        # nothing to show a "Reauthenticate" prompt against.
        entry.async_start_reauth(hass)
        return False

    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Set up all platforms for this device/entry
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Set up options update listener
    entry.async_on_unload(entry.add_update_listener(async_update_options))

    # Register services for the integration
    async def handle_refresh_device(call):
        """Handle the service call to refresh a device."""
        device_id = call.data.get("device_id", None)
        coordinator = hass.data[DOMAIN][entry.entry_id]

        if device_id:
            # Refresh specific device
            _LOGGER.info("Service called to refresh device: %s", device_id)
            await coordinator.force_device_update(device_id)
        else:
            # Refresh all devices
            _LOGGER.info("Service called to refresh all devices")
            await coordinator.async_refresh()

    # Register custom services
    hass.services.async_register(
        DOMAIN,
        "refresh_device",
        handle_refresh_device,
        schema=vol.Schema(
            {
                vol.Optional("device_id"): cv.string,
            }
        ),
    )
    await async_setup_services(hass, entry)

    return True


async def async_update_options(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Update options."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    # Check if update interval has changed
    old_update_interval = coordinator._update_interval_minutes
    new_update_interval = entry.options.get(
        CONF_UPDATE_INTERVAL,
        entry.data.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL),
    )

    # If update interval changed, log it
    if old_update_interval != new_update_interval:
        _LOGGER.warning(
            "Update interval changed from %s to %s minutes",
            old_update_interval,
            new_update_interval,
        )

    # Reloading tears down and recreates the coordinator with the new
    # interval and performs its own first refresh.
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        # Cancels any pending leak-detection expiry checks, on top of the
        # coordinator's own polling - see LKSystemCoordinator.async_shutdown().
        await hass.data[DOMAIN][entry.entry_id].async_shutdown()

        # Clear token from cache on unload
        TOKEN_STORAGE.pop(entry.entry_id, None)
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


class LksystemsError(HomeAssistantError):
    """Base error."""


class InvalidAuth(LksystemsError):
    """Raised when invalid authentication credentials are provided."""


class APIRatelimitExceeded(LksystemsError):
    """Raised when the API rate limit is exceeded."""


class UnknownError(LksystemsError):
    """Raised when an unknown error occurs."""
