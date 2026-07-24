"""LK Systems integration."""

from __future__ import annotations

import logging
from typing import TypedDict
from datetime import timedelta
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
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)
from homeassistant.util import dt as dt_util
import voluptuous as vol
from homeassistant.helpers import config_validation as cv

from .const import CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL, DOMAIN
from .pylksystems import (
    LKSystemsManager,
    LKSystemsError,
    LKThresholds,
    LKPressureThresholds,
)

from .services import async_setup_services

_LOGGER = logging.getLogger(__name__)

# Define the platforms we support
PLATFORMS = [Platform.SENSOR, Platform.CLIMATE]


class LkStructureResp(TypedDict):
    """API response structure"""

    realestateId: str
    name: str
    city: str
    address: str
    zip: str
    country: str
    ownerId: str
    cubic_machine_info: LkStructureMashine
    cubic_last_measurement: LkCubicSecureResp
    cubic_configuration: LKCubicSecureConfigResp
    cacheUpdated: int
    update_time: str
    next_update_time: str


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


class LkStructureMashine(TypedDict):
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


class LKSystemCoordinator(DataUpdateCoordinator[LkStructureResp]):
    """Data update coordinator for LK Systems."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the coordinator."""
        # Always convert to integer in case it comes as string from config
        update_interval_minutes = int(
            entry.data.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL)
        )

        _LOGGER.warning(
            "Initializing LK Systems coordinator with update interval: %d minutes",
            update_interval_minutes,
        )

        # Store for later reference
        self._update_interval_minutes = update_interval_minutes
        self._entry = entry
        self._cubic_identity = None
        self._last_update_time = dt_util.now()
        self._entry_id = entry.entry_id

        # Initialize coordinator with update interval
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(minutes=update_interval_minutes),
        )

        # Schedule regular updates
        self._setup_update_interval()

    def _setup_update_interval(self):
        """Set up the update interval."""
        _LOGGER.warning(
            f"Setting up update interval for {DOMAIN} to {self._update_interval_minutes} minutes"
        )

        # Cancel any existing scheduled updates
        self._unsub_refresh = None

        # Ensure the update interval is correctly set
        self.update_interval = timedelta(minutes=self._update_interval_minutes)

        # Log next update time
        next_update = dt_util.utcnow() + self.update_interval
        _LOGGER.warning(
            f"Next automatic update scheduled for: {next_update.isoformat()}"
        )

    async def set_thermostat_temperature(self, device_id, temperature):
        """Set thermostat temperature through the API.

        Args:
            device_id: The device identity (MAC or unique ID)
            temperature: The temperature value in tenths of a degree (e.g. 215 = 21.5°C)

        Returns:
            Result of the API call
        """
        _LOGGER.debug("Setting temperature for device %s to %s", device_id, temperature)

        try:
            # Create a new instance of LKSystemsManager for this operation
            username = self._entry.data.get(CONF_USERNAME)
            password = self._entry.data.get(CONF_PASSWORD)

            async with LKSystemsManager(username, password) as lk_inst:
                # Call the LKSystemsManager method to set the temperature
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

        except Exception as ex:
            _LOGGER.error("Failed to set temperature: %s", ex)
            return False

    async def force_device_update(self, device_id: str) -> bool:
        """Force update for a specific device from API."""
        _LOGGER.warning("FORCE UPDATE REQUESTED for device %s", device_id)

        try:
            # Get credentials
            username = self._entry.data.get(CONF_USERNAME)
            password = self._entry.data.get(CONF_PASSWORD)

            async with LKSystemsManager(username, password) as lk_inst:
                # Use existing token if available
                stored_tokens = TOKEN_STORAGE.get(self._entry_id, {})
                stored_jwt = stored_tokens.get("jwt")

                if stored_jwt and is_token_valid(stored_jwt):
                    lk_inst.jwt_token = stored_jwt
                    lk_inst.refresh_token = stored_tokens.get("refresh")
                else:
                    # Login if no valid token
                    if not await lk_inst.login():
                        _LOGGER.error("Login failed when forcing device update")
                        return False

                    # Store the new tokens
                    TOKEN_STORAGE[self._entry_id] = {
                        "jwt": lk_inst.jwt_token,
                        "refresh": lk_inst.refresh_token,
                        "expiry": dt_util.utcnow().timestamp() + 3600,
                    }

                # Always force update for this device
                success = await lk_inst.get_device_measurement(
                    device_id, force_update=True
                )

                if success and device_id in lk_inst.device_measurements:
                    measurement_data = lk_inst.device_measurements[device_id]

                    # Log the raw measurement data
                    _LOGGER.warning(
                        "Got fresh data for %s: Temperature=%s, Humidity=%s, Battery=%s",
                        device_id,
                        measurement_data.get("currentTemperature"),
                        measurement_data.get("currentHumidity"),
                        measurement_data.get("currentBattery"),
                    )

                    # Update our local data
                    if self.data:
                        # Create device_details dict if not exists
                        if "device_details" not in self.data:
                            self.data["device_details"] = {}

                        if device_id not in self.data["device_details"]:
                            self.data["device_details"][device_id] = {}

                        # Ensure measurement dict exists
                        if "measurement" not in self.data["device_details"][device_id]:
                            self.data["device_details"][device_id]["measurement"] = {}

                        # Update with latest data - full replacement to ensure all fields are updated
                        self.data["device_details"][device_id]["measurement"] = (
                            measurement_data
                        )

                        # Also update in devices list
                        for device in self.data.get("devices", []):
                            device_title = device.get("deviceTitle", {})
                            if (
                                device.get("mac") == device_id
                                or device_title.get("identity") == device_id
                            ):
                                device["measurement"] = measurement_data.copy()
                                break

                        # Also update any devices in hub_data
                        if "hub_data" in self.data:
                            for hub_id, hub_data in self.data["hub_data"].items():
                                if isinstance(hub_data, dict) and "devices" in hub_data:
                                    for device in hub_data["devices"]:
                                        if device.get("mac") == device_id:
                                            device["measurement"] = (
                                                measurement_data.copy()
                                            )

                        # Trigger all listeners to update with new data
                        self.async_set_updated_data(self.data)

                        return True

                return success

        except Exception as ex:
            _LOGGER.error("Error during forced device update: %s", ex)
            return False

    async def _async_update_data(self) -> LkStructureResp:  # noqa: C901
        """Fetch the latest data from the source."""
        # Record update time at the beginning of update
        self._last_update_time = dt_util.now()
        _LOGGER.info(
            "Starting LK Systems data update at %s", self._last_update_time.isoformat()
        )

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

            _LOGGER.debug("Using credentials for user: %s", username)

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
                    "cubic_machine_info": next(
                        (
                            x
                            for x in lk_inst.user_structure["realestateMachines"]
                            if x["deviceType"] == "cubicsecure"
                            and x["deviceRole"] == "cubicsecure"
                        ),
                        None,
                    ),
                    "cubic_last_messurement": None,
                    "devices": [],
                    "device_details": {},  # Will store detailed information about each device
                    "update_time": self._last_update_time.isoformat(),
                    "next_update_time": (
                        self._last_update_time + self.update_interval
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

                                # Fetch configuration data
                                if await lk_inst.get_device_configuration(
                                    device_identity
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
                            resp["cubic_machine_info"] = machine
                            self._cubic_identity = device_identity

                            # Try to get cubic measurements but don't fail if not available
                            try:
                                if await lk_inst.get_cubic_secure_measurement(
                                    device_identity
                                ):
                                    resp["cubic_last_messurement"] = (
                                        lk_inst.cubic_secure_messurement
                                    )

                                if lk_inst.cubic_secure_messurement is not None:
                                    # Get time as unix timestamp
                                    timestamp = int(time.time())
                                    if (
                                        timestamp
                                        - lk_inst.cubic_secure_messurement[
                                            "cacheUpdated"
                                        ]
                                        > self.update_interval.total_seconds()
                                    ):
                                        _LOGGER.debug(
                                            "Cubic secure measurement is older than update interval, force update"
                                        )
                                        if not await lk_inst.get_cubic_secure_measurement(
                                            self._cubic_identity, force_update=True
                                        ):
                                            _LOGGER.error(
                                                "Failed to get cubic secure measurement, abort update"
                                            )
                                            raise UpdateFailed(
                                                "Unknown error get_cubic_secure_measurement"
                                            )

                                resp["cubic_last_measurement"] = (
                                    lk_inst.cubic_secure_messurement
                                )
                                if not await lk_inst.get_cubic_secure_configuration(
                                    self._cubic_identity
                                ):
                                    _LOGGER.error(
                                        "Failed to get cubic secure configuration, abort update"
                                    )
                                    raise UpdateFailed(
                                        "Unknown error get_cubic_secure_measurement"
                                    )
                                if lk_inst.cubic_secure_configuration is not None:
                                    # Get time as unix timestamp
                                    timestamp = int(time.time())
                                    if (
                                        timestamp
                                        - lk_inst.cubic_secure_configuration[
                                            "cacheUpdated"
                                        ]
                                        > self.update_interval.total_seconds()
                                    ):
                                        _LOGGER.debug(
                                            "Cubic secure configuration is older than update interval, force update"
                                        )
                                        if not await lk_inst.get_cubic_secure_configuration(
                                            self._cubic_identity, force_update=True
                                        ):
                                            _LOGGER.error(
                                                "Failed to get cubic secure configuration, abort update"
                                            )
                                            raise UpdateFailed(
                                                "Unknown error get_cubic_secure_configuration"
                                            )

                                resp["cubic_configuration"] = (
                                    lk_inst.cubic_secure_configuration
                                )
                            except Exception as err:
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

                return resp

        except InvalidAuth as err:
            _LOGGER.error("Authentication error during update: %s", str(err))
            raise ConfigEntryAuthFailed from err
        except LKSystemsError as err:
            _LOGGER.error("LK Systems error during update: %s", str(err))
            raise UpdateFailed(str(err)) from err


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
        # If we get an auth error, we'll try to reauth
        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN,
                context={"source": "reauth"},
                data=entry.data,
            )
        )
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

        # Force immediate update after reload
        hass.async_create_task(coordinator.async_refresh())

    # Reload entry
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
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
