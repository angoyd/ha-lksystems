"""Lk Systems module."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta
import json
import logging
import re
from typing import TypedDict


from aiohttp import ClientError, ClientResponseError, ClientSession
from dateutil.relativedelta import relativedelta

_LOGGER = logging.getLogger(__name__)


# Add the missing LKSystemsError class
class LKSystemsError(Exception):
    """Exception raised for LK Systems related errors."""

    pass


class InvalidAuth(LKSystemsError):
    """Exception raised for authentication errors."""

    pass


class LKLeakThresholds(TypedDict):
    """Leak thresholds structure"""

    threshold: float
    closeDelay: int
    notificationDelay: int


class LKPressureThresholds(TypedDict):
    """Pressure thresholds structure"""

    sensitivity: float
    duration: int
    closeDelay: int
    notificationDelay: int


class LKThresholds(TypedDict):
    """Thresholds structure"""

    pressure: LKPressureThresholds
    leakMedium: LKLeakThresholds
    leakLarge: LKLeakThresholds


class LKSystemsManager:
    """LKSystems manager."""

    def __init__(self, username, password) -> None:
        """Initialize the LK systems manager."""
        if username is None or password is None:
            raise ValueError("Username and password must be provided.")
        self.session = None
        self.base_url = "https://link2.lk.nu/"
        self.username = username
        self.password = password
        self.userid = None
        self.jwt_token = None
        self.refresh_token = None
        self._cubic_secure_messurement = None
        self._user_structure = None
        self._cubic_secure_configuration = None
        self._cubic_secure_pressure_test_reports = None
        self._cubic_secure_structure = None
        self._cubic_secure_pressure_test_schedule = None
        self._devices = None
        self._hub_devices = None
        self._device_measurements = {}
        self._device_configurations = {}

    async def __aenter__(self):
        """Asynchronous enter."""
        self.session = ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """Asynchronous exit."""
        await self.session.close()

    async def handle_client_error(self, endpoint, headers, error):
        """Handle ClientError and log relevant information."""
        _LOGGER.error(
            "An error occurred during the request. URL: %s, Headers: %s. Error: %s",
            self.base_url + endpoint,
            headers,
            error,
        )
        return False

    def _get_headers(self):
        """Define common headers."""

        return {
            "content-type": "application/json",
            "api-version": "1",
            "Accept": "application/json, application/xml, text/plain, text/html, *.*",
            "User-Agent": "MyLk",
            "ocp-apim-subscription-key": "d2d308826cd14e7d92660b28bc7d859c",
        }

    async def _get(self, endpoint):
        """Helper method to perform GET requests."""
        headers = {}
        try:
            # Define headers with the JwtToken
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    res = await response.json()

                    return True, res

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False, None

        except (ClientResponseError, ClientError) as error:
            return (await self.handle_client_error(endpoint, headers, error)), None

    async def _post(self, endpoint, payload):
        """Helper method to perform POST requests."""
        headers = {}
        try:
            # Define headers with the JwtToken
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            async with self.session.post(
                self.base_url + endpoint, json=payload, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status in [200, 201]:
                    res = await response.json(content_type=None)

                    return True, res

                _LOGGER.error(
                    "Posting data to URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False, None

        except (ClientResponseError, ClientError) as error:
            return (await self.handle_client_error(endpoint, headers, error)), None

    async def login(self):
        """Login to LK systems and get userId"""
        endpoint = "auth/auth/login"
        endpointUserId = "auth/auth/user"
        try:
            payload = {"email": self.username, "password": self.password}
            headers = {**self._get_headers()}
            # Define headers with the encoded credentials
            async with self.session.post(
                self.base_url + endpoint, json=payload, headers=headers
            ) as response:
                data = await response.json()
                if response.status == 200:
                    self.jwt_token = data.get("accessToken")
                    self.refresh_token = data.get("refreshToken")
                    # Get userId
                    headers = {
                        **self._get_headers(),
                        "authorization": f"Bearer {self.jwt_token}",
                    }
                    async with self.session.get(
                        self.base_url + endpointUserId, headers=headers
                    ) as responseUserid:
                        responseUserid.raise_for_status()
                        if responseUserid.status == 200:
                            useridJson = await responseUserid.json()
                            self.userid = useridJson["userId"]
                            return True

                        _LOGGER.error(
                            "Obtaining data from URL %s failed with status code %d",
                            self.base_url + endpoint,
                            responseUserid.status,
                        )
                        return False

                if response.status == 401:
                    _LOGGER.error(
                        "Unauthorized: Check your LK Systems authentication credentials"
                    )
                    return False

                _LOGGER.error("Unexpected HTTP status code: %s", response.status)
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_cubic_secure_measurement(
        self, cubic_identity: str, force_update=False
    ):
        """Fetch Cubic secure measurement"""
        if force_update:
            _LOGGER.debug("Force update from LK API")
            endpoint = f"service/cubic/secure/{cubic_identity}/measurement/1"
        else:
            endpoint = f"service/cubic/secure/{cubic_identity}/measurement/0"
        success, res = await self._get(endpoint)
        if success:
            self._cubic_secure_messurement = res
            return True
        return False

    @property
    def cubic_secure_messurement(self):
        """Property for Cubic Secure messurement"""
        return self._cubic_secure_messurement

    async def get_user_structure(self):
        """Fetch user secure measurement"""
        endpoint = f"service/users/user/{self.userid}/structure/1"
        success, res = await self._get(endpoint)
        if success:
            self._user_structure = res[0]
            return True
        return False

    @property
    def user_structure(self):
        """Property for User Structure"""
        return self._user_structure

    def get_arc_hubs_from_structure(self):
        """Extract Arc hub devices from user structure."""
        if not self._user_structure or "realestateMachines" not in self._user_structure:
            return []

        arc_hubs = []
        for machine in self._user_structure["realestateMachines"]:
            if (
                machine.get("deviceGroup") == "arc"
                and machine.get("deviceType") == "arc-hub"
                and machine.get("deviceRole") == "arc-hub"
                and machine.get("identity")
            ):
                arc_hubs.append(machine)

        return arc_hubs

    def extract_devices_from_structure(self):
        """Extract devices from user structure if available."""
        if not self._user_structure:
            _LOGGER.debug("User structure not yet available, cannot extract devices")
            return None

        try:
            # Create a devices structure from the user structure data
            devices = []

            # Extract all machines (devices) from realestateMachines
            if "realestateMachines" in self._user_structure:
                for machine in self._user_structure["realestateMachines"]:
                    # Skip cubic devices as they're handled separately
                    if (
                        machine.get("deviceType") == "cubicsecure"
                        and machine.get("deviceRole") == "cubicsecure"
                    ):
                        continue

                    device_data = {
                        "deviceTitle": machine,
                        "mac": machine.get("identity"),
                        "cacheUpdated": self._user_structure.get("cacheUpdated", 0),
                    }

                    # Add extra information for Arc devices
                    if machine.get("deviceGroup") == "arc":
                        device_data["deviceGroup"] = "arc"
                        device_data["deviceType"] = machine.get("deviceType")
                        device_data["deviceRole"] = machine.get("deviceRole")
                        if "zone" in machine:
                            device_data["zone"] = machine["zone"]

                    devices.append(device_data)

            _LOGGER.debug("Extracted %d devices from user structure", len(devices))
            # Return in the expected format
            return {
                "devices": devices,
                "cacheUpdated": self._user_structure.get("cacheUpdated", 0),
            }
        except Exception as err:
            _LOGGER.warning("Error extracting devices from user structure: %s", err)
            return None

    async def get_devices(self):
        """Fetch devices from the API, prioritizing user structure if available."""
        # First try to extract devices from user structure
        if self._user_structure:
            _LOGGER.debug("Using user structure to get initial device information")
            extracted_devices = self.extract_devices_from_structure()
            if extracted_devices and extracted_devices.get("devices"):
                self._devices = extracted_devices
                _LOGGER.debug(
                    "Found %d devices in user structure",
                    len(extracted_devices.get("devices", [])),
                )

                # Identify Arc hubs for later processing
                arc_hubs = self.get_arc_hubs_from_structure()
                if arc_hubs:
                    _LOGGER.debug("Found %d Arc hubs in structure", len(arc_hubs))
                    for hub in arc_hubs:
                        _LOGGER.debug(
                            "Arc hub identified: %s", hub.get("identity", "unknown")
                        )

        # Always try to get detailed device information from the API
        try:
            endpoint = f"service/users/user/{self.userid}/structure/false"

            # Define headers with the JWT token
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            _LOGGER.debug("Fetching detailed device information from API")
            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    api_response = await response.json()
                    _LOGGER.debug("API response type: %s", type(api_response).__name__)

                    # Handle different response formats (list or dict)
                    if isinstance(api_response, list):
                        # Response is a list, likely containing structures
                        _LOGGER.debug(
                            "API returned a list with %d items", len(api_response)
                        )
                        api_devices = []

                        # Extract devices from each structure
                        for structure in api_response:
                            if (
                                isinstance(structure, dict)
                                and "realestateMachines" in structure
                            ):
                                for machine in structure.get("realestateMachines", []):
                                    # Skip cubic devices as they're handled separately
                                    if (
                                        machine.get("deviceType") == "cubicsecure"
                                        and machine.get("deviceRole") == "cubicsecure"
                                    ):
                                        continue

                                    device_data = {
                                        "deviceTitle": machine,
                                        "mac": machine.get("identity"),
                                        "cacheUpdated": structure.get(
                                            "cacheUpdated", 0
                                        ),
                                    }

                                    # Add extra information for Arc devices
                                    if machine.get("deviceGroup") == "arc":
                                        device_data["deviceGroup"] = "arc"
                                        device_data["deviceType"] = machine.get(
                                            "deviceType"
                                        )
                                        device_data["deviceRole"] = machine.get(
                                            "deviceRole"
                                        )
                                        if "zone" in machine:
                                            device_data["zone"] = machine["zone"]

                                    api_devices.append(device_data)

                        # Create a dictionary structure
                        api_data = {
                            "devices": api_devices,
                            "cacheUpdated": int(datetime.now().timestamp()),
                        }
                    elif isinstance(api_response, dict) and "devices" in api_response:
                        # Response is already in the expected format
                        api_data = api_response
                    else:
                        _LOGGER.warning(
                            "Unexpected API response format: %s", api_response
                        )
                        # Create an empty structure
                        api_data = {
                            "devices": [],
                            "cacheUpdated": int(datetime.now().timestamp()),
                        }

                    # Merge with existing data or replace if none exists
                    if self._devices and self._devices.get("devices"):
                        # Keep existing devices and add any new ones from API
                        existing_ids = {
                            d.get("mac") for d in self._devices.get("devices", [])
                        }
                        for device in api_data.get("devices", []):
                            if (
                                device.get("mac")
                                and device.get("mac") not in existing_ids
                            ):
                                self._devices["devices"].append(device)
                        # Update cache timestamp
                        self._devices["cacheUpdated"] = api_data.get(
                            "cacheUpdated", self._devices.get("cacheUpdated", 0)
                        )
                    else:
                        self._devices = api_data

                    _LOGGER.debug(
                        "Successfully processed device information, total devices: %d",
                        len(self._devices.get("devices", [])),
                    )
                    return True

                _LOGGER.error(
                    "Obtaining devices data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                # Even if API call fails, return True if we have devices from structure
                return (
                    self._devices is not None
                    and len(self._devices.get("devices", [])) > 0
                )

        except (ClientResponseError, ClientError) as error:
            # Handle the error but don't immediately return False
            await self.handle_client_error(endpoint, headers, error)
            # Return True if we already have devices from structure
            return (
                self._devices is not None and len(self._devices.get("devices", [])) > 0
            )

    @property
    def devices(self):
        """Property for devices data"""
        return self._devices

    async def get_hub_devices(self, hub_id: str):
        """Fetch devices connected to a specific ARC hub."""
        if not hub_id:
            _LOGGER.warning("Invalid hub ID provided: %s", hub_id)
            return False

        try:
            # Use the correct endpoint for Arc hubs
            endpoint = f"service/arc/hub/{hub_id}/structure/false"

            _LOGGER.debug("Fetching devices for hub %s", hub_id)

            # Define headers with the JWT token
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    self._hub_devices = await response.json()
                    _LOGGER.debug("Successfully fetched data for hub %s", hub_id)
                    return True

                _LOGGER.error(
                    "Obtaining hub devices from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    @property
    def hub_devices(self):
        """Property for hub devices data"""
        return self._hub_devices

    async def get_arc_sense_measurement(self, arc_sense_mac: str, force_update=False):
        """Fetch measurement data for a specific Arc Sense device."""
        if not arc_sense_mac:
            _LOGGER.warning("Invalid Arc Sense MAC provided")
            return False

        try:
            endpoint = f"service/arc/sense/{arc_sense_mac}/measurement/"
            endpoint += "true" if force_update else "false"

            # Define headers with the JWT token
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            _LOGGER.debug(
                "Fetching measurement data for Arc Sense device %s", arc_sense_mac
            )

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    measurement_data = await response.json()

                    # Update device data with the measurement information
                    if not hasattr(self, "_arc_sense_measurements"):
                        self._arc_sense_measurements = {}

                    self._arc_sense_measurements[arc_sense_mac] = measurement_data
                    return True

                _LOGGER.error(
                    "Obtaining Arc Sense measurement from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_arc_sense_configuration(self, arc_sense_mac: str, force_update=False):
        """Fetch configuration data for a specific Arc Sense device."""
        if not arc_sense_mac:
            _LOGGER.warning("Invalid Arc Sense MAC provided")
            return False

        try:
            endpoint = f"service/arc/sense/{arc_sense_mac}/configuration/"
            endpoint += "true" if force_update else "false"

            # Define headers with the JWT token
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            _LOGGER.debug(
                "Fetching configuration data for Arc Sense device %s", arc_sense_mac
            )

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    config_data = await response.json()

                    # Update device data with the configuration information
                    if not hasattr(self, "_arc_sense_configurations"):
                        self._arc_sense_configurations = {}

                    self._arc_sense_configurations[arc_sense_mac] = config_data
                    return True

                _LOGGER.error(
                    "Obtaining Arc Sense configuration from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_device_measurement(self, device_identity: str, force_update=False):
        """Fetch measurement data for a specific device."""
        if not device_identity:
            _LOGGER.warning("Invalid device identity provided")
            return False

        try:
            # Determine endpoint based on device type - if it contains ":" it's likely an Arc device
            if ":" in device_identity:
                endpoint = f"service/arc/sense/{device_identity}/measurement/"
                endpoint += "true" if force_update else "false"
            else:
                # For other device types, might need different endpoints
                # _LOGGER.info("Unknown device type for identity: %s", device_identity)
                return False

            # Define headers with the JWT token
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            # _LOGGER.info("Fetching measurement data for device %s", device_identity)

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    self._device_measurements[device_identity] = await response.json()
                    # _LOGGER.info(
                    #    "Successfully obtained measurements for device %s",
                    #    device_identity,
                    # )
                    return True

                _LOGGER.error(
                    "Obtaining device measurement from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_device_configuration(self, device_identity: str, force_update=False):
        """Fetch configuration data for a specific device."""
        if not device_identity:
            _LOGGER.warning("Invalid device identity provided")
            return False

        try:
            # Determine endpoint based on device type - if it contains ":" it's likely an Arc device
            if ":" in device_identity:
                endpoint = f"service/arc/sense/{device_identity}/configuration/"
                endpoint += "true" if force_update else "false"
            else:
                # For other device types, might need different endpoints
                _LOGGER.warning("Unknown device type for identity: %s", device_identity)
                return False

            # Define headers with the JWT token
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            _LOGGER.debug("Fetching configuration data for device %s", device_identity)

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    self._device_configurations[device_identity] = await response.json()
                    return True

                _LOGGER.error(
                    "Obtaining device configuration from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_device_title(self, device_identity: str, force_update=False):
        """Fetch title information for a specific device."""
        if not device_identity:
            _LOGGER.warning("Invalid device identity provided")
            return False

        try:
            endpoint = f"service/devices/device/{device_identity}/title/"
            endpoint += "true" if force_update else "false"

            # Define headers with the JWT token
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            _LOGGER.debug("Fetching title data for device %s", device_identity)

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    if not hasattr(self, "_device_titles"):
                        self._device_titles = {}

                    self._device_titles[device_identity] = await response.json()
                    return True

                _LOGGER.error(
                    "Obtaining device title from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def set_device_temperature(self, device_identity: str, temperature: float):
        """Set the desired temperature for a device.

        Args:
            device_identity: The device identity (MAC address for arc devices)
            temperature: The desired temperature in Celsius

        Returns:
            bool: True if successful, False otherwise
        """
        if not device_identity:
            _LOGGER.warning("Invalid device identity provided")
            return False

        # Calculate the temperature value (multiply by 10 to convert to the format used by LK Systems)
        temp_value = int(temperature * 10)

        try:
            # For Arc devices, use the specific endpoint
            if ":" in device_identity:
                # First fetch current data
                if not await self.get_device_measurement(
                    device_identity, force_update=True
                ):
                    _LOGGER.error(
                        "Failed to get current device measurement before setting temperature"
                    )
                    return False

                # Get the current data to preserve other fields
                current_data = self._device_measurements.get(device_identity, {})
                if not current_data:
                    _LOGGER.error(
                        "No current measurement data available for device %s",
                        device_identity,
                    )
                    return False

                # Create a copy of the current data and update the desired temperature
                update_data = current_data.copy()
                update_data["desiredTemperature"] = temp_value

                # Send the updated data to the device
                endpoint = f"service/arc/sense/{device_identity}/measurement/true"

                # Define headers with the JWT token
                headers = {
                    **self._get_headers(),
                    "authorization": f"Bearer {self.jwt_token}",
                }

                _LOGGER.debug(
                    "Setting temperature for device %s to %.1f°C (%d)",
                    device_identity,
                    temperature,
                    temp_value,
                )

                async with self.session.post(
                    self.base_url + endpoint, json=update_data, headers=headers
                ) as response:
                    response.raise_for_status()
                    if response.status == 200:
                        # Update our local copy with the new data
                        self._device_measurements[
                            device_identity
                        ] = await response.json()
                        return True

                    _LOGGER.error(
                        "Setting temperature for device %s failed with status code %d",
                        device_identity,
                        response.status,
                    )
                    return False
            else:
                # For other device types, you might need different endpoints
                _LOGGER.error(
                    "Unsupported device type for setting temperature: %s",
                    device_identity,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def set_thermostat_temperature(self, device_id, temperature):
        """Set thermostat temperature through the API.

        Args:
            device_id: The device identity (MAC or unique ID)
            temperature: The temperature value in tenths of a degree (e.g. 215 = 21.5°C)

        Returns:
            Result dictionary containing success status and any response data
        """
        result = {"success": False, "data": None, "error": None}

        try:
            # Use the correct Azure endpoint URL for thermostat temperature setting
            url = "https://lk-arc-structure-mapper.azurewebsites.net/api/measurement/sense"

            # Get base headers from _get_headers() method
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            _LOGGER.debug(
                "Using Azure endpoint for thermostat control with token: %s...",
                self.jwt_token[:20] if self.jwt_token else "None",
            )

            # Create simple payload according to the required format
            payload = {"temperature": temperature, "mac": device_id}

            _LOGGER.debug(
                "Setting thermostat %s to temperature %s with payload: %s",
                device_id,
                temperature,
                payload,
            )

            # Make the API request
            async with self.session.post(url, headers=headers, json=payload) as resp:
                if resp.status != 200 and resp.status != 201 and resp.status != 202:
                    error_text = await resp.text()
                    result["error"] = f"API error {resp.status}: {error_text}"
                    return result

                # Parse the response
                try:
                    response_data = await resp.json()
                    result["data"] = response_data

                    # Update our cached measurement data with the complete response
                    # The response contains full device state including all measurements
                    if device_id in self._device_measurements:
                        # Log the complete response for debugging
                        _LOGGER.debug(
                            "Received updated device state: %s", response_data
                        )

                        # Update all fields from the response
                        if isinstance(response_data, dict):
                            # Store the complete state including currentTemperature, currentHumidity, etc.
                            self._device_measurements[device_id].update(response_data)
                            _LOGGER.debug(
                                "Updated cached device state for %s", device_id
                            )
                except Exception as json_err:
                    # Handle case where response might not be JSON
                    result["data"] = await resp.text()
                    _LOGGER.warning(
                        "Failed to parse thermostat response as JSON: %s", json_err
                    )

                result["success"] = True
                return result

        except Exception as ex:
            result["error"] = f"Exception: {str(ex)}"
            return result

    @property
    def arc_sense_measurements(self):
        """Property for Arc Sense measurement data."""
        return getattr(self, "_arc_sense_measurements", {})

    @property
    def arc_sense_configurations(self):
        """Property for Arc Sense configuration data."""
        return getattr(self, "_arc_sense_configurations", {})

    @property
    def device_measurements(self):
        """Property for device measurement data."""
        return self._device_measurements

    @property
    def device_configurations(self):
        """Property for device configuration data."""
        return self._device_configurations

    @property
    def device_titles(self):
        """Property for device title data."""
        return getattr(self, "_device_titles", {})

    async def get_cubic_secure_configuration(
        self, cubic_identity: str, force_update=False
    ):
        """Fetch Cubic secure configuration"""
        if force_update:
            _LOGGER.debug("Force update from LK API")
            endpoint = f"service/cubic/secure/{cubic_identity}/configuration/1"
        else:
            endpoint = f"service/cubic/secure/{cubic_identity}/configuration/0"

        success, data = await self._get(endpoint)
        if success:
            self._cubic_secure_configuration = data
            return True
        return False

    @property
    def cubic_secure_configuration(self):
        """Property for Cubic Secure measurement"""
        return self._cubic_secure_configuration

    async def get_cubic_secure_pressure_test_reports(self, cubic_identity: str):
        """Fetch Cubic secure pressure test reports"""
        endpoint = f"service/cubic/secure/{cubic_identity}/pressure-test-reports/1"
        success, data = await self._get(endpoint)
        if success:
            self._cubic_secure_pressure_test_reports = data
            return True
        return False

    @property
    def cubic_secure_pressure_test_reports(self):
        """Property for Cubic Secure pressure test reports"""
        return self._cubic_secure_pressure_test_reports

    async def get_cubic_secure_structure(self, cubic_identity: str):
        """Fetch Cubic secure structure"""
        endpoint = f"service/cubic/secure/{cubic_identity}/structure/1"
        success, data = await self._get(endpoint)
        if success:
            self._cubic_secure_structure = data
            return True
        return False

    @property
    def cubic_secure_structure(self):
        """Property for Cubic Secure pressure test reports"""
        return self._cubic_secure_structure

    async def get_cubic_secure_pressure_test_schedule(self, cubic_identity: str):
        """Fetch Cubic secure structure"""
        endpoint = f"control/cubic/secure/{cubic_identity}/pressure-reports/time"
        success, data = await self._get(endpoint)
        if success:
            self._cubic_secure_pressure_test_schedule = data
            return True
        return False

    @property
    def cubic_secure_pressure_test_schedule(self):
        """Property for Cubic Secure pressure test schedule"""
        return self._cubic_secure_pressure_test_schedule

    async def cubic_secure_close_valve(self, cubic_identity: str):
        """Close valve"""
        endpoint = f"control/cubic/secure/{cubic_identity}/valve/close"
        payload = {}
        success, res = await self._post(endpoint, payload)
        if success:
            return True
        return False

    async def cubic_secure_open_valve(self, cubic_identity: str):
        """Open valve"""
        endpoint = f"control/cubic/secure/{cubic_identity}/valve/open"
        payload = {}
        success, res = await self._post(endpoint, payload)
        if success:
            return True
        return False

    async def cubic_secure_pause_leak_detection(
        self, cubic_identity: str, seconds: int = 3600
    ):
        """Pause leak detection for a specified number of seconds (default is 3600 seconds = 1 hour)"""
        endpoint = f"control/cubic/{cubic_identity}/disable-leak-detection"
        payload = {"seconds": seconds}
        success, res = await self._post(endpoint, payload)
        if success:
            return True
        return False

    async def cubic_secure_set_pressure_test_schedule(
        self, cubic_identity: str, hour: int = 4, minute: int = 0
    ):
        """Set pressure test schedule"""
        endpoint = f"control/cubic/secure/{cubic_identity}/pressure-reports/time"
        payload = {"hour": hour, "minute": minute}
        success, res = await self._post(endpoint, payload)
        if success:
            return True
        return False

    async def cubic_secure_set_thresholds(
        self, cubic_identity: str, threshold: LKThresholds
    ):
        """Set threshold"""
        endpoint = f"control/cubic/secure/{cubic_identity}/threshold"
        payload = threshold
        success, res = await self._post(endpoint, payload)
        if success:
            return True
        return False
