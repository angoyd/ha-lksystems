"""Lk Systems module."""

from __future__ import annotations

import logging
from typing import TypedDict

from aiohttp import ClientError, ClientResponseError, ClientSession

_LOGGER = logging.getLogger(__name__)


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
        self._cubic_secure_measurement = None
        self._user_structure = None
        self._cubic_secure_configuration = None
        self._cubic_secure_pressure_test_reports = None
        self._cubic_secure_structure = None
        self._cubic_secure_pressure_test_schedule = None

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
            self._cubic_secure_measurement = res
            return True
        return False


    @property
    def cubic_secure_measurement(self):
        """Property for Cubic Secure measurement"""
        return self._cubic_secure_measurement

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


    async def get_cubic_secure_pressure_test_reports(
        self, cubic_identity: str
    ):
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

    async def get_cubic_secure_structure(
        self, cubic_identity: str
    ):
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

    async def get_cubic_secure_pressure_test_schedule(
        self, cubic_identity: str
    ):
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

    async def cubic_secure_pause_leak_detection(self, cubic_identity: str, seconds: int = 3600):
        """Pause leak detection for a specified number of seconds (default is 3600 seconds = 1 hour)"""
        endpoint = f"control/cubic/{cubic_identity}/disable-leak-detection"
        payload = {"seconds": seconds}
        success, res = await self._post(endpoint, payload)
        if success:
            return True
        return False

    async def cubic_secure_set_pressure_test_schedule(self, cubic_identity: str, hour: int = 4, minute: int = 0):
        """Set pressure test schedule"""
        endpoint = f"control/cubic/secure/{cubic_identity}/pressure-reports/time"
        payload = {"hour": hour, "minute": minute}
        success, res = await self._post(endpoint, payload)
        if success:
            return True
        return False

    async def cubic_secure_set_thresholds(self, cubic_identity: str, threshold: LKThresholds):
        """Set threshold"""
        endpoint = f"control/cubic/secure/{cubic_identity}/threshold"
        payload = threshold
        success, res = await self._post(endpoint, payload)
        if success:
            return True
        return False