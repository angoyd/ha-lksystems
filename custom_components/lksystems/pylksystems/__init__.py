"""Lk Systems module."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta
import json
import logging
import re


from aiohttp import ClientError, ClientResponseError, ClientSession
from dateutil.relativedelta import relativedelta

_LOGGER = logging.getLogger(__name__)


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

    async def login(self):
        """Login to LK systems and get userId"""
        try:
            payload = {"email": self.username, "password": self.password}
            headers = {**self._get_headers()}

            endpoint = "auth/auth/login"
            endpointUserId = "auth/auth/user"
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

    async def get_cubic_secure_messurement(
        self, cubic_identity: str, force_update=False
    ):
        """Fetch Cubic secure messurement"""
        try:
            if force_update:
                _LOGGER.debug("Force update from LK API")
                endpoint = f"service/cubic/secure/{cubic_identity}/measurement/1"
            else:
                endpoint = f"service/cubic/secure/{cubic_identity}/measurement/0"

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
                    self._cubic_secure_messurement = await response.json()

                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    @property
    def cubic_secure_messurement(self):
        """Property for Cubic Secure messurement"""
        return self._cubic_secure_messurement

    async def get_user_structure(self):
        """Fetch Cubic secure messurement"""
        try:
            endpoint = f"service/users/user/{self.userid}/structure/1"

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
                    self._user_structure = (await response.json())[0]
                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    @property
    def user_structure(self):
        """Property for User Structure"""
        return self._user_structure
