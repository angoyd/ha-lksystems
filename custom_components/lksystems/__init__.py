"""The LK Systems integration."""

from __future__ import annotations
from .pylksystems import LKSystemsManager
from datetime import time, timedelta
import logging
import random
from typing import TypedDict
import time

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant

from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .const import (
    CONF_UPDATE_INTERVAL,
    DOMAIN,
    INTEGRATION_NAME,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]


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
    cubic_last_messurement: LkCubicSecureResp
    cacheUpdated: int
    update_time: str
    next_update_time: str


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
    leakState: str
    leak_meanFlow: int
    leak_dateStartedAt: int
    leak_dateUpdatedAt: int
    leak_acknowledged: bool
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


async def update_listener(hass: HomeAssistant, entry):
    """Handle options update."""
    _LOGGER.debug(entry.options)
    if not hass:  # Not sure, to remove warning
        await hass.config_entries.async_reload(entry.entry_id)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up LK Systems from a config entry."""
    coordinator = LKSystemCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    entry.async_on_unload(entry.add_update_listener(update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


class LKSystemCoordinator(DataUpdateCoordinator[LkStructureResp]):
    """Data update coordinator."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(minutes=entry.data.get(CONF_UPDATE_INTERVAL)),
        )
        self._entry = entry
        self._cubic_identity = None

    @property
    def entry_id(self) -> str:
        """Return entry ID."""
        return self._entry.entry_id

    async def _async_update_data(self) -> LkStructureResp:  # noqa: C901
        """Fetch the latest data from the source."""

        try:
            username = self._entry.data.get(CONF_USERNAME)
            password = self._entry.data.get(CONF_PASSWORD)

            async with LKSystemsManager(username, password) as lk_inst:
                if not await lk_inst.login():
                    _LOGGER.error("Failed to login, abort update")
                    raise UpdateFailed("Failed to login")

                if lk_inst.user_structure is None:
                    if not await lk_inst.get_user_structure():
                        _LOGGER.error("Failed to get user structure, abort update")
                        raise UpdateFailed("Unknown error get_user_structure")

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
                }

                if (
                    resp["cubic_machine_info"]
                    and resp["cubic_machine_info"]["identity"]
                ):
                    self._cubic_identity = resp["cubic_machine_info"]["identity"]

                if not await lk_inst.get_cubic_secure_messurement(self._cubic_identity):
                    _LOGGER.error(
                        "Failed to get cubic secure messurement, abort update"
                    )
                    raise UpdateFailed("Unknown error get_cubic_secure_messurement")
                if lk_inst.cubic_secure_messurement is not None:
                    # Get time as unix timestamp
                    timestamp = int(time.time())
                    if (
                        timestamp - lk_inst.cubic_secure_messurement["cacheUpdated"]
                        > 3600
                    ):
                        _LOGGER.debug(
                            "Cubic secure messurement is older than 1 hour, force update"
                        )
                        if not await lk_inst.get_cubic_secure_messurement(
                            self._cubic_identity, force_update=True
                        ):
                            _LOGGER.error(
                                "Failed to get cubic secure messurement, abort update"
                            )
                            raise UpdateFailed(
                                "Unknown error get_cubic_secure_messurement"
                            )

                resp["cubic_last_messurement"] = lk_inst.cubic_secure_messurement

                update_time = dt_util.now().strftime("%Y-%m-%d %H:%M:%S")
                next_update = dt_util.now() + timedelta(
                    minutes=self._entry.data.get(CONF_UPDATE_INTERVAL)
                )
                next_update_time = next_update.strftime("%Y-%m-%d %H:%M:%S")
                resp["update_time"] = update_time
                resp["next_update_time"] = next_update_time
                return resp

        except InvalidAuth as err:
            raise ConfigEntryAuthFailed from err
        except LksystemsError as err:
            raise UpdateFailed(str(err)) from err


class LksystemsError(HomeAssistantError):
    """Base error."""


class InvalidAuth(LksystemsError):
    """Raised when invalid authentication credentials are provided."""


class APIRatelimitExceeded(LksystemsError):
    """Raised when the API rate limit is exceeded."""


class UnknownError(LksystemsError):
    """Raised when an unknown error occurs."""
