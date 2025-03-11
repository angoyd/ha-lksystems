"""Config flow for LK Systems integration."""

from __future__ import annotations

import logging
from typing import Any, cast

from .pylksystems import LKSystemsManager
import voluptuous as vol

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv

from .const import DOMAIN, CONF_UPDATE_INTERVAL

CONF_TITLE = "LK Systems"

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_UPDATE_INTERVAL, default=30): vol.All(
            cv.string, vol.Coerce(int)
        ),
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate that the user input allows us to connect to LK Systems."""
    async with LKSystemsManager(data[CONF_USERNAME], data[CONF_PASSWORD]) as lk_inst:
        if not await lk_inst.login():
            raise InvalidAuth


class ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for LK Systems."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step. Username and password."""
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=CONFIG_SCHEMA)

        errors = {}
        self.data = user_input
        try:
            await validate_input(self.hass, self.data)
        except CannotConnect:
            errors["base"] = "cannot_connect"
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors["base"] = "unknown"
        else:
            return self.async_create_entry(
                title=CONF_TITLE,
                data=self.data,
            )

        return self.async_show_form(
            step_id="user", data_schema=CONFIG_SCHEMA, errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> OptionsFlow:
        """Create the options flow."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(OptionsFlow):
    """Handle a options flow for LK Systems."""

    def __init__(self, config_entry: ConfigEntry):
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Manage the options."""
        if user_input is not None:
            self.hass.config_entries.async_update_entry(
                self._config_entry, data=user_input, options=self._config_entry.options
            )
            return self.async_create_entry(title=CONF_TITLE, data={})

        schema: dict[Any, Any] = {
            vol.Required(
                CONF_UPDATE_INTERVAL,
                default=self._config_entry.data.get(CONF_UPDATE_INTERVAL),
            ): vol.All(cv.string, vol.Coerce(int)),
        }

        return cast(
            dict[str, Any],
            self.async_show_form(step_id="init", data_schema=vol.Schema(schema)),
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
