"""Config flow for LK Systems integration."""
from __future__ import annotations

import logging
from typing import Any, cast

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry, OptionsFlow
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
import homeassistant.helpers.config_validation as cv

# Import at the module level
from .pylksystems import LKSystemsManager
from .const import CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)

# Define schemas outside of async functions
USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Optional(CONF_UPDATE_INTERVAL, default=DEFAULT_UPDATE_INTERVAL): cv.positive_int,
    }
)

REAUTH_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate that the user input allows us to connect to LK Systems."""
    async with LKSystemsManager(data[CONF_USERNAME], data[CONF_PASSWORD]) as lk_inst:
        if not await lk_inst.login():
            raise InvalidAuth


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for LK Systems."""

    VERSION = 1
    
    # Store entry_id for reauth
    _entry_id = None

    async def async_step_reauth(self, user_input=None):
        """Handle reauth when authentication fails."""
        # Store entry ID from context
        if self.context.get("entry_id"):
            self._entry_id = self.context["entry_id"]
            
        # Get existing entry
        entry = None
        if self._entry_id:
            entry = self.hass.config_entries.async_get_entry(self._entry_id)
        
        if user_input is None:
            # Show initial form with existing username
            default_username = ""
            if entry and entry.data.get(CONF_USERNAME):
                default_username = entry.data.get(CONF_USERNAME)
                
            return self.async_show_form(
                step_id="reauth",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_USERNAME, default=default_username): cv.string,
                        vol.Required(CONF_PASSWORD): cv.string,
                    }
                ),
                description_placeholders={"reason": "Authentication failed"},
            )

        # Validate the credentials
        try:
            await validate_input(self.hass, user_input)
        except InvalidAuth:
            return self.async_show_form(
                step_id="reauth",
                data_schema=REAUTH_SCHEMA,
                errors={"base": "invalid_auth"},
            )
        except Exception:
            return self.async_show_form(
                step_id="reauth",
                data_schema=REAUTH_SCHEMA,
                errors={"base": "unknown"},
            )

        # Update entry with new credentials
        if self._entry_id:
            entry = self.hass.config_entries.async_get_entry(self._entry_id)
            if entry:
                # Create updated data
                entry_data = {
                    **entry.data,
                    CONF_USERNAME: user_input[CONF_USERNAME],
                    CONF_PASSWORD: user_input[CONF_PASSWORD],
                }
                
                # Update the entry
                self.hass.config_entries.async_update_entry(entry, data=entry_data)
                
                # Reload the config entry to apply new credentials
                self.hass.async_create_task(
                    self.hass.config_entries.async_reload(self._entry_id)
                )
                
                return self.async_abort(reason="reauth_successful")
                
        return self.async_abort(reason="reauth_failed")

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            # Check if we already have an entry for this username
            existing_entries = self._async_current_entries()
            for entry in existing_entries:
                if entry.data.get(CONF_USERNAME) == user_input[CONF_USERNAME]:
                    return self.async_abort(reason="already_configured")

            # Store data and create entry
            return self.async_create_entry(
                title=f"LK Systems ({user_input[CONF_USERNAME]})",
                data=user_input,
            )

        return self.async_show_form(
            step_id="user", data_schema=USER_SCHEMA, errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> OptionsFlow:
        """Create the options flow."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(OptionsFlow):
    """Handle options."""
    
    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow with config entry."""
        self._config_entry = config_entry
        super().__init__()

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        # Get current options or provide defaults
        options = self._config_entry.options or {}
        update_interval = options.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL)
        
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_UPDATE_INTERVAL, default=update_interval
                    ): cv.positive_int,
                }
            ),
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
