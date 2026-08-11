"""Tests for the LK Systems config flow.

These exercise the config/options flow machinery end to end through a real
(test-mode) Home Assistant core, proving out the tests_ha/
pytest-homeassistant-custom-component infra. `async_step_user` doesn't
currently call `validate_input` before creating an entry (see
config_flow.py) so no LK Systems API mocking is needed here yet - these
tests describe the flow's actual current behavior, not its API calls.
"""

from __future__ import annotations

from unittest.mock import patch

from homeassistant.config_entries import SOURCE_REAUTH
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lksystems.const import (
    CONF_UPDATE_INTERVAL,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
)

USER_INPUT = {
    CONF_USERNAME: "user@example.com",
    CONF_PASSWORD: "hunter2",
    CONF_UPDATE_INTERVAL: DEFAULT_UPDATE_INTERVAL,
}


async def test_user_step_shows_form(hass):
    """The initial step shows the user credentials form."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"


async def test_user_step_creates_entry(hass):
    """Submitting valid credentials creates a config entry.

    async_setup_entry is patched out so the newly-created entry doesn't
    trigger a real coordinator refresh (and a real network call) as a
    side effect of this config-flow-only test.
    """
    with patch(
        "custom_components.lksystems.async_setup_entry", return_value=True
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": "user"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], USER_INPUT
        )
        await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "LK Systems (user@example.com)"
    assert result["data"] == USER_INPUT


async def test_user_step_duplicate_username_aborts(hass):
    """A second entry for the same username is rejected."""
    MockConfigEntry(domain=DOMAIN, data=USER_INPUT).add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_options_flow_updates_interval(hass):
    """The options flow can change the update interval on an existing entry."""
    entry = MockConfigEntry(domain=DOMAIN, data=USER_INPUT)
    entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_UPDATE_INTERVAL: 30}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {CONF_UPDATE_INTERVAL: 30}


async def test_reauth_shows_form(hass):
    """Triggering reauth (as done in __init__.py on auth failure) shows
    a pre-filled credentials form."""
    entry = MockConfigEntry(domain=DOMAIN, data=USER_INPUT)
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth"


async def test_reauth_success_updates_entry_and_reloads(hass, fake_manager):
    """Valid new credentials update the entry and reload it.

    Both the config flow's own validate_input() call and the coordinator's
    refresh (triggered by the reload that follows) go through
    LKSystemsManager, so both import sites need patching.
    """
    entry = MockConfigEntry(domain=DOMAIN, data=USER_INPUT)
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )

    new_creds = {
        CONF_USERNAME: USER_INPUT[CONF_USERNAME],
        CONF_PASSWORD: "new-password",
    }
    with (
        patch(
            "custom_components.lksystems.config_flow.LKSystemsManager",
            return_value=fake_manager,
        ),
        patch(
            "custom_components.lksystems.LKSystemsManager", return_value=fake_manager
        ),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], new_creds
        )
        await hass.async_block_till_done()

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_PASSWORD] == "new-password"


async def test_reauth_invalid_auth_reshows_form_with_error(hass, fake_manager):
    """A failed login during reauth re-shows the form with an error."""
    entry = MockConfigEntry(domain=DOMAIN, data=USER_INPUT)
    entry.add_to_hass(hass)
    fake_manager.login_result = False

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )

    with patch(
        "custom_components.lksystems.config_flow.LKSystemsManager",
        return_value=fake_manager,
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_USERNAME: USER_INPUT[CONF_USERNAME], CONF_PASSWORD: "wrong"},
        )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth"
    assert result["errors"] == {"base": "invalid_auth"}
