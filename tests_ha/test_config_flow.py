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
