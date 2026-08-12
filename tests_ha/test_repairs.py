"""Tests for repairs.py's issue-registry helpers.

Coordinator-driven behavior (when a repair issue actually gets raised or
cleared during an update) is covered separately in test_coordinator.py -
these tests are only concerned with repairs.py's own create/clear logic
against the issue registry.
"""

from __future__ import annotations

from homeassistant.helpers import issue_registry as ir

from custom_components.lksystems.const import DOMAIN
from custom_components.lksystems.repairs import (
    async_clear_auth_failed_issue,
    async_clear_persistent_update_failure_issue,
    async_create_auth_failed_issue,
    async_create_persistent_update_failure_issue,
)


def _get_issue(hass, issue_id: str):
    return ir.async_get(hass).async_get_issue(DOMAIN, issue_id)


class TestAuthFailedIssue:
    async def test_create_registers_an_error_severity_issue(self, hass):
        async_create_auth_failed_issue(hass, "entry-1")

        issue = _get_issue(hass, "auth_failed_entry-1")
        assert issue is not None
        assert issue.severity == ir.IssueSeverity.ERROR
        assert issue.translation_key == "auth_failed"

    async def test_clear_removes_the_issue(self, hass):
        async_create_auth_failed_issue(hass, "entry-1")

        async_clear_auth_failed_issue(hass, "entry-1")

        assert _get_issue(hass, "auth_failed_entry-1") is None

    async def test_clear_without_a_prior_create_does_not_raise(self, hass):
        async_clear_auth_failed_issue(hass, "entry-never-failed")

    async def test_issues_are_keyed_per_entry(self, hass):
        async_create_auth_failed_issue(hass, "entry-1")

        assert _get_issue(hass, "auth_failed_entry-2") is None


class TestPersistentUpdateFailureIssue:
    async def test_create_registers_a_warning_severity_issue(self, hass):
        async_create_persistent_update_failure_issue(hass, "entry-1")

        issue = _get_issue(hass, "persistent_update_failure_entry-1")
        assert issue is not None
        assert issue.severity == ir.IssueSeverity.WARNING
        assert issue.translation_key == "persistent_update_failure"

    async def test_clear_removes_the_issue(self, hass):
        async_create_persistent_update_failure_issue(hass, "entry-1")

        async_clear_persistent_update_failure_issue(hass, "entry-1")

        assert _get_issue(hass, "persistent_update_failure_entry-1") is None

    async def test_clear_without_a_prior_create_does_not_raise(self, hass):
        async_clear_persistent_update_failure_issue(hass, "entry-never-failed")
