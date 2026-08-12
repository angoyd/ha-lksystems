"""Tests for repairs.py's issue-registry helpers.

Coordinator-driven behavior (when a repair issue actually gets raised or
cleared during an update) is covered separately in test_coordinator.py -
these tests are only concerned with repairs.py's own create/clear logic
against the issue registry.
"""

from __future__ import annotations

import pytest
from homeassistant.helpers import issue_registry as ir

from custom_components.lksystems.repairs import (
    _issue_id,
    async_clear_auth_failed_issue,
    async_clear_persistent_update_failure_issue,
    async_create_auth_failed_issue,
    async_create_persistent_update_failure_issue,
)

from .conftest import get_issue

ISSUE_KINDS = [
    pytest.param(
        "auth_failed",
        async_create_auth_failed_issue,
        async_clear_auth_failed_issue,
        ir.IssueSeverity.ERROR,
        id="auth_failed",
    ),
    pytest.param(
        "persistent_update_failure",
        async_create_persistent_update_failure_issue,
        async_clear_persistent_update_failure_issue,
        ir.IssueSeverity.WARNING,
        id="persistent_update_failure",
    ),
]


@pytest.mark.parametrize("kind, create_issue, clear_issue, severity", ISSUE_KINDS)
class TestIssueLifecycle:
    async def test_create_registers_issue_with_expected_severity(
        self, hass, kind, create_issue, clear_issue, severity
    ):
        create_issue(hass, "entry-1")

        issue = get_issue(hass, _issue_id(kind, "entry-1"))
        assert issue is not None
        assert issue.severity == severity
        assert issue.translation_key == kind

    async def test_clear_removes_the_issue(
        self, hass, kind, create_issue, clear_issue, severity
    ):
        create_issue(hass, "entry-1")

        clear_issue(hass, "entry-1")

        assert get_issue(hass, _issue_id(kind, "entry-1")) is None

    async def test_clear_without_a_prior_create_does_not_raise(
        self, hass, kind, create_issue, clear_issue, severity
    ):
        clear_issue(hass, "entry-never-failed")

    async def test_issues_are_keyed_per_entry(
        self, hass, kind, create_issue, clear_issue, severity
    ):
        create_issue(hass, "entry-1")

        assert get_issue(hass, _issue_id(kind, "entry-2")) is None
