"""Cubic Secure device-data accessors.

Free functions that read an already-fetched Cubic Secure device's state off
`LKSystemCoordinator.data` - configuration, thresholds, pressure-test
schedule/reports, the shared `DeviceInfo` builder, and similar. Populated
incrementally, one function at a time as each is next touched in
`__init__.py`, rather than moved here in one pass.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .const import CUBIC_SECURE_LEAK_STATES_WITHOUT_ALARM, CUBIC_SECURE_VALVE_STATE_CLOSED

if TYPE_CHECKING:
    from . import LKSystemCoordinator


def cubic_secure_alarm_awaits_acknowledgement(
    coordinator: LKSystemCoordinator, device_identity: str
) -> bool:
    """Whether, as of the last poll, a leak alarm has closed this device's
    valve and hasn't been acknowledged yet.

    The valve has to be closed too: leakState already reports a leak while
    a detection is still counting down towards closing the valve, and
    acknowledging then would reset that detection (per LK's manual).

    leak.acknowledged is compared as text: confirmed against a real device
    that the API returns it as the string "false", not a boolean.
    """
    device = coordinator.data.get("cubic_devices", {}).get(device_identity, {})
    leak = (device.get("last_measurement") or {}).get("leak") or {}
    leak_state = leak.get("leakState")
    valve_state = (device.get("configuration") or {}).get("valveState")
    return (
        valve_state == CUBIC_SECURE_VALVE_STATE_CLOSED
        and str(leak.get("acknowledged")).lower() == "false"
        and leak_state is not None
        and leak_state.lower() not in CUBIC_SECURE_LEAK_STATES_WITHOUT_ALARM
    )
