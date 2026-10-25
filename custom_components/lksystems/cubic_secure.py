"""Cubic Secure device-data accessors.

Free functions that read an already-fetched Cubic Secure device's state off
`LKSystemCoordinator.data` - configuration, thresholds, pressure-test
schedule/reports, the shared `DeviceInfo` builder, and similar. Populated
incrementally, one function at a time as each is next touched in
`__init__.py`, rather than moved here in one pass.
"""

from __future__ import annotations
