"""Arc device-data accessors.

Free functions that read an already-fetched Arc device's state off
`LKSystemCoordinator.data` - actuator states and similar. Populated
incrementally, one function at a time as each is next touched in
`__init__.py`, rather than moved here in one pass.
"""

from __future__ import annotations
