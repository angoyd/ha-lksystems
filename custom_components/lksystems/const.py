"""Constants for the LK Systems integration."""

from dataclasses import dataclass
from typing import Final

from homeassistant.components.number import NumberEntityDescription
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import EntityCategory, UnitOfPressure, UnitOfTime

DOMAIN = "lksystems"
INTEGRATION_NAME = "LK Systems"
ATTRIBUTION = "Data provided by LK Systems API"
MANUFACTURER = "LK Systems"

C_NEXT_UPDATE_TIME = "next_cloud_fetch_attempt"
C_UPDATE_TIME = "last_cloud_fetch_attempt"

CUBIC_SECURE_MODEL = "Cubic Secure"

# LK systems Sensor Attributes
# NOTE Keep these names aligned with strings.json
#
# C_ADR = "street_address"
CONF_UPDATE_INTERVAL = "update_interval"

# Default update interval in minutes
DEFAULT_UPDATE_INTERVAL = 5

# Default/bounds (in seconds) for the "Pause Duration" number
# entity. The default matches the pause_leak_detection service's own default.
DEFAULT_PAUSE_LEAK_DETECTION_SECONDS: Final = 3600
PAUSE_LEAK_DETECTION_MIN_SECONDS: Final = 60
PAUSE_LEAK_DETECTION_MAX_SECONDS: Final = 86400

# The API reports a Cubic Secure's valveState as "closed" for a shut
# valve; any other value is treated as open - "open" is the value the
# API itself actually reports for that case (confirmed against a real
# device), not just this integration's own placeholder.
CUBIC_SECURE_VALVE_STATE_CLOSED: Final = "closed"
CUBIC_SECURE_VALVE_STATE_OPEN: Final = "open"

# After an open/close write, poll the cloud at this interval until it
# confirms the valve actually reached the requested state - the physical
# motor takes on the order of 10-30s to finish moving (confirmed against
# a real device) and the API doesn't report the change until then, so a
# single immediate check right after the write reads a stale pre-action
# snapshot.
VALVE_ACTION_RETRY_INTERVAL_SECONDS: Final = 5

# Stop retrying this long after an open/close write - the longest the
# entity should ever show a transitional "closing"/"opening" state
# (confirmed real motor travel time tops out around 25s). Past this, the
# entity optimistically shows the state the write actually requested
# rather than lingering on a stale reading - HA already issued the
# command, so assume it succeeded, and let the next regular poll quietly
# correct it if it didn't.
VALVE_ACTION_MAX_RETRY_SECONDS: Final = 30

# Once a pause's target end time is reached, poll the cloud at this
# interval until it confirms the pause is actually over, so "Leak
# Detection Paused Until" clears promptly instead of waiting on the next
# regular poll. A single delayed check isn't reliable here - how long the
# cloud lags behind the device's real state past a pause's nominal end
# varies (confirmed empirically against the real API, but not to one
# fixed figure) - so this retries instead of guessing a wait long enough
# to always be right.
LEAK_DETECTION_EXPIRY_RETRY_INTERVAL_SECONDS: Final = 15

# Stop retrying this long past the target and fall back to the regular
# poll - a safety cap for if the cloud never resolves (e.g. the device
# has gone offline), not a value normal operation is expected to reach.
LEAK_DETECTION_EXPIRY_MAX_RETRY_SECONDS: Final = 180

# For this long after HA itself issues a pause/resume, don't let a
# reconciliation pass override the local state with what the cloud
# reports - the cloud's cached response can still be serving a pre-write
# snapshot for tens of seconds (confirmed empirically against the real
# API), and a poll landing in that window isn't caused by the write but
# can still land inside it by coincidence. HA's own just-made write is
# trusted for this window; past it, the cloud is trusted again.
LEAK_DETECTION_LOCAL_WRITE_GRACE_SECONDS: Final = 60


LK_CUBICSECURE_SENSORS: dict[str, SensorEntityDescription] = {
    "volumetotalday": SensorEntityDescription(
        key="volumeTotalDay",
        name="Total Volume Day",
        icon="mdi:water",
        device_class=SensorDeviceClass.WATER,
        unit_of_measurement="L",
        native_unit_of_measurement="L",
        state_class=SensorStateClass.TOTAL,
        translation_key="volume_total_day_sensor",
    ),
    "volumetotal": SensorEntityDescription(
        key="volumeTotal",
        name="Total Volume",
        icon="mdi:water",
        device_class=SensorDeviceClass.WATER,
        unit_of_measurement="L",
        native_unit_of_measurement="L",
        state_class=SensorStateClass.TOTAL,
        translation_key="volume_total_sensor",
    ),
    "tempWaterAverage": SensorEntityDescription(
        key="tempWaterAverage",
        name="Average Water Temperature",
        icon="mdi:thermometer",
        device_class=SensorDeviceClass.TEMPERATURE,
        unit_of_measurement="°C",
        native_unit_of_measurement="°C",
        state_class=SensorStateClass.MEASUREMENT,
        translation_key="temp_water_average_sensor",
    ),
    "tempWaterMin": SensorEntityDescription(
        key="tempWaterMin",
        name="Min Water Temperature",
        icon="mdi:thermometer",
        device_class=SensorDeviceClass.TEMPERATURE,
        unit_of_measurement="°C",
        native_unit_of_measurement="°C",
        state_class=SensorStateClass.MEASUREMENT,
        translation_key="temp_water_min_sensor",
        entity_registry_enabled_default=False,
    ),
    "tempWaterMax": SensorEntityDescription(
        key="tempWaterMax",
        name="Max Water Temperature",
        icon="mdi:thermometer",
        device_class=SensorDeviceClass.TEMPERATURE,
        unit_of_measurement="°C",
        native_unit_of_measurement="°C",
        state_class=SensorStateClass.MEASUREMENT,
        translation_key="temp_water_max_sensor",
        entity_registry_enabled_default=False,
    ),
    "waterPressure": SensorEntityDescription(
        key="waterPressure",
        name="Water Pressure",
        icon="mdi:gauge-low",
        device_class=SensorDeviceClass.PRESSURE,
        unit_of_measurement="hPa",
        native_unit_of_measurement="hPa",
        state_class=SensorStateClass.MEASUREMENT,
        translation_key="water_pressure_sensor",
    ),
    "ambientTemp": SensorEntityDescription(
        key="tempAmbient",
        name="Ambient Temperature",
        icon="mdi:thermometer",
        device_class=SensorDeviceClass.TEMPERATURE,
        unit_of_measurement="°C",
        native_unit_of_measurement="°C",
        state_class=SensorStateClass.MEASUREMENT,
        translation_key="temp_ambient_sensor",
    ),
    "lastStatus": SensorEntityDescription(
        key="lastStatus",
        name="Last Device Report",
        icon="mdi:information-outline",
        device_class=SensorDeviceClass.TIMESTAMP,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="last_status_sensor",
    ),
    "cacheUpdated": SensorEntityDescription(
        key="cacheUpdated",
        name="Cache Updated",
        icon="mdi:information-outline",
        device_class=SensorDeviceClass.TIMESTAMP,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="cache_updated_sensor",
        entity_registry_enabled_default=False,
    ),
    "leak.leakState": SensorEntityDescription(
        key="leak.leakState",
        name="Leak State",
        icon="mdi:water-off",
        device_class=None,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="leak_state_sensor",
    ),
    "leak.meanFlow": SensorEntityDescription(
        key="leak.meanFlow",
        name="Leak Mean Flow",
        icon="mdi:water-off",
        device_class=None,
        unit_of_measurement="L/h",
        native_unit_of_measurement="L/h",
        state_class=SensorStateClass.MEASUREMENT,
        translation_key="leak_mean_flow_sensor",
        entity_registry_enabled_default=False,
    ),
    "leak.dateStartedAt": SensorEntityDescription(
        key="leak.dateStartedAt",
        name="Leak Date Started At",
        icon="mdi:calendar-start",
        device_class=SensorDeviceClass.TIMESTAMP,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="leak_date_started_at_sensor",
        entity_registry_enabled_default=False,
    ),
    "leak.dateUpdatedAt": SensorEntityDescription(
        key="leak.dateUpdatedAt",
        name="Leak Date Updated At",
        icon="mdi:calendar-sync",
        device_class=SensorDeviceClass.TIMESTAMP,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="leak_date_updated_at_sensor",
        entity_registry_enabled_default=False,
    ),
    "leak.acknowledged": SensorEntityDescription(
        key="leak.acknowledged",
        name="Leak Acknowledged",
        icon="mdi:check-circle-outline",
        device_class=None,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="leak_acknowledged_sensor",
        entity_registry_enabled_default=False,
    ),
}
LK_CUBICSECURE_CONFIG_SENSORS: dict[str, SensorEntityDescription] = {
    "valveState": SensorEntityDescription(
        key="valveState",
        name="Valve State",
        icon="mdi:valve",
        device_class=None,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="valve_state_sensor",
    ),
    "firmwareVersion": SensorEntityDescription(
        key="firmwareVersion",
        name="Firmware Version",
        icon="mdi:chip",
        device_class=None,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="firmware_version_sensor",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    "hardwareVersion": SensorEntityDescription(
        key="hardwareVersion",
        name="Hardware Version",
        icon="mdi:chip",
        device_class=None,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="hardware_version_sensor",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
}


@dataclass(frozen=True)
class LKThresholdNumberDescription(NumberEntityDescription, frozen_or_thawed=True):
    """Describes one leak-detection threshold as a writable number entity.

    The real API's thresholds object is nested (category -> field) unlike
    the flat dicts SensorEntityDescription.key already handles, so this
    carries its own category/fields instead of relying on key alone.
    `fields` holds more than one name when a single displayed control
    writes the same value to multiple API fields at once - confirmed
    against a real account that the app's one "delay" slider per leak
    category does exactly this (closeDelay and notificationDelay always
    equal there).

    `api_unit_of_measurement` is the unit the API itself uses (always
    seconds for delay/duration fields) when it differs from
    `native_unit_of_measurement` (what's displayed) - number.py converts
    between the two via DurationConverter at its own boundary, the same
    way it already does for the sibling Pause Duration entity. None (the
    default) means the API and displayed units are the same field, no
    conversion needed.

    entity_category defaults to CONFIG - every threshold is a set-once
    tuning value, not something operated moment-to-moment, so it belongs
    in the device page's Configuration section rather than mixed in with
    Controls (the valve, Pause Duration/buttons) - matching how the LK
    app itself keeps "Advanced alarm settings" on its own screen, apart
    from the main dashboard.
    """

    category: str = ""
    fields: tuple[str, ...] = ()
    api_unit_of_measurement: str | None = None
    entity_category: EntityCategory | None = EntityCategory.CONFIG


# Field scope and min/max/step below come from the LK app's own "Advanced
# alarm settings" screen (checked by dragging every slider to both
# extremes on a real account), not just the raw API schema - the app
# never exposes closeDelay/notificationDelay as separate controls (one
# combined "delay" per leak category instead, confirmed writing the same
# value to both), and doesn't expose those two fields for pressure at all.
LK_CUBICSECURE_THRESHOLD_NUMBERS: dict[str, LKThresholdNumberDescription] = {
    "large_leak_threshold": LKThresholdNumberDescription(
        key="large_leak_threshold",
        name="Large Leak Threshold",
        category="leakLarge",
        fields=("threshold",),
        native_min_value=500,
        native_max_value=2500,
        native_step=50,
        native_unit_of_measurement="L/h",
        icon="mdi:water-alert",
    ),
    "large_leak_delay": LKThresholdNumberDescription(
        key="large_leak_delay",
        name="Large Leak Delay",
        category="leakLarge",
        fields=("closeDelay", "notificationDelay"),
        native_min_value=30,
        native_max_value=120,
        native_step=10,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        icon="mdi:timer-alert-outline",
    ),
    "medium_leak_threshold": LKThresholdNumberDescription(
        key="medium_leak_threshold",
        name="Medium Leak Threshold",
        category="leakMedium",
        fields=("threshold",),
        native_min_value=2,
        native_max_value=30,
        native_step=1,
        native_unit_of_measurement="L/h",
        icon="mdi:water-alert-outline",
    ),
    "medium_leak_delay": LKThresholdNumberDescription(
        key="medium_leak_delay",
        name="Medium Leak Delay",
        category="leakMedium",
        fields=("closeDelay", "notificationDelay"),
        native_min_value=5,
        native_max_value=120,
        native_step=5,
        native_unit_of_measurement=UnitOfTime.MINUTES,
        icon="mdi:timer-alert-outline",
        api_unit_of_measurement=UnitOfTime.SECONDS,
    ),
    "pressure_sensitivity": LKThresholdNumberDescription(
        key="pressure_sensitivity",
        name="Automatic Pressure Test Sensitivity",
        category="pressure",
        fields=("sensitivity",),
        native_min_value=0.2,
        native_max_value=0.8,
        native_step=0.1,
        native_unit_of_measurement=UnitOfPressure.BAR,
        icon="mdi:gauge",
    ),
    "pressure_duration": LKThresholdNumberDescription(
        key="pressure_duration",
        name="Automatic Pressure Test Duration",
        category="pressure",
        fields=("duration",),
        native_min_value=45,
        native_max_value=150,
        native_step=1,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        icon="mdi:timer-sand",
    ),
}

# The app's "prevent valve closing" toggle isn't a separate API field -
# confirmed empirically (a before/after diagnostics diff around toggling it
# in the app) that it overloads pressure.closeDelay, writing a value one
# below the signed-32-bit max so that delay effectively never elapses.
PREVENT_VALVE_CLOSING_SENTINEL: Final = 2147483646

# Every value below is confirmed against a real Cubic Secure device's
# "reset to factory defaults" action (Advanced alarm settings screen):
# a before/after diagnostics diff showed only leakMedium.threshold change
# (5.0 -> 15.0, correcting stale data from this integration's own
# now-fixed set_thresholds bug) - every other field, including this one,
# was already sitting at its factory default and stayed untouched.
PRESSURE_CLOSE_DELAY_DEFAULT: Final = 252000

LK_CUBICSECURE_THRESHOLD_FACTORY_DEFAULTS: Final[dict] = {
    "pressure": {
        "sensitivity": 0.3,
        "duration": 45,
        "closeDelay": PRESSURE_CLOSE_DELAY_DEFAULT,
        "notificationDelay": 169200,
    },
    "leakMedium": {
        "threshold": 15.0,
        "closeDelay": 2700,
        "notificationDelay": 2700,
    },
    "leakLarge": {
        "threshold": 1500.0,
        "closeDelay": 90,
        "notificationDelay": 90,
    },
}