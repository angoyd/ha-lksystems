"""Constants for the LK Systems integration."""

from typing import Final

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)

DOMAIN = "lksystems"
INTEGRATION_NAME = "LK Systems"
ATTRIBUTION = "Data provided by LK Systems API"
MANUFACTURER = "LK Systems"

C_NEXT_UPDATE_TIME = "next_update"
C_UPDATE_TIME = "last_update"

CUBIC_SECURE_MODEL = "Cubic Secure"

# LK systems Sensor Attributes
# NOTE Keep these names aligned with strings.json
#
# C_ADR = "street_address"
CONF_UPDATE_INTERVAL = "update_interval"

# Default update interval in minutes
DEFAULT_UPDATE_INTERVAL = 5


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
        name="Last Status",
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
    ),
}