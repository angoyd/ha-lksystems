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
}
