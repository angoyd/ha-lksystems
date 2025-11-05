"""Support for LK Systems sensors."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)
import homeassistant.util.dt as dt_util

from . import LKSystemCoordinator
from .const import (
    ATTRIBUTION,
    C_NEXT_UPDATE_TIME,
    C_UPDATE_TIME,
    CUBIC_SECURE_MODEL,
    DOMAIN,
    INTEGRATION_NAME,
    LK_CUBICSECURE_SENSORS,
    LK_CUBICSECURE_CONFIG_SENSORS,
    MANUFACTURER,
)

_LOGGER = logging.getLogger(__name__)

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
        device_class=None,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="last_status_sensor",
    ),
    "cacheUpdated": SensorEntityDescription(
        key="cacheUpdated",
        name="Cache Updated",
        icon="mdi:information-outline",
        device_class=None,
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
        device_class=None,
        unit_of_measurement=None,
        native_unit_of_measurement=None,
        state_class=None,
        translation_key="leak_date_started_at_sensor",
    ),
    "leak.dateUpdatedAt": SensorEntityDescription(
        key="leak.dateUpdatedAt",
        name="Leak Date Updated At",
        icon="mdi:calendar-sync",
        device_class=None,
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


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the LK system cubic sensor."""
    coordinator: LKSystemCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[AbstractLkCubicSensor] = []
    Lk_data: LkStructureResp = coordinator.data

    _LOGGER.debug(
        "Setting up LK Cubic sensors for %s",
        Lk_data["cubic_machine_info"]["zone"]["zoneName"],
    )
    for key, description in LK_CUBICSECURE_SENSORS.items():
        if key == "volumetotal":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "volumetotalday":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "tempWaterAverage":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "tempWaterMin":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "tempWaterMax":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "waterPressure":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "ambientTemp":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "lastStatus":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "cacheUpdated":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "leak.leakState":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "leak.meanFlow":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "leak.dateStartedAt":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "leak.dateUpdatedAt":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "leak.acknowledged":
            entities.append(LKCubicSensor(coordinator, description))

    for key, description in LK_CUBICSECURE_CONFIG_SENSORS.items():
        if key == "valveState":
            entities.append(LKCubicSensor(coordinator, description, data_source="configuration"))
        if key == "firmwareVersion":
            entities.append(LKCubicSensor(coordinator, description, data_source="configuration"))
        if key == "hardwareVersion":
            entities.append(LKCubicSensor(coordinator, description, data_source="configuration"))
    async_add_entities(entities, True)


class AbstractLkCubicSensor(CoordinatorEntity[LKSystemCoordinator], SensorEntity):
    """Abstract class for an LK Cubic secure sensor."""

    _attr_attribution = ATTRIBUTION
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: LKSystemCoordinator,
        description: SensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
        _LOGGER.debug("Creating %s sensor", description.name)
        super().__init__(coordinator)
        self._coordinator = coordinator
        self._device_model = CUBIC_SECURE_MODEL
        self._device_name = (
            f"Cubic Secure {coordinator.data['cubic_machine_info']['zone']['zoneName']}"
        )
        self._id = coordinator.data["cubic_machine_info"]["identity"]
        self.entity_description = description
        self.native_unit_of_measurement = description.native_unit_of_measurement
        self._attr_unique_id = f"LkUid_{description.key}_{coordinator.data['cubic_machine_info']['identity']}"
        self._attr_extra_state_attributes = {}

    @property
    def device_info(self) -> DeviceInfo:
        """Return the device_info of the device."""
        device_info = DeviceInfo(
            identifiers={(DOMAIN, self._id)},
            manufacturer=MANUFACTURER,
            model=self._device_model,
            name=self._device_name,
            serial_number=self._id,
        )
        return device_info


class LKCubicSensor(AbstractLkCubicSensor):
    """Representation of a LK Cubic sensor."""

    def __init__(
        self,
        coordinator: LKSystemCoordinator,
        description: SensorEntityDescription,
        data_source: str = "measurement",
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator=coordinator, description=description)
        self._data_source = data_source
        self._data_key = description.key
        self._attr_unique_id = f"LkUid_{description.key}_{coordinator.data['cubic_machine_info']['identity']}"
        # self.native_unit_of_measurement = description.native_unit_of_measurement
        self._attr_extra_state_attributes = {}

        if "update_time" in self._coordinator.data:
            self._attr_extra_state_attributes.update(
                {C_UPDATE_TIME: self._coordinator.data["update_time"]}
            )
        if "next_update_time" in self._coordinator.data:
            self._attr_extra_state_attributes.update(
                {C_NEXT_UPDATE_TIME: self._coordinator.data["next_update_time"]}
            )
        self._attr_available = False

    async def async_update(self) -> None:
        """Get the latest data and updates the states."""
        self._attr_available = True

    @callback
    def _handle_coordinator_update(self) -> None:
        """Get the latest data and updates the states."""
        if "update_time" in self._coordinator.data:
            self._attr_extra_state_attributes.update(
                {C_UPDATE_TIME: self._coordinator.data["update_time"]}
            )
        if "next_update_time" in self._coordinator.data:
            self._attr_extra_state_attributes.update(
                {C_NEXT_UPDATE_TIME: self._coordinator.data["next_update_time"]}
            )
        super()._handle_coordinator_update()

    @property
    def native_value(self) -> str | None:
        """Get the latest state value."""
        if self._data_source == "configuration":
            if self._data_key in self._coordinator.data["cubic_configuration"]:
                return self._coordinator.data["cubic_configuration"][self._data_key]
            elif '.' in self._data_key:
                keys = self._data_key.split('.')
                value = self._coordinator.data["cubic_configuration"]
                for key in keys:
                    value = value.get(key, None)
                    if value is None:
                        return None
                return value
            return None
        elif self._data_source == "measurement":
            _LOGGER.info("Getting measurement for key: %s", self._data_key)
            _LOGGER.info(self._coordinator.data["cubic_last_measurement"])
            if self._data_key in self._coordinator.data["cubic_last_measurement"]:
                return self._coordinator.data["cubic_last_measurement"][self._data_key]
            elif '.' in self._data_key:
                keys = self._data_key.split('.')
                value = self._coordinator.data["cubic_last_measurement"]
                for key in keys:
                    value = value.get(key, None)
                    if value is None:
                        return None
                return value

        return None
