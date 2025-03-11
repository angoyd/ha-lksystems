"""Support for LK Systems sensors."""

from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfEnergy
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import LKSystemCoordinator, LkStructureResp
from .const import (
    ATTRIBUTION,
    DOMAIN,
    MANUFACTURER,
    CUBIC_SECURE_MODEL,
    C_NEXT_UPDATE_TIME,
    C_UPDATE_TIME,
)

DEFAULT_SCAN_INTERVAL = timedelta(seconds=30)

_LOGGER = logging.getLogger(__name__)

LK_CUBICSECURE_SENSORS: dict[str, SensorEntityDescription] = {
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


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up the LK system cubic sensor."""
    coordinator: LKSystemCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[AbstractLkCubicSensorSensor] = []
    Lk_data: LkStructureResp = coordinator.data

    _LOGGER.debug(
        "Setting up LK Cubic sensors for %s",
        Lk_data["cubic_machine_info"]["zone"]["zoneName"],
    )
    for key, description in LK_CUBICSECURE_SENSORS.items():
        if key == "volumetotal":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "tempWaterAverage":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "tempWaterMin":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "tempWaterMax":
            entities.append(LKCubicSensor(coordinator, description))
        if key == "waterPressure":
            entities.append(LKCubicSensor(coordinator, description))

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
            f'Cubic Secure {coordinator.data["cubic_machine_info"]["zone"]["zoneName"]}'
        )
        self._id = coordinator.data["cubic_machine_info"]["identity"]
        self.entity_description = description
        self.native_unit_of_measurement = description.native_unit_of_measurement
        self._attr_unique_id = f'LkUid_{description.key}_{coordinator.data["cubic_machine_info"]["identity"]}'
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
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator=coordinator, description=description)
        self._data_key = description.key
        self._attr_unique_id = f'LkUid_{description.key}_{coordinator.data["cubic_machine_info"]["identity"]}'
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
        if self._data_key in self._coordinator.data["cubic_last_messurement"]:
            return self._coordinator.data["cubic_last_messurement"][self._data_key]

        return None
