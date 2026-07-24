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


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up LK Systems sensor based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    entities = []
    processed_devices = set()  # Track processed devices to avoid duplicates
    created_entity_ids = set()  # Track entity IDs to avoid duplicates

    # Log all available devices from API response
    _LOGGER.debug("Processing devices from API response")

    # First identify and organize by hubs
    hub_map = {}  # Maps hub identities to hub information
    device_to_hub_map = {}  # Maps device identities to their parent hub identity

    # Step 1: Find all hubs
    if coordinator.data and "devices" in coordinator.data:
        for device in coordinator.data["devices"]:
            if not device.get("deviceTitle"):
                continue

            device_title = device.get("deviceTitle", {})

            if device_title.get("deviceType") == "cubicsecure":
                _LOGGER.debug(
                    "Setting up LK Cubic sensors for %s",
                    coordinator.data["cubic_machine_info"]["zone"]["zoneName"],
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
                        entities.append(
                            LKCubicSensor(
                                coordinator, description, data_source="configuration"
                            )
                        )
                    if key == "firmwareVersion":
                        entities.append(
                            LKCubicSensor(
                                coordinator, description, data_source="configuration"
                            )
                        )
                    if key == "hardwareVersion":
                        entities.append(
                            LKCubicSensor(
                                coordinator, description, data_source="configuration"
                            )
                        )

                async_add_entities(entities, True)

            # Collect all hubs
            if device_title.get("deviceType") == "arc-hub":
                device_id = device.get("mac", "unknown")
                hub_identity = device_title.get("identity") or device_id

                hub_map[hub_identity] = {
                    "device": device,
                    "name": device_title.get("name", "LK ARC Hub"),
                    "children": [],
                    "parent": device_title.get("parentIdentity"),
                }
                _LOGGER.debug("Found hub device: %s", hub_identity)

    # Also collect hubs from hub_data
    if coordinator.data.get("hub_data"):
        for hub_id, hub_data in coordinator.data["hub_data"].items():
            if hub_id in hub_map:
                continue  # Already found this hub

            # Create hub entry from hub_id if it's in a MAC address format
            if isinstance(hub_id, str) and ":" in hub_id:
                # Try to find the hub in devices first for more details
                hub_found = False
                for device in coordinator.data.get("devices", []):
                    if (
                        device.get("mac") == hub_id
                        or device.get("deviceTitle", {}).get("identity") == hub_id
                    ):
                        device_title = device.get("deviceTitle", {})
                        hub_map[hub_id] = {
                            "device": device,
                            "name": device_title.get(
                                "name", f"LK ARC Hub {hub_id[-5:]}"
                            ),
                            "children": [],
                            "parent": device_title.get("parentIdentity"),
                        }
                        hub_found = True
                        break

                # If not found in devices, create a minimal entry
                if not hub_found:
                    hub_map[hub_id] = {
                        "device": {
                            "mac": hub_id,
                            "deviceTitle": {
                                "identity": hub_id,
                                "deviceType": "arc-hub",
                            },
                        },
                        "name": f"LK ARC Hub {hub_id[-5:]}",
                        "children": [],
                        "parent": None,
                    }
                _LOGGER.debug("Found hub from hub_data: %s", hub_id)

    # Step 2: Associate child devices with their parent hubs
    if coordinator.data and "devices" in coordinator.data:
        for device in coordinator.data["devices"]:
            if not device.get("deviceTitle"):
                continue

            device_title = device.get("deviceTitle", {})

            # Skip hubs, already processed
            if device_title.get("deviceType") == "arc-hub":
                continue

            # Find parent hub for this device
            parent_identity = device_title.get("parentIdentity")
            if parent_identity and parent_identity in hub_map:
                device_id = device.get("mac")
                device_identity = device_title.get("identity") or device_id

                # Add to parent's children list
                hub_map[parent_identity]["children"].append(device_identity)

                # Map device to its parent hub
                device_to_hub_map[device_identity] = parent_identity
                _LOGGER.debug(
                    "Device %s belongs to hub %s", device_identity, parent_identity
                )

    # Also check hub_data for child devices
    if coordinator.data.get("hub_data"):
        for hub_id, hub_data in coordinator.data["hub_data"].items():
            if isinstance(hub_data, dict) and "devices" in hub_data:
                for device in hub_data["devices"]:
                    device_title = device.get("deviceTitle", {})
                    if not device_title:
                        continue

                    # Skip if this is a hub
                    if device_title.get("deviceType") == "arc-hub":
                        continue

                    device_id = device.get("mac")
                    device_identity = device_title.get("identity") or device_id

                    # Determine parent hub - use the current hub_id if no explicit parent
                    parent_identity = device_title.get("parentIdentity") or hub_id

                    if parent_identity in hub_map:
                        # Add to parent's children list if not already there
                        if device_identity not in hub_map[parent_identity]["children"]:
                            hub_map[parent_identity]["children"].append(device_identity)

                        # Map device to its parent hub
                        device_to_hub_map[device_identity] = parent_identity
                        _LOGGER.debug(
                            "Device %s from hub_data belongs to hub %s",
                            device_identity,
                            parent_identity,
                        )

    # Step 3: Create hub entities first
    hub_entities = []
    for hub_identity, hub_info in hub_map.items():
        entity_id = f"{DOMAIN}_{hub_identity}_status"
        if entity_id not in created_entity_ids:
            hub_entity = LKArcHubEntity(
                coordinator,
                hub_info["device"],
                "status",
                "Status",
                "mdi:router-wireless",
                None,
                None,
            )
            hub_entities.append(hub_entity)
            created_entity_ids.add(entity_id)
            _LOGGER.debug(
                "Created hub entity: %s with %d children",
                entity_id,
                len(hub_info["children"]),
            )

    if hub_entities:
        async_add_entities(hub_entities)

    # Step 4: Create sensor entities for child devices, with proper parent references
    sensor_entities = []

    # Process child devices from main device list
    if coordinator.data and "devices" in coordinator.data:
        for device in coordinator.data["devices"]:
            if not device.get("deviceTitle"):
                continue

            device_title = device.get("deviceTitle", {})

            # Skip hubs
            if device_title.get("deviceType") == "arc-hub":
                continue

            # Process sensor data
            if (
                device_title.get("deviceGroup") == "arc"
                and device_title.get("deviceType") == "arc-sense"
            ):
                device_id = device.get("mac")
                device_identity = device_title.get("identity") or device_id

                # Get parent hub for this device
                parent_hub = device_to_hub_map.get(device_identity)

                # Set parent in device data for the entity creation
                if parent_hub and "deviceTitle" in device:
                    device["deviceTitle"]["parentIdentity"] = parent_hub

                # Add temperature entity
                if (
                    "measurement" in device
                    and device["measurement"].get("currentTemperature") is not None
                ):
                    entity_id = f"{DOMAIN}_{device_identity}_temperature"
                    if entity_id not in created_entity_ids:
                        sensor_entities.append(
                            LKArcSensorEntity(
                                coordinator,
                                device,
                                "temperature",
                                "Temperature",
                                "mdi:thermometer",
                                SensorDeviceClass.TEMPERATURE,
                                SensorStateClass.MEASUREMENT,
                                UnitOfTemperature.CELSIUS,
                            )
                        )
                        created_entity_ids.add(entity_id)

                # Add humidity entity
                if (
                    "measurement" in device
                    and device["measurement"].get("currentHumidity") is not None
                ):
                    entity_id = f"{DOMAIN}_{device_identity}_humidity"
                    if entity_id not in created_entity_ids:
                        sensor_entities.append(
                            LKArcSensorEntity(
                                coordinator,
                                device,
                                "humidity",
                                "Humidity",
                                "mdi:water-percent",
                                SensorDeviceClass.HUMIDITY,
                                SensorStateClass.MEASUREMENT,
                                PERCENTAGE,
                            )
                        )
                        created_entity_ids.add(entity_id)

                # Add battery entity
                if (
                    "measurement" in device
                    and device["measurement"].get("currentBattery") is not None
                ):
                    entity_id = f"{DOMAIN}_{device_identity}_battery"
                    if entity_id not in created_entity_ids:
                        sensor_entities.append(
                            LKArcSensorEntity(
                                coordinator,
                                device,
                                "battery",
                                "Battery",
                                "mdi:battery",
                                SensorDeviceClass.BATTERY,
                                SensorStateClass.MEASUREMENT,
                                PERCENTAGE,
                            )
                        )
                        created_entity_ids.add(entity_id)

                # Add RSSI entity
                if (
                    "measurement" in device
                    and device["measurement"].get("currentRssi") is not None
                ):
                    entity_id = f"{DOMAIN}_{device_identity}_rssi"
                    if entity_id not in created_entity_ids:
                        sensor_entities.append(
                            LKArcSensorEntity(
                                coordinator,
                                device,
                                "rssi",
                                "RSSI",
                                "mdi:wifi",
                                SensorDeviceClass.SIGNAL_STRENGTH,
                                SensorStateClass.MEASUREMENT,
                                SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
                            )
                        )
                        created_entity_ids.add(entity_id)

    # Also process from hub_data which often has more detailed information
    if sensor_entities:
        async_add_entities(sensor_entities)
        _LOGGER.debug("Added %d sensor entities", len(sensor_entities))


class LKArcSensorEntity(CoordinatorEntity, SensorEntity):
    """Representation of an LK Systems sensor entity."""

    def __init__(
        self,
        coordinator: LKSystemCoordinator,
        device: dict,
        entity_key: str,
        name_suffix: str,
        icon: str,
        device_class: Optional[str] = None,
        state_class: Optional[str] = None,
        unit_of_measurement: Optional[str] = None,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)

        self._device = device
        self._entity_key = entity_key
        self._device_class = device_class
        self._attr_icon = icon
        self._attr_state_class = state_class
        self._attr_unit_of_measurement = unit_of_measurement

        # Get device info
        device_title = device.get("deviceTitle", {})

        # Get identity which is more reliable than mac address
        device_id = device.get("mac")
        device_identity = device_title.get("identity") or device_id
        device_type = device_title.get("deviceType", "unknown")

        # Check if this is a thermostat-capable device
        self._is_thermostat = (
            device_title.get("deviceGroup") == "arc"
            and device_title.get("deviceType") == "arc-sense"
            and device_title.get("deviceRole") == "arc-tune"
        )

        # Store identity for reliable device lookup
        self._device_identity = device_identity

        # Get parent identity (hub/gateway) - crucial for proper via_device relationship
        parent_identity = device_title.get("parentIdentity")

        # Set entity unique ID (must be consistent and unique)
        self._attr_unique_id = f"{DOMAIN}_{device_identity}_{entity_key}"

        # Set entity name using friendly name if available
        friendly_name = device_title.get("name")
        if friendly_name:
            self._attr_name = f"{friendly_name} {name_suffix}"
        else:
            room_name = (
                device_title.get("zone", {}).get("zoneName")
                if device_title.get("zone")
                else None
            )
            if room_name:
                self._attr_name = f"LK {room_name} {name_suffix}"
            else:
                self._attr_name = f"LK Sensor {name_suffix}"

        # Get zone info for naming
        zone_name = None
        if "zone" in device_title and device_title["zone"].get("zoneName"):
            zone_name = device_title["zone"].get("zoneName")

        # Set up device info with proper connection to parent if available
        device_info = {
            "identifiers": {(DOMAIN, device_identity)},
            "name": self._attr_name.replace(f" {name_suffix}", ""),
            "manufacturer": "LK Systems",
            "model": device_type,
        }

        # Always set via_device to parent hub if available
        if parent_identity:
            device_info["via_device"] = (DOMAIN, parent_identity)
            _LOGGER.debug(
                "Device %s connected via %s", device_identity, parent_identity
            )

        self._attr_device_info = DeviceInfo(**device_info)

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        if not self.coordinator.last_update_success:
            return False

        # Check if device still exists in coordinator data using both mac and identity
        for device in self.coordinator.data.get("devices", []):
            device_title = device.get("deviceTitle", {})
            if (
                device.get("mac") == self._device.get("mac")
                or device_title.get("identity") == self._device_identity
            ):
                return True

        # Also check hub_data
        if "hub_data" in self.coordinator.data:
            for hub_id, hub_data in self.coordinator.data["hub_data"].items():
                if isinstance(hub_data, dict) and "devices" in hub_data:
                    for device in hub_data["devices"]:
                        device_title = device.get("deviceTitle", {})
                        if (
                            device.get("mac") == self._device.get("mac")
                            or device_title.get("identity") == self._device_identity
                        ):
                            return True

        return False

    @property
    def native_value(self) -> Any:
        """Return the value of the sensor."""
        # First check device_details for the most up-to-date information
        if "device_details" in self.coordinator.data:
            device_details = self.coordinator.data["device_details"].get(
                self._device_identity
            )
            if device_details and "measurement" in device_details:
                measurement = device_details["measurement"]
                if self._entity_key == "temperature":
                    temp_value = measurement.get("currentTemperature")
                    if temp_value is not None:
                        _LOGGER.debug(
                            "Using temperature from direct measurement: %s for %s",
                            temp_value,
                            self._device_identity,
                        )
                        return float(temp_value) / 10
                elif self._entity_key == "humidity":
                    humid_value = measurement.get("currentHumidity")
                    if humid_value is not None:
                        _LOGGER.debug(
                            "Using humidity from direct measurement: %s for %s",
                            humid_value,
                            self._device_identity,
                        )
                        return float(humid_value) / 10
                elif self._entity_key == "battery":
                    battery = measurement.get("currentBattery")
                    if battery is not None:
                        _LOGGER.debug(
                            "Using battery from direct measurement: %s for %s",
                            battery,
                            self._device_identity,
                        )
                        return battery
                elif self._entity_key == "rssi":
                    rssi = measurement.get("currentRssi")
                    if rssi is not None:
                        _LOGGER.debug(
                            "Using RSSI from direct measurement: %s for %s",
                            rssi,
                            self._device_identity,
                        )
                        return rssi
                elif self._entity_key == "desired_temperature":
                    temp_value = measurement.get("desiredTemperature")
                    if temp_value is not None:
                        _LOGGER.debug(
                            "Using desired temp from direct measurement: %s for %s",
                            temp_value,
                            self._device_identity,
                        )
                        return float(temp_value) / 10

        # Then check the devices list
        for device in self.coordinator.data.get("devices", []):
            device_title = device.get("deviceTitle", {})
            if (
                device.get("mac") == self._device.get("mac")
                or device_title.get("identity") == self._device_identity
            ):
                if "measurement" in device:
                    if self._entity_key == "temperature":
                        # Temperature values need to be divided by 10 to get Celsius
                        temp_value = device["measurement"].get("currentTemperature")
                        return (
                            float(temp_value) / 10 if temp_value is not None else None
                        )
                    elif self._entity_key == "humidity":
                        # Humidity values need to be divided by 10 to get percentage
                        humid_value = device["measurement"].get("currentHumidity")
                        return (
                            float(humid_value) / 10 if humid_value is not None else None
                        )
                    elif self._entity_key == "battery":
                        return device["measurement"].get("currentBattery")
                    elif self._entity_key == "rssi":
                        return device["measurement"].get("currentRssi")
                    elif self._entity_key == "desired_temperature":
                        # Desired temperature also needs division by 10
                        temp_value = device["measurement"].get("desiredTemperature")
                        return (
                            float(temp_value) / 10 if temp_value is not None else None
                        )

        # Check hub_data as well for the most up-to-date information
        if "hub_data" in self.coordinator.data:
            for hub_id, hub_data in self.coordinator.data["hub_data"].items():
                if isinstance(hub_data, dict) and "devices" in hub_data:
                    for device in hub_data["devices"]:
                        device_title = device.get("deviceTitle", {})
                        if (
                            device.get("mac") == self._device.get("mac")
                            or device_title.get("identity") == self._device_identity
                        ):
                            if "measurement" in device:
                                if self._entity_key == "temperature":
                                    temp_value = device["measurement"].get(
                                        "currentTemperature"
                                    )
                                    return (
                                        float(temp_value) / 10
                                        if temp_value is not None
                                        else None
                                    )
                                elif self._entity_key == "humidity":
                                    humid_value = device["measurement"].get(
                                        "currentHumidity"
                                    )
                                    return (
                                        float(humid_value) / 10
                                        if humid_value is not None
                                        else None
                                    )
                                elif self._entity_key == "battery":
                                    return device["measurement"].get("currentBattery")
                                elif self._entity_key == "rssi":
                                    return device["measurement"].get("currentRssi")
                                elif self._entity_key == "desired_temperature":
                                    temp_value = device["measurement"].get(
                                        "desiredTemperature"
                                    )
                                    return (
                                        float(temp_value) / 10
                                        if temp_value is not None
                                        else None
                                    )

        return None

    async def async_update(self) -> None:
        """Update the entity by forcing a new measurement."""
        _LOGGER.warning(
            "Force updating entity: %s (%s)", self._attr_name, self._device_identity
        )

        # Request specific update for this device
        if hasattr(self.coordinator, "force_device_update"):
            try:
                await self.coordinator.force_device_update(self._device_identity)
                _LOGGER.warning(
                    "Manual update completed for device: %s", self._device_identity
                )
            except Exception as ex:
                _LOGGER.error("Error during manual device update: %s", ex)

        # Call parent update method
        await super().async_update()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        _LOGGER.info(
            "Handling coordinator update for %s (%s)",
            self._attr_name,
            self._device_identity,
        )

        # Add explicit check for value changes
        old_value = self._attr_native_value
        new_value = self.native_value

        if old_value != new_value:
            _LOGGER.warning(
                "Value changed for %s: %s -> %s", self._attr_name, old_value, new_value
            )

        self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional sensor attributes."""
        attrs = {}

        # Add information about update intervals
        if self.coordinator and hasattr(self.coordinator, "update_interval"):
            attrs["update_interval_minutes"] = (
                self.coordinator.update_interval.total_seconds() / 60
            )

        # Add last update time
        if self.coordinator and hasattr(self.coordinator, "_last_update_time"):
            attrs["last_updated"] = self.coordinator._last_update_time.isoformat()

        # Add next scheduled update time
        if (
            self.coordinator
            and hasattr(self.coordinator, "update_interval")
            and hasattr(self.coordinator, "_last_update_time")
        ):
            next_update = (
                self.coordinator._last_update_time + self.coordinator.update_interval
            )
            attrs["next_update"] = next_update.isoformat()

        # Add refresh button attribute with a timestamp to force UI refresh
        attrs["refresh_timestamp"] = dt_util.now().timestamp()

        return attrs


class LKArcHubEntity(CoordinatorEntity, SensorEntity):
    """Representation of an LK Systems ARC Hub entity."""

    def __init__(
        self,
        coordinator: LKSystemCoordinator,
        device: dict,
        entity_key: str,
        name_suffix: str,
        icon: str,
        device_class: Optional[str] = None,
        state_class: Optional[str] = None,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)

        self._device = device
        self._entity_key = entity_key
        self._device_class = device_class
        self._attr_icon = icon
        self._attr_state_class = state_class

        # Get device info
        device_title = device.get("deviceTitle", {})

        # Get identity which is more reliable than mac address
        device_id = device.get("mac")
        device_identity = device_title.get("identity") or device_id
        device_type = device_title.get("deviceType", "unknown")

        # Store identity for reliable device lookup
        self._device_identity = device_identity

        # Get parent identity if available (for hub hierarchy)
        parent_identity = device_title.get("parentIdentity")

        # Create unique ID using identity if available, otherwise mac
        self._attr_unique_id = f"{DOMAIN}_{device_identity}_{entity_key}"

        # Set name - use device name if available
        friendly_name = device_title.get("name")
        if friendly_name:
            self._attr_name = f"{friendly_name} {name_suffix}"
        else:
            self._attr_name = f"LK ARC Hub {name_suffix}"

        # Set up device info
        device_info = {
            "identifiers": {(DOMAIN, device_identity)},
            "name": self._attr_name.replace(f" {name_suffix}", ""),
            "manufacturer": "LK Systems",
            "model": device_type,
            "sw_version": None,
        }

        # Add via_device connection to parent if parent identity exists
        # This handles the case of hub hierarchies where hubs connect through other hubs
        if parent_identity:
            device_info["via_device"] = (DOMAIN, parent_identity)
            _LOGGER.debug(
                "Hub device %s connected via %s", device_identity, parent_identity
            )

        self._attr_device_info = DeviceInfo(**device_info)

    @property
    def device_class(self) -> Optional[str]:
        """Return the device class."""
        return self._device_class

    @property
    def native_value(self) -> Any:
        """Return the value of the sensor."""
        # First check the device_details dictionary which has the most up-to-date information
        if "device_details" in self.coordinator.data:
            device_details = self.coordinator.data["device_details"].get(
                self._device_identity
            )
            if device_details and "measurement" in device_details:
                if self._entity_key == "status":
                    return device_details["measurement"].get(
                        "connectionState", "Unknown"
                    )

        # Then check the devices list
        for device in self.coordinator.data.get("devices", []):
            # Check both mac and identity for matching
            device_title = device.get("deviceTitle", {})
            if (
                device.get("mac") == self._device.get("mac")
                or device_title.get("identity") == self._device_identity
            ):
                if self._entity_key == "status":
                    # Return connection status if available
                    if "measurement" in device:
                        return device["measurement"].get("connectionState", "Unknown")

        # Finally check hub_data - this often has the most up-to-date thermostat information
        if "hub_data" in self.coordinator.data:
            for hub_id, hub_data in self.coordinator.data["hub_data"].items():
                if isinstance(hub_data, dict) and "devices" in hub_data:
                    for device in hub_data["devices"]:
                        device_title = device.get("deviceTitle", {})
                        if (
                            device.get("mac") == self._device.get("mac")
                            or device_title.get("identity") == self._device_identity
                        ):
                            if self._entity_key == "status":
                                if "measurement" in device:
                                    # Log when we find a matching thermostat device
                                    if device_title.get("deviceRole") == "arc-tune":
                                        _LOGGER.debug(
                                            "Found thermostat device %s in hub %s with state: %s",
                                            self._device_identity,
                                            hub_id,
                                            device["measurement"].get(
                                                "connectionState", "Connected"
                                            ),
                                        )
                                    return device["measurement"].get(
                                        "connectionState", "Connected"
                                    )
                                return "Connected"

        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()


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
    def native_value(self) -> Any | None:
        """Get the latest state value."""
        value = None

        if self._data_source == "configuration":
            if self._data_key in self._coordinator.data["cubic_configuration"]:
                value = self._coordinator.data["cubic_configuration"][self._data_key]
            elif "." in self._data_key:
                keys = self._data_key.split(".")
                value = self._coordinator.data["cubic_configuration"]
                for key in keys:
                    value = value.get(key, None)
                    if value is None:
                        break
        elif self._data_source == "measurement":
            _LOGGER.debug("Getting measurement for key: %s", self._data_key)
            _LOGGER.debug(self._coordinator.data["cubic_last_measurement"])
            if self._data_key in self._coordinator.data["cubic_last_measurement"]:
                value = self._coordinator.data["cubic_last_measurement"][self._data_key]
            elif "." in self._data_key:
                keys = self._data_key.split(".")
                value = self._coordinator.data["cubic_last_measurement"]
                for key in keys:
                    value = value.get(key, None)
                    if value is None:
                        break

        if value is not None and self.device_class == SensorDeviceClass.TIMESTAMP:
            try:
                return dt_util.utc_from_timestamp(float(value))
            except (ValueError, TypeError):
                pass
        
        return value
