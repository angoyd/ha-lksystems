"""Climate platform for LK Systems integration."""
from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Optional

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityDescription,
    ClimateEntityFeature,
    HVACAction,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import LKSystemCoordinator
from .const import DOMAIN, INTEGRATION_NAME

_LOGGER = logging.getLogger(__name__)

@dataclass
class LKClimateEntityDescription(ClimateEntityDescription):
    """Description for LK Systems climate entities."""


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up LK Systems climate based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    
    entities = []
    processed_devices = set()  # Track processed devices to avoid duplicates
    
    # Process Arc devices from main device list
    if coordinator.data and "devices" in coordinator.data:
        for device in coordinator.data["devices"]:
            if not device.get("deviceTitle"):
                continue
                
            device_title = device["deviceTitle"]
            device_mac = device.get("mac")
            
            # Check if this is a thermostat device (arc-sense with arc-tune role)
            if (device_title.get("deviceGroup") == "arc" and 
                device_title.get("deviceType") == "arc-sense" and 
                device_title.get("deviceRole") == "arc-tune" and
                device_mac and device_mac not in processed_devices):
                
                processed_devices.add(device_mac)
                
                # Only add if we have measurement data
                if "measurement" in device and device["measurement"].get("desiredTemperature") is not None:
                    entities.append(
                        LKThermostat(
                            coordinator=coordinator,
                            device=device,
                        )
                    )
    
    # Also check hub_data for devices
    if coordinator.data.get("hub_data"):
        for hub_id, hub_data in coordinator.data["hub_data"].items():
            if isinstance(hub_data, dict) and "devices" in hub_data:
                for device in hub_data["devices"]:
                    device_mac = device.get("mac")
                    if not device_mac or device_mac in processed_devices:
                        continue
                        
                    device_title = device.get("deviceTitle", {})
                    
                    # Check if this is a thermostat device
                    if (device_title.get("deviceGroup") == "arc" and 
                        device_title.get("deviceType") == "arc-sense" and 
                        device_title.get("deviceRole") == "arc-tune"):
                        
                        processed_devices.add(device_mac)
                        
                        # Only add if we have measurement data
                        if "measurement" in device and device["measurement"].get("desiredTemperature") is not None:
                            entities.append(
                                LKThermostat(
                                    coordinator=coordinator,
                                    device=device,
                                )
                            )
    
    if entities:
        async_add_entities(entities)
        _LOGGER.debug(f"Added {len(entities)} LK Systems climate entities")


class LKThermostat(CoordinatorEntity, ClimateEntity):
    """LK Systems thermostat climate entity."""

    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
    _attr_hvac_modes = [HVACMode.HEAT]
    _attr_min_temp = 5.0
    _attr_max_temp = 30.0
    _attr_target_temperature_step = 0.5

    def __init__(
        self,
        coordinator: LKSystemCoordinator,
        device: dict,
    ) -> None:
        """Initialize the thermostat."""
        super().__init__(coordinator)
        
        self._device = device
        
        # Get device info
        device_title = device.get("deviceTitle", {})
        device_mac = device.get("mac")
        zone_name = device_title.get("zone", {}).get("zoneName", "Unknown Zone")
        device_type = device_title.get("deviceType", "unknown")
        device_identity = device_title.get("identity") or device_mac
        
        # Get parent identity (hub/gateway ID) for via_device relationship
        parent_identity = device_title.get("parentIdentity")
        
        # Store the identity for reliable device lookup
        self._device_identity = device_identity
        
        # Create unique ID
        self._attr_unique_id = f"{DOMAIN}_{device_identity}_thermostat"
        
        # Set name
        self._attr_name = f"LK {zone_name} Thermostat"
        
        # Set up device info
        device_info = {
            "identifiers": {(DOMAIN, device_identity)},
            "name": self._attr_name,
            "manufacturer": "LK Systems",
            "model": device_type,
            "sw_version": None,
        }
        
        # Add via_device connection to parent hub if available
        if parent_identity:
            device_info["via_device"] = (DOMAIN, parent_identity)
            _LOGGER.debug("Thermostat %s connected via hub %s", device_identity, parent_identity)
        else:
            _LOGGER.debug("No parent identity found for thermostat %s, will appear as standalone device", 
                         device_identity)
        
        self._attr_device_info = DeviceInfo(**device_info)
        self._attr_hvac_mode = HVACMode.HEAT
    
    @property
    def available(self) -> bool:
        """Return if entity is available."""
        if not self.coordinator.last_update_success:
            return False
            
        # Look for the device in all data sources
        for device in self.coordinator.data.get("devices", []):
            device_title = device.get("deviceTitle", {})
            if (device.get("mac") == self._device.get("mac") or 
                device_title.get("identity") == self._device_identity):
                return True
                
        # Check hub_data
        if "hub_data" in self.coordinator.data:
            for hub_id, hub_data in self.coordinator.data["hub_data"].items():
                if isinstance(hub_data, dict) and "devices" in hub_data:
                    for device in hub_data["devices"]:
                        device_title = device.get("deviceTitle", {})
                        if (device.get("mac") == self._device.get("mac") or 
                            device_title.get("identity") == self._device_identity):
                            return True
        
        return False
    
    @property
    def current_temperature(self) -> Optional[float]:
        """Return the current temperature."""
        # Find the most recent temperature data
        for device in self.coordinator.data.get("devices", []):
            device_title = device.get("deviceTitle", {})
            if (device.get("mac") == self._device.get("mac") or 
                device_title.get("identity") == self._device_identity):
                if "measurement" in device:
                    temp_value = device["measurement"].get("currentTemperature")
                    if temp_value is not None:
                        return float(temp_value) / 10
        
        # Check hub_data
        if "hub_data" in self.coordinator.data:
            for hub_id, hub_data in self.coordinator.data["hub_data"].items():
                if isinstance(hub_data, dict) and "devices" in hub_data:
                    for device in hub_data["devices"]:
                        device_title = device.get("deviceTitle", {})
                        if (device.get("mac") == self._device.get("mac") or 
                            device_title.get("identity") == self._device_identity):
                            if "measurement" in device:
                                temp_value = device["measurement"].get("currentTemperature")
                                if temp_value is not None:
                                    return float(temp_value) / 10
        
        return None
    
    @property
    def target_temperature(self) -> Optional[float]:
        """Return the target temperature."""
        # Find the most recent temperature data
        for device in self.coordinator.data.get("devices", []):
            device_title = device.get("deviceTitle", {})
            if (device.get("mac") == self._device.get("mac") or 
                device_title.get("identity") == self._device_identity):
                if "measurement" in device:
                    temp_value = device["measurement"].get("desiredTemperature")
                    if temp_value is not None:
                        return float(temp_value) / 10
        
        # Check hub_data
        if "hub_data" in self.coordinator.data:
            for hub_id, hub_data in self.coordinator.data["hub_data"].items():
                if isinstance(hub_data, dict) and "devices" in hub_data:
                    for device in hub_data["devices"]:
                        device_title = device.get("deviceTitle", {})
                        if (device.get("mac") == self._device.get("mac") or 
                            device_title.get("identity") == self._device_identity):
                            if "measurement" in device:
                                temp_value = device["measurement"].get("desiredTemperature")
                                if temp_value is not None:
                                    return float(temp_value) / 10
        
        return None
    
    @property
    def hvac_action(self) -> Optional[HVACAction]:
        """Return the current HVAC action."""
        # We would need more data to determine if the system is actively heating
        # For now, we just return HEATING if the current temperature is below the target
        current_temp = self.current_temperature
        target_temp = self.target_temperature
        
        if current_temp is not None and target_temp is not None:
            if current_temp < target_temp:
                return HVACAction.HEATING
            else:
                return HVACAction.IDLE
                
        return None
    
    async def async_set_temperature(self, **kwargs) -> None:
        """Set new target temperature."""
        _LOGGER.debug("Setting temperature for %s: %s", self._device_identity, kwargs)
        temperature = kwargs.get(ATTR_TEMPERATURE)
        if temperature is None:
            return
            
        # Make sure to await the coroutine
        await self._set_temperature(temperature)
        
    async def _set_temperature(self, temperature: float) -> None:
        """Set target temperature."""
        _LOGGER.debug("Setting temperature for %s to %s°C", self._device_identity, temperature)
        
        # Convert to the format expected by the API (multiply by 10)
        api_temp = int(temperature * 10)
        
        try:
            # Use the coordinator's method instead of accessing api attribute
            result = await self.coordinator.set_thermostat_temperature(
                self._device_identity, 
                api_temp
            )
            
            if not result:
                _LOGGER.error("Failed to set temperature for %s", self._device_identity)
            
        except Exception as ex:
            _LOGGER.error("Failed to set temperature: %s", ex)
    
    async def async_set_preset_mode(self, preset_mode: str) -> None:
        """Set preset mode."""
        _LOGGER.debug("Setting preset mode for %s to %s", self._device_identity, preset_mode)
        
        # If this calls _set_temperature, make sure to await it
        if preset_mode == "comfort":
            await self._set_temperature(22)  # Example comfort temperature
        elif preset_mode == "eco":
            await self._set_temperature(18)  # Example eco temperature
    
    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle data update."""
        self.async_write_ha_state()
