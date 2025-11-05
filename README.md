# Custom Home Assistant integration for LK Systems
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge)](https://github.com/custom-components/hacs) 

## Summary
This integration uses cloud polling from the API provided by LK Systems.

The integration supports:
- Water Meter [Cubic Secure](https://www.lksystems.se/sv/produkter/teknisk-armatur/vattenfelsutrustning/vattenfelsbrytare/lk-cubicsecure-77792594)
- LK Arc thermostats [Arc Thermostats](https://www.lksystems.se/sv/produktsystem/golvvarme/lk-rumsreglering-arc/)

## Features

### LK Arc Thermostats
- Temperature control with 0.5°C precision (range: 5°C - 30°C)
- Real-time temperature monitoring
- Automatic heat control (HVAC mode: Heat)
- Displays current room temperature and target temperature
- Heat status indication (Heating/Idle based on current vs target temperature)
- Organized by zones for easy management
- Integrated with Home Assistant's climate controls

**Note**: The integration is in active development, as of now the support is in a very early stage use at own risk, breaking changes will most probably follow.. While core functionality is stable, additional features may be added in future updates.


# Installation
### HACS installation
[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=angoyd&repository=ha-lksystems&category=integration)


### Git installation
1. Make sure you have git installed on your machine.
2. Navigate to you home assistant configuration folder.
3. Create a `custom_components` folder of it does not exist, navigate down into it after creation.
4. Execute the following command: `git clone https://github.com/angoyd/ha-lksystems.git lksystems`
5. Restart Home-Assistant.

## Enable the integration
Go to Settings / Devices & Services / Integrations. Click **+ ADD INTEGRATION**
Follow the instructions
