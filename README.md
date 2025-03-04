# ha-lksystems
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge)](https://github.com/custom-components/hacs) 

## Summary
This integration uses cloud polling from the API provied by LK Systems.

As of now the support is limited to the WaterMeter [Cubic Secure](https://www.lksystems.se/sv/produkter/teknisk-armatur/vattenfelsutrustning/vattenfelsbrytare/lk-cubicsecure-77792594) but support for other LK components as LK Arc will follow.

# Installation
### HACS installation
[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=angoyd&repository=ha-lksystems&category=integration)


### Git installation
1. Make sure you have git installed on your machine.
2. Navigate to you home assistant configuration folder.
3. Create a `custom_components` folder of it does not exist, navigate down into it after creation.
4. Execute the following command: `git clone https://github.com/faanskit/ha-checkwatt.git checkwatt`
5. Restart Home-Assistant.

## Enable the integration
Go to Settings / Devices & Services / Integrations. Click **+ ADD INTEGRATION**
Follow the instructions
