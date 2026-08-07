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

## Installation

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

## Contributing

Contributions are welcome, whether that's a bug fix, a new sensor/entity, or tests for existing code.

### Setting up a dev environment

1. Fork the repo and clone your fork.
2. Install the test dependencies: `pip install -r requirements_test.txt`

### Running the tests

```bash
pytest
```

The test suite covers `custom_components/lksystems/pylksystems` (the LK Systems API client) and mocks all HTTP calls with [aioresponses](https://github.com/pnuckowski/aioresponses), so it runs without a real LK Systems account and without Home Assistant installed.

Note: `sensor.py`, `climate.py`, and `config_flow.py` aren't covered yet — testing those needs Home Assistant's own test harness (`pytest-homeassistant-custom-component`), which hasn't been wired up. Contributions adding that setup are very welcome.

### Deploying to a test Home Assistant instance

`deploy.sh` syncs your local `custom_components/lksystems/` straight into a running Home Assistant instance over SSH, for testing changes against a real account before opening a PR.

```bash
./deploy.sh <user> <host>
# e.g. ./deploy.sh homeassistant homeassistant.local
```

Requirements on the target instance: SSH access (e.g. the [Terminal & SSH add-on](https://github.com/home-assistant/addons/tree/master/ssh) on HAOS) reachable with `ssh <user>@<host>`, and a `/config` directory. The script creates `/config/custom_components/lksystems/` if needed and `rsync`s the integration's files there.

After syncing, reload the integration (**Settings → Devices & Services → LK Systems → ⋮ → Reload**), or restart HA on a first install.

### Using the Home Assistant MCP server for live testing

If your test instance has the built-in [**Model Context Protocol Server**](https://www.home-assistant.io/integrations/mcp_server/) integration enabled, an AI coding assistant (like Claude Code) can query live entity states and call services directly against it — useful for verifying a change actually behaves correctly in HA, not just that the unit tests pass.

To set it up:

1. In HA, add the **Model Context Protocol Server** integration and create a long-lived access token for it (**Settings → People → your profile → Security → Long-lived access tokens**).
2. Install [`mcp-proxy`](https://github.com/sparfenyuk/mcp-proxy) locally (e.g. `pip install --user mcp-proxy`), which bridges your editor/tool's MCP client to HA's HTTP-based MCP endpoint (`https://<host>:8123/api/mcp`). At time of writing, `mcp-proxy` needs `mcp<2` (`pip install --user "mcp==1.29.0"`) — the just-released `mcp` 2.0.0 changed internals in a way `mcp-proxy` 0.12.0 doesn't support yet.
3. Point your tool's MCP config at it, e.g. for Claude Code, a project-local `.mcp.json`. The token goes in as an `Authorization: Bearer` header via `-H`, not an environment variable:

   ```json
   {
     "mcpServers": {
       "Home Assistant": {
         "command": "mcp-proxy",
         "args": [
           "--transport=streamablehttp",
           "--stateless",
           "-H",
           "Authorization",
           "Bearer <your-long-lived-token>",
           "https://<your-host>:8123/api/mcp"
         ]
       }
     }
   }
   ```

Keep this file out of version control (it's gitignored here) since it points at your personal instance and carries a live token.

### Submitting a change

1. Create a branch off `main` in your fork.
2. If you're changing behavior in `pylksystems`, please add or update a test alongside the change — see `tests/test_pylksystems.py` for the existing pattern.
3. Open a pull request against `main` describing what changed and why.

CI runs the test suite automatically on every pull request.

### API documentation

The integration uses the API exposed by LK System. [API documentation](https://lk-home-assistant-prod.developer.azure-api.net/)

