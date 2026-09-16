#!/usr/bin/env python3
"""Polls a real Home Assistant instance's log over its WebSocket API and
prints new entries as they appear - for watching a live test (e.g. a
rate-limit check) as it happens rather than digging through
Settings -> System -> Logs afterwards.

Uses the WebSocket API's system_log/list command rather than the REST
API's GET /api/error_log: that REST endpoint is still listed in Home
Assistant's developer docs but has been removed from Core and now
returns a plain 404 - confirmed against a real instance rather than
trusted from the docs (https://community.home-assistant.io/t/what-happened-to-api-error-log/982722
independently confirms the same). The Threaded resolver override below
works around an aiodns/pycares version mismatch in this project's own
test venv (unrelated to Home Assistant itself); harmless to keep even on
setups where the default resolver would have worked fine.

Usage: ./tail_logs.py [pattern]
Requires HA_LONG_LIVED_TOKEN in .env - see .env.example. HA_URL is
optional there too: defaults to https://$HA_SSH_HOST:8123 when not set
explicitly. Defaults pattern to "lksystems".
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
from aiohttp.resolver import ThreadedResolver

POLL_SECONDS = 3


def _load_env(path: Path) -> None:
    """Load KEY=value lines from an .env file into os.environ, without
    overriding any already-set in the real environment."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def _websocket_url() -> str:
    ha_url = os.environ.get("HA_URL")
    if not ha_url:
        ssh_host = os.environ.get("HA_SSH_HOST")
        if not ssh_host:
            print("Set HA_LONG_LIVED_TOKEN in .env, and either HA_URL or "
                  "HA_SSH_HOST - see .env.example")
            sys.exit(1)
        ha_url = f"https://{ssh_host}:8123"
    scheme = "wss" if urlsplit(ha_url).scheme == "https" else "ws"
    netloc = urlsplit(ha_url).netloc
    return f"{scheme}://{netloc}/api/websocket"


async def _authenticated_connection(
    session: aiohttp.ClientSession, url: str, token: str
) -> aiohttp.ClientWebSocketResponse:
    ws = await session.ws_connect(url)
    greeting = await ws.receive_json()
    if greeting.get("type") != "auth_required":
        raise RuntimeError(f"Unexpected greeting from {url}: {greeting}")
    await ws.send_json({"type": "auth", "access_token": token})
    reply = await ws.receive_json()
    if reply.get("type") != "auth_ok":
        raise RuntimeError(f"Authentication failed: {reply}")
    return ws


async def _poll(url: str, token: str, pattern: str) -> None:
    connector = aiohttp.TCPConnector(resolver=ThreadedResolver())
    async with aiohttp.ClientSession(connector=connector) as session:
        ws = await _authenticated_connection(session, url, token)
        seen_timestamps: set[float] = set()
        request_id = 0
        first_poll = True
        while True:
            request_id += 1
            await ws.send_json({"id": request_id, "type": "system_log/list"})
            reply = await ws.receive_json()
            entries = reply.get("result") or []
            # Oldest first, matching how a log file reads top-to-bottom.
            for entry in reversed(entries):
                timestamp = entry.get("timestamp")
                if timestamp in seen_timestamps:
                    continue
                seen_timestamps.add(timestamp)
                if first_poll:
                    continue  # Only show the tail on the first poll, not all history.
                name = entry.get("name", "")
                if pattern.lower() not in name.lower():
                    continue
                for line in entry.get("message", []):
                    print(f"{entry.get('level')} {name}: {line}")
            first_poll = False
            await asyncio.sleep(POLL_SECONDS)


def main() -> None:
    sys.stdout.reconfigure(line_buffering=True)
    _load_env(Path(__file__).resolve().parent / ".env")
    pattern = sys.argv[1] if len(sys.argv) > 1 else "lksystems"
    token = os.environ.get("HA_LONG_LIVED_TOKEN")
    if not token:
        print("Set HA_LONG_LIVED_TOKEN in .env - see .env.example")
        sys.exit(1)
    url = _websocket_url()
    print(f"==> Polling {url} every {POLL_SECONDS}s, filtered to '{pattern}' "
          "(Ctrl-C to stop)...")
    try:
        asyncio.run(_poll(url, token, pattern))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
