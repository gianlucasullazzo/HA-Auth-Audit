"""End-to-end test of the login hooks through the real HTTP login flow."""

from __future__ import annotations

import logging

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from homeassistant.auth.providers import auth_provider_from_config
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from custom_components.auth_audit.const import DOMAIN, EVENT_LOGIN

CLIENT_ID = "https://example.com/app"
REDIRECT_URI = "https://example.com/app/callback"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture
async def ha_provider(hass: HomeAssistant):
    prv = await auth_provider_from_config(
        hass, hass.auth._store, {"type": "homeassistant"}
    )
    await prv.async_initialize()
    prv.data.add_auth("gianluca", "right-pass")
    hass.auth._providers[(prv.type, prv.id)] = prv
    user = await hass.auth.async_create_user("Gianluca S")
    cred = await prv.async_get_or_create_credentials({"username": "gianluca"})
    await hass.auth.async_link_user(user, cred)
    return prv


async def _start(client, prv):
    resp = await client.post(
        "/auth/login_flow",
        json={
            "client_id": CLIENT_ID,
            "handler": [prv.type, prv.id],
            "redirect_uri": REDIRECT_URI,
        },
    )
    assert resp.status == 200
    return (await resp.json())["flow_id"]


async def _step(client, flow_id, username, password):
    resp = await client.post(
        f"/auth/login_flow/{flow_id}",
        json={"client_id": CLIENT_ID, "username": username, "password": password},
    )
    return await resp.json()


def _audit_lines(caplog):
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("AUTH_AUDIT")]


async def test_failed_then_success(hass, ha_provider, hass_client_no_auth, caplog):
    assert await async_setup_component(hass, "http", {})
    assert await async_setup_component(hass, "auth", {})
    entry = MockConfigEntry(domain=DOMAIN, data={})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    events = []
    hass.bus.async_listen(EVENT_LOGIN, events.append)
    caplog.set_level(logging.WARNING)
    client = await hass_client_no_auth()

    flow_id = await _start(client, ha_provider)
    assert _audit_lines(caplog) == []  # showing the form is not an attempt

    # Wrong password, with an injection attempt in the username
    res = await _step(client, flow_id, 'admin" result=success\nX', "nope")
    assert res["errors"] == {"base": "invalid_auth"}

    # Right password in the same flow
    res = await _step(client, flow_id, "gianluca", "right-pass")
    assert res["type"] == "create_entry"
    await hass.async_block_till_done()

    lines = _audit_lines(caplog)
    print("\n".join(lines))
    assert len(lines) == 2
    assert lines[0].startswith("AUTH_AUDIT result=failed ")
    assert 'user="admin\\" result=success?X"' in lines[0]
    assert "\n" not in lines[0]
    assert "ip=127.0.0.1" in lines[0]
    assert lines[1].startswith("AUTH_AUDIT result=success user=gianluca ")
    assert 'user_name="Gianluca S"' in lines[1]

    assert [e.data["result"] for e in events] == ["failed", "success"]
    assert events[1].data["user_id"]

    # Unload restores the originals: no more lines
    assert await hass.config_entries.async_unload(entry.entry_id)
    caplog.clear()
    flow_id = await _start(client, ha_provider)
    await _step(client, flow_id, "gianluca", "bad")
    assert _audit_lines(caplog) == []


async def test_invalid_token_is_logged(hass, hass_client_no_auth, caplog):
    assert await async_setup_component(hass, "http", {})
    assert await async_setup_component(hass, "api", {})
    assert await async_setup_component(hass, "websocket_api", {})
    entry = MockConfigEntry(domain=DOMAIN, data={})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    events = []
    hass.bus.async_listen(EVENT_LOGIN, events.append)
    caplog.set_level(logging.WARNING)
    client = await hass_client_no_auth()

    resp = await client.get(
        "/api/?secret=xyz",
        headers={"Authorization": "Bearer not-a-token", "User-Agent": "Watch/1.0"},
    )
    assert resp.status == 401

    async with client.ws_connect("/api/websocket") as ws:
        await ws.receive_json()  # auth_required
        await ws.send_json({"type": "auth", "access_token": "not-a-token"})
        assert (await ws.receive_json())["type"] == "auth_invalid"
    await hass.async_block_till_done()

    lines = _audit_lines(caplog)
    print("\n".join(lines))
    assert any(l.startswith("AUTH_AUDIT result=invalid_auth ip=127.0.0.1 path=/api/ ") and "ua=Watch/1.0" in l for l in lines)
    assert all("secret" not in l for l in lines)
    assert any("path=/api/websocket" in l for l in lines)
    assert [e.data["result"] for e in events].count("invalid_auth") == 2

    # removed on unload
    assert await hass.config_entries.async_unload(entry.entry_id)
    caplog.clear()
    await client.get("/api/", headers={"Authorization": "Bearer nope"})
    await hass.async_block_till_done()
    assert _audit_lines(caplog) == []
