import base64
import hashlib
import hmac
import os.path
from typing import Optional, List, Dict, Any

import orjson
from fastapi import FastAPI, HTTPException
from loguru import logger
from tortoise.exceptions import DoesNotExist
from tortoise import timezone

from settings import settings
from models import AgentDevice, Room, ClientDevice
from security import b64


# ===================== Client Device Database Helpers =====================

async def client_device_get(device_id: str) -> Optional[ClientDevice]:
    """Gets client device from DB by device_id"""
    return await ClientDevice.filter(device_id=device_id, is_active=True).first()


async def client_pub_get(device_id: str) -> Optional[bytes]:
    """Gets client's public key from DB"""
    device = await client_device_get(device_id)
    return device.public_key if device else None


async def client_device_create_or_update(
        device_id: str,
        pub_b: bytes,
        platform: Optional[str] = None,
        app_version: Optional[str] = None,
        label: Optional[str] = None,
        client_static_pub: Optional[str] = None
):
    """Creates or updates client device in DB"""
    # Form fingerprint as SHA256:base64
    fingerprint = "SHA256:" + b64(hashlib.sha256(pub_b).digest())

    device = await ClientDevice.filter(device_id=device_id).first()
    if device:
        # Update existing device
        device.public_key = pub_b
        device.fingerprint = fingerprint
        if platform:
            device.platform = platform
        if app_version:
            device.app_version = app_version
        if label:
            device.label = label
        if client_static_pub is not None:
            device.client_static_pub = client_static_pub
        device.is_active = True
        device.revoked_at = None
        await device.save()
    else:
        # Create new device
        await ClientDevice.create(
            device_id=device_id,
            public_key=pub_b,
            fingerprint=fingerprint,
            platform=platform,
            app_version=app_version,
            label=label,
            client_static_pub=client_static_pub,
            is_active=True
        )


async def client_device_update_last_seen(device_id: str):
    """Updates timestamp of device's last activity"""
    await ClientDevice.filter(device_id=device_id).update(last_seen=timezone.now())


# ===================== Push Notification Helpers =====================

async def push_agents_update(app: FastAPI, client_device_id: str):
    """
    Sends client full snapshot of their agents (all that they have access to).
    Push message format: {"type":"agents.update","data":{"agents":[...]}}
    """
    from models import AgentAccess

    try:
        client_ws = app.state.clients_ws.get(client_device_id)
        if not client_ws:
            logger.debug("Push agents update: client not online", client_device_id=client_device_id)
            return  # Client not online - just exit silently

        # Get all agents this client has access to
        accesses = await AgentAccess.filter(client_device_id=client_device_id).prefetch_related("agent_device")

        out = []
        for access in accesses:
            d = access.agent_device
            connections = get_agent_connections(app, d.id)
            out.append({
                "id": str(d.id),
                "device_name": d.device_name,
                "fingerprint": d.fingerprint,
                "connections": connections
            })

        payload = {"type": "agents.update", "data": {"agent_devices": out}}
        await client_ws.send_text(orjson.dumps(payload).decode())
        logger.debug("Push agents update sent", client_device_id=client_device_id, agent_count=len(out))
    except Exception as e:
        logger.error("Failed to push agents update", client_device_id=client_device_id, error=str(e), exc_info=True)


# ===================== ICE/TURN Server Helpers =====================

def make_ice_servers_credentials(ttl_sec: int = 600):
    """Generates temporary credentials for TURN server"""
    import time
    username = str(int(time.time()) + ttl_sec)
    digest = hmac.new(settings.turn_secret.encode(), username.encode(), hashlib.sha1).digest()
    credential = base64.b64encode(digest).decode()

    ice_servers = [{'urls': f"stun:{settings.turn_host}:{settings.turn_port}"}]
    for url in [
        f"turn:{settings.turn_host}:{settings.turn_port}?transport=udp",
        f"turn:{settings.turn_host}:{settings.turn_port}?transport=tcp",
    ]:
        ice_servers.append({
            'urls': url,
            'username': username,
            'credential': credential,
        })

    return ice_servers


# ===================== Agent Connection Helpers =====================

def is_agent_online(app: FastAPI, agent_device_id: str) -> bool:
    """Checks if there are active connections for given agent_device_id"""
    return (agent_device_id in app.state.agent_device_id_to_agent_uuids
            and len(app.state.agent_device_id_to_agent_uuids[agent_device_id]) > 0)


def get_agent_connection(app: FastAPI, agent_device_id: str):
    """Returns first available WebSocket connection for agent_device_id, or None"""
    uuids = app.state.agent_device_id_to_agent_uuids.get(agent_device_id)
    if not uuids:
        return None
    conn_uuid = next(iter(uuids), None)
    if conn_uuid:
        return app.state.agents_ws.get(conn_uuid)
    return None


def get_agent_connections(app: FastAPI, agent_device_id: str) -> List[Dict[str, Any]]:
    """Returns list of all active connections for agent_device_id with metadata"""
    result = []
    uuids = app.state.agent_device_id_to_agent_uuids.get(str(agent_device_id), set())
    for conn_uuid in uuids:
        ws = app.state.agents_ws.get(conn_uuid)
        if ws:
            result.append({
                "uuid": conn_uuid,
                "version": ws.scope.get("version", "0.0.0"),
                "mode": ws.scope.get("viberra_mode", "UNKNOWN"),
                "agent_workdir_path": ws.scope.get("agent_workdir", "UNKNOWN"),
                "agent_workdir_name": os.path.basename(ws.scope.get("agent_workdir", "UNKNOWN")),
                "online": ws.client_state.name == 'CONNECTED' and ws.scope.get("viberra_mode") == "READY",
            })
    return result


# ===================== Authorization Helpers =====================

async def assert_client_owns_agent(agent_device_id: str, device_id: str) -> AgentDevice:
    """Verifies client access to agent via agent_access table"""
    from models import AgentAccess

    try:
        d = await AgentDevice.get(id=agent_device_id)
    except DoesNotExist:
        raise HTTPException(404, "agent not found")

    try:
        await AgentAccess.get(agent_device_id=agent_device_id, client_device_id=device_id)
    except DoesNotExist:
        raise HTTPException(403, "forbidden: access denied to this agent")

    return d


async def assert_client_owns_room(room_id: str, device_id: str) -> Room:
    """Verifies that room belongs to specified client device"""
    try:
        r = await Room.get(room_id=room_id)
    except DoesNotExist:
        raise HTTPException(404, "room not found")
    if r.owner_device_id != device_id:
        raise HTTPException(403, "forbidden: room not owned by this client device")
    return r


# ===================== Exports =====================

__all__ = [
    'client_device_get',
    'client_pub_get',
    'client_device_create_or_update',
    'client_device_update_last_seen',
    'push_agents_update',
    'make_ice_servers_credentials',
    'is_agent_online',
    'get_agent_connection',
    'get_agent_connections',
    'assert_client_owns_agent',
    'assert_client_owns_room',
]
