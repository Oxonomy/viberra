import base64
import hashlib
import os

import orjson
import time
from typing import Optional, Dict, Any, Callable, Awaitable

from fastapi import WebSocket
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from redis.asyncio import Redis
from loguru import logger

from models import AgentDevice, Room, ClientDevice, AgentAccess
from security import b64, b64d
from services import push_agents_update, make_ice_servers_credentials, client_device_get, get_agent_connection


# Context for RPC message signature
CLIENT_CTX_RPC = b"viberra-client-rpc-v1"

# Error codes
ERR_INVALID_REQUEST = 4000
ERR_METHOD_NOT_FOUND = 4004
ERR_UNAUTHORIZED = 4001
ERR_FORBIDDEN = 4003
ERR_BAD_SIGNATURE = 4002
ERR_REPLAY_ATTACK = 4005
ERR_STALE_TIMESTAMP = 4006
ERR_INTERNAL = 5000


class RPCError(Exception):
    """RPC error with code and details"""

    def __init__(self, code: int, message: str, details: Optional[Dict[str, Any]] = None):
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(message)


class RPCContext:
    """RPC request context with authentication and session information"""

    def __init__(
            self,
            ws: WebSocket,
            device_id: str,
            claims: dict,
            public_key: bytes,
            redis: Redis
    ):
        self.ws = ws
        self.device_id = device_id
        self.claims = claims
        self.public_key = public_key
        self.redis = redis


class RPCHandler:
    """RPC request handler with method registration and routing"""

    def __init__(self, redis: Redis, jti_status_fn: Callable, store):
        self.redis = redis
        self.jti_status_fn = jti_status_fn
        self.store = store
        self.methods: Dict[str, Callable[[RPCContext, dict], Awaitable[dict]]] = {}

    def register(self, name: str):
        """Decorator for registering RPC method"""

        def decorator(fn: Callable):
            self.methods[name] = fn
            return fn

        return decorator

    async def verify_signature(
            self,
            method: str,
            params: dict,
            ts: int,
            nonce: str,
            sig_b64: str,
            token: str,
            public_key: bytes
    ) -> bool:
        """
        Verifies RPC request signature.
        Sign(CLIENT_CTX_RPC || method || ts || nonce || sha256(token) || sha256(canonical_json(params)))
        """
        now = int(time.time())
        if abs(now - ts) > 60:
            logger.debug("RPC signature verification failed: stale timestamp", ts=ts, now=now, method=method)
            raise RPCError(ERR_STALE_TIMESTAMP, f"stale timestamp: {ts} vs {now}")

        nonce_key = f"rpc:nonce:{nonce}"
        exists = await self.redis.exists(nonce_key)
        if exists:
            logger.warning("RPC signature verification failed: replay attack detected", nonce=nonce[:16], method=method)
            raise RPCError(ERR_REPLAY_ATTACK, "nonce already used")

        await self.redis.setex(nonce_key, 300, "used")

        token_hash = hashlib.sha256(token.encode()).digest()
        params_canonical = orjson.dumps(params, option=orjson.OPT_SORT_KEYS)
        params_hash = hashlib.sha256(params_canonical).digest()

        body = b"".join([
            CLIENT_CTX_RPC,
            method.encode(),
            str(ts).encode(),
            nonce.encode(),
            token_hash,
            params_hash
        ])

        try:
            sig = bytes.fromhex(sig_b64) if len(sig_b64) == 128 else __import__('base64').b64decode(sig_b64)
            VerifyKey(public_key).verify(body, sig)
            logger.debug("RPC signature verified", method=method, nonce=nonce[:16])
            return True
        except BadSignatureError:
            logger.warning("RPC signature verification failed: bad signature", method=method)
            raise RPCError(ERR_BAD_SIGNATURE, "invalid signature")
        except Exception as e:
            logger.warning("RPC signature verification failed", method=method, error=str(e))
            raise RPCError(ERR_BAD_SIGNATURE, f"signature verification failed: {e}")

    async def handle_request(self, ctx: RPCContext, msg: dict) -> dict:
        """
        Handles RPC request and returns result or error.

        Request format:
        {
          "id": "uuid",
          "method": "ns.operation",
          "params": {...},
          "ts": 1234567890,
          "nonce": "base64...",
          "sig": "base64..."
        }
        """
        try:
            req_id = msg.get("id")
            method = msg.get("method")
            params = msg.get("params", {})
            ts = msg.get("ts")
            nonce = msg.get("nonce")
            sig = msg.get("sig")

            if not all([req_id, method, ts is not None, nonce, sig]):
                logger.warning("RPC request invalid: missing fields", device_id=ctx.device_id)
                raise RPCError(ERR_INVALID_REQUEST, "missing required fields: id, method, ts, nonce, sig")

            token = ctx.ws.scope.get("viberra_token")
            if not token:
                logger.warning("RPC request failed: no token in session", device_id=ctx.device_id, method=method)
                raise RPCError(ERR_UNAUTHORIZED, "no token in session")

            await self.verify_signature(method, params, ts, nonce, sig, token, ctx.public_key)

            handler = self.methods.get(method)
            if not handler:
                logger.warning("RPC method not found", device_id=ctx.device_id, method=method)
                raise RPCError(ERR_METHOD_NOT_FOUND, f"method not found: {method}")

            logger.debug("RPC method called", device_id=ctx.device_id, method=method, req_id=req_id)
            result = await handler(ctx, params)
            logger.debug("RPC method completed", device_id=ctx.device_id, method=method, req_id=req_id)

            return {
                "id": req_id,
                "result": result
            }

        except RPCError as e:
            logger.info("RPC error", device_id=ctx.device_id, method=msg.get("method"), code=e.code, message=e.message)
            return {
                "id": msg.get("id"),
                "error": {
                    "code": e.code,
                    "message": e.message,
                    "details": e.details
                }
            }
        except Exception as e:
            logger.error("RPC internal error", device_id=ctx.device_id, method=msg.get("method"), error=str(e), exc_info=True)
            return {
                "id": msg.get("id"),
                "error": {
                    "code": ERR_INTERNAL,
                    "message": "internal server error",
                    "details": {"error": str(e)}
                }
            }


# Global handler instance (will be initialized in main.py)
rpc_handler: Optional[RPCHandler] = None


def init_rpc_handler(redis: Redis, jti_status_fn: Callable, store) -> RPCHandler:
    """Initializes global RPC handler"""
    global rpc_handler
    rpc_handler = RPCHandler(redis, jti_status_fn, store)
    return rpc_handler


# ======================== Helper Functions ========================

async def assert_client_owns_agent_rpc(ctx: RPCContext, agent_device_id: str) -> AgentDevice:
    """Verifies client access to agent via agent_access table."""
    from tortoise.exceptions import DoesNotExist
    try:
        d = await AgentDevice.get(id=agent_device_id)
    except DoesNotExist:
        raise RPCError(ERR_FORBIDDEN, "agent not found")

    # Check for access in agent_access
    try:
        await AgentAccess.get(agent_device_id=agent_device_id, client_device_id=ctx.device_id)
    except DoesNotExist:
        raise RPCError(ERR_FORBIDDEN, "access denied to this agent")

    return d


async def assert_client_owns_room_rpc(ctx: RPCContext, room_id: str) -> Room:
    """Verifies room ownership (for RPC)"""
    from tortoise.exceptions import DoesNotExist
    from tortoise import timezone

    try:
        r = await Room.get(room_id=room_id)
    except DoesNotExist:
        raise RPCError(ERR_FORBIDDEN, "room not found")

    if r.owner_device_id != ctx.device_id:
        raise RPCError(ERR_FORBIDDEN, "room not owned by this client")

    return r


# ======================== RPC Method Implementations ========================

async def rpc_agent_devices_list(ctx: RPCContext, params: dict) -> dict:
    """
    RPC method: agent_devices.list
    Returns list of agent devices the client has access to.
    Includes online status and active connections.
    """

    # Get all agents the client has access to
    accesses = await AgentAccess.filter(client_device_id=ctx.device_id).prefetch_related("agent_device")
    app = ctx.ws.scope["app"]

    agent_devices = []
    for access in accesses:
        d = access.agent_device
        connections = []
        uuids = app.state.agent_device_id_to_agent_uuids.get(str(d.id), set())
        for conn_uuid in uuids:
            ws = app.state.agents_ws.get(conn_uuid)
            if ws:
                agent_workdir = ws.scope.get("agent_workdir", "UNKNOWN")
                connections.append({
                    "uuid": conn_uuid,
                    "version": ws.scope.get("version", "0.0.0"),
                    "mode": ws.scope.get("viberra_mode", "UNKNOWN"),
                    "agent_workdir_path": agent_workdir,
                    "agent_workdir_name": os.path.basename(agent_workdir),
                    "online": ws.client_state.name == 'CONNECTED' and ws.scope.get("viberra_mode") == "READY"
                })

        agent_devices.append({
            "id": str(d.id),
            "device_name": d.device_name,
            "fingerprint": d.fingerprint,
            "connections": connections
        })

    return {"agent_devices": agent_devices}


async def rpc_agent_devices_get(ctx: RPCContext, params: dict) -> dict:
    """
    RPC method: devices.get
    Gets information about specific device.
    Params: { "agent_device_id": str }
    """
    agent_device_id = params.get("agent_device_id")
    if not agent_device_id:
        raise RPCError(ERR_INVALID_REQUEST, "agent_id required")

    d = await assert_client_owns_agent_rpc(ctx, agent_device_id)

    return {
        "agent_id": d.id,
        "agent_static_pub": d.agent_static_pub,
        "agent_sign_pub": d.agent_sign_pub,
        "fingerprint": d.fingerprint
    }


async def rpc_agent_devices_delete(ctx: RPCContext, params: dict) -> dict:
    """
    RPC method: devices.delete
    Deletes device.
    Params: { "agent_device_id": str }
    """
    agent_device_id = params.get("agent_device_id")
    if not agent_device_id:
        raise RPCError(ERR_INVALID_REQUEST, "agent_id required")

    await assert_client_owns_agent_rpc(ctx, agent_device_id)
    await AgentDevice.filter(id=agent_device_id).delete()

    logger.info("Agent device deleted", device_id=ctx.device_id, agent_device_id=agent_device_id)

    # Push update to owner after deletion
    app = ctx.ws.scope["app"]
    await push_agents_update(app, ctx.device_id)

    return {"ok": True}


async def rpc_agent_devices_add_client(ctx: RPCContext, params: dict) -> dict:
    """
    RPC method: agent_devices.add_client
    Adds client (device) access to agent.
    Params: { "agent_device_id": str, "client_device_id": str }
    """
    from tortoise.exceptions import DoesNotExist

    agent_device_id = params.get("agent_device_id")
    client_device_id = params.get("client_device_id")

    if not agent_device_id or not client_device_id:
        raise RPCError(ERR_INVALID_REQUEST, "agent_device_id and client_device_id required")

    # Verify current client's access to agent
    await assert_client_owns_agent_rpc(ctx, agent_device_id)

    # Verify that target client exists
    try:
        await ClientDevice.get(device_id=client_device_id)
    except DoesNotExist:
        raise RPCError(ERR_FORBIDDEN, "target client device not found")

    # Add access (or update if already exists)
    await AgentAccess.get_or_create(
        agent_device_id=agent_device_id,
        client_device_id=client_device_id
    )

    logger.info(
        "Added client access to agent",
        device_id=ctx.device_id,
        agent_device_id=agent_device_id,
        client_device_id=client_device_id
    )

    return {"ok": True}


async def rpc_agent_devices_remove_client(ctx: RPCContext, params: dict) -> dict:
    """
    RPC method: agent_devices.remove_client
    Removes client access from agent.
    Params: { "agent_device_id": str, "client_device_id": str }
    """
    agent_device_id = params.get("agent_device_id")
    client_device_id = params.get("client_device_id")

    if not agent_device_id or not client_device_id:
        raise RPCError(ERR_INVALID_REQUEST, "agent_device_id and client_device_id required")

    # Verify current client's access to agent
    await assert_client_owns_agent_rpc(ctx, agent_device_id)

    # Remove access
    await AgentAccess.filter(
        agent_device_id=agent_device_id,
        client_device_id=client_device_id
    ).delete()

    logger.info(
        "Removed client access from agent",
        device_id=ctx.device_id,
        agent_device_id=agent_device_id,
        client_device_id=client_device_id
    )

    return {"ok": True}


async def rpc_agent_devices_list_clients(ctx: RPCContext, params: dict) -> dict:
    """
    RPC method: agent_devices.list_clients
    Shows list of clients with access to agent.
    Params: { "agent_device_id": str }
    """
    agent_device_id = params.get("agent_device_id")

    if not agent_device_id:
        raise RPCError(ERR_INVALID_REQUEST, "agent_device_id required")

    # Verify current client's access to agent
    await assert_client_owns_agent_rpc(ctx, agent_device_id)

    # Get list of accesses
    accesses = await AgentAccess.filter(agent_device_id=agent_device_id).prefetch_related("client_device")

    clients = []
    for access in accesses:
        client = access.client_device
        clients.append({
            "device_id": client.device_id,
            "label": client.label,
            "platform": client.platform,
        })

    return {"clients": clients}


async def rpc_rooms_create(ctx: RPCContext, params: dict) -> dict:
    """
    RPC method: rooms.create
    Creates WebRTC room.
    Params: {}
    """
    import secrets
    import datetime as dt
    from tortoise import timezone
    from settings import settings

    room_id = secrets.token_hex(8)
    token = secrets.token_hex(16)
    expires = timezone.now() + dt.timedelta(seconds=settings.room_ttl_sec)

    await Room.create(
        room_id=room_id,
        owner_device_id=ctx.device_id,
        token=token,
        ttl_sec=settings.room_ttl_sec,
        expires_at=expires,
        status="open",
    )

    logger.info("WebRTC room created", device_id=ctx.device_id, room_id=room_id, ttl=settings.room_ttl_sec)

    return {
        "room_id": room_id,
        "ttl": settings.room_ttl_sec,
        "iceServers": make_ice_servers_credentials(),
        "token": token
    }


async def rpc_rooms_invite(ctx: RPCContext, params: dict) -> dict:
    """
    RPC method: rooms.invite
    Sends invite to agent to connect to room.
    Ensures exclusive access: if another client is already connected, disconnects them.
    Params: { "room_id": str, "agent_id": str }
    """
    from tortoise import timezone

    room_id = params.get("room_id")
    agent_id = params.get("agent_id")

    if not room_id or not agent_id:
        raise RPCError(ERR_INVALID_REQUEST, "room_id and agent_id required")

    # Verify room ownership
    room = await assert_client_owns_room_rpc(ctx, room_id)

    if room.status != "open" or room.expires_at < timezone.now():
        raise RPCError(ERR_FORBIDDEN, "room expired or closed")

    app = ctx.ws.scope["app"]

    # Verify that agent is online
    ws = app.state.agents_ws.get(agent_id)
    if not ws:
        raise RPCError(ERR_FORBIDDEN, "agent offline")

    agent_device_id = ws.scope.get('agent_device_id')

    # Verify agent ownership
    await assert_client_owns_agent_rpc(ctx, agent_device_id)

    # Verify agent mode
    if ws.scope.get("viberra_mode") != "READY":
        raise RPCError(ERR_FORBIDDEN, "agent not ready for invitations")

    # Exclusive access: if another client is active, disconnect them
    active = app.state.agent_active_room.get(str(agent_device_id))
    if active and active.get("client_device_id") != ctx.device_id:
        # There's an active client from another device
        logger.info(
            "Disconnecting previous client from agent",
            agent_id=agent_device_id,
            prev_client=active.get("client_device_id"),
            new_client=ctx.device_id
        )

        # Send disconnect signal to previous client
        prev_client_ws = app.state.clients_ws.get(active.get("client_device_id"))
        if prev_client_ws:
            try:
                bye_payload = {
                    "type": "push",
                    "method": "room.disconnected",
                    "data": {
                        "room_id": active.get("room_id"),
                        "reason": "another_client_connected"
                    }
                }
                await prev_client_ws.send_text(orjson.dumps(bye_payload).decode())
            except Exception as e:
                logger.warning(
                    "Failed to notify previous client of disconnection",
                    error=str(e)
                )

        # Send disconnect signal to agent as well
        agent_ws = app.state.agents_ws.get(active.get("conn_uuid"))
        if agent_ws:
            try:
                agent_bye_payload = {
                    "type": "push",
                    "method": "room.disconnected",
                    "data": {
                        "room_id": active.get("room_id"),
                        "reason": "another_client_connected"
                    }
                }
                await agent_ws.send_text(orjson.dumps(agent_bye_payload).decode())
            except Exception as e:
                logger.warning(
                    "Failed to notify agent of room disconnection",
                    error=str(e)
                )

    # Get client information
    client = await client_device_get(ctx.device_id)

    # Send invite to new client (with client information for agent logging)
    payload = {
        "type": "invite",
        "room_id": room.room_id,
        "token": room.token,
        "iceServers": make_ice_servers_credentials(),
        "client": {
            "device_id": client.device_id if client else ctx.device_id,
            "fingerprint": client.fingerprint if client else "",
            "label": client.label or "" if client else "",
        },
    }

    try:
        await ws.send_text(orjson.dumps(payload).decode())
        logger.info("Room invite sent", device_id=ctx.device_id, room_id=room.room_id, agent_id=agent_id)
    except Exception as e:
        logger.error("Failed to send room invite", device_id=ctx.device_id, room_id=room.room_id, agent_id=agent_id, error=str(e))
        raise RPCError(ERR_INTERNAL, f"failed to push invite: {e}")

    # Save active connection
    app.state.agent_active_room[str(agent_device_id)] = {
        "room_id": room.room_id,
        "client_device_id": ctx.device_id,
        "conn_uuid": agent_id
    }

    return {"ok": True}


async def rpc_rtc_signal(ctx: RPCContext, params: dict) -> dict:
    """
    RPC method: rtc.signal
    Sends RTC signal to agent.
    Params: { "room_id": str, "agent_id": str, "stableData": dict }
    """
    from tortoise import timezone

    room_id = params.get("room_id")
    agent_id = params.get("agent_id")
    data = params.get("stableData")

    if not room_id or not agent_id or not data:
        raise RPCError(ERR_INVALID_REQUEST, "room_id, agent_id, and stableData required")

    # Verify room ownership
    room = await assert_client_owns_room_rpc(ctx, room_id)

    if room.status != "open" or room.expires_at < timezone.now():
        raise RPCError(ERR_FORBIDDEN, "room expired or closed")

    app = ctx.ws.scope["app"]
    ws = app.state.agents_ws.get(agent_id)
    agent_device_id = ws.scope.get('agent_device_id')

    # Verify agent ownership
    await assert_client_owns_agent_rpc(ctx, agent_device_id)

    # Verify that agent is online
    if not ws:
        raise RPCError(ERR_FORBIDDEN, "agent offline")

    # Verify agent mode
    if ws.scope.get("viberra_mode") != "READY":
        raise RPCError(ERR_FORBIDDEN, "agent not ready for signaling")

    # Send signal to agent
    payload = {"type": "rtc_signal", "room_id": room_id, "data": data}

    try:
        await ws.send_text(orjson.dumps(payload).decode())
        logger.debug("RTC signal sent to agent", device_id=ctx.device_id, room_id=room_id, agent_id=agent_id)
    except Exception as e:
        logger.error("Failed to send RTC signal to agent", device_id=ctx.device_id, room_id=room_id, agent_id=agent_id, error=str(e))
        raise RPCError(ERR_INTERNAL, f"failed to push signal: {e}")

    return {"ok": True}


async def rpc_client_token_renew(ctx: RPCContext, params: dict) -> dict:
    """
    RPC method: client.token.renew
    Renews client PASETO token.
    Params: {}
    """
    from crypto_paseto import issue_token

    device_id = ctx.device_id

    # Issue new token
    new_token, exp, new_jti = issue_token(
        device_id,
        scope="client",
        mode="CLIENT",
        ttl_sec=600,
        audience="viberra-app"
    )

    if new_token and new_jti:
        await ctx.redis.setex(f"paseto:jti:{new_jti}", max(1, exp - int(time.time())), "issued")

    # Update token in WebSocket scope
    ctx.ws.scope["viberra_token"] = new_token

    return {"session_token": new_token, "exp": exp}
