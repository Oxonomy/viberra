import base64, hmac, time, secrets, hashlib, json, orjson, datetime as dt, asyncio, uuid
import os
from contextlib import asynccontextmanager
from typing import Set

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, APIRouter, HTTPException, Request, Depends
from starlette.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from loguru import logger

from settings import settings
from schemas import *
from db import init_db
from protocol_constants import *
from models import AgentDevice, Room, ClientDevice
from ws_rpc import init_rpc_handler, RPCContext, RPCError

# Imports from refactored modules
from security import redis, store, b64, b64d, jti_status, jti_store, paseto_issue, paseto_verify, require_client
from services import (
    client_device_create_or_update, client_pub_get, client_device_get, client_device_update_last_seen,
    push_agents_update, get_agent_connection, get_agent_connections
)


# Initialize RPC handler
rpc_handler = init_rpc_handler(redis, jti_status, store)


# Register RPC methods (after app.state is available)
def register_rpc_methods():
    """Register all RPC methods"""
    from ws_rpc import (
        rpc_agent_devices_list, rpc_agent_devices_get, rpc_agent_devices_delete,
        rpc_agent_devices_add_client, rpc_agent_devices_remove_client, rpc_agent_devices_list_clients,
        rpc_rooms_create, rpc_rooms_invite, rpc_rtc_signal,
        rpc_client_token_renew
    )
    # CRUD operations
    rpc_handler.register("agent_devices.list")(rpc_agent_devices_list)
    rpc_handler.register("agent_devices.get")(rpc_agent_devices_get)
    rpc_handler.register("agent_devices.delete")(rpc_agent_devices_delete)

    # Agent access management
    rpc_handler.register("agent_devices.add_client")(rpc_agent_devices_add_client)
    rpc_handler.register("agent_devices.remove_client")(rpc_agent_devices_remove_client)
    rpc_handler.register("agent_devices.list_clients")(rpc_agent_devices_list_clients)

    # Rooms & WebRTC
    rpc_handler.register("rooms.create")(rpc_rooms_create)
    rpc_handler.register("rooms.invite")(rpc_rooms_invite)
    rpc_handler.register("rtc.signal")(rpc_rtc_signal)

    # Token management
    rpc_handler.register("client.token.renew")(rpc_client_token_renew)


def configure_logging():
    """Configure loguru based on settings"""
    import sys

    # Remove default handler
    logger.remove()

    # Determine format based on settings
    if settings.log_format == "json":
        # JSON format for production (easily parsed by monitoring systems)
        log_format = (
            '{"time": "{time:YYYY-MM-DD HH:mm:ss.SSS}", '
            '"level": "{level}", '
            '"message": "{message}", '
            '"extra": {extra}}'
        )
    else:
        # Human-readable text format for dev
        log_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level> | "
            "{extra}"
        )

    # Add handler with configured level
    logger.add(
        sys.stderr,
        format=log_format,
        level=settings.log_level,
        colorize=settings.log_format == "text",
        serialize=settings.log_format == "json"
    )

    logger.info("Logging configured", level=settings.log_level, format=settings.log_format, env=settings.env)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    logger.info("Starting viberra-control-api", env=settings.env)

    await init_db()
    logger.info("Database initialized")

    register_rpc_methods()
    logger.info("RPC methods registered")

    try:
        yield
    finally:
        logger.info("Shutting down viberra-control-api")
        try:
            await redis.aclose()
            logger.debug("Redis connection closed")
        except Exception as e:
            logger.error("Failed to close Redis connection", error=str(e))


app = FastAPI(title="viberra-control-api", lifespan=lifespan)
http = APIRouter()

# Setup rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Load allowed origins from environment
allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")
allowed_origins = [origin.strip() for origin in allowed_origins_str.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["authorization", "content-type", "x-auth-ts", "x-auth-sig"],
    max_age=3600,
)

app.state.agents_ws: Dict[str, WebSocket] = {}
app.state.agent_device_id_to_agent_uuids: Dict[str, Set[str]] = {}
app.state.clients_ws: Dict[str, WebSocket] = {}
app.state.pair_waiters: Dict[str, asyncio.Future] = {}
app.state.agent_active_room: Dict[str, dict] = {}

# Validate critical secrets on startup
FORBIDDEN_SECRETS = ["please_change_me", "changeme", "secret", ""]

if settings.turn_secret in FORBIDDEN_SECRETS:
    raise RuntimeError(
        "CRITICAL: TURN_SECRET must be changed from default value! "
        "Set a secure random value in .env file."
    )

if len(settings.turn_secret) < 32:
    logger.warning("TURN_SECRET is too short, recommended length: 32+ characters")


@http.get("/health")
async def health():
    return {"ok": True}

@http.get("/client/register_challenge")
@limiter.limit("10/minute")
async def client_register_challenge(request: Request):
    """Issue nonce for client device registration"""
    logger.debug("Issued registration challenge")
    return {"server_nonce": b64(secrets.token_bytes(16)), "ts": int(time.time())}


@http.post("/client/register")
@limiter.limit("5/minute")
async def client_register(request: Request, body: dict):
    """
    Register client device with Ed25519 signature.
    Expected payload:
    {
      "device_pub": "<base64 ed25519 pk>",   # 32 bytes
      "server_nonce": "<base64>",
      "ts": <int>,
      "sig": "<base64>",                      # Sign(CTX_REG || nonce || device_pub || ts)
      "platform": "ios/android/web",          # optional
      "app_version": "1.0.0",                 # optional
      "label": "iPhone 14 Pro"                # optional
    }
    """
    try:
        device_pub_b = b64d(body["device_pub"])
        server_nonce = b64d(body["server_nonce"])
        ts = int(body["ts"])
        sig = b64d(body["sig"])
    except Exception as e:
        logger.warning("Client registration failed: bad payload", error=str(e))
        raise HTTPException(400, "bad payload")

    if len(device_pub_b) != 32:
        logger.warning("Client registration failed: invalid device_pub length", length=len(device_pub_b))
        raise HTTPException(400, "bad device_pub")
    if abs(time.time() - ts) > 60:
        logger.warning("Client registration failed: stale timestamp", ts=ts, now=int(time.time()))
        raise HTTPException(400, "stale ts")

    # Verify Ed25519 signature
    msg = b"".join([CLIENT_CTX_REG, server_nonce, device_pub_b, str(ts).encode()])
    try:
        VerifyKey(device_pub_b).verify(msg, sig)
    except BadSignatureError:
        logger.warning("Client registration failed: invalid signature")
        raise HTTPException(403, "invalid signature")

    # Generate device_id from public key hash
    device_id = hashlib.sha256(device_pub_b).hexdigest()[:32]

    # Save device to DB with metadata
    await client_device_create_or_update(
        device_id,
        device_pub_b,
        platform=body.get("platform"),
        app_version=body.get("app_version"),
        label=body.get("label"),
        client_static_pub=body.get("client_static_pub")  # X25519 for E2EE ECDH
    )

    # Issue short-lived PASETO token with scope=client
    token, exp, jti = paseto_issue(
        device_id,
        scope="client",
        mode="CLIENT",
        ttl_sec=600,
        audience="viberra-app"
    )

    if token and jti:
        await jti_store(jti, exp)

    # Generate fingerprint for display
    fingerprint = "SHA256:" + b64(hashlib.sha256(device_pub_b).digest())

    logger.info(
        "Client device registered",
        device_id=device_id,
        fingerprint=fingerprint,
        platform=body.get("platform"),
        app_version=body.get("app_version")
    )

    return {
        "device_id": device_id,
        "session_token": token,
        "exp": exp,
        "fingerprint": fingerprint
    }


@http.post("/client/token/renew")
@limiter.limit("20/minute")
async def client_token_renew(request: Request, body: dict):
    """
    Renew client token with PoP verification.
    Header: Authorization: Bearer <token>
    Body: { "ts": <int>, "sig": "<base64>" }
    sig = Sign( CTX_RENEW || device_id || ts || SHA256(token) )
    """
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "missing token")

    token = auth.split(" ", 1)[1]

    # Verify token
    claims = paseto_verify(token)
    if not claims or claims.get("aud") != "viberra-app" or claims.get("scope") != "client":
        logger.warning("Token renewal failed: invalid token")
        raise HTTPException(401, "invalid token")

    # Check JTI status
    jti = claims.get("jti")
    if jti and (await jti_status(jti)) == "revoked":
        logger.warning("Token renewal failed: revoked token", jti=jti)
        raise HTTPException(401, "revoked")

    device_id = claims["sub"]

    # Get client public key
    pub_b = await client_pub_get(device_id)
    if not pub_b:
        raise HTTPException(401, "unknown device")

    try:
        ts = int(body["ts"])
        sig = b64d(body["sig"])
    except Exception:
        raise HTTPException(400, "bad payload")

    if abs(time.time() - ts) > 60:
        raise HTTPException(400, "stale ts")

    # Verify signature with token binding
    th = hashlib.sha256(token.encode()).digest()
    m = b"".join([CLIENT_CTX_RENEW, device_id.encode(), str(ts).encode(), th])

    try:
        VerifyKey(pub_b).verify(m, sig)
    except BadSignatureError:
        logger.warning("Token renewal failed: invalid signature", device_id=device_id)
        raise HTTPException(403, "invalid signature")

    # Issue new token
    new_token, exp, new_jti = paseto_issue(
        device_id,
        scope="client",
        mode="CLIENT",
        ttl_sec=600,
        audience="viberra-app"
    )

    if new_token and new_jti:
        await jti_store(new_jti, exp)

    logger.info("Client token renewed", device_id=device_id)

    return {"session_token": new_token, "exp": exp}


@http.post("/client/pair/start")
@limiter.limit("10/minute")
async def client_pair_start(request: Request, body: dict, claims=Depends(require_client)):
    """
    Endpoint to start agent pairing.
    Body: { "agent_device_id": "...", "code": "123456" }
    Authentication: Client DPoP (require_client)
    """
    from models import AgentAccess

    # Accept agent id from any key (compatibility with web)
    agent_device_id = (body.get("agent_device_id") or body.get("agent_id") or "").strip()
    code = (body.get("code") or "").strip()
    client_device_id = claims["sub"]
    client_static_pub = body.get("client_static_pub")    # X25519 (base64, ORIGINAL)
    client_static_ts = body.get("client_static_ts")      # ms timestamp (int/str)
    client_static_sig = body.get("client_static_sig")    # Ed25519 signature (base64, ORIGINAL)

    if not agent_device_id or not code or len(code) > 16:
        logger.warning("Pairing start failed: bad payload", client_device_id=client_device_id)
        raise HTTPException(400, "bad payload")

    # Check if client is already paired with this agent
    existing_access = await AgentAccess.filter(
        agent_device_id=agent_device_id,
        client_device_id=client_device_id
    ).first()
    if existing_access:
        logger.warning("Pairing start failed: agent already paired with this client",
                       client_device_id=client_device_id, agent_device_id=agent_device_id)
        raise HTTPException(409, "agent already paired with this device")

    ws = get_agent_connection(app, agent_device_id)
    if not ws:
        logger.warning("Pairing start failed: agent offline", client_device_id=client_device_id, agent_device_id=agent_device_id)
        raise HTTPException(409, "agent offline")

    # Note: agent can be in READY mode if paired, but if started with --pair-mode,
    # then in PAIRING_ONLY. Pairing is allowed in both cases - logic at WebSocket level.

    challenge_id = secrets.token_hex(16)
    nonce = secrets.token_bytes(16)
    waiter = asyncio.get_event_loop().create_future()
    app.state.pair_waiters[challenge_id] = waiter

    client = await client_device_get(client_device_id)
    if not client:
        logger.error("Pairing start failed: client device not found", client_device_id=client_device_id)
        raise HTTPException(401, "unknown client device")

    # Update client_static_pub and signature if provided in request
    if client_static_pub:
        client.client_static_pub = client_static_pub
        client.client_static_ts = int(client_static_ts) if client_static_ts is not None else None
        client.client_static_sig = client_static_sig
        await client.save()
        logger.info("Updated client_static_pub + signature for E2EE",
                    client_device_id=client_device_id)

    logger.info("Pairing started", client_device_id=client_device_id, agent_device_id=agent_device_id, challenge_id=challenge_id)

    payload = {
        "type": "pair_request",
        "challenge_id": challenge_id,
        "nonce": b64(nonce),
        "code": code,
        "expires": 60,
        "client": {
            "device_id": client.device_id,
            "fingerprint": client.fingerprint,
            "label": client.label or "",
            "sign_pub": b64(client.public_key),            # Ed25519 pubkey (base64 ORIGINAL)
            "static_pub": client.client_static_pub or "",  # X25519 pub (base64 ORIGINAL)
            "static_ts": client.client_static_ts,          # ms timestamp
            "static_sig": client.client_static_sig or "",  # signature (base64 ORIGINAL)
        },
    }
    try:
        await ws.send_text(orjson.dumps(payload).decode())
    except Exception as e:
        app.state.pair_waiters.pop(challenge_id, None)
        logger.error("Pairing failed: could not deliver pair_request", client_device_id=client_device_id, agent_device_id=agent_device_id, error=str(e))
        raise HTTPException(500, f"failed to deliver pair_request: {e}")

    # Wait for agent decision
    try:
        resp = await asyncio.wait_for(waiter, timeout=60.0)
    except asyncio.TimeoutError:
        app.state.pair_waiters.pop(challenge_id, None)
        logger.warning("Pairing timeout", client_device_id=client_device_id, agent_device_id=agent_device_id, challenge_id=challenge_id)
        raise HTTPException(408, "pairing timeout")

    accept = bool(resp.get("accept"))
    agent_sign_pub_b   = b64d(resp.get("agent_sign_pub") or "")     # 32b Ed25519
    agent_static_pub_b = b64d(resp.get("agent_static_pub") or "")   # 32b X25519
    agent_static_ts    = resp.get("agent_static_ts")                # ms timestamp
    agent_static_sig   = resp.get("agent_static_sig") or ""         # base64 ORIGINAL
    sig_b = b64d(resp.get("sig") or "")

    if not accept:
        logger.info("Pairing declined by agent", client_device_id=client_device_id, agent_device_id=agent_device_id, challenge_id=challenge_id)
        return {"ok": False, "reason": "declined"}

    # Verify agent signature: Sign( CTX || nonce || device_id || code )
    m = b"".join([
        PAIR_CTX,
        nonce,
        client.device_id.encode(),
        code.encode(),
    ])
    try:
        VerifyKey(agent_sign_pub_b).verify(m, sig_b)
    except BadSignatureError:
        logger.warning("Pairing failed: invalid agent signature", client_device_id=client_device_id, agent_device_id=agent_device_id, challenge_id=challenge_id)
        raise HTTPException(403, "invalid signature")

    # Save pairing (new agent device in Device table)
    from models import AgentAccess

    fingerprint = "SHA256:" + b64(hashlib.sha256(agent_sign_pub_b).digest())

    # Use get_or_create: if AgentDevice already exists (reconnection to second device),
    # then use existing one, don't overwrite its fields
    agent_device, created = await AgentDevice.get_or_create(
        id=agent_device_id,
        defaults={
            "device_name": ws.scope.get("agent_device_name", ""),
            "agent_static_pub": b64(agent_static_pub_b),
            "agent_sign_pub": b64(agent_sign_pub_b),
            "fingerprint": fingerprint,
        }
    )

    # Add client access to agent via agent_access
    # Use get_or_create in case reconnection happens again
    access, access_created = await AgentAccess.get_or_create(
        agent_device_id=agent_device_id,
        client_device_id=client.device_id
    )

    action_str = "created" if created else "already exists"
    access_str = "new access granted" if access_created else "access already exists"
    logger.info("Pairing successful", client_device_id=client_device_id, agent_device_id=agent_device_id,
                fingerprint=fingerprint, agent_device_action=action_str, access_action=access_str)

    # Transition WS session to READY + issue new token
    ws.scope["viberra_mode"] = "READY"
    session_token, exp, jti = paseto_issue(agent_device_id, scope="agent:online", mode="READY")
    if session_token and jti:
        await jti_store(jti, exp)
        try:
            await ws.send_text(orjson.dumps({
                "type": "token_update",
                "session_token": session_token,
                "exp": exp
            }).decode())
            await ws.send_text(orjson.dumps({
                "type": "pair_ok",
                "challenge_id": challenge_id,
                "mode": "READY",
            }).decode())
        except Exception:
            pass

    # Push update to client after successful pairing
    try:
        await push_agents_update(app, client.device_id)
    except Exception:
        pass

    return {
        "ok": True,
        "agent_sign_pub":    b64(agent_sign_pub_b)   if agent_sign_pub_b   else None,
        "agent_static_pub":  b64(agent_static_pub_b) if agent_static_pub_b else None,
        "agent_static_ts":   agent_static_ts,
        "agent_static_sig":  agent_static_sig,
    }


@http.get("/agents")
async def get_agents(claims=Depends(require_client)):
    """
    HTTP endpoint to get list of available agents.
    Fallback for cases when WebSocket is not connected.
    Authentication: Client DPoP (require_client)
    """
    from models import AgentAccess

    device_id = claims["sub"]

    # Get all agents that this client has access to
    accesses = await AgentAccess.filter(client_device_id=device_id).prefetch_related("agent_device")

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

    logger.info("Agents list requested via HTTP", device_id=device_id, agent_count=len(out))

    return {"agent_devices": out}


app.include_router(http)


# ===================== WebSocket Endpoints =====================

# Import and setup WebSocket router
from ws_endpoints import router as ws_router
import ws_endpoints

# Set rpc_handler in ws_endpoints module
ws_endpoints.rpc_handler = rpc_handler

app.include_router(ws_router)


if __name__ == "__main__":
    ssl_certfile = os.getenv("SSL_CERTFILE")
    ssl_keyfile = os.getenv("SSL_KEYFILE")
    kwargs = {}
    if ssl_certfile and ssl_keyfile:
        kwargs["ssl_certfile"] = ssl_certfile
        kwargs["ssl_keyfile"] = ssl_keyfile

    uvicorn.run(app, host="0.0.0.0", port=8080, lifespan="on", **kwargs,)

