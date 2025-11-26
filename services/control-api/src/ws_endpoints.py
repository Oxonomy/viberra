import asyncio
import hashlib
import secrets
import time
import uuid

import orjson
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from loguru import logger
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from tortoise.exceptions import DoesNotExist

from settings import settings
from protocol_constants import CLIENT_WS_HELLO_CTX, HELLO_CTX
from models import AgentDevice, Room
from security import b64, b64d, redis, store, paseto_verify, jti_status, jti_store, paseto_issue
from services import client_device_get, client_device_update_last_seen, push_agents_update
from ws_rpc import RPCContext


# Global variable for rpc_handler will be filled in main.py after initialization
rpc_handler = None


# ===================== WebSocket Router =====================

router = APIRouter()


# ===================== Client WebSocket Endpoint =====================

@router.websocket("/ws/client")
async def ws_client(ws: WebSocket):
    """
    WebSocket endpoint for client devices.
    Supports:
    - Ed25519 handshake with token binding
    - RPC requests/responses with signatures
    - Push events from server
    """
    app = ws.app
    await ws.accept()
    logger.debug("Client WebSocket connection accepted")
    device_id = None
    try:
        server_nonce = secrets.token_bytes(16)
        await ws.send_text(orjson.dumps({
            "type": "server_hello",
            "nonce": b64(server_nonce),
            "ts": int(time.time()),
            "alg": "ed25519",
            "ctx": "viberra-client-ws-hello-v1"
        }).decode())
        try:
            raw = await asyncio.wait_for(ws.receive_text(), timeout=10.0)
        except asyncio.TimeoutError:
            logger.warning("Client WebSocket handshake timeout")
            await ws.close(code=4408, reason="client_hello timeout")
            return

        msg = orjson.loads(raw)

        if msg.get("type") != "client_hello":
            logger.warning("Client WebSocket: invalid message type, expected client_hello", msg_type=msg.get("type"))
            await ws.close(code=4000)
            return

        device_id = msg["device_id"]
        ts = int(msg["ts"])
        version = msg.get("version", "0.0.0")

        if abs(time.time() - ts) > 60:
            await ws.close(code=4000)
            return

        sig = b64d(msg["sig"])
        token = msg.get("token")
        token_hash_b = b64d(msg.get("token_hash", "")) if msg.get("token_hash") else b"\x00" * 32

        if not token:
            logger.warning("Client WebSocket auth failed: missing token", device_id=device_id)
            await ws.close(code=4401)  # Missing token
            return

        claims = paseto_verify(token)
        if not claims:
            logger.warning("Client WebSocket auth failed: invalid token", device_id=device_id)
            await ws.close(code=4401)
            return

        jti = claims.get("jti")
        if jti:
            status = await jti_status(jti)
            if status == "revoked":
                logger.warning("Client WebSocket auth failed: revoked token", device_id=device_id, jti=jti)
                await ws.close(code=4404)
                return

        if claims.get("aud") != "viberra-app" or claims.get("scope") != "client":
            logger.warning("Client WebSocket auth failed: audience/scope mismatch", device_id=device_id, aud=claims.get("aud"), scope=claims.get("scope"))
            await ws.close(code=4403)
            return

        if claims.get("sub") != device_id:
            logger.warning("Client WebSocket auth failed: device ID mismatch", claimed_device_id=device_id, token_sub=claims.get("sub"))
            await ws.close(code=4403)
            return

        if hashlib.sha256(token.encode()).digest() != token_hash_b:
            logger.warning("Client WebSocket auth failed: token binding mismatch", device_id=device_id)
            await ws.close(code=4402)
            return

        device = await client_device_get(device_id)
        if not device:
            logger.warning("Client WebSocket auth failed: unknown device", device_id=device_id)
            await ws.close(code=4401)
            return

        pub_b = device.public_key

        body = b"".join([
            CLIENT_WS_HELLO_CTX,
            server_nonce,
            device_id.encode(),
            str(ts).encode(),
            pub_b,
            token_hash_b
        ])

        try:
            VerifyKey(pub_b).verify(body, sig)
        except BadSignatureError:
            logger.warning("Client WebSocket auth failed: invalid signature", device_id=device_id)
            await ws.close(code=4002)
            return

        old = app.state.clients_ws.get(device_id)
        if old and old is not ws:
            logger.debug("Closing old client WebSocket connection", device_id=device_id)
            try:
                await old.close()
            except Exception as e:
                logger.debug("Failed to close old client connection", device_id=device_id, error=str(e))

        app.state.clients_ws[device_id] = ws
        ws.scope["viberra_device_id"] = device_id
        ws.scope["viberra_token"] = token
        ws.scope["viberra_claims"] = claims
        ws.scope["viberra_public_key"] = pub_b
        ws.scope["viberra_version"] = version

        await client_device_update_last_seen(device_id)

        await ws.send_text(orjson.dumps({
            "type": "hello_ok",
            "interval": settings.heartbeat_interval_sec,
            "mode": "READY"
        }).decode())

        logger.info("Client WebSocket connected", device_id=device_id, version=version)

        ctx = RPCContext(
            ws=ws,
            device_id=device_id,
            claims=claims,
            public_key=pub_b,
            redis=redis
        )

        while True:
            raw = await ws.receive_text()
            msg = orjson.loads(raw)

            if "id" in msg and "method" in msg:
                logger.debug("Client RPC request", device_id=device_id, method=msg.get("method"), req_id=msg.get("id"))
                response = await rpc_handler.handle_request(ctx, msg)
                await ws.send_text(orjson.dumps(response).decode())

            elif msg.get("type") == "heartbeat":
                logger.debug("Client heartbeat", device_id=device_id)
                await client_device_update_last_seen(device_id)

            elif msg.get("type") == "bye":
                logger.debug("Client bye received", device_id=device_id)
                break

    except WebSocketDisconnect:
        logger.info("Client WebSocket disconnected", device_id=device_id)
    except Exception as e:
        logger.error("Client WebSocket error", device_id=device_id, error=str(e), exc_info=True)
    finally:
        if device_id and app.state.clients_ws.get(device_id) is ws:
            del app.state.clients_ws[device_id]
            logger.debug("Client WebSocket cleanup", device_id=device_id)

            agents_to_clean = [
                agent_id for agent_id, active in app.state.agent_active_room.items()
                if active and active.get("client_device_id") == device_id
            ]
            for agent_id in agents_to_clean:
                del app.state.agent_active_room[agent_id]
                logger.debug(
                    "Cleaned up active room for agent",
                    agent_device_id=agent_id,
                    client_device_id=device_id
                )


# ===================== Agent WebSocket Endpoint =====================

@router.websocket("/ws/agent")
async def ws_agent(ws: WebSocket):
    app = ws.app
    await ws.accept()
    logger.debug("Agent WebSocket connection accepted")
    agent_device_id = None
    try:
        server_nonce = secrets.token_bytes(16)
        await ws.send_text(orjson.dumps({
            "type": "server_hello",
            "nonce": b64(server_nonce),
            "ts": int(time.time()),
            "alg": "ed25519",
            "ctx": "viberra-ws-hello-v1"
        }).decode())

        raw = await ws.receive_text()
        msg = orjson.loads(raw)

        if msg.get("type") == "agent_hello":
            agent_device_id = msg["agent_device_id"]
            agent_device_name = msg["agent_device_label"]
            agent_workdir = msg["agent_workdir"]
            ts = int(msg["ts"])
            version = msg.get("version", "0.0.0")

            if abs(time.time() - ts) > 60:
                await ws.close(code=4000)
                return

            sig = b64d(msg["sig"])
            presented_pub_b64 = msg.get("agent_sign_pub")

            token = msg.get("token")
            token_hash_b = b64d(msg["token_hash"]) if msg.get("token_hash") else b"\x00" * 32
            claims = None

            if token:
                claims = paseto_verify(token)
                if not claims:
                    logger.warning("Agent WebSocket auth failed: invalid token", agent_device_id=agent_device_id)
                    await ws.close(code=4401)
                    return

                jti = claims.get("jti")
                if jti:
                    status = await jti_status(jti)
                    if status == "revoked":
                        logger.warning("Agent WebSocket auth failed: revoked token", agent_device_id=agent_device_id, jti=jti)
                        await ws.close(code=4404)
                        return

                if claims.get("aud") != "viberra-ws" or claims.get("sub") != agent_device_id:
                    logger.warning("Agent WebSocket auth failed: audience/subject mismatch", agent_device_id=agent_device_id, aud=claims.get("aud"), sub=claims.get("sub"))
                    await ws.close(code=4403)
                    return

                if hashlib.sha256(token.encode()).digest() != token_hash_b:
                    logger.warning("Agent WebSocket auth failed: token binding mismatch", agent_device_id=agent_device_id)
                    await ws.close(code=4402)
                    return

            known = await AgentDevice.filter(id=agent_device_id).first()
            pairing_mode = msg.get("pairing_mode", False)

            if known and not pairing_mode:
                pub_b = b64d(known.agent_sign_pub)
                ws.scope["viberra_mode"] = "READY"
                logger.debug("Agent authenticated: known device", agent_device_id=agent_device_id, mode="READY")
            else:
                if not presented_pub_b64:
                    logger.warning("Agent WebSocket auth failed: missing public key for unknown device", agent_device_id=agent_device_id)
                    await ws.close(code=4001)
                    return
                pub_b = b64d(presented_pub_b64)
                ws.scope["viberra_mode"] = "PAIRING_ONLY"
                mode_str = "PAIRING_ONLY (reconnect)" if pairing_mode else "PAIRING_ONLY (new)"
                logger.debug("Agent authenticated: new device or pairing mode", agent_device_id=agent_device_id, mode=mode_str)

            ws.scope["version"] = version

            body = b"".join([
                HELLO_CTX,
                server_nonce,
                agent_device_id.encode(),
                str(ts).encode(),
                pub_b,
                token_hash_b
            ])
            try:
                VerifyKey(pub_b).verify(body, sig)
            except BadSignatureError:
                logger.warning("Agent WebSocket auth failed: invalid signature", agent_device_id=agent_device_id)
                await ws.close(code=4002)
                return

            conn_uuid = str(uuid.uuid4())

            app.state.agents_ws[conn_uuid] = ws

            if agent_device_id not in app.state.agent_device_id_to_agent_uuids:
                app.state.agent_device_id_to_agent_uuids[agent_device_id] = set()
            app.state.agent_device_id_to_agent_uuids[agent_device_id].add(conn_uuid)

            ws.scope["agent_device_id"] = agent_device_id
            ws.scope["conn_uuid"] = conn_uuid
            ws.scope["agent_device_name"] = agent_device_name
            ws.scope["agent_workdir"] = agent_workdir

            await store.set_presence(agent_device_id, settings.heartbeat_interval_sec * 3,
                                     {"agent_device_id": agent_device_id,
                                      "version": msg.get("version", "0.0.0"),
                                      "conn_uuid": conn_uuid})

            if known:
                from models import AgentAccess
                accesses = await AgentAccess.filter(agent_device_id=agent_device_id).all()
                for access in accesses:
                    await push_agents_update(app, access.client_device_id)

            scope = "agent:online" if ws.scope.get("viberra_mode") == "READY" else "pair:open"
            session_token, exp, jti = paseto_issue(
                agent_device_id,
                scope,
                ws.scope.get("viberra_mode", "PAIRING_ONLY")
            )

            if session_token and jti:
                await jti_store(jti, exp)

            response = {
                "type": "hello_ok",
                "interval": settings.heartbeat_interval_sec,
                "mode": ws.scope.get("viberra_mode", "PAIRING_ONLY")
            }

            if session_token:
                response["session_token"] = session_token
                response["exp"] = exp

            await ws.send_text(orjson.dumps(response).decode())

            logger.info("Agent WebSocket connected", agent_device_id=agent_device_id, version=version, mode=ws.scope.get("viberra_mode"), conn_uuid=conn_uuid)

        else:
            logger.warning("Agent WebSocket: invalid message type", msg_type=msg.get("type"))
            await ws.close()
            return

        while True:
            raw = await ws.receive_text()
            msg = orjson.loads(raw)
            t = msg.get("type")

            if t == "heartbeat":
                if agent_device_id:
                    logger.debug("Agent heartbeat", agent_device_id=agent_device_id)
                    await store.set_presence(agent_device_id, settings.heartbeat_interval_sec * 3,
                                             {"agent_device_id": agent_device_id, "version": msg.get("version", "0.0.0")})

            elif t == "pair_response":
                # Allowed in both modes (old protocol)
                cid = msg.get("challenge_id")
                fut = app.state.pair_waiters.get(cid)
                if fut and not fut.done():
                    fut.set_result({"sig": msg.get("sig")})

            elif t == "pair_decision":
                cid = msg.get("challenge_id")
                fut = app.state.pair_waiters.get(cid)
                if fut and not fut.done():
                    fut.set_result({
                        "accept": bool(msg.get("accept")),
                        "agent_sign_pub": msg.get("agent_sign_pub"),
                        "agent_static_pub": msg.get("agent_static_pub"),
                        "agent_static_ts": msg.get("agent_static_ts"),
                        "agent_static_sig": msg.get("agent_static_sig"),
                        "sig": msg.get("sig"),
                    })

            elif t == "rtc_signal_from_agent":
                if ws.scope.get("viberra_mode") != "READY":
                    continue
                room_id = msg.get("room_id")
                data = msg.get("data")
                if room_id and data:
                    try:
                        room = await Room.get(room_id=room_id)
                        owner_device_id = room.owner_device_id

                        client_ws = app.state.clients_ws.get(owner_device_id)
                        if client_ws:
                            push_event = {
                                "type": "rtc.signal",
                                "data": {
                                    "room_id": room_id,
                                    "data": data
                                }
                            }
                            try:
                                await client_ws.send_text(orjson.dumps(push_event).decode())
                                logger.debug("RTC signal delivered to client via WebSocket", room_id=room_id, owner_device_id=owner_device_id)
                            except Exception as e:
                                logger.warning("Failed to deliver RTC signal via WebSocket, using Redis fallback", room_id=room_id, error=str(e))
                                await redis.rpush(f"rtc:signals:{room_id}", orjson.dumps({"room_id": room_id, "data": data}))
                        else:
                            logger.debug("Client not connected via WebSocket, storing RTC signal in Redis", room_id=room_id, owner_device_id=owner_device_id)
                            await redis.rpush(f"rtc:signals:{room_id}", orjson.dumps({"room_id": room_id, "data": data}))
                    except DoesNotExist:
                        logger.warning("RTC signal for unknown room", room_id=room_id)
                    except Exception as e:
                        logger.error("Failed to process RTC signal from agent", room_id=room_id, error=str(e), exc_info=True)
                        await redis.rpush(f"rtc:signals:{room_id}", orjson.dumps({"room_id": room_id, "data": data}))

            elif t == "renew_token":
                if not agent_device_id:
                    continue

                scope = "agent:online" if ws.scope.get("viberra_mode") == "READY" else "pair:open"
                mode = ws.scope.get("viberra_mode", "PAIRING_ONLY")
                session_token, exp, jti = paseto_issue(agent_device_id, scope, mode)

                if session_token and jti:
                    await jti_store(jti, exp)
                    await ws.send_text(orjson.dumps({
                        "type": "token_update",
                        "session_token": session_token,
                        "exp": exp
                    }).decode())

            elif t == "bye":
                logger.debug("Agent bye received", agent_device_id=agent_device_id)
                break

    except WebSocketDisconnect:
        logger.info("Agent WebSocket disconnected", agent_device_id=agent_device_id)
    except Exception as e:
        logger.error("Agent WebSocket error", agent_device_id=agent_device_id, error=str(e), exc_info=True)
    finally:
        conn_uuid = ws.scope.get("conn_uuid")
        agent_device_id = ws.scope.get("agent_device_id") or agent_device_id

        if conn_uuid:
            app.state.agents_ws.pop(conn_uuid, None)

            if agent_device_id and agent_device_id in app.state.agent_device_id_to_agent_uuids:
                app.state.agent_device_id_to_agent_uuids[agent_device_id].discard(conn_uuid)
                if not app.state.agent_device_id_to_agent_uuids[agent_device_id]:
                    del app.state.agent_device_id_to_agent_uuids[agent_device_id]

        if agent_device_id and str(agent_device_id) in app.state.agent_active_room:
            active = app.state.agent_active_room[str(agent_device_id)]
            if active and active.get("conn_uuid") == conn_uuid:
                del app.state.agent_active_room[str(agent_device_id)]
                logger.debug(
                    "Cleaned up active room for disconnected agent",
                    agent_device_id=agent_device_id,
                    conn_uuid=conn_uuid
                )

        if agent_device_id:
            from models import AgentAccess
            try:
                accesses = await AgentAccess.filter(agent_device_id=agent_device_id).all()
                for access in accesses:
                    await push_agents_update(app, access.client_device_id)
            except Exception as e:
                logger.debug("Failed to notify clients during agent cleanup", agent_device_id=agent_device_id, error=str(e))

        logger.debug("Agent WebSocket cleanup complete", agent_device_id=agent_device_id, conn_uuid=conn_uuid)
