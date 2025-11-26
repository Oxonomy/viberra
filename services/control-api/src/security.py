import base64
import hashlib
import time
from typing import Optional

from fastapi import HTTPException, Request
from loguru import logger
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from redis.asyncio import Redis

from settings import settings
from redis_store import Store
from crypto_paseto import load_keys_from_settings, issue_token, verify_token
from protocol_constants import CLIENT_CTX_REQ


# ===================== Redis Instance =====================

redis = Redis.from_url(str(settings.redis_url), decode_responses=True)
store = Store(redis)


# ===================== Base64 Utilities =====================

def b64(b: bytes) -> str:
    """Encodes bytes to base64 string"""
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    """Decodes base64 string to bytes"""
    return base64.b64decode(s)


# ===================== JTI (JWT ID) Management =====================

def jti_key(jti: str) -> str:
    """Forms Redis key for JTI"""
    return f"paseto:jti:{jti}"


async def jti_status(jti: str) -> Optional[str]:
    """Returns JTI status: issued/revoked/None"""
    return await redis.get(jti_key(jti))


async def jti_store(jti: str, exp_ts: int):
    """Saves JTI in Redis with TTL until token expiration"""
    ttl = max(1, exp_ts - int(time.time()))
    await redis.setex(jti_key(jti), ttl, "issued")


async def jti_revoke(jti: str, exp_ts: Optional[int] = None):
    """Revokes token by marking JTI as revoked"""
    if exp_ts:
        ttl = max(1, exp_ts - int(time.time()))
        await redis.setex(jti_key(jti), ttl, "revoked")
    else:
        # If exp not specified, set default TTL (1 hour)
        await redis.setex(jti_key(jti), 3600, "revoked")


# ===================== PASETO Token Management =====================

def paseto_issue(subject_id: str, scope: str, mode: str, ttl_sec: int | None = None, audience: str = "viberra-ws"):
    """Wrapper for issuing PASETO token"""
    ttl = ttl_sec or settings.paseto_ttl_sec
    return issue_token(subject_id, scope, mode, ttl, audience)


def paseto_verify(token: str) -> Optional[dict]:
    """Wrapper for PASETO token verification"""
    return verify_token(token)


# ===================== DPoP Authentication =====================

async def require_client(request: Request):
    """
    Requires DPoP authentication:
    - Authorization: Bearer <PASETO>
    - X-Auth-TS: <int>
    - X-Auth-Sig: base64( Sign( CTX_REQ || METHOD || PATH || TS || SHA256(token) ) )

    Returns claims from token on successful authentication
    """
    # Import here to avoid circular dependencies
    from services import client_device_get, client_device_update_last_seen

    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "missing token")

    token = auth.split(" ", 1)[1]

    claims = paseto_verify(token)
    if not claims or claims.get("aud") != "viberra-app" or claims.get("scope") != "client":
        raise HTTPException(401, "invalid token")

    jti = claims.get("jti")
    if jti and (await jti_status(jti)) == "revoked":
        raise HTTPException(401, "revoked")

    device_id = claims["sub"]

    device = await client_device_get(device_id)
    if not device:
        raise HTTPException(401, "unknown device")

    pub_b = device.public_key

    try:
        x_ts = int(request.headers.get("x-auth-ts") or "0")
        x_sig = b64d(request.headers.get("x-auth-sig") or "")
    except Exception:
        raise HTTPException(401, "bad dpop headers")

    if abs(time.time() - x_ts) > 60:
        raise HTTPException(401, "stale dpop ts")

    th = hashlib.sha256(token.encode()).digest()
    path = request.url.path.encode()
    m = b"".join([CLIENT_CTX_REQ, request.method.encode(), path, str(x_ts).encode(), th])

    try:
        VerifyKey(pub_b).verify(m, x_sig)
    except BadSignatureError:
        raise HTTPException(401, "bad dpop signature")

    await client_device_update_last_seen(device_id)

    return claims


# ===================== Initialization =====================

# Load PASETO keys on module import
load_keys_from_settings(settings)


# ===================== Exports =====================

__all__ = [
    'redis',
    'store',
    'b64',
    'b64d',
    'jti_key',
    'jti_status',
    'jti_store',
    'jti_revoke',
    'paseto_issue',
    'paseto_verify',
    'require_client',
]
