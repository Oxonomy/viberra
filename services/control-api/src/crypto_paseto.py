import pyseto
import secrets, json
from typing import Optional, Dict
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass


@dataclass
class PasetoKeyPair:
    kid: str
    priv: pyseto.Key  # for signing
    pub: pyseto.Key  # for verification


class PasetoKeyRing:
    def __init__(self):
        self._by_kid: Dict[str, PasetoKeyPair] = {}
        self._active_kid: Optional[str] = None

    def add_pair(self, pair: PasetoKeyPair, active: bool = False):
        self._by_kid[pair.kid] = pair
        if active or self._active_kid is None:
            self._active_kid = pair.kid

    @property
    def active(self) -> PasetoKeyPair:
        return self._by_kid[self._active_kid]

    def get_by_kid(self, kid: str) -> Optional[PasetoKeyPair]:
        return self._by_kid.get(kid)


keyring = PasetoKeyRing()


def load_keys_from_settings(settings):
    """
    Load PEM keys from files or strings (env), form active pair.
    No seeds, only PEM.
    """
    kid = settings.paseto_kid
    if not kid:
        raise RuntimeError("PASETO_KID is required")

    # 1) Private PEM
    if getattr(settings, "paseto_priv_pem", None):
        priv_pem = settings.paseto_priv_pem.encode()
    elif getattr(settings, "paseto_priv_pem_path", None):
        priv_pem = open(settings.paseto_priv_pem_path, "rb").read()
    else:
        raise RuntimeError("No private PEM configured")

    # 2) Public PEM
    if getattr(settings, "paseto_pub_pem", None):
        pub_pem = settings.paseto_pub_pem.encode()
    elif getattr(settings, "paseto_pub_pem_path", None):
        pub_pem = open(settings.paseto_pub_pem_path, "rb").read()
    else:
        raise RuntimeError("No public PEM configured")

    priv = pyseto.Key.new(4, "public", priv_pem)  # ← IMPORTANT: PEM
    pub = pyseto.Key.new(4, "public", pub_pem)  # ← IMPORTANT: PEM

    pair = PasetoKeyPair(kid=kid, priv=priv, pub=pub)
    keyring.add_pair(pair, active=True)


def issue_token(subject_id: str, scope: str, mode: str, ttl_sec: int, audience: str):
    pair = keyring.active
    now_dt = datetime.now(timezone.utc)
    exp_dt = now_dt + timedelta(seconds=int(ttl_sec))

    iso = lambda dt: dt.isoformat().replace("+00:00", "Z")
    jti = secrets.token_hex(16)

    claims = {
        "iss": "viberra-control",
        "aud": audience,
        "sub": subject_id,
        "scope": scope,
        "mode": mode,
        "iat": iso(now_dt),
        "nbf": iso(now_dt),
        "exp": iso(exp_dt),          # ← ISO-8601 instead of int
        "jti": jti,
        "kid": pair.kid,             # ← key label for rotation
    }
    tok = pyseto.encode(pair.priv, claims, serializer=json).decode()
    return tok, int(exp_dt.timestamp()), jti


def verify_token(token: str) -> Optional[dict]:
    pair = keyring.active
    try:
        dec = pyseto.decode(pair.pub, token.encode(), deserializer=json)
        return dec.payload
    except Exception as e:
        for k, other in list(keyring._by_kid.items()):
            if k == pair.kid:
                continue
            try:
                dec = pyseto.decode(other.pub, token.encode(), deserializer=pyseto.json)
                return dec.payload
            except Exception as e:
                pass
    return None
