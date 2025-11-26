from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class AttachDeviceReq(BaseModel):
    agent_id: str
    agent_static_pub: str  # X25519 (base64)
    agent_sign_pub: str  # Ed25519 (base64)
    pair_nonce: str  # one-time code from QR (string)
    fingerprint: Optional[str] = None
    ts: Optional[int] = None


class DeviceOut(BaseModel):
    agent_id: str
    agent_static_pub: str
    agent_sign_pub: str
    fingerprint: Optional[str] = None
