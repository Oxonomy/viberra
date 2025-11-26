import json, time
from typing import Optional, Dict, Any
from redis.asyncio import Redis

PRES_KEY = "presence:device:{}"


class Store:
    def __init__(self, r: Redis):
        self.r = r

    async def set_presence(self, agent_id: str, ttl: int, payload: Dict[str, Any]):
        key = PRES_KEY.format(agent_id)
        payload["ts"] = int(time.time())
        await self.r.set(key, json.dumps(payload), ex=ttl)

    async def get_presence(self, agent_id: str) -> Optional[Dict[str, Any]]:
        raw = await self.r.get(PRES_KEY.format(agent_id))
        return json.loads(raw) if raw else None