from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "agent_devices" (
    "id" UUID NOT NULL PRIMARY KEY,
    "device_name" VARCHAR(128) NOT NULL,
    "agent_static_pub" TEXT NOT NULL,
    "agent_sign_pub" TEXT NOT NULL,
    "fingerprint" VARCHAR(128),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS "client_devices" (
    "device_id" VARCHAR(32) NOT NULL PRIMARY KEY,
    "public_key" BYTEA NOT NULL,
    "fingerprint" VARCHAR(64) NOT NULL UNIQUE,
    "platform" VARCHAR(16),
    "app_version" VARCHAR(32),
    "label" VARCHAR(64),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen" TIMESTAMPTZ,
    "is_active" BOOL NOT NULL DEFAULT True,
    "revoked_at" TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS "idx_client_devi_device__04d340" ON "client_devices" ("device_id", "fingerprint");
COMMENT ON TABLE "client_devices" IS 'Device-as-account model for client devices.';
CREATE TABLE IF NOT EXISTS "agent_access" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "added_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "agent_device_id" UUID NOT NULL REFERENCES "agent_devices" ("id") ON DELETE CASCADE,
    "client_device_id" VARCHAR(32) NOT NULL REFERENCES "client_devices" ("device_id") ON DELETE CASCADE,
    CONSTRAINT "uid_agent_acces_agent_d_6404c9" UNIQUE ("agent_device_id", "client_device_id")
);
CREATE INDEX IF NOT EXISTS "idx_agent_acces_agent_d_6404c9" ON "agent_access" ("agent_device_id", "client_device_id");
COMMENT ON TABLE "agent_access" IS 'Managing client access to agents.';
CREATE TABLE IF NOT EXISTS "rooms" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "room_id" VARCHAR(64) NOT NULL UNIQUE,
    "token" VARCHAR(128) NOT NULL,
    "ttl_sec" INT NOT NULL,
    "expires_at" TIMESTAMPTZ NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" VARCHAR(16) NOT NULL DEFAULT 'open',
    "owner_device_id" VARCHAR(32) REFERENCES "client_devices" ("device_id") ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS "idx_rooms_room_id_03c98b" ON "rooms" ("room_id");
CREATE INDEX IF NOT EXISTS "idx_rooms_expires_ed154b" ON "rooms" ("expires_at");
CREATE INDEX IF NOT EXISTS "idx_rooms_room_id_f38ddc" ON "rooms" ("room_id", "owner_device_id", "expires_at");
CREATE TABLE IF NOT EXISTS "aerich" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "version" VARCHAR(255) NOT NULL,
    "app" VARCHAR(100) NOT NULL,
    "content" JSONB NOT NULL
);"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        """
