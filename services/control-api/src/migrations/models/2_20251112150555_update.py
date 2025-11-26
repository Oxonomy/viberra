from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "client_devices" ADD "client_static_ts" BIGINT;
        ALTER TABLE "client_devices" ADD "client_static_sig" TEXT;"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "client_devices" DROP COLUMN "client_static_ts";
        ALTER TABLE "client_devices" DROP COLUMN "client_static_sig";"""
