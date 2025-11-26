from pydantic import AnyUrl
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # infra
    redis_url: AnyUrl = "redis://redis:6379/0"
    turn_realm: str = "example.com"
    turn_secret: str
    turn_host: str = "localhost"
    turn_port: int = 3478
    turn_tls_port: int = 5349
    heartbeat_interval_sec: int = 15
    room_ttl_sec: int = 300
    db_url: str = "postgres://USER:PASSWORD@HOST:5432/DBNAME"
    env: str = "dev"  # dev|staging|prod

    # PASETO v4.public (new fields)
    paseto_kid: str = ""  # e.g. "v4-202510-f19c"
    paseto_priv_pem_path: Optional[str] = None
    paseto_pub_pem_path: Optional[str] = None
    paseto_priv_pem: Optional[str] = None  # if storing PEM directly in ENV/secret manager
    paseto_pub_pem: Optional[str] = None

    paseto_ttl_sec: int = 600

    # Feature flags
    ws_rpc_enabled: bool = True  # Enable WebSocket RPC (new architecture)
    http_endpoints_deprecated: bool = True  # Mark HTTP endpoints as deprecated

    # Logging configuration
    log_level: str = "INFO"  # DEBUG|INFO|WARNING|ERROR|CRITICAL
    log_format: str = "text"  # text|json (json for production)

    class Config:
        env_prefix = ""
        case_sensitive = False


settings = Settings()
