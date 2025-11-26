from tortoise import fields
from tortoise.models import Model


class AgentDevice(Model):
    id = fields.UUIDField(pk=True)
    device_name = fields.CharField(max_length=128, unique=False)

    agent_static_pub = fields.TextField()  # X25519 (base64)
    agent_sign_pub = fields.TextField()  # Ed25519 (base64)
    fingerprint = fields.CharField(max_length=128, null=True)  # SHA256(pub) or other printable

    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "agent_devices"


class Room(Model):
    id = fields.IntField(pk=True)
    room_id = fields.CharField(max_length=64, unique=True, index=True)

    # Owner device (FK → ClientDevice)
    owner_device: fields.ForeignKeyRelation["ClientDevice"] = fields.ForeignKeyField(
        "models.ClientDevice",
        related_name="rooms",
        on_delete=fields.CASCADE,
        null=True,
    )

    token = fields.CharField(max_length=128)
    ttl_sec = fields.IntField()
    expires_at = fields.DatetimeField(index=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    status = fields.CharField(max_length=16, default="open")  # open/closed/expired

    class Meta:
        table = "rooms"
        indexes = ["room_id", "owner_device", "expires_at"]


class ClientDevice(Model):
    """Device-as-account model for client devices.

    Device is identified by Ed25519 public key.
    device_id = SHA256(public_key)[:32] in hex.
    """
    device_id = fields.CharField(max_length=32, pk=True)  # SHA256(pub)[:32] in hex
    public_key = fields.BinaryField()  # 32 bytes Ed25519 public key
    fingerprint = fields.CharField(max_length=64, unique=True)  # SHA256:base64 for display
    client_static_pub = fields.TextField(null=True)  # X25519 public key (base64) for E2EE ECDH
    client_static_ts = fields.BigIntField(null=True)  # timestamp (ms) for client_static_pub signature
    client_static_sig = fields.TextField(null=True)  # Ed25519 signature for client_static_pub (base64)

    # Device metadata
    platform = fields.CharField(max_length=16, null=True)  # ios/android/web
    app_version = fields.CharField(max_length=32, null=True)  # app version
    label = fields.CharField(max_length=64, null=True)  # user-defined device name

    # Timestamps
    created_at = fields.DatetimeField(auto_now_add=True)
    last_seen = fields.DatetimeField(null=True)  # updated on each successful DPoP

    # Device status
    is_active = fields.BooleanField(default=True)  # false = revoked/blocked
    revoked_at = fields.DatetimeField(null=True)  # when was revoked

    class Meta:
        table = "client_devices"
        indexes = ["device_id", "fingerprint"]


class AgentAccess(Model):
    """Managing client access to agents.

    Allows one agent to be linked to multiple client devices.
    All devices have equal access rights to the agent.
    """
    id = fields.IntField(pk=True)

    # Agent and client associated with this access
    agent_device: fields.ForeignKeyRelation["AgentDevice"] = fields.ForeignKeyField(
        "models.AgentDevice",
        related_name="client_accesses",
        on_delete=fields.CASCADE,
    )
    client_device: fields.ForeignKeyRelation["ClientDevice"] = fields.ForeignKeyField(
        "models.ClientDevice",
        related_name="agent_accesses",
        on_delete=fields.CASCADE,
    )

    # When access was added
    added_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "agent_access"
        indexes = ["agent_device", "client_device"]
        unique_together = [("agent_device", "client_device")]
