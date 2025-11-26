# Constants and utilities for Ed25519 authentication
HELLO_CTX = b"viberra-ws-hello-v1"

# Constants for client authentication
CLIENT_CTX_REG = b"viberra-client-reg-v1"  # PoP on registration
CLIENT_CTX_REQ = b"viberra-client-dpop-v1"  # PoP of each HTTP request
CLIENT_CTX_RENEW = b"viberra-client-renew-v1"  # PoP for token renewal

# Constant for new pairing flow
PAIR_CTX = b"viberra-pair-v1"

# Constant for client WebSocket handshake
CLIENT_WS_HELLO_CTX = b"viberra-client-ws-hello-v1"
