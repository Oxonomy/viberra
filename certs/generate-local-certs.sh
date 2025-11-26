#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_FILE="$SCRIPT_DIR/localhost.pem"
KEY_FILE="$SCRIPT_DIR/localhost-key.pem"

echo "🔐 Viberra Local HTTPS Certificate Generator (using mkcert)"
echo "============================================================"
echo ""

# Check if mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "❌ mkcert is not installed!"
    echo ""
    echo "Please install mkcert using Homebrew:"
    echo "  brew install mkcert"
    echo ""
    echo "Or download from: https://github.com/FiloSottile/mkcert"
    exit 1
fi

echo "✅ mkcert found: $(which mkcert)"
echo ""

# Install local CA (idempotent - won't reinstall if already exists)
echo "📦 Installing local CA to system trust store..."
mkcert -install
echo ""

# Detect LAN IP address
echo "🔍 Detecting LAN IP address..."
LAN_IP=""

# Try macOS method first (en0 is usually Wi-Fi, en1 is Ethernet)
if command -v ipconfig &> /dev/null; then
    LAN_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "")
fi

# Fallback: try Linux/BSD method
if [ -z "$LAN_IP" ] && command -v hostname &> /dev/null; then
    LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")
fi

if [ -n "$LAN_IP" ]; then
    echo "✅ Detected LAN IP: $LAN_IP"
else
    echo "⚠️  Could not auto-detect LAN IP. Using localhost only."
    echo "   To add your LAN IP manually, run:"
    echo "   mkcert -cert-file localhost.pem -key-file localhost-key.pem localhost 127.0.0.1 ::1 YOUR_IP"
fi
echo ""

# Generate certificate with SAN (Subject Alternative Names)
echo "🔑 Generating certificate with SAN..."
echo "   Subject Alternative Names:"
echo "   - localhost"
echo "   - 127.0.0.1 (IPv4 loopback)"
echo "   - ::1 (IPv6 loopback)"
if [ -n "$LAN_IP" ]; then
    echo "   - $LAN_IP (your LAN IP for mobile testing)"
fi
echo ""

# Build mkcert command with all SANs
MKCERT_ARGS=(
    -cert-file "$CERT_FILE"
    -key-file "$KEY_FILE"
    localhost
    127.0.0.1
    "::1"
)

if [ -n "$LAN_IP" ]; then
    MKCERT_ARGS+=("$LAN_IP")
fi

mkcert "${MKCERT_ARGS[@]}"
echo ""

# Verify files were created
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "✅ Certificate generated successfully!"
    echo ""
    echo "📁 Files created:"
    echo "   Certificate: $CERT_FILE"
    echo "   Private Key: $KEY_FILE"
    echo ""
    echo "🎉 You can now run your dev server with HTTPS!"
    echo ""
    if [ -n "$LAN_IP" ]; then
        echo "📱 To test from mobile device on same network:"
        echo "   https://$LAN_IP:3000"
        echo ""
    fi
    echo "💡 Tip: Your browser will trust this certificate automatically."
else
    echo "❌ Failed to generate certificate files"
    exit 1
fi
