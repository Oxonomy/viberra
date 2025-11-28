# Viberra

[![npm version](https://img.shields.io/npm/v/viberra)](https://www.npmjs.com/package/viberra)
[![license](https://img.shields.io/npm/l/viberra)](https://github.com/kirillribkin/viberra/blob/main/LICENSE)

> Secure P2P terminal access - end-to-end encrypted WebRTC, no SSH, VPNs or port forwarding

Viberra is a WebRTC-based agent that enables remote access to your local terminal from any device. Perfect for continuing work with your CLI code agents (like Claude Code) from your phone or any browser.

## Quick Start

### Install

```bash
npm install -g viberra
```

### Launch with your CLI agent

```bash
# Start with Claude Code (default)
vibe -c claude

# Or with any other command
vibe -c gemini
vibe -- bash -l
```

### Connect from any device

Open [https://viberra.life/app](https://viberra.life/app) on your phone or browser, scan the QR code, and you're connected via P2P WebRTC.

## Commands

Viberra provides three command aliases: `viberra`, `viberra-agent`, and `vibe` (shortest).

### Usage

```
viberra [options] [command] [args...]
```

### Options

- `-c, --cli <command>` - Set PTY command (default: `claude`)
- `--pair-mode` - Wait for client pairing without spawning PTY
- `--list-clients` - List all trusted clients and exit
- `--revoke-client <id>` - Revoke a trusted client by device ID
- `-h, --help` - Show help message
- `-v, --version` - Show version number

## Examples

```bash
# Start with default CLI agent (Claude Code)
vibe

# Start with a specific CLI agent
vibe -c cursor

# Start with bash
vibe -- bash -l

# Start with zsh
vibe -- zsh

# Pairing mode (wait for client without spawning PTY)
vibe --pair-mode

# List trusted clients
vibe --list-clients

# Revoke a specific client
vibe --revoke-client <device-id>
```

## How It Works

1. **Agent** runs on your dev machine and attaches to a PTY (terminal)
2. **Control API** handles WebRTC signaling and authentication
3. **Web client** connects from any browser via end-to-end encrypted P2P WebRTC
4. Your terminal session flows directly between browser and agent - no server middleman

## Environment Variables

- `CONTROL_WSS_URL` - Control API WebSocket URL (default: `wss://api.viberra.life/ws/agent`)
- `APP_URL` - Web app URL for pairing (default: `https://viberra.life/app`)
- `VIBE_DEVICE_LABEL` - Custom device label (default: hostname)
- `VIBE_CMD` - Default PTY command (default: `claude`)
- `VIBE_LOCAL_TTY` - Enable/disable local TTY bridge (`0` or `1`)

## Documentation

For complete documentation, architecture details, and self-hosting guide, see:

**[https://github.com/kirillribkin/viberra](https://github.com/kirillribkin/viberra)**

## License

Apache-2.0 - see [LICENSE](https://github.com/kirillribkin/viberra/blob/main/LICENSE) for details.
