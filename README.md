# viberra

Access your dev machine's CLI code agent from any device with secure P2P connections.

Viberra lets you vibecode on your own hardware from an phone, or any browser—no cloud IDE, no SSH hassle. 

**Key features:**
- End-to-end encrypted WebRTC connection (P2P, no server middleman)
- Full terminal access with your environment, not a sandboxed browser IDE
- Zero config: no SSH keys, VPNs, or port forwarding

## Stack

- **Control API**: FastAPI + PostgreSQL + Redis
- **Agent**: Node.js + node-pty + WebRTC
- **Web**: React + Vite + xterm.js

## License

Apache License
