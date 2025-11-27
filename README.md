# Viberra

[![Version](https://img.shields.io/npm/v/viberra)](https://www.npmjs.com/package/viberra)
[![License](https://img.shields.io/github/license/Oxonomy/viberra)](https://github.com/Oxonomy/viberra/blob/main/LICENSE)
[![Website](https://img.shields.io/badge/website-viberra.life-18181B)](https://viberra.life/)
![term2web.gif](images%2Fterm2web.gif)
> **🔐 Secure P2P access** — end-to-end encrypted WebRTC, no SSH keys, VPNs, or port forwarding

Viberra is an open-source way to keep coding together with your CLI code agent without losing context — and you can continue working right from your phone wherever you are: at the airport, on a walk, in a cafe, or anywhere else.

---

## Overview

Viberra is a self-hosted “access layer” for CLI agents:

- **Remote vibe-coding with your own environment** – full terminal access to your real dev machine, not a sandboxed browser IDE
- **Secure P2P WebRTC** – end-to-end encrypted connection between device and agent, no server middleman for terminal data
- **Device-agnostic** – connect from any modern browser (desktop or mobile)
- **CLI-first** – designed around agents that expose a CLI / TTY interface
- **Open-source** – hackable, auditable, and built to evolve in the open

Access your dev machine's CLI code agent from any device with secure P2P connections.  
Viberra lets you vibecode from a phone, or any browser—no cloud IDE, no SSH hassle.

---

### Key Features

![keep_coding.gif](images%2Fkeep_coding.gif)

- **Session continuity**  
  Keep your agent’s context instead of restarting from scratch every time you switch devices.

- **End-to-end encrypted WebRTC**  
  P2P connection between client and agent (no central server proxying terminal data).

- **Full terminal access**  
  Work in your real environment — your shell, tools, dotfiles, models, and data.

- **Zero-config remote access**  
  No SSH keys, VPNs, or port forwarding. Just run the agent and connect.

- **CLI agent–oriented design**  
  Built specifically around “code agents” that run in a terminal and interact via stdin/stdout.

- **Open-source core**  
  Contributions are welcome — from bug fixes to new transport / UX experiments.

---

### How It Works

At a high level, Viberra consists of three main pieces:

- **Control API (FastAPI + PostgreSQL + Redis)**  
  Coordinates sessions, identity, signaling, and metadata for WebRTC.

- **Agent (Node.js + node-pty + WebRTC)**  
  Runs on your dev machine, attaches to a real PTY, and exposes it over an encrypted P2P channel.

- **Web client (React + Vite + xterm.js)**  
  Runs in the browser (desktop or mobile), rendering the terminal and relaying input/output over WebRTC.

**Flow (simplified):**

1. Start the Viberra agent on your dev machine.
2. The agent registers with the control API for signaling.
3. You open the Viberra web UI from any device and authenticate.
4. Client and agent negotiate a WebRTC P2P connection.
5. Once the tunnel is up, your terminal session flows directly between browser and agent.

---

## Quick Start

> Note: commands and flags are examples — adjust to your actual CLI once it’s stable.

### 1. Install Viberra

From npm:

```bash
npm install -g viberra
# or
pnpm add -g viberra
````

### 2. Start the agent on your dev machine

```bash
viberra agent start
# or, if using npx:
# npx viberra agent
```

This will:

* attach to your local shell via `node-pty`
* connect to the control API for signaling
* expose a WebRTC endpoint for clients

### 3. Open the web client

In your browser:

```text
https://viberra.life
```

Or, if you are self-hosting the web app:

```text
http://localhost:3000
```

Then:

1. Log in / identify your dev machine.
2. Select the agent session.
3. Start vibe-coding with your CLI agent from your current device.

For more detailed setup (self-hosting, TLS, multiple agents), see the docs section below.

---

## Documentation

Planned / recommended documentation structure:

* **Getting Started** – installation, first agent, first remote connection
* **Configuration** – environment variables, multi-agent setups, auth options
* **Architecture** – control API, signaling, WebRTC, PTY handling
* **Security** – threat model, E2EE details, recommended deployment patterns
* **Self-hosting Guide** – running the full stack (API + agent + web) on your own infra
* **CLI Reference** – commands and flags for `viberra` CLI

---

## What's New

Early-stage highlights (example roadmap-style):

* **Alpha:**

    * Initial WebRTC-based P2P terminal bridge
    * Basic agent ↔ web client connectivity
    * Simple session handling

* **Next up:**

    * Multi-session / multi-agent support
    * Better mobile UX
    * Fine-grained access controls and auditing
    * More robust reconnect and resume behavior

Update this section as releases ship (e.g. `v0.1.0`, `v0.2.0`, etc.).

---

## Popular Use Cases

Some ways Viberra can fit into real workflows:

### Nudge long-running work from your phone

You’ve got a long-running CLI agent working through a codebase on your dev machine.
With Viberra, you:

* open the web UI on your phone,
* reconnect to the existing session,
* check progress, tweak prompts, or kick off the next step.

### Remote “one more tweak” to your agent

You’re away from your main laptop but remember a small change your agent needs:

* connect from a different machine,
* attach to the same agent running on your dev box,
* make the edit, run tests, ship.

### Travel / low-trust device workflows

Use Viberra as a way to:

* keep all real work on your own hardware,
* interact via an E2EE terminal from a browser on a temporary device,
* avoid logging into SSH from that device entirely.

---

## Stack

* **Control API:** FastAPI + PostgreSQL + Redis
* **Agent:** Node.js + `node-pty` + WebRTC
* **Web:** React + Vite + `xterm.js`

---

## Contributing

Contributions, ideas, and experiments are very welcome.

* **Issues:**

    * real-world use cases you want to support
    * bugs, rough edges, UX pain points
    * architecture / protocol discussions

* **Pull Requests:**

    * small, focused improvements
    * docs & examples
    * new features aligned with remote vibe-coding + CLI agents

If you’re unsure whether an idea fits, open an issue and describe your workflow — that’s usually the best starting point.

---

## License

Viberra is open-source software licensed under the **Apache-2.0 License**.

See [`LICENSE`](./LICENSE) for details.
