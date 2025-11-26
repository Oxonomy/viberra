import process from 'node:process';
import os from 'node:os';
import crypto from 'node:crypto';
import wrtcLib from '@roamhq/wrtc';
import { VERSION } from './version.mjs';

export const RETRY_DELAY_MS   = 2000;
export const ESCALATE_1_MS    = 1500;
export const ESCALATE_2_MS    = 1500;
export const CTRL_C           = 0x03; // ^C (ETX)
export const CTRL_D           = 0x04; // ^D (EOT)
export const HELLO_CTX        = Buffer.from('viberra-ws-hello-v1'); // Context for Ed25519 authentication
export const PAIR_CTX         = Buffer.from('viberra-pair-v1'); // Context for new pairing flow

// Generate 6-digit pairing code
export let pairCode = String(crypto.randomInt(100000, 999999)).padStart(6, '0');

// Ring buffer constants
export const MAX_CHUNK_SIZE = 1024;
export const MAX_SEND_SIZE = 32 * 1024 * 1024;
export const MAX_RING       = 2 * 1024 * 1024;

// Client state constants
export const MAX_CONNECTIONS = 100;  // Keep last N connections

/**
 * @typedef {Object} AgentOptions
 * @property {string}  controlUrl  - WSS address of Control-API (ws[s]://.../ws/agent)
 * @property {string|null}  agentId     - Agent identifier (UUID)
 * @property {string}  agentVersion
 * @property {string}  deviceLabel - Device name
 * @property {string}  launchCwd   - Absolute path of the directory from which agent was launched
 * @property {string}  cmd         - PTY command (default 'claude', set via --cli/-c)
 * @property {string[]} args       - PTY command arguments
 * @property {boolean} localTty    - Whether local TTY bridge is enabled
 * @property {boolean} pairingMode - Reconnection mode (pairing without PTY spawn)
 */
export const opts /** @type {AgentOptions} */ = {
  controlUrl: process.env.CONTROL_WSS_URL || 'wss://api.viberra.life/ws/agent',
  appUrl: process.env.APP_URL || 'https://viberra.life/app',
  agentId: null, // Will be loaded/generated in ensureKeysLoaded()
  agentVersion: process.env.AGENT_VERSION || VERSION,
  deviceLabel: process.env.VIBE_DEVICE_LABEL || os.hostname(),
  launchCwd: process.cwd(),
  cmd: process.env.VIBE_CMD || 'claude',
  args: [],
  localTty: process.env.VIBE_LOCAL_TTY ? process.env.VIBE_LOCAL_TTY === '1'
      : !!(process.stdin.isTTY && process.stdout.isTTY),
  pairingMode: false, // Reconnection mode flag (--pair-mode)
  listClients: false, // --list-clients flag
  revokeClient: null, // device_id for --revoke-client
  showHelp: false, // --help/-h flag
  showVersion: false, // --version/-v flag
};

/** Builds QR code URL with agent and code parameters */
export function buildPairUrl() {
  const base = opts.appUrl;
  const q = new URLSearchParams({ agent: opts.agentId, code: pairCode });
  return `${base}/?${q.toString()}`; // SPA will pick up parameters from location.search
}

function pickWrtc(mod) {
  const c = [mod, mod?.default, mod?.wrtc];
  for (const m of c) {
    if (
        m &&
        typeof m.RTCPeerConnection === 'function' &&
        typeof m.RTCIceCandidate === 'function' &&
        typeof m.RTCSessionDescription === 'function'
    ) return m;
  }
  throw new Error('No usable wrtc export');
}
export const WRTC = pickWrtc(wrtcLib);

// Expose to globals as fallback (some libraries expect this)
Object.assign(globalThis, {
  RTCPeerConnection: globalThis.RTCPeerConnection || WRTC.RTCPeerConnection,
  RTCSessionDescription: globalThis.RTCSessionDescription || WRTC.RTCSessionDescription,
  RTCIceCandidate: globalThis.RTCIceCandidate || WRTC.RTCIceCandidate,
});

/**
 * Parses command-line arguments and modifies opts in place
 * @param {string[]} argv - Command-line arguments
 */
export function parseCliArgs(argv) {
  let i = 0, seenDashes = false;
  while (i < argv.length) {
    const a = argv[i];
    if (!seenDashes && a === '--') { seenDashes = true; i++; break; }
    if (!seenDashes && (a === '--help' || a === '-h')) { opts.showHelp = true; i++; continue; }
    if (!seenDashes && (a === '--version' || a === '-v')) { opts.showVersion = true; i++; continue; }
    if (!seenDashes && (a === '--cli' || a === '-c')) { opts.cmd = argv[++i]; i++; continue; }
    if (!seenDashes && a === '--pair-mode') { opts.pairingMode = true; i++; continue; }
    if (!seenDashes && a === '--list-clients') { opts.listClients = true; i++; continue; }
    if (!seenDashes && a === '--revoke-client') { opts.revokeClient = argv[++i]; i++; continue; }
    break;
  }
  if (i < argv.length) { const rest = argv.slice(i); if (rest.length > 0) { opts.cmd = rest[0]; opts.args = rest.slice(1); } }
}

/**
 * Prints version information and exits
 */
export function printVersion() {
  process.stdout.write(`viberra v${VERSION}\n`);
}

/**
 * Prints help message and exits
 */
export function printHelp() {
  process.stdout.write(`viberra v${VERSION} - Secure remote terminal over WebRTC

Usage: viberra [options] [command] [args...]

Options:
  -h, --help              Show this help message
  -v, --version           Show version number
  -c, --cli <command>     Set PTY command (default: claude)
  --pair-mode             Wait for client pairing (don't spawn PTY)
  --list-clients          List trusted clients and exit
  --revoke-client <id>    Revoke trusted client and exit

Examples:
  viberra                 Start agent with default command (claude)
  viberra -- bash -l      Start agent with bash
  viberra --pair-mode     Wait for pairing without spawning PTY

For more details, see: https://github.com/kirillribkin/viberra
`);
}
