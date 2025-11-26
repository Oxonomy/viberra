import { Buffer } from 'node:buffer';

// Keep agentState separate (used by crypto.mjs with direct import)
export const agentState = {
  trusted_clients: {},  // device_id -> { device_id, fingerprint, label, first_seen, last_seen, psk_b64 }
  connections: [],      // [{ ts, device_id, label, fingerprint, room_id }]
};

/**
 * Mutable runtime state object
 * Use: import { runtime as state } from './state.mjs'
 * Then: state.control = new WebSocket(...)
 */
export const runtime = {
  ringChunks: [],                    // Array of chunks
  ringTotalBytes: 0,                 // Total size of all chunks
  pendingChunk: Buffer.alloc(0),     // Accumulator for small chunks (<1KB)

  /**
   * @type {SessionState|null}
   * @typedef {Object} SessionState
   * @property {SimplePeer.Instance} peer
   * @property {() => void} kill
   * @property {string} roomId
   * @property {boolean} sizeOk   // true after first resize from client
   */
  current: null,

  /** @type {WebSocket|null} */
  control: null,

  /** @type {NodeJS.Timeout|null} */
  hbTimer: null,

  /** @type {import('node-pty').IPty|null} */
  term: null,

  sendPending: Buffer.alloc(0),      // Accumulator for sending to peer

  /** @type {NodeJS.Timeout|null} */
  sendTimer: null,                    // Deferred send timer

  lastClientSize: { cols: null, rows: null },

  onStdinData: null,
  onResize: null,

  /** @type {{t1: NodeJS.Timeout|null, t2: NodeJS.Timeout|null}} */
  ctrlCTimers: { t1: null, t2: null },

  ctrlCArmed: false,

  sessionToken: null,  // Current PASETO token
  sessionExp: 0,        // Unix timestamp of token expiration

  /** @type {NodeJS.Timeout|null} */
  renewTimer: null,     // Timer for automatic token renewal

  pairPromptActive: false,

  /**
   * E2EE encryption state for current WebRTC connection
   * @type {{
   *   ready: boolean,
   *   keySend: Buffer|null,
   *   keyRecv: Buffer|null,
   *   noncePrefixSend: Buffer|null,
   *   noncePrefixRecv: Buffer|null,
   *   sendCounter: bigint,
   *   recvCounter: bigint,
   *   handshakeInProgress: boolean,
   *   handshakeTimeout: NodeJS.Timeout|null
   * }}
   */
  enc: {
    ready: false,
    keySend: null,
    keyRecv: null,
    noncePrefixSend: null,
    noncePrefixRecv: null,
    sendCounter: 0n,
    recvCounter: 0n,
    handshakeInProgress: false,
    handshakeTimeout: null,
  },
};

/**
 * Resets E2EE state for new/closed connection
 */
export function resetEncState() {
  runtime.enc = {
    ready: false,
    keySend: null,
    keyRecv: null,
    noncePrefixSend: null,
    noncePrefixRecv: null,
    sendCounter: 0n,
    recvCounter: 0n,
    handshakeInProgress: false,
  };
}
