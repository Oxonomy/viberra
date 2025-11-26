import process from 'node:process';
import pty from 'node-pty';
import sodium from 'libsodium-wrappers-sumo';
import { opts, CTRL_C, CTRL_D, ESCALATE_1_MS, ESCALATE_2_MS, MAX_CHUNK_SIZE, MAX_RING, MAX_SEND_SIZE } from './constants.mjs';
import { runtime as state } from './state.mjs';
import { log, logW } from './logger.mjs';
import { frameCtrl, framePty, toBuffer } from './framing-helpers.mjs';
import { encryptChunk } from './webrtc-crypto.mjs';

/** Adds data to PTY output ring buffer. Combines small chunks (<1KB) for efficiency. */
export function ringPush(chunk) {
  const c = toBuffer(chunk);

  state.pendingChunk = Buffer.concat([state.pendingChunk, c]);

  // If accumulated >= 1KB, save as separate chunk
  if (state.pendingChunk.length >= MAX_CHUNK_SIZE) {
    state.ringChunks.push(state.pendingChunk);
    state.ringTotalBytes += state.pendingChunk.length;
    state.pendingChunk = Buffer.alloc(0);

    // Evict old chunks if exceeded limit
    while (state.ringTotalBytes > MAX_RING && state.ringChunks.length > 0) {
      const removed = state.ringChunks.shift();
      state.ringTotalBytes -= removed.length;
    }
  }
}

/** Sends accumulated data to peer and clears timer. */
export function flushSendPending(reason = 'UNKNOWN') {
  if (state.sendTimer) {
    clearTimeout(state.sendTimer);
    state.sendTimer = null;
  }

  if (state.sendPending.length > 0 && state.current?.peer?.connected && state.current.sizeOk) {
    log('Flushing send pending (%s): %d bytes', reason, state.sendPending.length);
    try {
      // E2EE: encrypt PTY data before sending
      if (!state.enc.ready) {
        logW('E2EE not ready, cannot send PTY data');
        return;
      }

      const ptyFrame = framePty(state.sendPending);
      const encrypted = encryptChunk(sodium, state.enc, ptyFrame);
      state.current.peer.send(encrypted);
    } catch (err) {
      log('Send failed (%s): %s', reason, err.message);
    }
    state.sendPending = Buffer.alloc(0);
  } else {
    // For diagnostics — if flush called but nothing sent
    log('Flush skipped (%s): nothing to send or peer not ready', reason);
  }
}

/**
 * Resets ring buffer and resizes PTY if needed.
 * If force === true — resize even if dimensions match.
 */
export function resetRingAndResize(cols, rows, { force = false } = {}) {
  if (!state.term) return;

  const needResize =
    (state.term.cols ?? 0) !== cols ||
    (state.term.rows ?? 0) !== rows;

  if (!force && !needResize){
    log('Size not changed: cols=%d, rows=%d, force=%s', cols, rows, force);
    return;
  }

  // Clear accumulated output before "new" render
  state.ringChunks = [];
  state.ringTotalBytes = 0;
  try {
    if (force && !needResize){
      state.term.resize(cols, rows-1)
    }
    else {
      state.term.resize(cols, rows)
    }

    log('Resized PTY to %dx%d', cols, rows);
  } catch (e) {
    logW('Failed to resize PTY: %s', e?.message || e);
  }
}

/**
 * Enables PTY data sending mode and flushes backlog once.
 * Called after first resize from client.
 * IMPORTANT: Now sends encrypted data!
 */
export function markSizeOkAndFlush() {
  if (!state.current || state.current.sizeOk || !state.current.peer?.connected) return;

  // E2EE: Don't send anything until encryption is ready
  if (!state.enc.ready) {
    logW('markSizeOkAndFlush: E2EE not ready, cannot flush backlog');
    return;
  }

  state.current.sizeOk = true;

  try {
    // First, what accumulated in pendingChunk (small pieces)
    if (state.pendingChunk.length > 0) {
      const ptyFrame = framePty(state.pendingChunk);
      const encrypted = encryptChunk(sodium, state.enc, ptyFrame);
      state.current.peer.send(encrypted);
    }

    // Then all chunks from ring buffer
    for (const chunk of state.ringChunks) {
      const ptyFrame = framePty(chunk);
      const encrypted = encryptChunk(sodium, state.enc, ptyFrame);
      state.current.peer.send(encrypted);
    }

    // Just in case — what might have accumulated in sendPending
    if (state.sendPending.length > 0) {
      const ptyFrame = framePty(state.sendPending);
      const encrypted = encryptChunk(sodium, state.enc, ptyFrame);
      state.current.peer.send(encrypted);
      state.sendPending = Buffer.alloc(0);
    }
  } catch (e) {
    logW('Failed to flush PTY backlog after size negotiation: %s', e?.message || e);
  }
}

/**
 * Starts PTY, configures:
 *  - PTY flow → console (if localTty) and → remote DC;
 *  - local input/resize → PTY and optionally notify DC;
 *  - PTY termination ⇒ agent termination.
 */
export function spawnInitialPTY(cleanupAndExit) {
  let cols = 100;
  let rows = 30;

  state.term = pty.spawn(opts.cmd, opts.args, {
    name: 'xterm-256color',
    cols, rows,
    cwd: process.cwd(),
    env: process.env,
  });

  state.term.onExit(({ exitCode }) => {
    log('PTY exited: %s', exitCode);
    cleanupAndExit(exitCode ?? 0);
  });

  state.term.onData((data) => {
    const buf = toBuffer(data);
    ringPush(buf);

    // Local output — as before
    if (opts.localTty && process.stdout?.write) {
      try { process.stdout.write(buf); } catch {}
    }

    // To network — ONLY if there's active peer and size already negotiated
    if (state.current?.peer?.connected && state.current.sizeOk) {
      // Clear current timer if exists
      if (state.sendTimer) {
        clearTimeout(state.sendTimer);
        state.sendTimer = null;
      }

      state.sendPending = Buffer.concat([state.sendPending, buf]);

      // If accumulated >= MAX_SEND_SIZE - send immediately
      if (state.sendPending.length >= MAX_SEND_SIZE) {
        flushSendPending('MAX_SEND_SIZE');
      } else {
        // Otherwise wait 10ms
        state.sendTimer = setTimeout(() => flushSendPending('TIMER'), 10);
      }
    }
  });

  if (opts.localTty && process.stdin?.isTTY) {
    try { process.stdin.setRawMode(true); } catch {}
    process.stdin.resume();

    state.onStdinData = (d) => {
      if (!state.term) return;
      const buf = Buffer.isBuffer(d) ? d : Buffer.from(d);
      if (buf.includes(CTRL_C)) { handleCtrlC(cleanupAndExit); return; }
      if (buf.includes(CTRL_D)) { try { state.term.kill(); } catch {} return; }
      try { state.term.write(buf); } catch {}
    };
    process.stdin.on('data', state.onStdinData);

    state.onResize = () => {
      const c = process.stdout?.columns ?? cols;
      const r = process.stdout?.rows ?? rows;

      // Local screen is our "source of truth", so always hard resize
      resetRingAndResize(c, r, { force: true });
    };
    if (typeof process.stdout?.on === 'function') process.stdout.on('resize', state.onResize);
  } else if (!opts.localTty) {
    log('Local TTY bridge disabled.');
  }

  cols = process.stdout?.columns ?? cols;
  rows = process.stdout?.rows ?? rows;
  try { state.term?.resize(cols, rows); } catch {}

  log('PTY spawned: %s %s', opts.cmd, opts.args.join(' '));
}

export function handleCtrlC(cleanupAndExit) {
  if (!state.term) { cleanupAndExit(0); return; }
  if (state.ctrlCArmed) {
    logW('Ctrl-C x2: force exit now');
    forceKillAndExit(cleanupAndExit);
    return;
  }

  state.ctrlCArmed = true; setTimeout(() => { state.ctrlCArmed = false; }, 800);

  try {
    if (process.platform === 'win32') {
      state.term.write(Buffer.from([CTRL_C])); // Windows
    } else {
      state.term.kill('SIGINT'); // Unix
    }
  } catch {}
  clearCtrlCTimers();

  state.ctrlCTimers.t1 = setTimeout(() => {
    if (!state.term) return;
    logW('Escalate: SIGTERM');
    try { state.term.kill('SIGTERM'); } catch {}

    state.ctrlCTimers.t2 = setTimeout(() => {
      if (!state.term) return;
      logW('Escalate: FORCE KILL');
      forceKillAndExit(cleanupAndExit);
    }, ESCALATE_2_MS);
  }, ESCALATE_1_MS);
}

export function clearCtrlCTimers() {
  if (state.ctrlCTimers.t1) { clearTimeout(state.ctrlCTimers.t1); state.ctrlCTimers.t1 = null; }
  if (state.ctrlCTimers.t2) { clearTimeout(state.ctrlCTimers.t2); state.ctrlCTimers.t2 = null; }
}

export function forceKillAndExit(cleanupAndExit) {
  clearCtrlCTimers();
  try { state.term?.kill(); } catch {}
  cleanupAndExit(0);
}
