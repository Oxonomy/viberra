import process from 'node:process';
import sodium from 'libsodium-wrappers-sumo';
import { opts, parseCliArgs, printHelp, printVersion } from '../src/constants.mjs';
import { runtime as state, agentState } from '../src/state.mjs';
import { log, logE, LOG_FILE } from '../src/logger.mjs';
import { ensureKeysLoaded, loadAgentState, saveAgentState } from '../src/crypto.mjs';
import { spawnInitialPTY, clearCtrlCTimers, flushSendPending } from '../src/pty.mjs';
import { connectControl, sendControl } from '../src/control.mjs';
import { frameCtrl } from '../src/framing-helpers.mjs';
import { printLogo } from '../src/logo.mjs';

// Wait for libsodium readiness before use
await sodium.ready;

const argv = process.argv.slice(2);
parseCliArgs(argv);

// Handle --help and --version early (before key loading)
if (opts.showHelp) {
  printHelp();
  process.exit(0);
}

if (opts.showVersion) {
  printVersion();
  process.exit(0);
}

ensureKeysLoaded();
loadAgentState();

// Handle CLI commands for client management (executed before connecting to server)
if (opts.listClients) {
  process.stdout.write('\n\x1b[1m=== Trusted Clients ===\x1b[0m\n');
  const clients = Object.values(agentState.trusted_clients);
  process.stdout.write('\x1b[37m');
  if (clients.length === 0) {
    process.stdout.write('No trusted clients.\n\n');
  } else {
    for (const c of clients) {
      const label = c.label || c.device_id;
      process.stdout.write(`\n${label}\n`);
      process.stdout.write(`  Device ID:   ${c.device_id}\n`);
      process.stdout.write(`  Fingerprint: ${c.fingerprint}\n`);
      process.stdout.write(`  First seen:  ${c.first_seen}\n`);
      process.stdout.write(`  Last seen:   ${c.last_seen}\n`);
    }
    process.stdout.write(`\nTotal: ${clients.length}\n\n`);
  }
  process.stdout.write('\x1b[0m');
  process.exit(0);
}

if (opts.revokeClient) {
  const deviceId = opts.revokeClient;
  if (agentState.trusted_clients[deviceId]) {
    const label = agentState.trusted_clients[deviceId].label || deviceId;
    delete agentState.trusted_clients[deviceId];
    saveAgentState();
    process.stdout.write(`Client removed from trusted: ${label} (${deviceId})\n`);
  } else {
    process.stdout.write(`Client not found: ${deviceId}\n`);
    process.exit(1);
  }
  process.exit(0);
}

// Print logo on normal startup
printLogo();

log('Options: %o', { ...opts, args: opts.args, LOG_FILE });

// Connect to Control-API
connectControl(() => spawnInitialPTY(cleanupAndExit));

/** Properly frees resources and terminates process. */
function cleanupAndExit(code = 0) {
  clearCtrlCTimers();

  // Send accumulated data before termination
  flushSendPending('EXIT');

  // Notify server of termination
  try { sendControl({ type: 'bye', reason: code === 0 ? 'normal-exit' : 'error-exit' }); } catch {}

  // Notify client via SimplePeer of termination (if connected)
  if (state.current?.peer?.connected) {
    try {
      const shutdownMsg = frameCtrl({
        type: 'shutdown',
        reason: code === 0 ? 'normal-exit' : 'error-exit',
        exitCode: code
      });
      state.current.peer.send(shutdownMsg);
      log('Sent shutdown notification to client (code: %d)', code);
    } catch (e) {
      logE('Failed to send shutdown notification: %s', e?.message || e);
    }
  }

  if (opts.localTty && process.stdin?.isTTY) {
    try { process.stdin.setRawMode(false); } catch {}
    try { process.stdin.pause(); } catch {}
    if (state.onStdinData) { try { process.stdin.off('data', state.onStdinData); } catch {} state.onStdinData = null; }
    if (state.onResize && process.stdout?.off) { try { process.stdout.off('resize', state.onResize); } catch {} state.onResize = null; }
  }

  try { state.term?.kill(); } catch {}

  // Small delay to ensure message delivery
  setTimeout(() => process.exit(code), 100);
}

// Write errors to log and exit without cluttering console
process.on('uncaughtException',  (err)    => { logE('Uncaught exception: %s', err); cleanupAndExit(1); });
process.on('unhandledRejection', (reason) => { logE('Unhandled rejection: %s', reason); cleanupAndExit(1); });

// System signals (if not in raw-mode)
process.on('SIGINT',  () => cleanupAndExit(0));
process.on('SIGTERM', () => cleanupAndExit(0));
