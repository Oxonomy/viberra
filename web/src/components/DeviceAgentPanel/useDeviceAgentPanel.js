import { useState, useRef, useEffect } from 'react';
import { bootstrapClient, authFetch, getClientStaticKey, getDeviceKey, getSodium } from '../../lib/client-auth';
import { getWSClient } from '../../lib/ws-rpc-client';
import { savePSK, loadPSK, saveAgentSignPub, loadAgentSignPub } from '../../lib/key-store';
import { deriveSessionKeys, encryptChunk, decryptChunk } from '../../lib/webrtc-crypto';
import {
  fetchAgentsList,
  pairAgent,
  unbindAgent,
  createRoom,
  inviteAgentToRoom,
  sendRTCSignal,
  consumeRTCSignals
} from '../../lib/device-agent-api';

/**
 * Concatenate Uint8Array (libsodium doesn't provide concatArrays)
 * @param {...Uint8Array} arrays - arrays to concatenate
 * @returns {Uint8Array} concatenation result
 */
function concatUint8Arrays(...arrays) {
  const filtered = arrays.filter(Boolean);

  if (filtered.length === 0) {
    return new Uint8Array(0);
  }

  const totalLength = filtered.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of filtered) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

export function useDeviceAgentPanel() {
  // ========== State Variables (28) ==========
  const [showQRModal, setShowQRModal] = useState(false);
  const [activeTerminal, setActiveTerminal] = useState(null);  // Session UUID
  const [activeDeviceId, setActiveDeviceId] = useState(null);  // Device's device_id
  const [activeLabel, setActiveLabel] = useState('');
  const [connectStage, setConnectStage] = useState('idle'); // idle|preparing|room|invite|rtc-init|signal→ws|connected|reconnecting|closed|error
  const [agent_devices, setAgents] = useState([]);
  const [agentsStatus, setAgentsStatus] = useState('idle'); // idle|loading|loaded|error
  const [apiBase, setApiBase] = useState('');
  const [authStatus, setAuthStatus] = useState('initializing');
  const [notification, setNotification] = useState({ isOpen: false, type: 'info', title: '', message: '' });
  const [confirmUnbind, setConfirmUnbind] = useState(null); // {deviceId, deviceName}
  const [scrollIndicator, setScrollIndicator] = useState({
    top: 0,      // 0..1 - indicator position from top
    height: 1,   // 0..1 - indicator height relative to track height
    visible: false,
  });
  const [isCoarsePointer, setIsCoarsePointer] = useState(false);
  const [isAtBottom, setIsAtBottom] = useState(true); // Show button only if false
  const [isMobile, setIsMobile] = useState(false);
  const [isKeyboardVisible, setIsKeyboardVisible] = useState(true);
  const [isInitialized, setIsInitialized] = useState(false); // Hide animation on initial load
  const [dvhReady, setDvhReady] = useState(false); // --app-dvh CSS variable ready flag
  // Fixed keyboard status bar height (always visible even when collapsed)
  const KB_STATUS_PX = 48;
  const [enterMode, setEnterMode] = useState('default');
  // 'default' | 'approve_auto' | 'approve_manual' | 'stop'

  // ========== Refs (23) ==========
  const activeDeviceIdRef = useRef(null);
  const terminalRef = useRef(null);
  const termRef = useRef(null);
  const fitAddonRef = useRef(null);
  const peerRef = useRef(null);
  const sessionGenRef = useRef(0); // One "generation" per terminal session
  const bootRef = useRef(false); // Guard against double useEffect in React StrictMode
  const onDataDisposeRef = useRef(null); // xterm onData disposable to prevent leaks
  const resizeHandlerRef = useRef(null); // window resize handler function
  const rtcHandlerRef = useRef(null); // Unsubscribe handler for ws signals
  const writeQueueRef = useRef([]); // String accumulator for terminal
  const writeScheduledRef = useRef(false); // Flush already scheduled flag
  const onScrollDisposeRef = useRef(null); // xterm onScroll disposable
  const updateScrollIndicatorRef = useRef(null); // Function to update scroll indicator
  const isMobileRef = useRef(false);
  const mobileInputRef = useRef(null);
  const keyboardBaseRef = useRef(0); // Max screen height without system keyboard
  const viewportBaseRef = useRef(0); // Max visualViewport height during terminal lifetime
  // WebRTC auto-reconnection control
  const allowReconnectRef = useRef(false);       // Auto-reconnect permission flag
  const reconnectAttemptRef = useRef(0);         // Reconnection attempt counter
  const reconnectTimerRef = useRef(null);        // Timer between attempts
  const activeTerminalRef = useRef(null);        // Current activeTerminal for callbacks
  // Heartbeat for detecting dead RTC connections
  const heartbeatTimerRef = useRef(null);        // Ping/pong check timer
  const lastRxAtRef = useRef(0);                 // Timestamp of last incoming packet

  // E2EE encryption state
  const encStateRef = useRef({
    ready: false,
    keySend: null,           // keyC2A (client → agent)
    keyRecv: null,           // keyA2C (agent → client)
    noncePrefixSend: null,   // noncePrefixC2A
    noncePrefixRecv: null,   // noncePrefixA2C
    sendCounter: 0n,
    recvCounter: 0n,
    handshakeInProgress: false,
    handshakeTimeout: null,
  });

  // Buffer for packets received during enc_hello verification
  const pendingAfterHelloRef = useRef([]);
  const agentHelloVerifyingRef = useRef(false);

  // ========== Constants ==========
  const STAGE_META = {
    idle:             { text: 'IDLE',             dot: 'bg-gray-600',  textClass: 'text-gray-500' },
    preparing:        { text: 'PREPARING',        dot: 'bg-amber-500', textClass: 'text-amber-400' },
    room:             { text: 'ROOM',             dot: 'bg-amber-500', textClass: 'text-amber-400' },
    invite:           { text: 'INVITE',           dot: 'bg-amber-500', textClass: 'text-amber-400' },
    'rtc-init':       { text: 'RTC',              dot: 'bg-amber-500', textClass: 'text-amber-400' },
    'signal→ws':      { text: 'SIGNAL→WS',        dot: 'bg-amber-500', textClass: 'text-amber-400' },
    connected:        { text: 'CONNECTED',        dot: 'bg-green-500', textClass: 'text-green-600' },
    reconnecting:     { text: 'RECONNECTING',     dot: 'bg-amber-500', textClass: 'text-amber-400' },
    closed:           { text: 'CLOSED',           dot: 'bg-gray-600',  textClass: 'text-gray-500' },
    error:            { text: 'ERROR',            dot: 'bg-rose-600',  textClass: 'text-rose-500' },
    'agent-shutdown': { text: 'AG SHUTDOWN',   dot: 'bg-amber-500', textClass: 'text-amber-400' },
    'agent-exit-error':{ text: 'AG ERROR', dot: 'bg-rose-600',  textClass: 'text-rose-500' },
  };

  const AUTH_STATUS_META = {
    initializing:  { text: 'INITIALIZING',  dot: 'bg-gray-600',  textClass: 'text-gray-500' },
    authenticating:{ text: 'AUTHENTICATING',dot: 'bg-amber-500', textClass: 'text-amber-400' },
    ready:         { text: 'READY',         dot: 'bg-green-500', textClass: 'text-green-600' },
    failed:        { text: 'FAILED',        dot: 'bg-rose-600',  textClass: 'text-rose-500' },
  };

  // ========== Helper Functions ==========

  // Reconnect URL helpers
  const buildReconnectURL = (agentUuid, deviceId, label) => {
    const url = new URL(window.location.href);
    url.searchParams.set('reconnect', '1');
    url.searchParams.set('agent', agentUuid);
    url.searchParams.set('device', deviceId);
    url.searchParams.set('label', encodeURIComponent(label || agentUuid));
    return url.toString();
  };

  const cleanupReconnectURLParams = () => {
    try {
      const url = new URL(window.location.href);
      url.searchParams.delete('reconnect');
      url.searchParams.delete('agent');
      url.searchParams.delete('device');
      url.searchParams.delete('label');
      window.history.replaceState({}, document.title, url.pathname + (url.search ? url.search : ''));
    } catch (e) {
      console.warn('[cleanupReconnectURLParams] Error:', e);
    }
  };

  const isAgentOnline = (devices, agentUuid) => {
    if (!devices || !Array.isArray(devices)) return false;
    for (const device of devices) {
      if (device.sessions && Array.isArray(device.sessions)) {
        const session = device.sessions.find(s => s.uuid === agentUuid);
        if (session && session.online) return true;
      }
    }
    return false;
  };

  // sessionStorage reload counter helpers
  const RELOAD_COUNTER_KEY = 'viberra_reconnect_reload_count';
  const MAX_RELOAD_CYCLES = 2;

  const getReloadCounter = () => {
    try {
      const val = sessionStorage.getItem(RELOAD_COUNTER_KEY);
      return val ? parseInt(val, 10) : 0;
    } catch {
      return 0;
    }
  };

  const incrementReloadCounter = () => {
    const current = getReloadCounter();
    const next = current + 1;
    try {
      sessionStorage.setItem(RELOAD_COUNTER_KEY, String(next));
    } catch {}
    return next;
  };

  const resetReloadCounter = () => {
    try {
      sessionStorage.removeItem(RELOAD_COUNTER_KEY);
    } catch {}
  };
  const waitForWSOpen = (ms = 1500) => new Promise((resolve) => {
    const c = getWSClient?.();
    if (c?.isConnected) return resolve(true);
    const onOpen = () => { cleanup(); resolve(true); };
    const timer = setTimeout(() => { cleanup(); resolve(false); }, ms);
    const cleanup = () => { c?.off?.('open', onOpen); clearTimeout(timer); };
    c?.on?.('open', onOpen);
  });

  const resetEncState = () => {
    encStateRef.current = {
      ready: false,
      keySend: null,
      keyRecv: null,
      noncePrefixSend: null,
      noncePrefixRecv: null,
      sendCounter: 0n,
      recvCounter: 0n,
      handshakeInProgress: false,
      handshakeTimeout: null,
    };

    pendingAfterHelloRef.current = [];
    agentHelloVerifyingRef.current = false;
  };

  const cleanup = (label) => {
    console.log('cleanup:', label);
    setConnectStage('idle');

    // Invalidate generation (stops all loops for this terminal)
    sessionGenRef.current++;

    // Reset E2EE state (including handshake timeout)
    if (encStateRef.current.handshakeTimeout) {
      clearTimeout(encStateRef.current.handshakeTimeout);
    }
    resetEncState();

    // Unsubscribe from ws signals (if subscribed)
    try {
      const ws = getWSClient?.();
      if (rtcHandlerRef.current && ws?.off) {
        ws.off('rtc.signal', rtcHandlerRef.current);
      }
    } catch {}
    rtcHandlerRef.current = null;

    if (resizeHandlerRef.current) {
      try {
        window.removeEventListener('resize', resizeHandlerRef.current);
      } catch {}
      resizeHandlerRef.current = null;
    }

    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }

    if (heartbeatTimerRef.current) {
      clearInterval(heartbeatTimerRef.current);
      heartbeatTimerRef.current = null;
    }
    lastRxAtRef.current = 0;

    if (onDataDisposeRef.current) {
      try {
        onDataDisposeRef.current.dispose();
      } catch {}
      onDataDisposeRef.current = null;
    }

    if (onScrollDisposeRef.current) {
      try {
        onScrollDisposeRef.current();
      } catch {}
      onScrollDisposeRef.current = null;
    }

    setScrollIndicator(prev => (prev.visible ? { ...prev, visible: false } : prev));

    try { peerRef.current?.destroy(); } catch {}
    peerRef.current = null;

    // Dispose the terminal itself (important!)
    try { termRef.current?.dispose(); } catch {}
    termRef.current = null;
    fitAddonRef.current = null;

    writeQueueRef.current = [];
    writeScheduledRef.current = false;

    setEnterMode('default');
  };

  // ========== Frame Helper Functions ==========
  const frameCtrl = (obj) => {
    const enc = new TextEncoder();
    const b = enc.encode(JSON.stringify(obj));
    const u = new Uint8Array(1 + b.length);
    u[0] = 0x00;
    u.set(b, 1);
    return u;
  };

  const framePty = (buf) => {
    const u = new Uint8Array(1 + buf.length);
    u[0] = 0x01;
    u.set(buf, 1);
    return u;
  };

  const parseFrame = (data) => {
    const buf = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (!buf.length) return { type: null };
    const tag = buf[0], payload = buf.subarray(1);
    if (tag === 0x00) {
      try {
        return { type: 'ctrl', json: JSON.parse(new TextDecoder().decode(payload)) };
      } catch {
        return { type: 'bad-ctrl' };
      }
    }
    if (tag === 0x01) return { type: 'pty', buf: payload };
    return { type: 'unknown' };
  };

  const handleDecryptedFrame = (f) => {
    if (f.type === 'pty') {
      const text = new TextDecoder().decode(f.buf);

      // Put in queue
      writeQueueRef.current.push(text);

      // If flush not scheduled yet - schedule on next tick
      if (!writeScheduledRef.current) {
        writeScheduledRef.current = true;
        setTimeout(flushWriteQueue, 16);
      }
    } else if (f.type === 'ctrl') {
      const ctrl = f.json;
      if (ctrl?.type === 'shutdown') {
        // Agent notified about its shutdown
        const exitCode = ctrl.exitCode || 0;
        const reason = ctrl.reason || 'unknown';
        console.log(`[DeviceAgentPanel] Agent shutdown: reason=${reason}, exitCode=${exitCode}`);

        // Set appropriate status
        setConnectStage(exitCode === 0 ? 'agent-shutdown' : 'agent-exit-error');

        // Return to agents list after a second
        setTimeout(() => {
          handleExitTerminal();
        }, 1000);
      } else if (ctrl?.type === 'pong') {
        // Heartbeat response from agent (lastRxAtRef already updated above)
      }
    }
  };

  // ========== Authentication & Agent Management ==========
  const initAuth = async (base) => {
    try {
      setAuthStatus('authenticating');
      await bootstrapClient(base);
      setAuthStatus('ready');
      setAgentsStatus('loading');

      // If WS is already open - load immediately
      const ws = getWSClient();
      if (ws?.isConnected) {
        await loadAgents(base);
        return;
      }

      // Wait up to 1.5s for WS to open. If not opened - try HTTP fallback
      const opened = await waitForWSOpen(1500);
      if (!opened) {
        try {
          await loadAgents(base);
        } catch (e) {
          if (String(e?.message || '').includes('401 Unauthorized')) {
            console.warn('[DeviceAgentPanel] Initial HTTP /agents 401 ignored; WS will load soon');
          } else {
            throw e;
          }
        }
      }
    } catch (err) {
      console.error('Auth failed:', err);
      setAuthStatus('failed');
    }
  };

  const loadAgents = async (base) => {
    try {
      setAgentsStatus('loading');

      // Use API layer with automatic WS → HTTP fallback
      const list = await fetchAgentsList(base);
      setAgents(list);
      setAgentsStatus('loaded');
    } catch (err) {
      console.error('Failed to load agents:', err);
      setAgentsStatus('error');
    }
  };

  const startPairing = async ({ agentId, code, silent = false }) => {
    if (!agentId || !code) {
      if (!silent) {
        setNotification({
          isOpen: true,
          type: 'warning',
          title: 'Incomplete data',
          message: 'Missing agent/code for pairing'
        });
      }
      return;
    }

    if (!silent) {
      setNotification({
        isOpen: true,
        type: 'pending',
        title: 'Awaiting confirmation',
        message: 'Confirm pairing in agent console...'
      });
    }

    try {
      console.log('[DeviceAgentPanel] Starting pairing with agent', agentId, 'code', code, 'apiBase', apiBase);

      const S = getSodium();
      const clientStatic = getClientStaticKey();
      const deviceKey = getDeviceKey();

      // Calculate clientDeviceId (exactly as on server!)
      const pkHash = new Uint8Array(
        await crypto.subtle.digest('SHA-256', deviceKey.pk)
      );
      const clientDeviceId = Array.from(pkHash.slice(0, 16))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      // CRITICAL: use ORIGINAL base64 for network transmission
      const clientStaticPkB64 = S.to_base64(
        clientStatic.pk,
        S.base64_variants.ORIGINAL
      );

      // Generate signature for client_static_pub (MITM protection for X25519 key)
      // Format: 'viberra-static-v1' || static_pub || timestamp || clientDeviceId
      const staticTs = Date.now();
      const staticCtx = S.from_string('viberra-static-v1');
      const staticTsBuf = S.from_string(String(staticTs));
      const clientIdBuf = S.from_string(clientDeviceId);
      const staticPayload = concatUint8Arrays(staticCtx, clientStatic.pk, staticTsBuf, clientIdBuf);
      const staticSig = S.crypto_sign_detached(staticPayload, deviceKey.sk);
      const staticSigB64 = S.to_base64(staticSig, S.base64_variants.ORIGINAL);

      console.log('[SECURITY] Signing client_static_pub with Ed25519');

      // Use API layer for pairing
      const data = await pairAgent(apiBase, {
        agentId,
        code,
        clientStaticPubB64: clientStaticPkB64,
        clientStaticTs: staticTs,
        clientStaticSigB64: staticSigB64
      });

      if (data.ok || data.status === 'ok') {
        // Calculate PSK if server returned agent_static_pub
        if (data.agent_static_pub && clientStatic && deviceKey) {
          try {
            // Decode agent X25519 public key (ORIGINAL format!)
            const agentStaticPub = S.from_base64(
              data.agent_static_pub,
              S.base64_variants.ORIGINAL
            );

            // Required fields for signature verification
            if (!data.agent_sign_pub || !data.agent_static_sig || data.agent_static_ts == null) {
              console.error('[SECURITY] Missing agent signature fields - cannot verify agent_static_pub');
              throw new Error('[SECURITY] Agent did not return static key signature. Update agent/server and retry pairing.');
            }

            // Verify agent_static_pub signature (MITM protection for X25519 key)
            {
              const agentSignPub = S.from_base64(data.agent_sign_pub, S.base64_variants.ORIGINAL);
              const agentStaticSig = S.from_base64(data.agent_static_sig, S.base64_variants.ORIGINAL);

              // Check for key rotation (if saved key exists)
              const savedAgentSignPub = await loadAgentSignPub(agentId);
              if (savedAgentSignPub && savedAgentSignPub !== data.agent_sign_pub) {
                console.warn('[SECURITY] Agent sign_pub changed! Old:', savedAgentSignPub, 'New:', data.agent_sign_pub);
                setNotification({
                  isOpen: true,
                  type: 'warning',
                  title: 'Agent key changed',
                  message: 'Agent fingerprint changed. This could be key rotation or an attack.'
                });
              }

              // Build payload exactly as agent does
              const agentStaticCtx = S.from_string('viberra-static-v1');
              const agentStaticTsBuf = S.from_string(String(data.agent_static_ts));
              const agentIdBuf = S.from_string(agentId);
              const agentStaticPayload = concatUint8Arrays(agentStaticCtx, agentStaticPub, agentStaticTsBuf, agentIdBuf);

              const sigValid = S.crypto_sign_verify_detached(agentStaticSig, agentStaticPayload, agentSignPub);

              if (!sigValid) {
                console.error('[SECURITY] Invalid agent_static_pub signature - MITM detected!');
                throw new Error('[SECURITY] Invalid agent signature - possible MITM attack!');
              }

              console.log('[SECURITY] ✓ agent_static_pub signature verified');

              // Save agent's Ed25519 pub strictly by device_id (from QR agent param)
              await saveAgentSignPub(agentId, data.agent_sign_pub);
            }

            // ECDH: sharedRaw = X25519(client.sk, agent.pk)
            const sharedRaw = S.crypto_scalarmult(clientStatic.sk, agentStaticPub);

            // KDF: PSK = BLAKE2b(sharedRaw || ctx || agentId || clientDeviceId)
            // CRITICAL: same order as on agent!
            const ctx = S.from_string('viberra-psk-v1');
            const agentIdBuf = S.from_string(agentId);
            const clientIdBuf = S.from_string(clientDeviceId);

            const input = concatUint8Arrays(sharedRaw, ctx, agentIdBuf, clientIdBuf);
            const psk = S.crypto_generichash(32, input);

            const pskB64 = S.to_base64(psk, S.base64_variants.ORIGINAL);

            // Save PSK strictly under device_id (universal for any sessions)
            const ok = await savePSK(agentId, pskB64);
            console.log('[DeviceAgentPanel] ✓ PSK saved for device_id', agentId, ok);
          } catch (e) {
            console.error('[DeviceAgentPanel] Failed to compute/save PSK:', e);
          }
        }

        setNotification({
          isOpen: true,
          type: 'success',
          title: 'Device paired',
          message: 'Agent successfully paired to your account'
        });

        // Refresh agents list
        loadAgents(apiBase);

        // Clean up query parameters from URL
        try {
          const url = new URL(window.location.href);
          url.searchParams.delete('agent');
          url.searchParams.delete('code');
          window.history.replaceState({}, document.title, url.pathname + (url.search ? '?' + url.search : ''));
        } catch {}

        setTimeout(() => {
          setNotification({ isOpen: false, type: 'info', title: '', message: '' });
        }, 3000);
      } else {
        setNotification({
          isOpen: true,
          type: 'error',
          title: 'Pairing error',
          message: data.detail || data.reason || 'Pairing failed'
        });
      }
    } catch (err) {
      setNotification({
        isOpen: true,
        type: 'error',
        title: 'Connection error',
        message: err.message
      });
    }
  };

  const handleQRScan = async (qrText) => {
    try {
      // Parse URL from QR code
      const url = new URL(qrText);
      const agent = url.searchParams.get('agent');
      const code = url.searchParams.get('code');

      if (!agent || !code) throw new Error('QR code missing agent/code');

      setShowQRModal(false);
      await startPairing({ agentId: agent, code });
    } catch (err) {
      setShowQRModal(false);
      setNotification({
        isOpen: true,
        type: 'error',
        title: 'QR code error',
        message: err.message
      });
    }
  };

  const handleUnbindAgent = async () => {
    if (!confirmUnbind) return;

    try {
      // Use API layer for unbind
      await unbindAgent(confirmUnbind.deviceId);

      // Refresh agents list immediately
      await loadAgents(apiBase);

      setConfirmUnbind(null);

      setNotification({
        isOpen: true,
        type: 'success',
        title: 'Device unpaired',
        message: `Agent "${confirmUnbind.deviceName}" successfully unpaired from your account`
      });

      // Auto-close after 3 seconds
      setTimeout(() => {
        setNotification({ isOpen: false, type: 'info', title: '', message: '' });
      }, 3000);
    } catch (err) {
      setConfirmUnbind(null);
      setNotification({
        isOpen: true,
        type: 'error',
        title: 'Unbind error',
        message: err.message
      });
    }
  };

  const handleAgentClick = (agent, deviceId, status) => {
    if (status === 'online') {
      setActiveTerminal(agent.uuid);
      setActiveDeviceId(deviceId);
      setActiveLabel(agent.agent_workdir_name || agent.uuid);

      // New terminal session - enable auto-reconnection
      sessionGenRef.current++;
      allowReconnectRef.current = true;
      reconnectAttemptRef.current = 0;
    }
  };

  const handleExitTerminal = () => {
    // Hard terminal close - disable auto-reconnection
    allowReconnectRef.current = false;
    reconnectAttemptRef.current = 0;

    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }

    if (heartbeatTimerRef.current) {
      clearInterval(heartbeatTimerRef.current);
      heartbeatTimerRef.current = null;
    }
    lastRxAtRef.current = 0;

    // First switch UI, then invalidate all background loops
    setActiveTerminal(null);
    setActiveDeviceId(null);
    setActiveLabel('');
    setConnectStage('idle');
    cleanup('terminal closed');
  };

  // ========== Terminal Functions ==========
  const sendResize = (peer) => {
    if (!peer || !peer.connected || !fitAddonRef.current) return;
    if (!encStateRef.current.ready) return; // Don't send until handshake complete
    fitAddonRef.current.fit();
    const cols = termRef.current.cols || 100;
    const rows = termRef.current.rows || 30;
    try {
      const S = getSodium();
      const plainCtrl = frameCtrl({ type: 'resize', cols, rows });
      const encrypted = encryptChunk(S, encStateRef.current, plainCtrl);
      peer.send(encrypted);
    } catch (err) {
      console.error('[E2EE] Failed to send encrypted resize:', err);
    }
  };

  const detectEnterModeFromLines = (lines) => {
    // Iterate from end to get the most recent match
    for (let i = lines.length - 1; i >= 0; i--) {
      const raw = lines[i] ?? '';
      const line = raw.trimStart();

      if (
        line.includes('❯ 1. Yes, and auto-accept edits') ||
        line.includes('❯ 1. Yes')
      ) {
        return 'approve_auto';
      }

      if (
        line.includes('❯ 2. Yes, and manually approve edits') ||
        line.includes("❯ 2. Yes, and don't ask again")
      ) {
        return 'approve_manual';
      }

      if (line.includes('❯ 3. No, keep planning')) {
        return 'stop';
      }
    }

    return 'default';
  };

  const detectEnterModeFromTerminal = () => {
    const term = termRef.current;
    if (!term) return;

    const buffer = term.buffer.active;
    const maxLines = 50;

    // baseY - index of first "historical" buffer line
    // cursorY - current line in visible area
    const lastY = buffer.baseY + buffer.cursorY;
    const firstY = Math.max(0, lastY - (maxLines - 1));

    const lines = [];

    for (let y = firstY; y <= lastY; y++) {
      const line = buffer.getLine(y);
      if (!line) continue;

      // translateToString() already returns text without ANSI
      const text = line.translateToString().trim();
      if (text) {
        lines.push(text);
      }
    }

    const mode = detectEnterModeFromLines(lines);
    setEnterMode((prev) => (prev === mode ? prev : mode));
  };

  const handleKeyboardPress = (key) => {
    if (!termRef.current || !peerRef.current?.connected) return;
    if (!encStateRef.current.ready) return; // Don't send until handshake complete

    // Map keyboard shortcuts to terminal escape sequences
    const keyMap = {
      escape: '\x1b',           // ESC
      enter: '\r',              // Enter (CR)
      tab: '\t',                // Tab
      slash: '/',               // Forward slash
      up: '\x1b[A',             // Up arrow
      down: '\x1b[B',           // Down arrow
      left: '\x1b[D',           // Left arrow
      right: '\x1b[C',          // Right arrow
      shiftTab: '\x1b[Z',       // Shift+Tab
      ctrlC: '\x03',            // Ctrl+C (SIGINT)
      backspace: '\x7f',        // Backspace (DEL)
    };

    const sequence = keyMap[key];
    if (sequence) {
      // Send to peer connection (encrypted!)
      try {
        const S = getSodium();
        const plainPty = framePty(new TextEncoder().encode(sequence));
        const encrypted = encryptChunk(S, encStateRef.current, plainPty);
        peerRef.current.send(encrypted);
      } catch (err) {
        console.error('[E2EE] Failed to send encrypted key:', err);
      }
    }
  };

  const sendTextToTerminal = (text) => {
    const peer = peerRef.current;
    if (!peer || !peer.connected) return;
    if (!text) return;
    if (!encStateRef.current.ready) return; // Don't send until handshake complete

    try {
      const S = getSodium();
      const plainPty = framePty(new TextEncoder().encode(text));
      const encrypted = encryptChunk(S, encStateRef.current, plainPty);
      peer.send(encrypted);
    } catch (err) {
      console.error('[E2EE] Failed to send encrypted text:', err);
    }

    scrollTerminalToBottom();
  };

  const scrollTerminalToBottom = () => {
    if (!termRef.current) return;
    try {
      termRef.current.scrollToBottom();
      updateScrollIndicatorRef.current?.();
    } catch (e) {
      console.warn('scrollToBottom failed', e);
    }
  };

  const flushWriteQueue = () => {
    if (!termRef.current) {
      writeQueueRef.current = [];
      writeScheduledRef.current = false;
      return;
    }

    // Concatenate everything into one chunk for xterm to render at once
    const chunk = writeQueueRef.current.join('');
    writeQueueRef.current = [];
    writeScheduledRef.current = false;

    if (chunk.length > 0) {
      // write accepts callback that's called after rendering
      termRef.current.write(chunk, () => {
        // First update scroll indicator
        updateScrollIndicatorRef.current?.();
        // Then read last 50 lines and update enterMode
        detectEnterModeFromTerminal();
      });
    }
  };

  // ========== WebRTC Connection Functions ==========
  const connectWithRetry = async (gen) => {
    // Auto-reconnection constants
    const MAX_RECONNECT_ATTEMPTS = 3;
    const RECONNECT_BASE_DELAY = 500;   // ms
    const RECONNECT_MAX_DELAY = 5000;   // ms

    // Check session validity
    if (sessionGenRef.current !== gen) return;

    // Check reconnection permission
    if (!allowReconnectRef.current) return;

    // UI indication
    if (reconnectAttemptRef.current > 0) {
      setConnectStage(`reconnecting (${reconnectAttemptRef.current}/${MAX_RECONNECT_ATTEMPTS})`);
    } else {
      setConnectStage('connecting');
    }

    try {
      // One WebRTC connection "lifetime"
      await connectOnce(gen);
      // If connectOnce returned normally (peer closed), handlePeerEnd already scheduled retry
    } catch (err) {
      console.error('[connectWithRetry] connectOnce error:', err);

      // Handle session expiration - reload page for automatic re-authentication
      if (String(err.message).includes('SESSION_EXPIRED') ||
          String(err.message).includes('no sessionToken') ||
          String(err.message).includes('Unauthorized')) {
        console.log('[connectWithRetry] Auth fatal error, stopping reconnect:', err.message);
        allowReconnectRef.current = false;
        reconnectAttemptRef.current = 0;
        setConnectStage('error');

        setNotification({
          isOpen: true,
          type: 'info',
          title: 'Session expired',
          message: 'Session expired, reloading page...'
        });

        // Reload page after short delay to allow notification to be shown
        setTimeout(() => {
          window.location.reload();
        }, 1000);
        return;
      }

      // Check reconnection permission
      if (!allowReconnectRef.current) {
        setConnectStage('error');
        return;
      }

      // Increment attempt counter
      reconnectAttemptRef.current += 1;

      // Check attempt limit
      if (reconnectAttemptRef.current > MAX_RECONNECT_ATTEMPTS) {
        console.log('[connectWithRetry] Max reconnect attempts reached');

        // Check if agent is still online
        const agentUuid = activeTerminalRef.current;
        const deviceId = activeDeviceIdRef.current;
        const label = activeLabel;

        if (!isAgentOnline(agent_devices, agentUuid)) {
          console.log('[connectWithRetry] Agent offline, closing terminal');
          handleExitTerminal();
          return;
        }

        // Check reload counter
        const reloadCount = getReloadCounter();
        if (reloadCount >= MAX_RELOAD_CYCLES) {
          console.log('[connectWithRetry] Max reload cycles reached, closing terminal');
          handleExitTerminal();
          return;
        }

        // Build reconnect URL
        const reconnectURL = buildReconnectURL(agentUuid, deviceId, label);

        // Show notification
        setNotification({
          isOpen: true,
          type: 'info',
          title: 'Переподключение',
          message: 'Перезагрузка страницы для переподключения...'
        });

        // Increment reload counter
        incrementReloadCounter();

        // Reload page after short delay
        setTimeout(() => {
          window.location.href = reconnectURL;
        }, 500);

        return;
      }

      // Exponential backoff
      const backoff = Math.min(
        RECONNECT_BASE_DELAY * (2 ** (reconnectAttemptRef.current - 1)),
        RECONNECT_MAX_DELAY
      );

      setConnectStage(`reconnecting (${reconnectAttemptRef.current}/${MAX_RECONNECT_ATTEMPTS})`);

      // Schedule next attempt
      reconnectTimerRef.current = setTimeout(() => {
        // Check conditions before new attempt
        if (sessionGenRef.current === gen &&
            allowReconnectRef.current &&
            activeTerminalRef.current) {
          connectWithRetry(gen);
        }
      }, backoff);
    }
  };

  const connectOnce = async (gen) => {
    // Try WebSocket RPC first
    const wsClient = getWSClient();
    let room;

    const sessionUuid = activeTerminalRef.current || activeTerminal;
    let deviceId = activeDeviceIdRef.current;
    if (!deviceId) {
      const err = new Error('Cannot resolve device_id for active agent session (UUID)');
      console.error('[E2EE]', err.message, { sessionUuid });
      throw err;
    }

    // Use API layer for room creation and invitation
    setConnectStage('room');
    room = await createRoom(apiBase);

    // Validate that room was created successfully with valid room_id
    if (!room || !room.room_id) {
      throw new Error('[DeviceAgentPanel] createRoom returned no room_id');
    }

    setConnectStage('invite');
    await inviteAgentToRoom(apiBase, {
      roomId: room.room_id,
      agentId: activeTerminal
    });

    // ============================== E2EE: Load PSK and derive keys ==============================
    console.log('[E2EE] Loading PSK for device:', deviceId, '(session uuid:', activeTerminal, ')');
    const pskB64 = await loadPSK(deviceId);   // Only by device_id
    if (!pskB64) {
      const err = new Error('No PSK for agent - re-pairing required');
      console.error('[E2EE]', err.message);
      setNotification({
        isOpen: true,
        type: 'error',
        title: 'Re-pairing required',
        message: 'Encryption key not found. Please pair the agent again.'
      });
      throw err;
    }

    const S = getSodium();
    const psk = S.from_base64(pskB64, S.base64_variants.ORIGINAL);

    console.log('[E2EE] Deriving session keys for room:', room.room_id);
    const { keyA2C, keyC2A, noncePrefixA2C, noncePrefixC2A } = deriveSessionKeys(S, psk, room.room_id);

    // Load agent's Ed25519 public key for enc_hello signature verification
    console.log('[E2EE] Loading agent_sign_pub for device:', deviceId);
    const agentSignPubB64 = await loadAgentSignPub(deviceId);
    if (!agentSignPubB64) {
      const err = new Error('No agent_sign_pub stored - re-pairing required');
      console.error('[E2EE]', err.message);
      setNotification({
        isOpen: true,
        type: 'error',
        title: 'Re-pairing required',
        message: 'Agent public key not found. Please pair the agent again.'
      });
      throw err;
    }
    const agentSignPub = S.from_base64(agentSignPubB64, S.base64_variants.ORIGINAL);

    // Reset and initialize encState
    resetEncState();
    encStateRef.current.keySend = keyC2A;         // client → agent
    encStateRef.current.keyRecv = keyA2C;         // agent → client
    encStateRef.current.noncePrefixSend = noncePrefixC2A;
    encStateRef.current.noncePrefixRecv = noncePrefixA2C;
    encStateRef.current.sendCounter = 0n;
    encStateRef.current.recvCounter = 0n;
    encStateRef.current.ready = false;  // Will become true after enc_hello handshake
    encStateRef.current.handshakeInProgress = false;

    console.log('[E2EE] Session keys derived and encState initialized');
    // =============================================================================================

    // Lazy-load simple-peer browser build
    const { default: SimplePeer } = await import('simple-peer/simplepeer.min.js');

    setConnectStage('rtc-init');
    const peer = new SimplePeer({
      initiator: true,
      trickle: true,
      config: {
        iceServers: room.iceServers || [] //, iceTransportPolicy: 'relay'
      }
    });

    peerRef.current = peer;

    peer.on('signal', async (signal) => {
      setConnectStage('signal→ws');
      try {
        // Prepare stable data for signaling
        const safe = JSON.parse(JSON.stringify(signal));

        // Deterministic deep sorting for consistent signaling
        const deepSort = (v) => {
          if (Array.isArray(v)) return v.map(deepSort);
          if (v && typeof v === 'object') {
            const o = {};
            for (const k of Object.keys(v).sort()) o[k] = deepSort(v[k]);
            return o;
          }
          return v;
        };

        const sortedSignal = deepSort(safe);

        // Use API layer for signaling
        await sendRTCSignal(apiBase, {
          roomId: room.room_id,
          agentId: activeTerminal,
          stableData: sortedSignal
        });
      } catch (err) {
        console.error('[RTC] signal error:', err);
        setConnectStage('error');

        // CRITICAL: Any signaling error is considered fatal for current peer.
        // Destroy peer → triggers handlePeerEnd → universal reconnect.
        try {
          peerRef.current?.destroy(err);
        } catch {}
      }
    });

    // Subscribe to WebSocket RTC signal events (replaces HTTP polling!)
    if (wsClient?.isConnected) {
      console.log('[DeviceAgentPanel] Subscribing to WebSocket RTC signals');

      const handleRTCSignal = (eventData) => {
        // Protection by generation and room
        if (sessionGenRef.current !== gen) return;
        if (eventData.room_id !== room.room_id) return;
        if (peer.destroyed) return;

        console.log('[DeviceAgentPanel] Received RTC signal via WebSocket (gen', gen, ')');

        try {
          peer.signal(eventData.data);   // IMPORTANT: local peer, not peerRef.current
        } catch (e) {
          console.error('Error processing RTC signal:', e);
          setConnectStage('error');
          try {
            peer.destroy(e);            // Also using local peer
          } catch {}
        }
      };

      wsClient.on('rtc.signal', handleRTCSignal);
      rtcHandlerRef.current = handleRTCSignal;

      const detachRTCSignal = () => {
        wsClient.off('rtc.signal', handleRTCSignal);
        if (rtcHandlerRef.current === handleRTCSignal) {
          rtcHandlerRef.current = null;
        }
      };

      peer.on('close', detachRTCSignal);
      peer.on('error', detachRTCSignal);
    } else {
      // Fallback to HTTP polling
      pumpSignals(room.room_id, gen, peer);
    }

    peer.on('connect', async () => {
      console.log('RTC connected');
      setConnectStage('connected');

      // Reset reload counter on successful connection
      resetReloadCounter();

      // ============================== E2EE: Send enc_hello ==============================
      console.log('[E2EE] Sending enc_hello handshake');
      try {
        const deviceKey = getDeviceKey();
        const ts = Date.now();

        // PSK fingerprint for verification
        const pskHash = await crypto.subtle.digest('SHA-256', psk);
        const pskFp = new Uint8Array(pskHash);
        const pskFpB64 = S.to_base64(pskFp, S.base64_variants.ORIGINAL);

        // Calculate clientDeviceId exactly as during pairing
        const pkHashRaw = await crypto.subtle.digest('SHA-256', deviceKey.pk);
        const pkHash = new Uint8Array(pkHashRaw);
        const clientDeviceId = Array.from(pkHash.slice(0, 16))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');

        // Signature: payload = ctx || roomId || senderId || ts || pskFp (all as bytes)
        const ctx = S.from_string('viberra-enc-hello-v1');
        const roomIdBuf = S.from_string(room.room_id);
        const senderIdBuf = S.from_string(clientDeviceId);
        const tsBuf = S.from_string(String(ts));
        const payload = concatUint8Arrays(ctx, roomIdBuf, senderIdBuf, tsBuf, pskFp);

        const sig = S.crypto_sign_detached(payload, deviceKey.sk);
        const sigB64 = S.to_base64(sig, S.base64_variants.ORIGINAL);

        // Send enc_hello (NOT encrypted - this is part of handshake!)
        peer.send(frameCtrl({
          type: 'enc_hello',
          room_id: room.room_id,
          sender_id: clientDeviceId,
          ts,
          psk_fp: pskFpB64,
          sig: sigB64,
        }));

        encStateRef.current.handshakeInProgress = true;

        // Handshake timeout - 5 seconds
        encStateRef.current.handshakeTimeout = setTimeout(() => {
          if (!encStateRef.current.ready && peer && !peer.destroyed) {
            console.error('[E2EE] Handshake timeout - no enc_hello from agent');
            try {
              peer.destroy(new Error('E2EE handshake timeout'));
            } catch {}
          }
        }, 5000);

        console.log('[E2EE] enc_hello sent, waiting for agent response');
      } catch (err) {
        console.error('[E2EE] Failed to send enc_hello:', err);
        try {
          peer.destroy(err);
        } catch {}
        return;
      }
      // ==================================================================================

      // Release old handler if exists (prevent leaks on reconnects)
      if (onDataDisposeRef.current) {
        try {
          onDataDisposeRef.current.dispose();
        } catch {}
        onDataDisposeRef.current = null;
      }

      // IMPORTANT: xterm.onData NOT connected until enc.ready = true!
      // Will connect it after successful enc_hello handshake
      // sendResize will also be sent only after enc.ready = true

      // Initialize heartbeat for detecting dead connections
      lastRxAtRef.current = Date.now();

      // On reconnect - clear previous timer
      if (heartbeatTimerRef.current) {
        clearInterval(heartbeatTimerRef.current);
        heartbeatTimerRef.current = null;
      }

      const PING_INTERVAL = 3_000;   // Every 3 seconds
      const IDLE_TIMEOUT  = 30_000;   // Consider channel dead if 30+ seconds without incoming data

      const myGen = gen; // Capture generation for extra protection

      heartbeatTimerRef.current = setInterval(() => {
        // If session changed or auto-reconnection disabled - do nothing
        if (sessionGenRef.current !== myGen || !allowReconnectRef.current) return;

        const peer = peerRef.current;
        if (!peer || peer.destroyed) return;

        const now = Date.now();

        // If no incoming data for a long time - consider connection dead
        if (lastRxAtRef.current && now - lastRxAtRef.current > IDLE_TIMEOUT) {
          console.warn('[RTC] idle timeout, destroying peer');
          try {
            peer.destroy(new Error('RTC idle timeout'));
          } catch (e) {
            console.error('[RTC] idle timeout destroy error', e);
          }
          // Timer will expire in cleanup/handlePeerEnd
          return;
        }

        // Ping agent with ctrl-frame (encrypted!)
        try {
          if (encStateRef.current.ready) {
            const S = getSodium();
            const plainPing = frameCtrl({ type: 'ping', ts: now });
            const encrypted = encryptChunk(S, encStateRef.current, plainPing);
            peer.send(encrypted);
          }
        } catch (e) {
          console.error('[RTC] ping send error', e);
          // Send error - also good reason to consider connection broken
          try {
            peer.destroy(e);
          } catch {}
        }
      }, PING_INTERVAL);
    });

    peer.on('data', async (data) => {
      lastRxAtRef.current = Date.now();
      const u8 = new Uint8Array(data);

      // ============================== E2EE: Handshake or decryption ==============================
      if (!encStateRef.current.ready) {
        const f = parseFrame(u8);

        if (f.type === 'ctrl' && f.json?.type === 'enc_hello') {
          if (agentHelloVerifyingRef.current) {
            console.log('[E2EE] Duplicate enc_hello from agent, ignoring');
            return;
          }

          agentHelloVerifyingRef.current = true;
          console.log('[E2EE] Received enc_hello from agent');

          const { psk_fp, sig, room_id: agentRoomId, sender_id, ts } = f.json;

          // Verify PSK fingerprint and signature (await directly here, no async IIFE!)
          try {
            const pskHash = await crypto.subtle.digest('SHA-256', psk);
            const localPskFp = S.to_base64(new Uint8Array(pskHash), S.base64_variants.ORIGINAL);
            if (psk_fp !== localPskFp) {
              console.error('[E2EE] PSK fingerprint mismatch!');
              agentHelloVerifyingRef.current = false;
              try {
                peer.destroy(new Error('E2EE PSK mismatch'));
              } catch {}
              return;
            }

            // Verify enc_hello signature (MITM protection and identity confirmation)
            const { sig: agentSig } = f.json;
            if (!agentSig) {
              console.error('[SECURITY] Missing signature in enc_hello from agent');
              agentHelloVerifyingRef.current = false;
              try {
                peer.destroy(new Error('Missing enc_hello signature'));
              } catch {}
              return;
            }

            const agentSigBuf = S.from_base64(agentSig, S.base64_variants.ORIGINAL);

            // Payload: 'viberra-enc-hello-v1' || room_id || sender_id || ts || psk_fp
            const encHelloPayload = concatUint8Arrays(
              S.from_string('viberra-enc-hello-v1'),
              S.from_string(agentRoomId),
              S.from_string(sender_id),
              S.from_string(String(ts)),
              S.from_base64(psk_fp, S.base64_variants.ORIGINAL)
            );

            const sigValid = S.crypto_sign_verify_detached(agentSigBuf, encHelloPayload, agentSignPub);
            if (!sigValid) {
              console.error('[SECURITY] enc_hello signature invalid from agent');
              agentHelloVerifyingRef.current = false;
              try {
                peer.destroy(new Error('Invalid enc_hello signature from agent'));
              } catch {}
              return;
            }

            console.log('[SECURITY] ✓ enc_hello signature verified from agent');

            // Handshake successful!
            if (encStateRef.current.handshakeTimeout) {
              clearTimeout(encStateRef.current.handshakeTimeout);
              encStateRef.current.handshakeTimeout = null;
            }

            encStateRef.current.handshakeInProgress = false;
            encStateRef.current.ready = true;
            agentHelloVerifyingRef.current = false;

            console.log('[E2EE] ✓ Handshake complete, encryption ready');

            // Now can connect xterm.onData for user input
            if (!isMobileRef.current && termRef.current) {
              onDataDisposeRef.current = termRef.current.onData((d) => {
                if (!encStateRef.current.ready) return; // Extra protection
                try {
                  // Encrypt PTY data before sending
                  const plainPty = framePty(new TextEncoder().encode(d));
                  const encrypted = encryptChunk(S, encStateRef.current, plainPty);
                  peer.send(encrypted);
                } catch (err) {
                  console.error('[E2EE] Failed to send encrypted data:', err);
                }
              });
            }

            // Send first resize (now encrypted!)
            sendResize(peer);
            setTimeout(() => sendResize(peer), 50);

            // Auto-scroll
            scrollTerminalToBottom();
            setTimeout(scrollTerminalToBottom, 100);

            // Replay buffered packets
            if (pendingAfterHelloRef.current.length > 0) {
              console.log('[E2EE] Replaying', pendingAfterHelloRef.current.length, 'buffered chunks');
              for (const chunk of pendingAfterHelloRef.current) {
                try {
                  const plain = decryptChunk(S, encStateRef.current, new Uint8Array(chunk));
                  const ff = parseFrame(plain);
                  handleDecryptedFrame(ff);
                } catch (e) {
                  console.error('[E2EE] Failed to process buffered chunk:', e);
                }
              }
              pendingAfterHelloRef.current = [];
            }
          } catch (err) {
            agentHelloVerifyingRef.current = false;
            console.error('[E2EE] Error during enc_hello verification:', err);
            try {
              peer.destroy(err);
            } catch {}
          }

          return;
        }

        // Buffer packets received during verification
        if (agentHelloVerifyingRef.current) {
          pendingAfterHelloRef.current.push(u8);
          return;
        }

        // Unexpected packet before enc_hello
        console.error('[E2EE] Expected enc_hello from agent, got:', f.type, f.json?.type);
        try {
          peer.destroy(new Error('Unexpected frame before enc_hello'));
        } catch {}
        return;
      }

      // Encryption ready - decrypt incoming data
      let plainData;
      try {
        plainData = decryptChunk(S, encStateRef.current, u8);
      } catch (err) {
        console.error('[E2EE] Decryption failed:', err);
        try {
          peer.destroy(err);
        } catch {}
        return;
      }

      const f2 = parseFrame(plainData);
      handleDecryptedFrame(f2);
      // ============================================================================================
    });

    // Auto-reconnection constants (used in handlePeerEnd)
    const MAX_RECONNECT_ATTEMPTS = 3;
    const RECONNECT_BASE_DELAY = 500;   // ms
    const RECONNECT_MAX_DELAY = 5000;   // ms

    // Handshake timeout - if connection not established in 15 seconds, destroy peer
    const handshakeTimeout = setTimeout(() => {
      if (
        !peer.connected &&
        allowReconnectRef.current &&
        sessionGenRef.current === gen &&
        activeTerminalRef.current
      ) {
        console.warn('[connectOnce] RTC handshake timeout, destroying peer');
        try {
          peer.destroy(new Error('RTC handshake timeout'));
        } catch {}
      }
    }, 15000); // 15 seconds

    return new Promise((resolve) => {
      let ended = false;

      // Peer connection end handler (soft disconnect or error)
      const handlePeerEnd = (reason, err) => {
        if (ended) return;
        ended = true;

        console.log('[connectOnce] peer ended:', reason, err?.message);

        // Clear handshake timer
        clearTimeout(handshakeTimeout);

        // Disconnect only WebRTC part, NOT closing logical terminal session
        if (peerRef.current === peer) {
          try { peer.destroy(); } catch {}
          peerRef.current = null;
        }

        // If we can still reconnect - start retry
        if (
          allowReconnectRef.current &&
          sessionGenRef.current === gen &&
          activeTerminalRef.current
        ) {
          reconnectAttemptRef.current += 1;

          // Check attempt limit
          if (reconnectAttemptRef.current > MAX_RECONNECT_ATTEMPTS) {
            console.log('[connectOnce] Max reconnect attempts reached');

            // Check if agent is still online
            const agentUuid = activeTerminalRef.current;
            const deviceId = activeDeviceIdRef.current;
            const label = activeLabel;

            if (!isAgentOnline(agent_devices, agentUuid)) {
              console.log('[connectOnce] Agent offline, closing terminal');
              handleExitTerminal();
              resolve();
              return;
            }

            // Check reload counter
            const reloadCount = getReloadCounter();
            if (reloadCount >= MAX_RELOAD_CYCLES) {
              console.log('[connectOnce] Max reload cycles reached, closing terminal');
              handleExitTerminal();
              resolve();
              return;
            }

            // Build reconnect URL
            const reconnectURL = buildReconnectURL(agentUuid, deviceId, label);

            // Show notification
            setNotification({
              isOpen: true,
              type: 'info',
              title: 'Переподключение',
              message: 'Перезагрузка страницы для переподключения...'
            });

            // Increment reload counter
            incrementReloadCounter();

            // Reload page after short delay
            setTimeout(() => {
              window.location.href = reconnectURL;
            }, 500);

            resolve();
            return;
          }

          // Exponential backoff
          const backoff = Math.min(
            RECONNECT_BASE_DELAY * (2 ** (reconnectAttemptRef.current - 1)),
            RECONNECT_MAX_DELAY
          );

          setConnectStage(`reconnecting (${reconnectAttemptRef.current}/${MAX_RECONNECT_ATTEMPTS})`);

          // Schedule next attempt
          reconnectTimerRef.current = setTimeout(() => {
            if (
              sessionGenRef.current === gen &&
              allowReconnectRef.current &&
              activeTerminalRef.current
            ) {
              connectWithRetry(gen);
            }
          }, backoff);
        } else {
          // Auto-reconnection not allowed - set appropriate status
          setConnectStage(reason === 'close' ? 'closed' : 'error');
        }

        resolve();  // Complete connectOnce
      };

      peer.on('close', () => handlePeerEnd('close'));
      peer.on('error', (err) => handlePeerEnd('error', err));
    });
  };

  const pumpSignals = (roomId, gen, peer) => {
    (async () => {
      while (sessionGenRef.current === gen && !peer.destroyed) {
        try {
          const data = await consumeRTCSignals(apiBase, roomId);
          if (data.items?.length) {
            for (const item of data.items) {
              // Additional protection inside loop
              if (sessionGenRef.current !== gen || peer.destroyed) return;

              peer.signal(item.data);
            }
          }
        } catch (e) {
          console.warn('[DeviceAgentPanel] pumpSignals error:', e);
        }

        await new Promise(res => setTimeout(res, 350));
      }
    })();
  };

  // ========== useEffect Hooks ==========

  // Initial boot effect
  useEffect(() => {
    // Prevent double initialization in React 18 StrictMode (dev mode)
    if (bootRef.current) {
      console.log('[DeviceAgentPanel] Skipping duplicate useEffect call (StrictMode)');
      return;
    }
    bootRef.current = true;

    // Auto-detect API host from current location or use environment variable
    const base = import.meta.env.API_URL || `https://api.viberra.life`;
    console.log('[DeviceAgentPanel] API Base:', base);
    setApiBase(base);
    initAuth(base);
  }, []);

  // Detect coarse pointer (touch devices)
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;

    const mq = window.matchMedia('(pointer: coarse)');
    const update = () => setIsCoarsePointer(mq.matches);

    update();

    if (mq.addEventListener) mq.addEventListener('change', update);
    else if (mq.addListener) mq.addListener(update);

    return () => {
      if (mq.removeEventListener) mq.removeEventListener('change', update);
      else if (mq.removeListener) mq.removeListener(update);
    };
  }, []);

  // Detect mobile devices
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const detect = () => {
      const hasTouch =
        'ontouchstart' in window || navigator.maxTouchPoints > 0;
      const smallScreen = window.innerWidth <= 768;
      const mobile = hasTouch && smallScreen;
      setIsMobile(mobile);
      isMobileRef.current = mobile;
    };

    detect();
    window.addEventListener('resize', detect);

    return () => {
      window.removeEventListener('resize', detect);
    };
  }, []);

  // Sync activeDeviceIdRef with activeDeviceId
  useEffect(() => {
    activeDeviceIdRef.current = activeDeviceId;
  }, [activeDeviceId]);

  // Sync activeTerminalRef with activeTerminal
  useEffect(() => {
    activeTerminalRef.current = activeTerminal;
  }, [activeTerminal]);

  // Recalculate terminal size when keyboard visibility changes
  useEffect(() => {
    if (!fitAddonRef.current) return;

    const timer = setTimeout(() => {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          fitAddonRef.current?.fit();
          sendResize(peerRef.current);
        });
      });
    }, 300); // Wait for CSS transition completion (0.3s)

    return () => clearTimeout(timer);
  }, [isKeyboardVisible]);

  // Enable animations after first render (hide flash on load)
  useEffect(() => {
    setIsInitialized(true);
  }, []);

  // Subscribe to server push updates for agents list
  useEffect(() => {
    if (authStatus !== 'ready') return;
    const wsClient = getWSClient();
    if (!wsClient) return;

    const handleAgentsUpdate = (evt) => {
      // Server sends {"type":"agents.update","data":{"agent_devices":[...]}}
      console.log('[DeviceAgentPanel] Received agents.update push event');
      const list = evt?.data?.agent_devices || evt?.agent_devices || [];
      setAgents(Array.isArray(list) ? list : []);
      setAgentsStatus('loaded'); // Received first snapshot via WS
    };

    wsClient.on('agents.update', handleAgentsUpdate);

    // On reconnect - request fresh snapshot
    const onReconnected = () => {
      console.log('[DeviceAgentPanel] WebSocket reconnected, reloading agents');
      setAgentsStatus('loading');
      loadAgents(apiBase);
    };
    if (wsClient.on) {
      wsClient.on('open', onReconnected);
    }

    return () => {
      wsClient.off('agents.update', handleAgentsUpdate);
      if (wsClient.off) {
        wsClient.off('open', onReconnected);
      }
    };
  }, [authStatus, apiBase]);

  // Auto-pairing when entering via link
  useEffect(() => {
    if (authStatus !== 'ready') return;

    try {
      const url = new URL(window.location.href);
      const agent = url.searchParams.get('agent');
      const code = url.searchParams.get('code');

      if (agent && code) {
        // Don't show QR modal - try pairing immediately
        startPairing({ agentId: agent, code, silent: false });
      }
    } catch (e) {
      console.warn('URL parse error:', e);
    }
  }, [authStatus, apiBase]);

  // Auto-reconnect after page reload
  useEffect(() => {
    if (authStatus !== 'ready') return;

    try {
      const params = new URLSearchParams(window.location.search);
      const isReconnect = params.get('reconnect') === '1';

      if (!isReconnect) return;

      const agentUuid = params.get('agent');
      const deviceId = params.get('device');
      const label = params.get('label');

      // Clean URL immediately to prevent loops
      cleanupReconnectURLParams();

      if (!agentUuid || !deviceId) {
        console.log('[auto-reconnect] Missing agent or device parameters');
        return;
      }

      // Check if agent is online
      if (!isAgentOnline(agent_devices, agentUuid)) {
        console.log('[auto-reconnect] Agent offline, skipping reconnect');
        setNotification({
          isOpen: true,
          type: 'warning',
          title: 'Agent offline',
          message: 'Agent is no longer online'
        });
        return;
      }

      // Trigger connection
      console.log('[auto-reconnect] Starting auto-reconnect to agent', agentUuid);
      setActiveTerminal(agentUuid);
      setActiveDeviceId(deviceId);
      setActiveLabel(decodeURIComponent(label || agentUuid));
      sessionGenRef.current++;
      allowReconnectRef.current = true;
      reconnectAttemptRef.current = 0;
    } catch (e) {
      console.warn('[auto-reconnect] Error:', e);
    }
  }, [authStatus, agent_devices, activeLabel]);

  // Handle room.disconnected event when another device connects to the agent
  useEffect(() => {
    if (!activeTerminal) return;

    const wsClient = getWSClient();
    if (!wsClient?.isConnected) return;

    const handleRoomDisconnected = (eventData) => {
      console.log('[DeviceAgentPanel] Received room.disconnected event:', eventData);

      // Hard close - disable auto-reconnection
      allowReconnectRef.current = false;
      reconnectAttemptRef.current = 0;

      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }

      // Close the peer connection
      if (peerRef.current) {
        try {
          peerRef.current.destroy();
        } catch (e) {
          console.error('Error closing peer connection:', e);
        }
        peerRef.current = null;
      }

      // Show notification to user
      setNotification({
        isOpen: true,
        type: 'warning',
        title: 'Connection terminated',
        message: 'Another device connected to this agent. Connection closed.'
      });

      // Reset terminal state and navigate back home
      setActiveTerminal(null);
      setActiveLabel('');
      setConnectStage('closed');
      cleanup('room disconnected');
    };

    // Subscribe to room.disconnected event
    wsClient.on('room.disconnected', handleRoomDisconnected);

    return () => {
      // Unsubscribe when component unmounts or activeTerminal changes
      wsClient.off('room.disconnected', handleRoomDisconnected);
    };
  }, [activeTerminal]);

  // Terminal WebRTC logic (main terminal initialization effect)
  useEffect(() => {
    if (!activeTerminal || !terminalRef.current) return;

    // Updates visual scroll indicator based on .xterm-viewport DOM scroll
    const updateScrollIndicator = () => {
      const container = terminalRef.current;
      if (!container) {
        setScrollIndicator(prev =>
          prev.visible ? { ...prev, visible: false } : prev
        );
        setIsAtBottom(true);
        return;
      }

      const viewport = container.querySelector('.xterm-viewport');
      if (!viewport) {
        setScrollIndicator(prev =>
          prev.visible ? { ...prev, visible: false } : prev
        );
        setIsAtBottom(true);
        return;
      }

      const scrollHeight = viewport.scrollHeight || 0;
      const clientHeight = viewport.clientHeight || 0;
      const scrollTop = viewport.scrollTop || 0;

      // If content smaller than viewport height - indicator not needed
      if (!scrollHeight || scrollHeight <= clientHeight + 1) {
        setScrollIndicator(prev =>
          prev.visible ? { top: 0, height: 1, visible: false } : prev
        );
        setIsAtBottom(true);
        return;
      }

      const maxScroll = Math.max(scrollHeight - clientHeight, 1);
      let scrollFrac = scrollTop / maxScroll;
      if (!Number.isFinite(scrollFrac)) scrollFrac = 0;
      scrollFrac = Math.max(0, Math.min(scrollFrac, 1));

      let heightFrac = clientHeight / scrollHeight;
      if (!Number.isFinite(heightFrac) || heightFrac <= 0) heightFrac = 1;

      const MIN_HEIGHT = 0.08;
      const MAX_HEIGHT = 0.9;
      heightFrac = Math.max(MIN_HEIGHT, Math.min(MAX_HEIGHT, heightFrac));

      const topFrac = scrollFrac * (1 - heightFrac);

      setScrollIndicator({
        top: topFrac,
        height: heightFrac,
        visible: true,
      });

      // Consider "bottom" with small tolerance due to subpixel scrolling on iOS
      const EPS = 2; // px
      setIsAtBottom(maxScroll - scrollTop <= EPS);
    };

    // Save function in ref for access from other functions
    updateScrollIndicatorRef.current = updateScrollIndicator;

    // Lazy-load xterm and CSS
    const initTerminal = async () => {
      // New generation for terminal launch
      const myGen = ++sessionGenRef.current;
      setConnectStage('preparing');

      const [{ Terminal }, { FitAddon }] = await Promise.all([
        import('xterm'),
        import('xterm-addon-fit'),
        import('xterm/css/xterm.css')
      ]);

      const term = new Terminal({
        fontSize: 11,
        convertEol: true,
        cursorBlink: false,
        theme: { cursor: '#09090b', background: '#09090b' },
        fontFamily: `'JetBrains Mono','Fira Code','DejaVu Sans Mono','Noto Sans Mono','Noto Sans Symbols 2',monospace`,
        disableStdin: isMobileRef.current
      });
      const fitAddon = new FitAddon();
      term.loadAddon(fitAddon);
      term.open(terminalRef.current);
      fitAddon.fit();

      termRef.current = term;
      fitAddonRef.current = fitAddon;

      // Attach DOM listener to .xterm-viewport
      const container = terminalRef.current;
      const viewport = container?.querySelector('.xterm-viewport');
      if (viewport) {
        const onDomScroll = () => {
          updateScrollIndicator();
          // Close keyboard on scroll (mobile only)
          if (isMobileRef.current && document.activeElement === mobileInputRef.current) {
            try { mobileInputRef.current?.blur(); } catch {}
          }
        };
        const onViewportClick = () => {
          // On mobile, tap on terminal toggles keyboard
          if (isMobileRef.current) {
            if (document.activeElement === mobileInputRef.current) {
              // Close keyboard
              try { mobileInputRef.current?.blur(); } catch {}
            } else {
              // Open keyboard
              try { mobileInputRef.current?.focus(); } catch {}
            }
          }
        };
        viewport.addEventListener('scroll', onDomScroll, { passive: true });
        viewport.addEventListener('click', onViewportClick, { passive: true });

        // Save cleanup function
        onScrollDisposeRef.current = () => {
          try {
            viewport.removeEventListener('scroll', onDomScroll);
            viewport.removeEventListener('click', onViewportClick);
          } catch {}
        };

        // Initialize indicator position
        updateScrollIndicator();
      }

      // Start connection tied to current generation
      connectWithRetry(myGen);

      // Fit size on window resize
      const onWinResize = () => sendResize(peerRef.current);
      window.addEventListener('resize', onWinResize);
      resizeHandlerRef.current = onWinResize;
    };

    initTerminal();

    return () => {
      cleanup('unmount');
    };
  }, [activeTerminal]);

  // iOS Safari viewport fix: lock body scroll and fix base screen height
  useEffect(() => {
    if (!activeTerminal) return;
    if (typeof window === 'undefined') return;

    // 1) Lock document scroll (without "jerks" when address bar collapses)
    const scrollY = window.scrollY || document.documentElement.scrollTop || 0;
    const prev = {
      position: document.body.style.position,
      top: document.body.style.top,
      width: document.body.style.width,
      overflow: document.body.style.overflow,
      overscroll: document.documentElement.style.overscrollBehavior,
    };
    document.body.style.position = 'fixed';
    document.body.style.top = `-${scrollY}px`;
    document.body.style.width = '100%';
    document.body.style.overflow = 'hidden';
    document.documentElement.style.overscrollBehavior = 'none';

    if (window.visualViewport) {
      const update = () => {
        const { height } = window.visualViewport;

        // Remember max height we've seen (screen without system keyboard)
        if (!viewportBaseRef.current || height > viewportBaseRef.current) {
          viewportBaseRef.current = height;
        }

        const appHeight = viewportBaseRef.current || height;

        // IMPORTANT: always use base height, don't shrink when keyboard appears
        document.documentElement.style.setProperty('--app-dvh', `${appHeight}px`);
      };

      update();
      requestAnimationFrame(() => setDvhReady(true));
      window.visualViewport.addEventListener('resize', update);

      return () => {
        document.body.style.position = prev.position;
        document.body.style.top = prev.top;
        document.body.style.width = prev.width;
        document.body.style.overflow = prev.overflow;
        document.documentElement.style.overscrollBehavior = prev.overscroll || '';
        window.scrollTo(0, scrollY);

        window.visualViewport.removeEventListener('resize', update);
        document.documentElement.style.removeProperty('--app-dvh');
        viewportBaseRef.current = 0;
        setDvhReady(false);
      };
    } else {
      // visualViewport not available — simply enable dvhReady and use 100vh
      setDvhReady(true);

      return () => {
        document.body.style.position = prev.position;
        document.body.style.top = prev.top;
        document.body.style.width = prev.width;
        document.body.style.overflow = prev.overflow;
        document.documentElement.style.overscrollBehavior = prev.overscroll || '';
        window.scrollTo(0, scrollY);
      };
    }
  }, [activeTerminal]);

  // Fix base screen height for keyboard size calculation
  // (independent of system keyboard appearance)
  useEffect(() => {
    if (!activeTerminal) return;
    if (typeof window === 'undefined') return;

    const captureBaseHeight = () => {
      const vv = window.visualViewport;

      // Base height = max of layout viewport and visual viewport
      let baseHeight = window.innerHeight;
      if (vv) {
        baseHeight = Math.max(baseHeight, vv.height);
      }

      if (!keyboardBaseRef.current || baseHeight > keyboardBaseRef.current) {
        keyboardBaseRef.current = baseHeight;
        document.documentElement.style.setProperty(
          '--keyboard-base-height',
          `${baseHeight}px`
        );
      }
    };

    captureBaseHeight();

    const vv = window.visualViewport;
    vv?.addEventListener('resize', captureBaseHeight);
    window.addEventListener('orientationchange', captureBaseHeight);

    return () => {
      vv?.removeEventListener('resize', captureBaseHeight);
      window.removeEventListener('orientationchange', captureBaseHeight);
      document.documentElement.style.removeProperty('--keyboard-base-height');
      keyboardBaseRef.current = 0; // Reset on unmount
    };
  }, [activeTerminal]);

  // Disable page auto-zoom during terminal session (iOS)
  useEffect(() => {
    if (!activeTerminal) return;
    const meta = document.querySelector('meta[name="viewport"]');
    if (!meta) return;
    const prev = meta.getAttribute('content') || '';
    // Remove old maximum-scale/user-scalable and add our own
    const cleaned = prev
      .replace(/maximum-scale=[^,]+,?/i, '')
      .replace(/user-scalable=[^,]+,?/i, '')
      .replace(/,\s*,/g, ',')
      .replace(/^,|,$/g, '');
    const next = [cleaned, 'maximum-scale=1', 'user-scalable=no'].filter(Boolean).join(', ');
    meta.setAttribute('content', next);
    return () => meta.setAttribute('content', prev);
  }, [activeTerminal]);

  // Close keyboard on window scroll (mobile)
  useEffect(() => {
    if (!activeTerminal) return;
    if (!isMobile) return;

    const handleWindowScroll = () => {
      if (document.activeElement === mobileInputRef.current) {
        try { mobileInputRef.current?.blur(); } catch {}
      }
    };

    window.addEventListener('scroll', handleWindowScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleWindowScroll);
  }, [activeTerminal, isMobile]);

  // ========== Return Hook API ==========
  return {
    // State
    showQRModal,
    setShowQRModal,
    activeTerminal,
    activeDeviceId,
    activeLabel,
    connectStage,
    agent_devices,
    agentsStatus,
    apiBase,
    authStatus,
    notification,
    setNotification,
    confirmUnbind,
    setConfirmUnbind,
    scrollIndicator,
    isCoarsePointer,
    isAtBottom,
    isMobile,
    isKeyboardVisible,
    setIsKeyboardVisible,
    isInitialized,
    dvhReady,
    KB_STATUS_PX,
    enterMode,

    // Constants
    STAGE_META,
    AUTH_STATUS_META,

    // Refs (for UI components that need direct access)
    terminalRef,
    termRef,
    mobileInputRef,

    // Handlers
    handleQRScan,
    handleUnbindAgent,
    handleAgentClick,
    handleExitTerminal,
    handleKeyboardPress,
    sendTextToTerminal,
    scrollTerminalToBottom,

    // Helper functions exposed for UI
    loadAgents,
  };
}
