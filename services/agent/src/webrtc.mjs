import { log, logW } from './logger.mjs';

/**
 * Collects detailed ICE connection state information from SimplePeer
 * @param {SimplePeer} sp - SimplePeer instance
 * @returns {Object} Object with diagnostic information
 */
export function collectIceStats(sp) {
  const stats = {
    peerState: {
      connected: sp?.connected ?? false,
      destroyed: sp?.destroyed ?? false,
    },
    iceState: null,
  };

  try {
    const pc = sp?._pc; // RTCPeerConnection (internal)
    if (pc) {
      stats.iceState = {
        connection: pc.connectionState ?? 'unknown',
        iceConnection: pc.iceConnectionState ?? 'unknown',
        iceGathering: pc.iceGatheringState ?? 'unknown',
        signalingState: pc.signalingState ?? 'unknown',
      };

      // Async collection of ICE candidates via getStats()
      // Don't block main flow, just launch Promise
      pc.getStats()
        .then((statsReport) => {
          let pairs = 0;
          let localCandidates = 0;
          let remoteCandidates = 0;

          statsReport.forEach((stat) => {
            if (stat.type === 'candidate-pair') pairs++;
            if (stat.type === 'local-candidate') localCandidates++;
            if (stat.type === 'remote-candidate') remoteCandidates++;
          });

          log(
            'ICE stats on error: connection=%s iceConnection=%s pairs=%d local=%d remote=%d',
            stats.iceState.connection,
            stats.iceState.iceConnection,
            pairs,
            localCandidates,
            remoteCandidates
          );
        })
        .catch(() => {}); // Ignore getStats errors
    }
  } catch (err) {
    // If stats collection fails — don't break main flow
    stats.iceState = { error: err?.message || 'unknown' };
  }

  return stats;
}

/**
 * Logs selected ICE pair (local/remote candidate) via getStats()
 */
export async function logSelectedCandidatePair(sp, prefix = '[ICE]') {
  try {
    const pc = sp?._pc;
    if (!pc || typeof pc.getStats !== 'function') {
      logW('%s getStats not available on peerConnection', prefix);
      return;
    }

    const stats = await pc.getStats();
    let selectedPair = null;
    const candidates = {};

    stats.forEach((s) => {
      // node-webrtc typically returns these types
      if (s.type === 'candidate-pair' && (s.selected || s.state === 'succeeded')) {
        selectedPair = s;
      } else if (s.type === 'local-candidate' || s.type === 'remote-candidate') {
        candidates[s.id] = s;
      }
    });

    if (!selectedPair) {
      logW('%s no selected ICE candidate pair in stats', prefix);
      return;
    }

    const local = candidates[selectedPair.localCandidateId] || {};
    const remote = candidates[selectedPair.remoteCandidateId] || {};

    log(
      '%s selected pair: local %s:%s (%s,%s) -> remote %s:%s (%s,%s) state=%s nominated=%s',
      prefix,
      local.ip || local.address, local.port,
      local.protocol, local.candidateType,
      remote.ip || remote.address, remote.port,
      remote.protocol, remote.candidateType,
      selectedPair.state, selectedPair.nominated
    );
  } catch (e) {
    logW('%s failed to get ICE selected pair: %s', prefix, e?.message || e);
  }
}

/**
 * Attaches detailed ICE state and candidate logging to SimplePeer._pc
 */
export function attachIceDebug(sp, { roomId, clientDeviceId, agentDeviceId }) {
  const pc = sp?._pc;
  if (!pc) {
    logW('attachIceDebug: peerConnection not available');
    return;
  }

  const prefix = `[ICE room=${roomId} client=${clientDeviceId || '-'} agent=${agentDeviceId || '-'}]`;

  const dumpStates = () => {
    log(
      '%s states: connection=%s iceConnection=%s iceGathering=%s signaling=%s',
      prefix,
      pc.connectionState || 'n/a',
      pc.iceConnectionState || 'n/a',
      pc.iceGatheringState || 'n/a',
      pc.signalingState || 'n/a'
    );
  };

  const onIceConnChange = () => {
    dumpStates();

    // Log selected pair when state becomes interesting
    if (
      pc.iceConnectionState === 'connected' ||
      pc.iceConnectionState === 'completed' ||
      pc.iceConnectionState === 'disconnected' ||
      pc.iceConnectionState === 'failed'
    ) {
      logSelectedCandidatePair(sp, prefix).catch(() => {});
    }
  };

  // Fallback: try both addEventListener and onXYZ
  if (pc.addEventListener) {
    pc.addEventListener('iceconnectionstatechange', onIceConnChange);
    pc.addEventListener('connectionstatechange', () => {
      log('%s connectionState changed: %s', prefix, pc.connectionState || 'n/a');
    });
    pc.addEventListener('signalingstatechange', () => {
      log('%s signalingState changed: %s', prefix, pc.signalingState || 'n/a');
    });
    pc.addEventListener('icegatheringstatechange', () => {
      log('%s iceGatheringState changed: %s', prefix, pc.iceGatheringState || 'n/a');
    });
    pc.addEventListener('icecandidate', (ev) => {
      const c = ev.candidate;
      if (!c) {
        log('%s local ICE candidate gathering complete', prefix);
        return;
      }
      log(
        '%s local candidate: %s %s:%s type=%s rel=%s:%s',
        prefix,
        c.protocol,
        c.address || c.ip,
        c.port,
        c.type,
        c.relatedAddress || '-',
        c.relatedPort || '-'
      );
    });
  } else {
    pc.oniceconnectionstatechange = onIceConnChange;
  }

  dumpStates();
}

export function normalizeIceServers(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.map((s) => {
    if (Array.isArray(s.urls)) return s;
    if (typeof s.urls === 'string') return s;
    if (s.url) return { urls: s.url, username: s.username, credential: s.credential };
    return s;
  });
}

export function safeParseJSON(raw) {
  try {
    return JSON.parse(typeof raw === 'string' ? raw : String(raw));
  } catch {
    return null;
  }
}
