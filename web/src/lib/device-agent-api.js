import { authFetch } from './client-auth';
import { getWSClient } from './ws-rpc-client';

/**
 * Fetch list of paired agent devices
 * @param {string} apiBase - API base URL
 * @returns {Promise<Array>} Array of agent devices
 */
export async function fetchAgentsList(apiBase) {
  const wsClient = getWSClient();

  if (wsClient?.isConnected) {
    console.log('[device-agent-api] Loading agents via WebSocket RPC');
    const result = await wsClient.call('agent_devices.list', {});
    console.log('[device-agent-api] Received agents:', result.agent_devices);
    return result.agent_devices || [];
  }

  // Fallback to HTTP
  console.log('[device-agent-api] Falling back to HTTP for agents list');
  const res = await authFetch(apiBase, 'agents');
  const data = await res.json();
  return data.agent_devices || [];
}

/**
 * Pair a new agent device with E2EE key exchange
 * @param {string} apiBase - API base URL
 * @param {Object} params - Pairing parameters
 * @param {string} params.agentId - Agent device ID
 * @param {string} params.code - Pairing code
 * @param {string} params.clientStaticPubB64 - Client static public key (base64)
 * @param {number} params.clientStaticTs - Client static key timestamp
 * @param {string} params.clientStaticSigB64 - Client static signature (base64)
 * @returns {Promise<Object>} Pairing response with agent public key
 */
export async function pairAgent(apiBase, {
  agentId,
  code,
  clientStaticPubB64,
  clientStaticTs,
  clientStaticSigB64
}) {
  console.log('[device-agent-api] Pairing agent:', agentId);

  const res = await authFetch(apiBase, 'client/pair/start', {
    method: 'POST',
    body: JSON.stringify({
      agent_device_id: agentId,
      agent_id: agentId,
      code,
      client_static_pub: clientStaticPubB64,
      client_static_ts: clientStaticTs,
      client_static_sig: clientStaticSigB64,
    }),
  });

  if (!res.ok) {
    throw new Error(`Pairing failed: ${res.status} ${res.statusText}`);
  }

  return await res.json();
}

/**
 * Unbind (delete) a paired agent device
 * @param {string} agentDeviceId - Agent device ID to unbind
 * @returns {Promise<void>}
 * @throws {Error} If WebSocket is not connected or unbind fails
 */
export async function unbindAgent(agentDeviceId) {
  const wsClient = getWSClient();

  if (!wsClient?.isConnected) {
    throw new Error('WebSocket not connected - cannot unbind agent');
  }

  console.log('[device-agent-api] Unbinding agent:', agentDeviceId);
  await wsClient.call('agent_devices.delete', {
    agent_device_id: agentDeviceId
  });
}

/**
 * Create a new WebRTC signaling room
 * @param {string} apiBase - API base URL
 * @returns {Promise<Object>} Room object with room_id
 */
export async function createRoom(apiBase) {
  const wsClient = getWSClient();

  if (wsClient?.isConnected) {
    console.log('[device-agent-api] Creating room via WebSocket RPC');
    return await wsClient.call('rooms.create', {});
  }

  // HTTP fallback for rooms is not implemented yet
  throw new Error('[device-agent-api] WebSocket not connected, HTTP fallback for rooms is not implemented yet');
}

/**
 * Invite an agent to a WebRTC room
 * @param {string} apiBase - API base URL
 * @param {Object} params - Invite parameters
 * @param {string} params.roomId - Room ID
 * @param {string} params.agentId - Agent UUID to invite
 * @returns {Promise<void>}
 */
export async function inviteAgentToRoom(apiBase, { roomId, agentId }) {
  const wsClient = getWSClient();

  if (wsClient?.isConnected) {
    console.log('[device-agent-api] Inviting agent via WebSocket RPC');
    await wsClient.call('rooms.invite', {
      room_id: roomId,
      agent_id: agentId
    });
    return;
  }

  // HTTP fallback for rooms.invite is not implemented yet
  throw new Error('[device-agent-api] WebSocket not connected, HTTP fallback for rooms.invite is not implemented yet');
}

/**
 * Send WebRTC signal to agent
 * @param {string} apiBase - API base URL
 * @param {Object} params - Signal parameters
 * @param {string} params.roomId - Room ID
 * @param {string} params.agentId - Agent UUID
 * @param {Object} params.stableData - Serialized WebRTC signal data
 * @returns {Promise<void>}
 */
export async function sendRTCSignal(apiBase, { roomId, agentId, stableData }) {
  const wsClient = getWSClient();

  if (wsClient?.isConnected) {
    await wsClient.call('rtc.signal', {
      room_id: roomId,
      agent_id: agentId,
      stableData
    });
    return;
  }

  // Fallback to HTTP
  await authFetch(apiBase, `rooms/${roomId}/signal`, {
    method: 'POST',
    body: JSON.stringify({
      room_id: roomId,
      agent_id: agentId,
      stableData
    })
  });
}

/**
 * Consume (poll) WebRTC signals from room (HTTP fallback only)
 * @param {string} apiBase - API base URL
 * @param {string} roomId - Room ID
 * @returns {Promise<Object>} Response with array of signal items
 */
export async function consumeRTCSignals(apiBase, roomId) {
  if (!roomId || roomId === 'undefined') {
    throw new Error('[device-agent-api] Invalid roomId for consumeRTCSignals');
  }

  const res = await authFetch(apiBase, `rooms/${roomId}/consume`);
  if (!res.ok) {
    throw new Error(`Failed to consume signals: ${res.status}`);
  }
  return await res.json();
}
