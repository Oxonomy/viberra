import React from 'react';
import { useNavigate } from 'react-router-dom';
import { QrCode, X } from 'lucide-react';
import QRScanner from '../QRScanner';
import NotificationModal from '../NotificationModal';
import ConfirmDialog from '../ConfirmDialog';

const AgentsList = ({
  agentDevices,
  agentsStatus,
  onAgentClick,
  showQRModal,
  onOpenQR,
  onCloseQR,
  handleQRScan,
  notification,
  setNotification,
  confirmUnbind,
  setConfirmUnbind,
  handleUnbindAgent,
  authStatus,
  AUTH_STATUS_META
}) => {
  const navigate = useNavigate();
  const authMeta = AUTH_STATUS_META[authStatus] || AUTH_STATUS_META.initializing;
  const authPulse = authStatus === 'authenticating' ? 'animate-pulse' : '';

  const handleGetStarted = () => {
    navigate('/');
    setTimeout(() => {
      document.getElementById('getting-started')?.scrollIntoView();
    }, 100);
  };

  const showAgentsSpinner =
    authStatus === 'initializing' ||
    authStatus === 'authenticating' ||
    (authStatus === 'ready' && agentsStatus === 'loading');

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono p-2 sm:p-3 pb-24">
      <div className="w-full max-w-6xl mx-auto">
        <div className="mb-4">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${authMeta.dot} ${authPulse}`}></span>
            <span className={`text-sm ${authMeta.textClass}`}>{authMeta.text}</span>
          </div>
        </div>

        <div className="space-y-4">
          {agentDevices.map((device) => (
            <div key={device.id} className="bg-gray-950 border border-green-900 rounded-lg p-4">
              <div className="flex items-center justify-between mb-4 pb-3 border-green-900">
                <h2 className="text-sm font-semibold">{device.device_name.toUpperCase()}</h2>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-green-600">{device.connections?.length ?? 0} agent(s)</span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setConfirmUnbind({ deviceId: device.id, deviceName: device.device_name });
                    }}
                    className="text-rose-500 hover:text-rose-400 transition-colors p-1 hover:bg-rose-950 rounded"
                    title="Unbind device"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                {device.connections.map((agent) => (
                  <div
                    key={agent.uuid}
                    onClick={() => onAgentClick(agent, device.id, agent.online ? 'online' : 'offline')}
                    className={`flex items-center justify-between p-3 transition-all duration-200 ${
                      agent.online
                        ? 'hover:border-t-green-500 hover:border-l-green-500 hover:border-b-black hover:border-r-black hover:bg-green-950 hover:shadow-lg hover:shadow-green-900/50 hover:scale-[1.02] cursor-pointer active:scale-[0.98] active:border-t-green-950 active:border-l-green-950 active:border-b-green-500 active:border-r-green-500'
                        : 'opacity-60 cursor-not-allowed'
                    }`}
                  >
                    <div className="flex items-center gap-3 flex-1">
                      <div className={`w-3 h-3 rounded-full ${agent.online ? 'bg-green-500' : 'bg-gray-600'}`}></div>
                      <span className={`font-medium ${agent.online ? 'text-green-400' : 'text-gray-600'}`}>
                        {agent.agent_workdir_name}
                      </span>
                    </div>
                    <span
                      className={`text-xs px-3 py-1 rounded ${
                        agent.online ? 'bg-green-900 text-green-300' : 'bg-gray-900 text-gray-500'
                      }`}
                    >
                      {agent.mode}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {agentsStatus === 'loading' && (
          <div className="space-y-3 animate-pulse py-4">
            {[0].map(i => (
              <div key={i} className="h-24 bg-gray-900/40 border border-green-900 rounded-lg" />
            ))}
          </div>
        )}

        {agentsStatus === 'loaded' && agentDevices.length === 0 && (
          <div className="text-center py-8">
            <p className="text-green-700 mb-4">
              No paired agents yet. Get started by setting up your first device.
            </p>
            <button
              onClick={handleGetStarted}
              className="inline-flex items-center justify-center gap-2 bg-transparent border border-green-600 text-green-600 hover:bg-green-600/10 hover:shadow-[0_0_20px_hsl(142_76%_56%/0.4)] transition-all duration-300 px-6 py-2 text-sm font-medium rounded-lg cursor-pointer"
            >
              Get Started
            </button>
          </div>
        )}

        {agentsStatus === 'error' && (
          <div className="text-center text-rose-500 py-8">
            Failed to load agent list. Please try again later.
          </div>
        )}
      </div>

      <div className="fixed bottom-0 left-0 right-0 p-6 bg-gradient-to-t from-black via-black to-transparent">
        <div className="w-full max-w-6xl mx-auto">
          <button
            onClick={onOpenQR}
            className="w-full bg-green-900 hover:bg-green-800 text-green-100 py-4 rounded-lg font-semibold flex items-center justify-center gap-2 transition-colors border border-green-700"
          >
            <QrCode className="w-5 h-5" />
            PAIR DEVICE VIA QR
          </button>
        </div>
      </div>

      <QRScanner
        isOpen={showQRModal}
        onClose={onCloseQR}
        onScan={handleQRScan}
      />

      <NotificationModal
        isOpen={notification.isOpen}
        type={notification.type}
        title={notification.title}
        message={notification.message}
        onClose={() => setNotification({ ...notification, isOpen: false })}
        autoCloseMs={notification.type === 'success' ? 3000 : null}
      />

      <ConfirmDialog
        isOpen={!!confirmUnbind}
        title="Unbind device?"
        message={`Are you sure you want to unbind agent "${confirmUnbind?.deviceName}"? This action cannot be undone.`}
        onConfirm={handleUnbindAgent}
        onCancel={() => setConfirmUnbind(null)}
      />

      {showAgentsSpinner && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/80 backdrop-blur-sm">
          <div className="flex flex-col items-center">
            <div className="spinner-container">
              <div className="spinner" />
            </div>
            <div className="mt-6 flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${authMeta.dot} ${authPulse}`}></span>
              <span className={`text-sm ${authMeta.textClass}`}>{authMeta.text}</span>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        .spinner-container {
          position: relative;
          width: 80px;
          height: 80px;
        }

        .spinner {
          width: 100%;
          height: 100%;
          border: 4px solid transparent;
          border-top: 4px solid #22c55e;
          border-right: 4px solid #22c55e;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          box-shadow: 0 0 20px rgba(34, 197, 94, 0.5), inset 0 0 10px rgba(34, 197, 94, 0.2);
        }
      `}</style>
    </div>
  );
};

export default AgentsList;
