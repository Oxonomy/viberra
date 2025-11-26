import React from 'react';
import { useDeviceAgentPanel } from './useDeviceAgentPanel';
import AgentsList from './AgentsList';
import TerminalView from './TerminalView';

/**
 * DeviceAgentPanel - Main container component
 *
 * Thin wrapper that uses the useDeviceAgentPanel custom hook for all logic
 * and delegates rendering to AgentsList and TerminalView components.
 */
const DeviceAgentPanel = () => {
  const panel = useDeviceAgentPanel();

  // When terminal is active, show terminal view
  if (panel.activeTerminal) {
    return (
      <TerminalView
        terminalRef={panel.terminalRef}
        connectStage={panel.connectStage}
        STAGE_META={panel.STAGE_META}
        scrollIndicator={panel.scrollIndicator}
        isAtBottom={panel.isAtBottom}
        isCoarsePointer={panel.isCoarsePointer}
        scrollTerminalToBottom={panel.scrollTerminalToBottom}
        KB_STATUS_PX={panel.KB_STATUS_PX}
        isKeyboardVisible={panel.isKeyboardVisible}
        setIsKeyboardVisible={panel.setIsKeyboardVisible}
        isInitialized={panel.isInitialized}
        dvhReady={panel.dvhReady}
        handleKeyboardPress={panel.handleKeyboardPress}
        enterMode={panel.enterMode}
        isMobile={panel.isMobile}
        mobileInputRef={panel.mobileInputRef}
        sendTextToTerminal={panel.sendTextToTerminal}
        onExitTerminal={panel.handleExitTerminal}
      />
    );
  }

  // Otherwise, show agents list view
  return (
    <AgentsList
      agentDevices={panel.agent_devices}
      agentsStatus={panel.agentsStatus}
      onAgentClick={panel.handleAgentClick}
      showQRModal={panel.showQRModal}
      onOpenQR={() => panel.setShowQRModal(true)}
      onCloseQR={() => panel.setShowQRModal(false)}
      handleQRScan={panel.handleQRScan}
      notification={panel.notification}
      setNotification={panel.setNotification}
      confirmUnbind={panel.confirmUnbind}
      setConfirmUnbind={panel.setConfirmUnbind}
      handleUnbindAgent={panel.handleUnbindAgent}
      authStatus={panel.authStatus}
      AUTH_STATUS_META={panel.AUTH_STATUS_META}
    />
  );
};

export default DeviceAgentPanel;
