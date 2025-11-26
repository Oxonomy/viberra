import React, { useState, useRef, useEffect } from 'react';
import {
  ArrowUp,
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  Delete,
  ArrowBigUp,
  CornerDownLeft,
  Check,
  CheckCheck,
  OctagonX,
} from 'lucide-react';

const KeyboardShortcuts = ({ onKeyPress, enterMode = 'default' }) => {
  const [activeKey, setActiveKey] = useState(null);
  const repeatTimeoutRef = useRef(null);
  const repeatIntervalRef = useRef(null);

  const renderEnterLabel = () => {
    switch (enterMode) {
      case 'approve_auto':
        return (
          <span className="flex items-center gap-1">
            <Check className="w-5 sm:w-6 h-5 sm:h-6" />
            <span>APPROVED</span>
          </span>
        );
      case 'approve_manual':
        return (
          <span className="flex items-center gap-1">
            <CheckCheck className="w-5 sm:w-6 h-5 sm:h-6" />
            <span>APPROVED</span>
          </span>
        );
      case 'stop':
        return (
          <span className="flex items-center gap-1">
            <OctagonX className="w-5 sm:w-6 h-5 sm:h-6" />
            <span>STOP</span>
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1">
            <CornerDownLeft className="w-5 sm:w-6 h-5 sm:h-6" />
            <span>ENTER</span>
          </span>
        );
    }
  };

  const handleKeyClick = (key) => {
    // Visual feedback
    setActiveKey(key);
    setTimeout(() => setActiveKey(null), 200);

    // Trigger callback
    onKeyPress?.(key);
  };

  // Auto-repeat configuration (like a real keyboard)
  const REPEAT_DELAY = 500;  // initial delay before repeat starts
  const REPEAT_RATE = 33;    // repeat every 33ms (like real keyboard)

  const handlePointerDown = (key, isRepeatable) => {
    // Visual feedback
    setActiveKey(key);

    // First press
    onKeyPress?.(key);

    // Auto-repeat only for arrows and backspace
    if (isRepeatable) {
      repeatTimeoutRef.current = setTimeout(() => {
        repeatIntervalRef.current = setInterval(() => {
          onKeyPress?.(key);
        }, REPEAT_RATE);
      }, REPEAT_DELAY);
    }
  };

  const handlePointerUp = () => {
    // Clear timers
    if (repeatTimeoutRef.current) {
      clearTimeout(repeatTimeoutRef.current);
      repeatTimeoutRef.current = null;
    }
    if (repeatIntervalRef.current) {
      clearInterval(repeatIntervalRef.current);
      repeatIntervalRef.current = null;
    }
    // Reset immediately without delay — reduces bouncing
    setActiveKey(null);
  };
  // Cleanup timers on unmount
  useEffect(() => {
    return () => {
      if (repeatTimeoutRef.current) clearTimeout(repeatTimeoutRef.current);
      if (repeatIntervalRef.current) clearInterval(repeatIntervalRef.current);
    };
  }, []);

  const getButtonClass = (key) => {
    const isEnterKey = key === 'enter';
    const isApprovedMode =
      enterMode === 'approve_auto' || enterMode === 'approve_manual';

    const baseStateClasses =
      activeKey === key
        ? 'bg-green-900 border-t-green-950 border-l-green-950 border-b-green-500 border-r-green-500'
        : 'bg-black border-t-green-700 border-l-green-700 border-b-green-950 border-r-green-950';

    // For ENTER in APPROVED modes, give green fill
    const approvedEnterClasses =
      isEnterKey && isApprovedMode
        ? activeKey === key
          ? ' bg-green-700 border-t-green-200 border-l-green-200 border-b-green-900 border-r-green-900'
          : ' bg-green-600 border-t-green-200 border-l-green-200 border-b-green-900 border-r-green-900'
        : '';

    // Text color: black on fill, green by default
    const textColorClasses =
      isEnterKey && isApprovedMode ? 'text-black' : 'text-green-400';

    return `
      ${baseStateClasses}
      ${approvedEnterClasses}
      border-2 rounded px-2.5 sm:px-3.5 py-2.5 sm:py-3.5 text-sm sm:text-base font-bold font-mono
      hover:border-t-green-500 hover:border-l-green-500 hover:border-b-black hover:border-r-black
      hover:bg-green-950 hover:shadow-lg hover:shadow-green-900/50
      active:scale-95 cursor-pointer
      transition-all duration-200
      flex items-center justify-center min-h-10 sm:min-h-12
      ${textColorClasses}
    `;
  };

  // Key button component
  const KeyButton = ({ keyName, label, className = '', isRepeatable = false }) => (
      <button
          onPointerDown={(e) => {
              e.preventDefault();
              // Capture pointer so finger doesn't wander between elements
              e.currentTarget.setPointerCapture?.(e.pointerId);
              handlePointerDown(keyName, isRepeatable);
          }}
          onPointerUp={(e) => {
              e.preventDefault();
              handlePointerUp();
          }}
          onPointerCancel={handlePointerUp}
          onPointerLeave={(e) => {
              // If pointer is captured - ignore leave
              if (e.currentTarget.hasPointerCapture?.(e.pointerId)) return;
              handlePointerUp();
          }}
          onContextMenu={(e) => e.preventDefault()}
          className={`keyboard-button ${getButtonClass(keyName)} ${className}`}
          title={keyName.toUpperCase()}
      >
          {label}
      </button>

  );

  // CSS to disable hover, active on touch devices, and text selection
  const styles = `
    .keyboard-button,
    .keyboard-button * {
        user-select: none;
        -webkit-user-select: none;
        -webkit-touch-callout: none;
        -webkit-tap-highlight-color: transparent;
        touch-action: manipulation;
    }
    
    @media (hover: none) {
        .keyboard-button:hover {
        background-color: black !important;
        border-top-color: rgb(21 128 61) !important;
        border-left-color: rgb(21 128 61) !important;
        border-bottom-color: rgb(20 83 45) !important;
        border-right-color: rgb(20 83 45) !important;
        box-shadow: none !important;
    }
    .keyboard-button:active {
        transform: none !important;
    }
    }
  `;

  return (
    <>
      <style>{styles}</style>
      <div className="grid grid-cols-4 gap-2 h-full">
      <KeyButton keyName="escape" label="ESC" />
      <KeyButton keyName="ctrlC" label="^C" />
      <KeyButton keyName="enter" label={renderEnterLabel()} className="col-span-2"/>

      <KeyButton keyName="tab" label="TAB" />
      <KeyButton keyName="slash" label="/" />
      <KeyButton keyName="up" label={<ArrowUp className="w-5 sm:w-6 h-5 sm:h-6" />} isRepeatable />
      <KeyButton keyName="backspace" label={<Delete className="w-5 sm:w-6 h-5 sm:h-6" />} isRepeatable />

      <KeyButton keyName="shiftTab" label={ <span className="flex items-center gap-1"> <ArrowBigUp className="w-5 sm:w-6 h-5 sm:h-6" /> <span>TAB</span> </span> }/>
      <KeyButton keyName="left" label={<ArrowLeft className="w-5 sm:w-6 h-5 sm:h-6" />} isRepeatable />
      <KeyButton keyName="down" label={<ArrowDown className="w-5 sm:w-6 h-5 sm:h-6" />} isRepeatable />
      <KeyButton keyName="right" label={<ArrowRight className="w-5 sm:w-6 h-5 sm:h-6" />} isRepeatable />

      </div>
    </>
  );
};

export default KeyboardShortcuts;
