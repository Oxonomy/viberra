import React, { useState, useRef, useEffect } from 'react';
import { ArrowDown, ArrowUp, ArrowLeft, ChevronDown } from 'lucide-react';
import KeyboardShortcuts from '../KeyboardShortcuts';

const MobileInputBar = React.forwardRef(({ onSubmit }, forwardedRef) => {
  const [value, setValue] = useState('');
  const [bottomOffset, setBottomOffset] = useState(0);
  const [keyboardVisible, setKeyboardVisible] = useState(false);
  const [textareaHeight, setTextareaHeight] = useState('auto');
  const localRef = useRef(null);
  const textareaRef = forwardedRef || localRef;
  const containerRef = useRef(null);

  // Keyboard height via VisualViewport
  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (!window.visualViewport) {
      // Fallback – show panel at bottom (without keyboard tracking)
      setKeyboardVisible(true);
      setBottomOffset(0);
      return;
    }
    const updateOffset = () => {
      const vv = window.visualViewport;
      const raw = window.innerHeight - vv.height - vv.offsetTop;
      const keyboardHeight = Math.max(0, Math.round(raw));
      setBottomOffset(keyboardHeight);
      setKeyboardVisible(keyboardHeight > 40);
    };
    window.visualViewport.addEventListener('resize', updateOffset);
    window.visualViewport.addEventListener('scroll', updateOffset);
    window.addEventListener('scroll', updateOffset, { passive: true }); // Fix for scroll jumping
    updateOffset();
    return () => {
      window.visualViewport?.removeEventListener('resize', updateOffset);
      window.visualViewport?.removeEventListener('scroll', updateOffset);
      window.removeEventListener('scroll', updateOffset);
    };
  }, []);

  // Adaptive textarea height
  useEffect(() => {
    const updateHeight = () => {
      const textarea = textareaRef.current;
      if (!textarea) return;

      // Reset height to get real scrollHeight
      textarea.style.height = 'auto';

      // Get required height based on content
      const scrollHeight = textarea.scrollHeight;

      // Minimum — 1 line (approx 44px with padding)
      const minHeight = 44;

      // Maximum — all available height (from top to keyboard)
      // Reserve 80px for top elements (padding, border, etc.)
      const topReserved = 80;
      const maxHeight = Math.max(minHeight * 3, window.innerHeight - bottomOffset - topReserved);

      const newHeight = Math.max(minHeight, Math.min(scrollHeight, maxHeight));
      textarea.style.height = `${newHeight}px`;
      setTextareaHeight(`${newHeight}px`);
    };

    updateHeight();
  }, [value, bottomOffset]);

  const handleSend = () => {
    const text = value;
    if (!text.trim()) return;
    onSubmit?.(text);
    setValue('');
  };

  const handleKeyDown = (e) => {
    // Enter just adds a new line (no submit)
    // Submit only via button click
  };

  return (
    <div
      ref={containerRef}
      className="fixed inset-x-0 z-30 bg-gradient-to-t from-black via-black/95 to-black/60 border-t border-green-900 px-3 pt-2 pb-[env(safe-area-inset-bottom,0px)]"
      style={{
        bottom: keyboardVisible ? `${bottomOffset}px` : '-200px',
        transition: 'bottom 0.3s cubic-bezier(0.4, 0.0, 0.2, 1), opacity 0.25s ease-out',
        opacity: keyboardVisible ? 1 : 0,
        pointerEvents: keyboardVisible ? 'auto' : 'none',
        maxHeight: '70vh'
      }}
    >
      <div className="max-w-6xl mx-auto flex items-end gap-2 max-h-[calc(70vh-40px)]">
        <textarea
          ref={textareaRef}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={handleKeyDown}
          className="
            flex-1 resize-none bg-black border border-green-800 rounded-md px-3 py-2
            text-[16px] md:text-sm
            text-green-100 focus:outline-none focus:border-green-500
            overflow-y-auto transition-[height] duration-75
          "
          style={{
            height: textareaHeight,
            minHeight: '44px'
          }}
        />
        <button
          type="button"
          onClick={handleSend}
          className="
            flex-shrink-0 grid place-items-center w-10 h-10
            bg-green-900 hover:bg-green-800 border border-green-700
            rounded-md text-green-50 transition-colors
          "
          aria-label="Send"
          title="Send"
        >
          <ArrowUp className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
});

const TerminalView = ({
  terminalRef,
  connectStage,
  STAGE_META,
  scrollIndicator,
  isAtBottom,
  isCoarsePointer,
  scrollTerminalToBottom,
  KB_STATUS_PX,
  isKeyboardVisible,
  setIsKeyboardVisible,
  isInitialized,
  dvhReady,
  handleKeyboardPress,
  enterMode,
  isMobile,
  mobileInputRef,
  sendTextToTerminal,
  onExitTerminal
}) => {
  // Parse dynamic stages (e.g., "reconnecting (3/10)")
  const baseStage = connectStage.startsWith('reconnecting') ? 'reconnecting' : connectStage;
  const stageMeta = STAGE_META[baseStage] || STAGE_META.idle;

  // For display, use full text (with attempt number if present)
  const displayText = connectStage.startsWith('reconnecting')
    ? connectStage.toUpperCase()  // "reconnecting (3/10)" → "RECONNECTING (3/10)"
    : stageMeta.text;

  const pulseStages = new Set(['preparing','room','invite','rtc-init','signal→ws','reconnecting']);
  const pulse = pulseStages.has(baseStage) ? 'animate-pulse' : '';

  // Show spinner during connection and reconnection
  const showSpinner = pulseStages.has(baseStage);

  // Recalculate indicator translateY relative to its height, not track
  const indicatorTranslatePercent =
    scrollIndicator.height > 0
      ? (scrollIndicator.top * 100) / scrollIndicator.height
      : 0;

  return (
    <div
      className="fixed inset-x-0 top-0 bg-black text-green-400 font-mono p-0 overflow-hidden pb-[env(safe-area-inset-bottom)]"
      style={{ height: 'var(--app-dvh, 100dvh)' }}
    >
      <div className="max-w-6xl mx-auto h-full px-1">
        <div className="flex flex-col h-full">
          <div className="relative min-h-[30vh] flex-1">
            <div
              ref={terminalRef}
              className="bg-black rounded w-full h-full"
            />

            {showSpinner && (
              <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/80 backdrop-blur-sm rounded">
                <div className="spinner-container">
                  <div className="spinner"></div>
                </div>
                <div className={`mt-6 text-sm font-semibold ${stageMeta.textClass} ${pulse}`}>
                  {displayText}
                </div>
              </div>
            )}

            {isCoarsePointer && scrollIndicator.visible && (
              <div className="absolute inset-y-3 right-1 flex items-stretch pointer-events-none">
                <div className="w-[3px] bg-zinc-900/70 rounded-full overflow-hidden">
                  <div
                    className="w-full bg-emerald-400/80"
                    style={{
                      height: `${scrollIndicator.height * 100}%`,
                      transform: `translateY(${indicatorTranslatePercent}%)`,
                      transition: 'transform 80ms linear',
                    }}
                  />
                </div>
              </div>
            )}

            {!isAtBottom && (
              <button
                type="button"
                onClick={scrollTerminalToBottom}
                title="To bottom"
                aria-label="To bottom"
                className="absolute bottom-3 right-3 z-20 grid place-items-center w-9 h-9 rounded-md bg-black/70 border border-green-700 text-green-200 hover:bg-green-950 hover:border-green-500 transition-colors"
              >
                <ArrowDown className="w-4 h-4" />
              </button>
            )}
          </div>

          <div
            className={`relative z-10 ${isInitialized && dvhReady ? 'transition-all duration-300' : ''}`}
            style={{
              flex: '0 0 auto',
              // Open: 32dvh + status; Hidden: status bar only
              flexBasis: isKeyboardVisible
                ? `clamp(180px, calc((var(--keyboard-base-height, var(--app-dvh, 100dvh)) * 0.32) + ${KB_STATUS_PX}px), 420px)`
                : `${KB_STATUS_PX}px`,
              overflow: 'hidden',
              transition: dvhReady ? 'flex-basis 300ms cubic-bezier(0.4, 0, 0.2, 1)' : 'none',
            }}
          >
            <div className="bg-gray-950 border-2 border-green-900 rounded-lg h-full flex flex-col">
              <div className="grid grid-cols-[1fr_auto_1fr] items-center h-12 px-3 border-b-2 border-green-900 gap-3">
                <button
                  onClick={onExitTerminal}
                  className="justify-self-start px-4 py-2 bg-green-900 hover:bg-green-800 rounded text-sm sm:text-base transition-colors flex items-center gap-2"
                >
                  <ArrowLeft className="w-4 h-4" />
                  EXIT
                </button>

                <button
                  onClick={() => setIsKeyboardVisible(!isKeyboardVisible)}
                  className="justify-self-center  bg-green-900 px-3 py-2 rounded text-sm sm:text-base transition-colors flex items-center justify-center"
                >
                  <ChevronDown
                    className="w-5 h-5 transition-transform duration-300"
                    style={{ transform: isKeyboardVisible ? 'rotate(0deg)' : 'rotate(180deg)'}}
                  />
                </button>

                <div className="min-w-0 justify-self-end flex items-center gap-3">
                  <span className={`text-xs ${stageMeta.textClass} inline-block truncate`}>
                    {displayText}
                  </span>
                  <span className={`w-2 h-2 rounded-full ${stageMeta.dot} ${pulse}`}></span>
                </div>
              </div>

              <div
                className="flex-1 overflow-hidden"
                style={{
                  // When hidden — keyboard area height = 0
                  maxHeight: isKeyboardVisible ? '9999px' : '0px',
                  transition: dvhReady ? 'max-height 300ms cubic-bezier(0.4, 0, 0.2, 1)' : 'none',
                }}
              >
                <div className="h-full px-2 py-3 sm:py-4">
                  <KeyboardShortcuts
                    onKeyPress={handleKeyboardPress}
                    enterMode={enterMode}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <style>{`
        /* Fix scroll jerks and rubber-banding */
        html, body { height: 100%; }
        body { overscroll-behavior: none; }

        /* On modern browsers height is taken from 100dvh; for older browsers – from --app-dvh */
        :root {
          /* If JS hasn't set the variable yet – use dynamic dvh */
          --app-dvh: 100dvh;
        }

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

        /* KEY FIX:
           .xterm-screen is the top layer with text that sits above xterm-viewport.
           It intercepts touch events and prevents scrolling.
           Disable pointer-events so all gestures reach the viewport. */
        .xterm .xterm-screen,
        .xterm .xterm-screen * {
          pointer-events: none !important;
        }

        /* Enable native inertial scroll on mobile */
        .xterm .xterm-viewport {
          -webkit-overflow-scrolling: touch;
          overflow-y: auto;
        }

        /* Mobile / coarse-pointer: hide native scrollbar completely,
           leaving only our custom green indicator */
        @media (pointer: coarse) {
          .xterm .xterm-viewport {
            scrollbar-width: none;              /* Firefox */
          }
          .xterm .xterm-viewport::-webkit-scrollbar {
            width: 0;
            height: 0;
            background: transparent;
          }
        }

        /* Custom scrollbar for xterm — DESKTOP ONLY */
        @media (pointer: fine) {
          .xterm .xterm-viewport::-webkit-scrollbar {
            width: 6px;
          }

          .xterm .xterm-viewport::-webkit-scrollbar-track {
            background: #09090b;
          }

          .xterm .xterm-viewport::-webkit-scrollbar-thumb {
            background: #22c55e;
            border-radius: 3px;
          }

          .xterm .xterm-viewport::-webkit-scrollbar-thumb:hover {
            background: #16a34a;
          }
        }
      `}</style>

      {isMobile && (
        <MobileInputBar
          ref={mobileInputRef}
          onSubmit={sendTextToTerminal}
        />
      )}
    </div>
  );
};

export default TerminalView;
