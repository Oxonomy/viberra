import React, { useEffect } from 'react';
import { X, CheckCircle, AlertCircle, Info, AlertTriangle } from 'lucide-react';

const NotificationModal = ({ isOpen, type = 'info', title, message, onClose, autoCloseMs = null }) => {
  useEffect(() => {
    if (isOpen && autoCloseMs && type !== 'pending') {
      const timer = setTimeout(() => {
        onClose?.();
      }, autoCloseMs);
      return () => clearTimeout(timer);
    }
  }, [isOpen, autoCloseMs, type, onClose]);

  if (!isOpen) return null;

  const TYPE_CONFIG = {
    pending: {
      icon: null,
      iconColor: 'text-amber-500',
      borderColor: 'border-amber-900',
      textColor: 'text-amber-400',
      bgDot: 'bg-amber-500',
    },
    success: {
      icon: CheckCircle,
      iconColor: 'text-green-500',
      borderColor: 'border-green-900',
      textColor: 'text-green-400',
      bgDot: 'bg-green-500',
    },
    error: {
      icon: AlertCircle,
      iconColor: 'text-rose-500',
      borderColor: 'border-rose-900',
      textColor: 'text-rose-400',
      bgDot: 'bg-rose-500',
    },
    warning: {
      icon: AlertTriangle,
      iconColor: 'text-amber-500',
      borderColor: 'border-amber-900',
      textColor: 'text-amber-400',
      bgDot: 'bg-amber-500',
    },
    info: {
      icon: Info,
      iconColor: 'text-blue-500',
      borderColor: 'border-blue-900',
      textColor: 'text-blue-400',
      bgDot: 'bg-blue-500',
    },
  };

  const config = TYPE_CONFIG[type] || TYPE_CONFIG.info;
  const Icon = config.icon;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-90 flex items-center justify-center p-6 z-50 animate-fadeIn">
      <div className={`bg-gray-950 border ${config.borderColor} rounded-lg p-6 max-w-md w-full`}>
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            {type === 'pending' ? (
              <div className="spinner-small"></div>
            ) : Icon ? (
              <Icon className={`w-6 h-6 ${config.iconColor}`} />
            ) : null}
            <h2 className={`text-xl font-bold ${config.textColor}`}>{title}</h2>
          </div>
          {type !== 'pending' && (
            <button
              onClick={onClose}
              className={`${config.textColor} hover:opacity-70 transition-opacity`}
            >
              <X className="w-6 h-6" />
            </button>
          )}
        </div>

        <p className={`text-sm ${config.textColor} mb-6`}>
          {message}
        </p>

        {type === 'pending' && (
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <span className={`w-2 h-2 rounded-full ${config.bgDot} animate-pulse`}></span>
            <span>Waiting...</span>
          </div>
        )}

        {type !== 'pending' && (
          <button
            onClick={onClose}
            className={`w-full bg-gray-900 hover:bg-gray-800 ${config.textColor} py-3 rounded-lg font-semibold transition-colors border ${config.borderColor}`}
          >
            CLOSE
          </button>
        )}
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        .animate-fadeIn {
          animation: fadeIn 0.2s ease-out;
        }

        .spinner-small {
          width: 24px;
          height: 24px;
          border: 3px solid transparent;
          border-top: 3px solid #f59e0b;
          border-right: 3px solid #f59e0b;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }
      `}</style>
    </div>
  );
};

export default NotificationModal;
