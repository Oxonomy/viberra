import React from 'react';
import { AlertTriangle, X } from 'lucide-react';

const ConfirmDialog = ({ isOpen, title, message, onConfirm, onCancel, confirmText = 'DELETE', cancelText = 'CANCEL' }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-90 flex items-center justify-center p-6 z-50 animate-fadeIn">
      <div className="bg-gray-950 border border-rose-900 rounded-lg p-6 max-w-md w-full">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-6 h-6 text-rose-500" />
            <h2 className="text-xl font-bold text-rose-400">{title}</h2>
          </div>
          <button
            onClick={onCancel}
            className="text-rose-400 hover:opacity-70 transition-opacity"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        <p className="text-sm text-rose-400 mb-6">
          {message}
        </p>

        <div className="flex gap-3">
          <button
            onClick={onCancel}
            className="flex-1 bg-gray-900 hover:bg-gray-800 text-green-400 py-3 rounded-lg font-semibold transition-colors border border-green-900"
          >
            {cancelText}
          </button>
          <button
            onClick={onConfirm}
            className="flex-1 bg-rose-900 hover:bg-rose-800 text-rose-100 py-3 rounded-lg font-semibold transition-colors border border-rose-700"
          >
            {confirmText}
          </button>
        </div>
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        .animate-fadeIn {
          animation: fadeIn 0.2s ease-out;
        }
      `}</style>
    </div>
  );
};

export default ConfirmDialog;
