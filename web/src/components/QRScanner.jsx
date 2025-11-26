import React, { useEffect, useRef, useState } from 'react';
import { X, QrCode } from 'lucide-react';

const QRScanner = ({ isOpen, onClose, onScan }) => {
  const videoRef = useRef(null);
  const [error, setError] = useState(null);
  const readerRef = useRef(null);
  const controlsRef = useRef(null);

  useEffect(() => {
    if (!isOpen) return;

    const startScanner = async () => {
      try {
        // Lazy-load ZXing when modal opens
        const { BrowserMultiFormatReader } = await import('@zxing/browser');

        const codeReader = new BrowserMultiFormatReader();
        readerRef.current = codeReader;

        const devices = await BrowserMultiFormatReader.listVideoInputDevices();
        if (devices.length === 0) {
          setError('No camera found');
          return;
        }

        const selectedDeviceId = devices[0].deviceId;

        const controls = await codeReader.decodeFromVideoDevice(
          selectedDeviceId,
          videoRef.current,
          (result, err) => {
            if (result) {
              onScan(result.getText());
              cleanup();
            }
          }
        );

        controlsRef.current = controls;
      } catch (err) {
        console.error('QR Scanner error:', err);
        setError(err.message);
      }
    };

    startScanner();

    return () => {
      cleanup();
    };
  }, [isOpen]);

  const cleanup = () => {
    try {
      if (controlsRef.current) {
        controlsRef.current.stop();
        controlsRef.current = null;
      }
      if (readerRef.current) {
        // Check if reset method exists before calling it
        if (typeof readerRef.current.reset === 'function') {
          readerRef.current.reset();
        }
        readerRef.current = null;
      }
    } catch (err) {
      console.error('Cleanup error:', err);
    }
  };

  const handleClose = () => {
    cleanup();
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-90 flex items-center justify-center p-6 z-50">
      <div className="bg-gray-950 border border-green-900 rounded-lg p-6 max-w-md w-full">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold">Pairing via QR</h2>
          <button
            onClick={handleClose}
            className="text-green-600 hover:text-green-400 transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        <p className="text-sm text-green-600 mb-4">
          Point camera at QR code from agent
        </p>

        <div className="bg-black border border-green-900 rounded-lg mb-4 aspect-square flex items-center justify-center relative overflow-hidden">
          {error ? (
            <div className="text-center z-10">
              <QrCode className="w-16 h-16 mx-auto mb-2 text-red-500" />
              <p className="text-sm text-red-500">{error}</p>
            </div>
          ) : (
            <>
              <video
                ref={videoRef}
                className="absolute inset-0 w-full h-full object-cover"
                autoPlay
                playsInline
              />
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="w-48 h-48 border-2 border-green-500 rounded-lg relative">
                  <div className="absolute top-0 left-0 w-6 h-6 border-t-4 border-l-4 border-green-500"></div>
                  <div className="absolute top-0 right-0 w-6 h-6 border-t-4 border-r-4 border-green-500"></div>
                  <div className="absolute bottom-0 left-0 w-6 h-6 border-b-4 border-l-4 border-green-500"></div>
                  <div className="absolute bottom-0 right-0 w-6 h-6 border-b-4 border-r-4 border-green-500"></div>
                </div>
              </div>
            </>
          )}
        </div>

        <button
          onClick={handleClose}
          className="w-full bg-gray-900 hover:bg-gray-800 text-green-400 py-3 rounded-lg font-semibold transition-colors border border-green-900"
        >
          CANCEL
        </button>
      </div>
    </div>
  );
};

export default QRScanner;
