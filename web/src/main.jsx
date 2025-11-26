import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';
import { Buffer } from 'buffer';

// Polyfills for packages expecting Node.js environment
if (!window.global) window.global = window;
if (!window.process) window.process = { env: {} };
if (!window.Buffer) window.Buffer = Buffer;

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
