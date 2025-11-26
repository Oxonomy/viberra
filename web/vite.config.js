import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// ESM-compatible __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Check for development HTTPS certificates (mkcert)
const certPath = path.resolve(__dirname, '../certs/localhost.pem');
const keyPath = path.resolve(__dirname, '../certs/localhost-key.pem');
const useHTTPS = fs.existsSync(certPath) && fs.existsSync(keyPath);

if (useHTTPS) {
  console.log('✅ HTTPS enabled: Found certificates in certs/ directory');
  console.log('   Access via: https://localhost:3000');
} else {
  console.log('ℹ️  HTTPS disabled: No certificates found. Running on HTTP.');
  console.log('   To enable HTTPS, run: ./certs/generate-local-certs.sh');
}

export default defineConfig({
  plugins: [react()],
  server: {
    host: true, // Allow access via LAN IP (0.0.0.0)
    port: 3000,
    https: useHTTPS ? {
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath),
    } : undefined,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true
  },
  define: {
    global: 'globalThis',
    'process.env': {},
    'import.meta.env.API_URL': JSON.stringify(process.env.API_URL || '')
  }
});
