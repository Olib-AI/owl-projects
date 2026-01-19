#!/usr/bin/env node
/**
 * Simple development server for SecureEmbed demo.
 * Serves static files with correct MIME types and Service Worker scope headers.
 */

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT_DIR = resolve(__dirname, '..');

const PORT = process.env.PORT ?? 3000;

/** MIME type mapping */
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.map': 'application/json',
  '.wasm': 'application/wasm',
};

/**
 * Resolves a URL path to a file system path.
 * Handles the Service Worker requirement to be at root.
 */
function resolveFilePath(urlPath) {
  // Service Worker (Wasm-secured)
  if (urlPath === '/secure-embed-sw.js') {
    return join(ROOT_DIR, 'dist', 'secure-sw.min.js');
  }

  // Wasm crypto core module
  if (urlPath === '/secure-embed-core.wasm') {
    return join(ROOT_DIR, 'wasm', 'build', 'crypto-core.wasm');
  }

  // Handle root path
  if (urlPath === '/' || urlPath === '') {
    return join(ROOT_DIR, 'examples', 'index.html');
  }

  // Handle dist files
  if (urlPath.startsWith('/dist/')) {
    return join(ROOT_DIR, urlPath.slice(1));
  }

  // Handle wasm files
  if (urlPath.startsWith('/wasm/')) {
    return join(ROOT_DIR, urlPath.slice(1));
  }

  // Handle examples files
  if (urlPath.startsWith('/examples/')) {
    return join(ROOT_DIR, urlPath.slice(1));
  }

  // Default to examples directory
  return join(ROOT_DIR, 'examples', urlPath.slice(1));
}

/**
 * Main request handler.
 */
async function handleRequest(req, res) {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);
  const filePath = resolveFilePath(url.pathname);

  console.log(`[${new Date().toISOString()}] ${req.method} ${url.pathname} -> ${filePath}`);

  try {
    // Security: prevent directory traversal
    const normalizedPath = resolve(filePath);
    if (!normalizedPath.startsWith(ROOT_DIR)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }

    // Check file exists
    const stats = await stat(normalizedPath);
    if (!stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    const ext = extname(normalizedPath);
    const mimeType = MIME_TYPES[ext] ?? 'application/octet-stream';
    const content = await readFile(normalizedPath);

    // Set headers
    const headers = {
      'Content-Type': mimeType,
      'Content-Length': content.length,
      'Cache-Control': 'no-cache',
      // Required for Service Worker to work at root scope
      'Service-Worker-Allowed': '/',
    };

    // CORS headers for development
    headers['Access-Control-Allow-Origin'] = '*';
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type';

    res.writeHead(200, headers);
    res.end(content);

  } catch (err) {
    if (err.code === 'ENOENT') {
      console.error(`  404: File not found - ${filePath}`);
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found: ' + url.pathname);
    } else {
      console.error(`  500: ${err.message}`);
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Server Error');
    }
  }
}

// Create and start server
const server = createServer(handleRequest);

server.listen(PORT, () => {
  console.log('');
  console.log('===========================================');
  console.log('  SecureEmbed Demo Server v2.0 (Wasm)');
  console.log('===========================================');
  console.log('');
  console.log(`  Local:   http://localhost:${PORT}`);
  console.log(`  Network: http://127.0.0.1:${PORT}`);
  console.log('');
  console.log('  Files served:');
  console.log('    /                       -> examples/index.html');
  console.log('    /secure-embed-sw.js     -> dist/secure-sw.min.js (Wasm)');
  console.log('    /secure-embed-core.wasm -> wasm/build/crypto-core.wasm');
  console.log('    /dist/*                 -> dist/*');
  console.log('    /wasm/*                 -> wasm/*');
  console.log('');
  console.log('  Press Ctrl+C to stop');
  console.log('');
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Error: Port ${PORT} is already in use`);
    console.error(`Try: PORT=3001 npm run demo`);
  } else {
    console.error('Server error:', err);
  }
  process.exit(1);
});
