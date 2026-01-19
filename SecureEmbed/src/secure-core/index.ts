/**
 * SecureEmbed Secure Core Module
 *
 * This module provides a hardened, Wasm-based implementation of SecureEmbed.
 * All security-critical operations are delegated to compiled WebAssembly
 * to prevent reverse engineering.
 *
 * Exports:
 * - SecureEmbed: Main API object
 * - init: Initialize a secure embed
 * - destroy: Remove an embed
 * - healthCheck: Check service worker health
 * - getMemoryStats: Get memory statistics
 * - cleanup: Release all resources
 */

export {
  SecureEmbed,
  init,
  destroy,
  healthCheck,
  getMemoryStats,
  abortAllOperations,
  cleanup,
} from './secure-loader.js';

export {
  loadWasmCore,
  getWasmCore,
  releaseWasmCore,
  ProtocolMessageType,
} from './wasm-loader.js';

export type { WasmCryptoCore } from './wasm-loader.js';
