/**
 * @olib-ai/secure-embed
 *
 * Securely embed third-party scripts without hardcoding credentials.
 * Uses Service Worker + WebAssembly encryption for runtime credential injection.
 *
 * All security-critical operations are compiled to WebAssembly to prevent
 * reverse engineering of the protection mechanisms.
 *
 * @example
 * ```tsx
 * // React
 * import { SecureEmbed } from '@olib-ai/secure-embed/react';
 *
 * <SecureEmbed
 *   provider="intercom"
 *   configUrl="/.secure-embed/intercom.enc"
 * />
 * ```
 *
 * @example
 * ```ts
 * // Vanilla JS
 * import { SecureEmbed } from '@olib-ai/secure-embed';
 *
 * SecureEmbed.init({
 *   provider: 'intercom',
 *   configUrl: '/.secure-embed/intercom.enc'
 * });
 * ```
 */

// Re-export types
export type {
  ProviderType,
  EncryptedConfig,
  CredentialPayload,
  EmbedConfig,
  CLIInputConfig,
  ProviderConfig,
  SWMessageType,
  SWResponse,
} from './types.js';

// Re-export crypto utilities (for CLI and config generation)
export {
  encryptCredentials,
  decryptCredentials,
  verifyIntegrity,
} from './crypto.js';

// Re-export provider utilities
export {
  getProviderConfig,
  interpolate,
  getInterceptRegexes,
  providers,
} from './providers/index.js';

// Re-export secure core API (main public API)
export {
  SecureEmbed,
  init,
  destroy,
  healthCheck,
  getMemoryStats,
  abortAllOperations,
  cleanup,
} from './secure-core/secure-loader.js';

// Re-export Wasm core utilities
export {
  loadWasmCore,
  getWasmCore,
  releaseWasmCore,
  ProtocolMessageType,
} from './secure-core/wasm-loader.js';

export type { WasmCryptoCore } from './secure-core/wasm-loader.js';
