/**
 * @olib-ai/secure-embed
 * 
 * Securely embed third-party scripts without hardcoding credentials.
 * Uses Service Worker encryption for runtime credential injection.
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
 * import { SecureEmbed } from '@olib-ai/secure-embed/vanilla';
 * 
 * SecureEmbed.init({
 *   provider: 'hubspot',
 *   configUrl: '/.secure-embed/hubspot.enc'
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

// Re-export crypto utilities
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

// Re-export vanilla API
export { SecureEmbed, init, destroy, healthCheck } from './vanilla/secure-embed.js';
