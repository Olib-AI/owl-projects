/**
 * Core types for @olib-ai/secure-embed
 */

/** Supported embed provider identifiers */
export type ProviderType =
  | 'intercom'
  | 'crisp'
  | 'hubspot'
  | 'drift'
  | 'google-analytics'
  | 'mixpanel'
  | 'segment'
  | 'typeform'
  | 'jotform'
  | 'custom';

/** Encrypted configuration stored on disk */
export interface EncryptedConfig {
  /** Version for future migrations */
  readonly version: 1;
  /** Provider identifier */
  readonly provider: ProviderType;
  /** Base64-encoded encrypted payload */
  readonly encryptedPayload: string;
  /** Base64-encoded initialization vector */
  readonly iv: string;
  /** Base64-encoded salt for key derivation */
  readonly salt: string;
  /** Authorized domains (used in key derivation) */
  readonly authorizedDomains: readonly string[];
  /** Optional Unix timestamp for expiry */
  readonly expiresAt?: number;
  /** Subresource Integrity hash for verification */
  readonly integrity?: string;
}

/** Decrypted credential payload */
export interface CredentialPayload {
  /** API key or primary credential */
  readonly apiKey: string;
  /** Optional secondary secret */
  readonly apiSecret?: string;
  /** Additional provider-specific data */
  readonly metadata?: Readonly<Record<string, string>>;
}

/** Configuration for embedding */
export interface EmbedConfig {
  /** Provider identifier */
  readonly provider: ProviderType;
  /** URL to the encrypted config file */
  readonly configUrl: string;
  /** Optional custom container element ID */
  readonly containerId?: string;
  /** Callback when embed is loaded */
  readonly onLoad?: () => void;
  /** Callback on error */
  readonly onError?: (error: Error) => void;
}

/** CLI input configuration format */
export interface CLIInputConfig {
  readonly provider: ProviderType;
  readonly credentials: CredentialPayload;
  readonly authorizedDomains: readonly string[];
  readonly expiresAt?: string; // ISO date string
}

/** Provider-specific embed configuration */
export interface ProviderConfig {
  /** Script URL template (use {{apiKey}} for interpolation) */
  readonly scriptUrl: string;
  /** Optional initialization script */
  readonly initScript?: string;
  /** Headers to inject for fetch requests */
  readonly headers?: Readonly<Record<string, string>>;
  /** Query params to inject */
  readonly queryParams?: Readonly<Record<string, string>>;
  /** Endpoints to intercept (regex patterns) */
  readonly interceptPatterns: readonly string[];
}

/** Service Worker message types */
export type SWMessageType =
  | { readonly type: 'REGISTER_CONFIG'; readonly configUrl: string; readonly domain: string }
  | { readonly type: 'CLEAR_CONFIG'; readonly configUrl: string }
  | { readonly type: 'HEALTH_CHECK' };

/** Service Worker response */
export interface SWResponse {
  readonly success: boolean;
  readonly error?: string;
}
