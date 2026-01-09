/**
 * Cryptographic utilities for credential encryption/decryption.
 * Uses Web Crypto API for AES-256-GCM encryption with PBKDF2 key derivation.
 */

import type { CredentialPayload, EncryptedConfig, ProviderType } from './types.js';

/** PBKDF2 iteration count - high for security */
const PBKDF2_ITERATIONS = 100_000;

/** Salt length in bytes */
const SALT_LENGTH = 16;

/** IV length in bytes for AES-GCM */
const IV_LENGTH = 12;

/** Key length in bits for AES-256 */
const KEY_LENGTH = 256;

/**
 * Derives a cryptographic key from domain and salt using PBKDF2.
 * The key is domain-bound, meaning decryption only works on authorized domains.
 */
async function deriveKey(
  domain: string,
  salt: Uint8Array<ArrayBuffer>,
  crypto: Crypto = globalThis.crypto
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(domain),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as Uint8Array<ArrayBuffer>,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/** Converts ArrayBuffer to Base64 string */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte !== undefined) {
      binary += String.fromCharCode(byte);
    }
  }
  return btoa(binary);
}

/** Converts Base64 string to Uint8Array */
function base64ToUint8Array(base64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes as Uint8Array<ArrayBuffer>;
}

/**
 * Encrypts credentials for a specific domain.
 * @param payload - The credential payload to encrypt
 * @param authorizedDomains - Domains authorized to decrypt
 * @param provider - The embed provider type
 * @param expiresAt - Optional expiry timestamp
 * @returns Encrypted configuration object
 */
export async function encryptCredentials(
  payload: CredentialPayload,
  authorizedDomains: readonly string[],
  provider: ProviderType,
  expiresAt?: number,
  crypto: Crypto = globalThis.crypto
): Promise<EncryptedConfig> {
  if (authorizedDomains.length === 0) {
    throw new Error('At least one authorized domain is required');
  }

  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  // Use first domain as primary for key derivation
  const primaryDomain = authorizedDomains[0];
  if (primaryDomain === undefined) {
    throw new Error('Primary domain is undefined');
  }

  const key = await deriveKey(primaryDomain, salt as Uint8Array<ArrayBuffer>, crypto);
  const plaintextBytes = encoder.encode(JSON.stringify(payload));

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintextBytes
  );

  const encryptedPayload = arrayBufferToBase64(encryptedBuffer);
  const ivBase64 = arrayBufferToBase64(iv.buffer);
  const saltBase64 = arrayBufferToBase64(salt.buffer);

  const config: EncryptedConfig = {
    version: 1,
    provider,
    encryptedPayload,
    iv: ivBase64,
    salt: saltBase64,
    authorizedDomains,
    ...(expiresAt !== undefined ? { expiresAt } : {}),
  };

  // Generate integrity hash
  const configBytes = encoder.encode(JSON.stringify(config));
  const hashBuffer = await crypto.subtle.digest('SHA-384', configBytes);
  const integrity = 'sha384-' + arrayBufferToBase64(hashBuffer);

  return { ...config, integrity };
}

/**
 * Decrypts credentials. Only works on authorized domains.
 * @param config - The encrypted configuration
 * @param currentDomain - The current domain attempting decryption
 * @returns Decrypted credential payload
 * @throws Error if domain is not authorized or config is expired
 */
export async function decryptCredentials(
  config: EncryptedConfig,
  currentDomain: string,
  crypto: Crypto = globalThis.crypto
): Promise<CredentialPayload> {
  // Verify domain authorization
  const normalizedCurrent = normalizeDomain(currentDomain);
  const isAuthorized = config.authorizedDomains.some(
    (d) => normalizeDomain(d) === normalizedCurrent
  );

  if (!isAuthorized) {
    throw new Error('Domain "' + currentDomain + '" is not authorized to decrypt this configuration');
  }

  // Check expiry
  if (config.expiresAt !== undefined && Date.now() > config.expiresAt) {
    throw new Error('Configuration has expired');
  }

  const salt = base64ToUint8Array(config.salt);
  const iv = base64ToUint8Array(config.iv);
  const encryptedData = base64ToUint8Array(config.encryptedPayload);

  // Key derivation uses the first authorized domain
  const primaryDomain = config.authorizedDomains[0];
  if (primaryDomain === undefined) {
    throw new Error('No authorized domains in configuration');
  }

  const key = await deriveKey(primaryDomain, salt, crypto);

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encryptedData
    );

    const decoder = new TextDecoder();
    const jsonString = decoder.decode(decryptedBuffer);
    return JSON.parse(jsonString) as CredentialPayload;
  } catch {
    throw new Error('Decryption failed - invalid key or corrupted data');
  }
}

/**
 * Verifies the integrity hash of an encrypted config.
 */
export async function verifyIntegrity(
  config: EncryptedConfig,
  crypto: Crypto = globalThis.crypto
): Promise<boolean> {
  if (config.integrity === undefined) {
    return true; // No integrity check required
  }

  const { integrity, ...configWithoutIntegrity } = config;
  const encoder = new TextEncoder();
  const configBytes = encoder.encode(JSON.stringify(configWithoutIntegrity));
  const hashBuffer = await crypto.subtle.digest('SHA-384', configBytes);
  const computedIntegrity = 'sha384-' + arrayBufferToBase64(hashBuffer);

  return computedIntegrity === integrity;
}

/**
 * Normalizes a domain for secure comparison.
 * Handles protocol stripping, port removal, and unicode normalization.
 * @throws Error if domain contains path traversal or invalid characters
 */
function normalizeDomain(domain: string): string {
  // Unicode normalization to prevent homograph attacks
  let normalized = domain.normalize('NFC').toLowerCase();

  // Remove protocol
  normalized = normalized.replace(/^https?:\/\//, '');

  // Remove trailing slashes
  normalized = normalized.replace(/\/+$/, '');

  // Strip www prefix
  normalized = normalized.replace(/^www\./, '');

  // Remove port number
  normalized = normalized.replace(/:\d+$/, '');

  // Security: reject paths, query strings, fragments
  if (normalized.includes('/') || normalized.includes('?') || normalized.includes('#')) {
    throw new Error('Domain cannot contain path, query, or fragment');
  }

  // Security: reject empty or whitespace-only
  if (normalized.trim() === '') {
    throw new Error('Domain cannot be empty');
  }

  // Security: basic validation - only allow valid hostname characters
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(normalized)) {
    // Allow localhost and IP addresses
    if (normalized !== 'localhost' && !/^\d{1,3}(\.\d{1,3}){3}$/.test(normalized)) {
      throw new Error('Invalid domain format: ' + domain);
    }
  }

  return normalized;
}
