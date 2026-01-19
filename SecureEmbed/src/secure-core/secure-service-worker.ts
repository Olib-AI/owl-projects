/**
 * Secure Service Worker for SecureEmbed
 *
 * This service worker uses the Wasm crypto core for security-critical operations.
 * All credential handling, domain validation, and cache management are delegated
 * to the compiled Wasm module to prevent reverse engineering.
 *
 * Architecture:
 * 1. Main thread sends encrypted protocol messages
 * 2. SW uses Wasm core to decode/validate messages
 * 3. Credentials are stored in Wasm-managed cache slots
 * 4. Fetch interception injects credentials at runtime
 */

import { loadWasmCore, ProtocolMessageType, releaseWasmCore } from './wasm-loader.js';
import type { WasmCryptoCore } from './wasm-loader.js';
import type { CredentialPayload, EncryptedConfig } from '../types.js';
// Provider configs are now in Wasm - no JS imports needed

declare const self: ServiceWorkerGlobalScope;

// Wasm core instance
let wasmCore: WasmCryptoCore | null = null;

// Credential cache (indexed by Wasm slot index)
interface CredentialEntry {
  readonly config: EncryptedConfig;
  readonly credentials: CredentialPayload;
  readonly providerId: number;
  readonly slotIndex: number;
}

const credentialCache = new Map<number, CredentialEntry>();

// URL to slot mapping
const urlToSlot = new Map<string, number>();

// Memory management constants
const CACHE_TTL_MS = BigInt(60 * 60 * 1000); // 1 hour
const MEMORY_CHECK_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_CREDENTIAL_ENTRIES = 50;

// Memory check timer
let memoryCheckInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Initialize the secure service worker
 */
async function initialize(): Promise<void> {
  if (wasmCore !== null) {
    return;
  }

  try {
    wasmCore = await loadWasmCore();

    // Start memory management
    startMemoryManagement();
  } catch (error) {
    console.error('[SecureEmbed SW] Failed to initialize Wasm core:', error);
    throw error;
  }
}

/**
 * Start periodic memory management
 */
function startMemoryManagement(): void {
  if (memoryCheckInterval !== null) {
    return;
  }

  memoryCheckInterval = setInterval(() => {
    performMemoryCleanup();
  }, MEMORY_CHECK_INTERVAL_MS);
}

/**
 * Perform memory cleanup - evict expired entries
 */
function performMemoryCleanup(): void {
  if (wasmCore === null) {
    return;
  }

  const now = BigInt(Date.now());

  // Check each slot for expiration
  for (const [slotIndex, entry] of credentialCache.entries()) {
    if (!wasmCore.isCacheSlotValid(slotIndex, CACHE_TTL_MS)) {
      // Slot expired, remove it
      removeCredentialEntry(slotIndex);
    } else if (entry.config.expiresAt !== undefined) {
      // Check config-level expiry
      if (wasmCore.isExpired(BigInt(entry.config.expiresAt), now)) {
        removeCredentialEntry(slotIndex);
      }
    }
  }
}

/**
 * Remove a credential entry and free its slot
 */
function removeCredentialEntry(slotIndex: number): void {
  const entry = credentialCache.get(slotIndex);
  if (entry === undefined) {
    return;
  }

  // Find and remove URL mapping
  for (const [url, slot] of urlToSlot.entries()) {
    if (slot === slotIndex) {
      urlToSlot.delete(url);
      break;
    }
  }

  // Free the Wasm slot
  if (wasmCore !== null) {
    wasmCore.freeCacheSlot(slotIndex);
  }

  // Remove from cache
  credentialCache.delete(slotIndex);
}

/**
 * Message handler for communication with main thread
 */
self.addEventListener('message', async (event: ExtendableMessageEvent) => {
  // Ensure initialization
  if (wasmCore === null) {
    try {
      await initialize();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Initialization failed';
      event.ports[0]?.postMessage({ success: false, error: errorMessage });
      return;
    }
  }

  const message = event.data;

  // Handle both legacy and new protocol messages
  if (message instanceof Uint8Array) {
    // New secure protocol message
    await handleSecureMessage(message, event.ports[0]);
  } else if (typeof message === 'object' && message !== null) {
    // Legacy protocol (backwards compatibility)
    await handleLegacyMessage(message, event.ports[0]);
  }
});

/**
 * Handle secure protocol message (Wasm-encoded)
 */
async function handleSecureMessage(data: Uint8Array, port: MessagePort | undefined): Promise<void> {
  if (wasmCore === null || port === undefined) {
    return;
  }

  const messageType = wasmCore.getProtocolMessageType(data);
  const payload = wasmCore.decodeProtocolMessage(data);

  if (payload === '') {
    // Invalid message (checksum failed or corrupted)
    const errorResponse = wasmCore.encodeProtocolMessage(
      ProtocolMessageType.ERROR_RESPONSE,
      JSON.stringify({ error: 'Invalid message' })
    );
    port.postMessage(errorResponse);
    return;
  }

  switch (messageType) {
    case ProtocolMessageType.REGISTER_CONFIG:
      await handleRegisterConfigSecure(payload, port);
      break;

    case ProtocolMessageType.CLEAR_CONFIG:
      handleClearConfigSecure(payload, port);
      break;

    case ProtocolMessageType.HEALTH_CHECK:
      handleHealthCheckSecure(port);
      break;

    default:
      const errorResponse = wasmCore.encodeProtocolMessage(
        ProtocolMessageType.ERROR_RESPONSE,
        JSON.stringify({ error: 'Unknown message type' })
      );
      port.postMessage(errorResponse);
  }
}

/**
 * Handle legacy protocol message (JSON)
 */
async function handleLegacyMessage(
  message: Record<string, unknown>,
  port: MessagePort | undefined
): Promise<void> {
  if (port === undefined) {
    return;
  }

  const type = message['type'] as string;

  switch (type) {
    case 'REGISTER_CONFIG':
      try {
        const response = await handleRegisterConfig(
          message['configUrl'] as string,
          message['domain'] as string
        );
        port.postMessage(response);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        port.postMessage({ success: false, error: errorMessage });
      }
      break;

    case 'CLEAR_CONFIG':
      handleClearConfig(message['configUrl'] as string);
      port.postMessage({ success: true });
      break;

    case 'HEALTH_CHECK':
      port.postMessage({ success: true });
      break;
  }
}

/**
 * Handle secure config registration
 */
async function handleRegisterConfigSecure(payload: string, port: MessagePort): Promise<void> {
  if (wasmCore === null) {
    return;
  }

  try {
    const { configUrl, domain } = JSON.parse(payload) as { configUrl: string; domain: string };
    const response = await handleRegisterConfig(configUrl, domain);

    const responseMessage = wasmCore.encodeProtocolMessage(
      ProtocolMessageType.CONFIG_RESPONSE,
      JSON.stringify(response)
    );
    port.postMessage(responseMessage);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const errorResponse = wasmCore.encodeProtocolMessage(
      ProtocolMessageType.ERROR_RESPONSE,
      JSON.stringify({ error: errorMessage })
    );
    port.postMessage(errorResponse);
  }
}

/**
 * Register a configuration
 */
async function handleRegisterConfig(
  configUrl: string,
  domain: string
): Promise<{ success: boolean; error?: string }> {
  if (wasmCore === null) {
    return { success: false, error: 'Core not initialized' };
  }

  // Check if already registered
  const existingSlot = urlToSlot.get(configUrl);
  if (existingSlot !== undefined) {
    // Refresh the slot
    if (wasmCore.isCacheSlotValid(existingSlot, CACHE_TTL_MS)) {
      return { success: true };
    }
    // Expired, remove old entry
    removeCredentialEntry(existingSlot);
  }

  // Check cache limits
  if (credentialCache.size >= MAX_CREDENTIAL_ENTRIES) {
    // Evict oldest entry
    performMemoryCleanup();

    if (credentialCache.size >= MAX_CREDENTIAL_ENTRIES) {
      // Still full, force evict oldest
      let oldestSlot = -1;
      for (const [slot] of credentialCache) {
        if (oldestSlot === -1 || slot < oldestSlot) {
          oldestSlot = slot;
        }
      }
      if (oldestSlot >= 0) {
        removeCredentialEntry(oldestSlot);
      }
    }
  }

  try {
    // Fetch the encrypted config
    const response = await fetch(configUrl);
    if (!response.ok) {
      return { success: false, error: 'Failed to fetch config: ' + response.status };
    }

    const configText = await response.text();

    // Validate structure using Wasm
    if (!wasmCore.validateConfigStructure(configText)) {
      return { success: false, error: 'Invalid config structure' };
    }

    const config = JSON.parse(configText) as EncryptedConfig;

    // Verify domain authorization using Wasm
    const authorizedDomainsJson = JSON.stringify(config.authorizedDomains);
    if (!wasmCore.isDomainAuthorized(domain, authorizedDomainsJson)) {
      return { success: false, error: 'Domain not authorized' };
    }

    // Check expiry using Wasm
    if (config.expiresAt !== undefined) {
      if (wasmCore.isExpired(BigInt(config.expiresAt), BigInt(Date.now()))) {
        return { success: false, error: 'Config expired' };
      }
    }

    // Verify integrity
    const isValid = await verifyConfigIntegrity(config);
    if (!isValid) {
      return { success: false, error: 'Integrity check failed' };
    }

    // Decrypt credentials
    const credentials = await decryptCredentialsSecure(config, domain);

    // Allocate cache slot using Wasm
    const cacheKey = wasmCore.generateCacheKey(configUrl, domain);
    const slotIndex = wasmCore.allocateCacheSlot(cacheKey);

    if (slotIndex < 0) {
      return { success: false, error: 'Cache allocation failed' };
    }

    // Get provider ID from Wasm
    const providerId = wasmCore.getProviderId(config.provider);

    // Store in credential cache
    credentialCache.set(slotIndex, {
      config,
      credentials,
      providerId,
      slotIndex,
    });

    // Map URL to slot
    urlToSlot.set(configUrl, slotIndex);

    return { success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return { success: false, error: errorMessage };
  }
}

/**
 * Verify config integrity using SHA-384
 */
async function verifyConfigIntegrity(config: EncryptedConfig): Promise<boolean> {
  if (config.integrity === undefined) {
    return true; // No integrity check required
  }

  const { integrity, ...configWithoutIntegrity } = config;
  const encoder = new TextEncoder();
  const configBytes = encoder.encode(JSON.stringify(configWithoutIntegrity));
  const hashBuffer = await crypto.subtle.digest('SHA-384', configBytes);

  // Convert to base64
  const hashArray = new Uint8Array(hashBuffer);
  let binary = '';
  for (let i = 0; i < hashArray.length; i++) {
    binary += String.fromCharCode(hashArray[i]!);
  }
  const computedIntegrity = 'sha384-' + btoa(binary);

  // Use secure comparison from Wasm
  if (wasmCore !== null) {
    return wasmCore.secureCompare(computedIntegrity, integrity);
  }

  return computedIntegrity === integrity;
}

/**
 * Decrypt credentials using Web Crypto API
 * Domain validation is handled by Wasm
 */
async function decryptCredentialsSecure(
  config: EncryptedConfig,
  _currentDomain: string
): Promise<CredentialPayload> {
  if (wasmCore === null) {
    throw new Error('Core not initialized');
  }

  // Get primary domain for key derivation
  const primaryDomain = config.authorizedDomains[0];
  if (primaryDomain === undefined) {
    throw new Error('No authorized domains');
  }

  // Normalize domain using Wasm
  const normalizedPrimary = wasmCore.normalizeDomain(primaryDomain);
  if (normalizedPrimary === '') {
    throw new Error('Invalid primary domain');
  }

  // Decode base64 values
  const salt = base64ToUint8Array(config.salt);
  const iv = base64ToUint8Array(config.iv);
  const encryptedData = base64ToUint8Array(config.encryptedPayload);

  // Derive key using PBKDF2
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(normalizedPrimary),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations: 100_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Decrypt
  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      key,
      encryptedData.buffer as ArrayBuffer
    );

    const decoder = new TextDecoder();
    const jsonString = decoder.decode(decryptedBuffer);
    return JSON.parse(jsonString) as CredentialPayload;
  } catch {
    throw new Error('Decryption failed');
  }
}

/**
 * Base64 to Uint8Array conversion
 */
function base64ToUint8Array(base64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes as Uint8Array<ArrayBuffer>;
}

/**
 * Handle secure clear config
 */
function handleClearConfigSecure(payload: string, port: MessagePort): void {
  if (wasmCore === null) {
    return;
  }

  try {
    const { configUrl } = JSON.parse(payload) as { configUrl: string };
    handleClearConfig(configUrl);

    const response = wasmCore.encodeProtocolMessage(
      ProtocolMessageType.CONFIG_RESPONSE,
      JSON.stringify({ success: true })
    );
    port.postMessage(response);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const errorResponse = wasmCore.encodeProtocolMessage(
      ProtocolMessageType.ERROR_RESPONSE,
      JSON.stringify({ error: errorMessage })
    );
    port.postMessage(errorResponse);
  }
}

/**
 * Clear a config registration
 */
function handleClearConfig(configUrl: string): void {
  const slotIndex = urlToSlot.get(configUrl);
  if (slotIndex !== undefined) {
    removeCredentialEntry(slotIndex);
  }
}

/**
 * Handle secure health check
 */
function handleHealthCheckSecure(port: MessagePort): void {
  if (wasmCore === null) {
    return;
  }

  // Include memory stats in health response
  const stats = wasmCore.getMemoryStats();
  const slotCount = wasmCore.getCacheSlotCount();

  const response = wasmCore.encodeProtocolMessage(
    ProtocolMessageType.CONFIG_RESPONSE,
    JSON.stringify({
      success: true,
      stats: {
        memoryStats: stats.toString(),
        cacheSlots: slotCount,
        credentialEntries: credentialCache.size,
      },
    })
  );
  port.postMessage(response);
}

/**
 * Fetch event handler - intercepts requests to inject credentials
 */
self.addEventListener('fetch', (event: FetchEvent) => {
  if (wasmCore === null) {
    return;
  }

  const url = event.request.url;

  // Find matching credential entry using Wasm patterns
  let matchedEntry: CredentialEntry | undefined;

  for (const entry of credentialCache.values()) {
    // Get patterns from Wasm
    const patternsJson = wasmCore.getProviderPatterns(entry.providerId);
    const patterns = JSON.parse(patternsJson) as string[];

    // Check if URL matches any pattern
    const isMatch = patterns.some((pattern) => {
      try {
        const regex = new RegExp(pattern);
        return regex.test(url);
      } catch {
        return false;
      }
    });

    if (isMatch) {
      matchedEntry = entry;
      break;
    }
  }

  if (matchedEntry === undefined) {
    return; // No interception needed
  }

  event.respondWith(handleInterceptedRequest(event.request, matchedEntry));
});

/**
 * Handle an intercepted request by injecting credentials
 */
async function handleInterceptedRequest(
  request: Request,
  entry: CredentialEntry
): Promise<Response> {
  if (wasmCore === null) {
    return fetch(request);
  }

  const { credentials, providerId } = entry;

  // Build variable map for interpolation
  const variables: Record<string, string> = {
    apiKey: credentials.apiKey,
    ...(credentials.apiSecret !== undefined ? { apiSecret: credentials.apiSecret } : {}),
    ...(credentials.metadata ?? {}),
  };
  const variablesJson = JSON.stringify(variables);

  // Clone and modify the request
  const url = new URL(request.url);

  // Inject query parameters from Wasm
  const queryParamsJson = wasmCore.getProviderQueryParams(providerId);
  if (queryParamsJson !== '{}') {
    const queryParams = JSON.parse(queryParamsJson) as Record<string, string>;
    for (const [key, template] of Object.entries(queryParams)) {
      const value = wasmCore.interpolateTemplate(template, variablesJson);
      url.searchParams.set(key, value);
    }
  }

  // Build new headers from Wasm
  const newHeaders = new Headers(request.headers);
  const headersJson = wasmCore.getProviderHeaders(providerId);
  if (headersJson !== '{}') {
    const headers = JSON.parse(headersJson) as Record<string, string>;
    for (const [key, template] of Object.entries(headers)) {
      const value = wasmCore.interpolateTemplate(template, variablesJson);
      newHeaders.set(key, value);
    }
  }

  // Create modified request
  const modifiedRequest = new Request(url.toString(), {
    method: request.method,
    headers: newHeaders,
    body: request.body,
    mode: request.mode,
    credentials: request.credentials,
    cache: request.cache,
    redirect: request.redirect,
    referrer: request.referrer,
    integrity: request.integrity,
  });

  return fetch(modifiedRequest);
}

/**
 * Install event - immediate takeover
 */
self.addEventListener('install', () => {
  void self.skipWaiting();
});

/**
 * Activate event - claim all clients and initialize
 */
self.addEventListener('activate', (event: ExtendableEvent) => {
  event.waitUntil(
    Promise.all([
      self.clients.claim(),
      initialize(),
    ])
  );
});

/**
 * Handle termination - cleanup resources
 */
self.addEventListener('unload', () => {
  // Clear sensitive data
  credentialCache.clear();
  urlToSlot.clear();

  // Stop memory management
  if (memoryCheckInterval !== null) {
    clearInterval(memoryCheckInterval);
    memoryCheckInterval = null;
  }

  // Release Wasm core
  releaseWasmCore();
});
