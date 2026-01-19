/**
 * SecureEmbed Public Loader
 *
 * This is the public-facing JavaScript API that loads secure embeds.
 * It uses the Wasm-based secure protocol to communicate with the service worker.
 *
 * Key security features:
 * - Protocol messages are encoded/checksummed before transmission
 * - No credentials are ever exposed in the main thread
 * - Memory is cleaned up after operations complete
 * - All sensitive operations delegated to SW + Wasm
 */

import type { EmbedConfig, EncryptedConfig, CredentialPayload, ProviderType } from '../types.js';
import { loadWasmCore, ProtocolMessageType, releaseWasmCore } from './wasm-loader.js';
import type { WasmCryptoCore } from './wasm-loader.js';
import { getProviderConfig, interpolate } from '../providers/index.js';

// Module state
let wasmCore: WasmCryptoCore | null = null;
let swRegistration: ServiceWorkerRegistration | null = null;
let isInitialized = false;

// Registered embeds for cleanup
const registeredEmbeds = new Map<ProviderType, {
  script: HTMLScriptElement;
  configUrl: string;
  cleanup: () => void;
}>();

// Pending operations for abort handling
const pendingOperations = new Map<string, AbortController>();

// Constants
const SW_REGISTRATION_TIMEOUT_MS = 10000;
const SW_CONTROLLER_TIMEOUT_MS = 5000;
const MESSAGE_RESPONSE_TIMEOUT_MS = 30000;

/**
 * Initialize the secure loader
 */
async function initializeLoader(): Promise<void> {
  if (isInitialized) {
    return;
  }

  // Check browser support
  if (!('serviceWorker' in navigator) || navigator.serviceWorker === undefined) {
    throw new Error('Service Workers not supported');
  }

  if (!window.isSecureContext) {
    throw new Error('Secure context required (HTTPS or localhost)');
  }

  // Load Wasm core
  wasmCore = await loadWasmCore();
  isInitialized = true;
}

/**
 * Ensure service worker is registered and controlling the page
 */
async function ensureServiceWorker(): Promise<ServiceWorker> {
  if (swRegistration !== null && navigator.serviceWorker.controller !== null) {
    return navigator.serviceWorker.controller;
  }

  // Check for existing registration
  const existing = await navigator.serviceWorker.getRegistration('/');

  if (existing !== undefined) {
    swRegistration = existing;
  } else {
    // Register new service worker
    swRegistration = await navigator.serviceWorker.register('/secure-embed-sw.js', {
      scope: '/',
    });
  }

  // Wait for activation
  const sw = swRegistration.installing ?? swRegistration.waiting ?? swRegistration.active;

  if (sw === null) {
    throw new Error('Service Worker not found');
  }

  if (sw.state !== 'activated') {
    await waitForActivation(sw);
  }

  // Wait for controller (critical for first load)
  if (navigator.serviceWorker.controller === null) {
    await waitForController();
  }

  return navigator.serviceWorker.controller!;
}

/**
 * Wait for service worker activation
 */
function waitForActivation(sw: ServiceWorker): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      sw.removeEventListener('statechange', handleStateChange);
      reject(new Error('Service Worker activation timeout'));
    }, SW_REGISTRATION_TIMEOUT_MS);

    const handleStateChange = (): void => {
      if (sw.state === 'activated') {
        clearTimeout(timeout);
        sw.removeEventListener('statechange', handleStateChange);
        resolve();
      } else if (sw.state === 'redundant') {
        clearTimeout(timeout);
        sw.removeEventListener('statechange', handleStateChange);
        reject(new Error('Service Worker became redundant'));
      }
    };

    sw.addEventListener('statechange', handleStateChange);
  });
}

/**
 * Wait for service worker to control the page
 */
function waitForController(): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      navigator.serviceWorker.removeEventListener('controllerchange', handleControllerChange);
      reject(new Error('Service Worker not controlling page. Try refreshing.'));
    }, SW_CONTROLLER_TIMEOUT_MS);

    const handleControllerChange = (): void => {
      if (navigator.serviceWorker.controller !== null) {
        clearTimeout(timeout);
        navigator.serviceWorker.removeEventListener('controllerchange', handleControllerChange);
        resolve();
      }
    };

    navigator.serviceWorker.addEventListener('controllerchange', handleControllerChange);

    // Check immediately
    if (navigator.serviceWorker.controller !== null) {
      clearTimeout(timeout);
      navigator.serviceWorker.removeEventListener('controllerchange', handleControllerChange);
      resolve();
    }
  });
}

/**
 * Send a secure protocol message to the service worker
 */
async function sendSecureMessage(
  sw: ServiceWorker,
  messageType: number,
  payload: string,
  operationId: string
): Promise<string> {
  if (wasmCore === null) {
    throw new Error('Loader not initialized');
  }

  // Create abort controller for this operation
  const abortController = new AbortController();
  pendingOperations.set(operationId, abortController);

  try {
    // Encode message using Wasm
    const encodedMessage = wasmCore.encodeProtocolMessage(messageType, payload);

    // Create message channel
    const channel = new MessageChannel();

    // Set up response promise
    const responsePromise = new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(() => {
        channel.port1.close();
        reject(new Error('Message response timeout'));
      }, MESSAGE_RESPONSE_TIMEOUT_MS);

      channel.port1.onmessage = (event: MessageEvent<Uint8Array | { success: boolean; error?: string }>) => {
        clearTimeout(timeout);
        channel.port1.close();

        // Handle both secure and legacy responses
        if (event.data instanceof Uint8Array) {
          // Secure response
          if (wasmCore !== null) {
            const decoded = wasmCore.decodeProtocolMessage(event.data);
            resolve(decoded);
          } else {
            reject(new Error('Core unavailable'));
          }
        } else {
          // Legacy response
          resolve(JSON.stringify(event.data));
        }
      };

      // Handle abort
      abortController.signal.addEventListener('abort', () => {
        clearTimeout(timeout);
        channel.port1.close();
        reject(new Error('Operation aborted'));
      });
    });

    // Send message
    sw.postMessage(encodedMessage, [channel.port2]);

    return await responsePromise;
  } finally {
    pendingOperations.delete(operationId);
  }
}

/**
 * Send a legacy protocol message (for backwards compatibility)
 */
async function sendLegacyMessage(
  sw: ServiceWorker,
  message: Record<string, unknown>,
  operationId: string
): Promise<{ success: boolean; error?: string }> {
  const abortController = new AbortController();
  pendingOperations.set(operationId, abortController);

  try {
    const channel = new MessageChannel();

    const responsePromise = new Promise<{ success: boolean; error?: string }>((resolve, reject) => {
      const timeout = setTimeout(() => {
        channel.port1.close();
        reject(new Error('Message response timeout'));
      }, MESSAGE_RESPONSE_TIMEOUT_MS);

      channel.port1.onmessage = (event: MessageEvent<{ success: boolean; error?: string }>) => {
        clearTimeout(timeout);
        channel.port1.close();
        resolve(event.data);
      };

      abortController.signal.addEventListener('abort', () => {
        clearTimeout(timeout);
        channel.port1.close();
        reject(new Error('Operation aborted'));
      });
    });

    sw.postMessage(message, [channel.port2]);

    return await responsePromise;
  } finally {
    pendingOperations.delete(operationId);
  }
}

/**
 * Initialize a secure embed
 */
export async function init(config: EmbedConfig): Promise<void> {
  const { provider, configUrl, containerId, onLoad, onError } = config;
  const operationId = generateOperationId();

  try {
    // Initialize loader if needed
    await initializeLoader();

    // Ensure service worker is ready
    const sw = await ensureServiceWorker();

    // Fetch and validate config locally first
    const response = await fetch(configUrl);
    if (!response.ok) {
      throw new Error('Failed to fetch config: ' + response.status);
    }

    const configText = await response.text();

    // Validate structure using Wasm
    if (wasmCore !== null && !wasmCore.validateConfigStructure(configText)) {
      throw new Error('Invalid config structure');
    }

    const encryptedConfig = JSON.parse(configText) as EncryptedConfig;

    // Verify provider matches
    if (encryptedConfig.provider !== provider) {
      throw new Error('Provider mismatch');
    }

    // Verify domain authorization using Wasm
    const currentDomain = window.location.hostname;
    if (wasmCore !== null) {
      const authorizedJson = JSON.stringify(encryptedConfig.authorizedDomains);
      if (!wasmCore.isDomainAuthorized(currentDomain, authorizedJson)) {
        throw new Error('Domain not authorized');
      }
    }

    // Check expiry using Wasm
    if (encryptedConfig.expiresAt !== undefined && wasmCore !== null) {
      if (wasmCore.isExpired(BigInt(encryptedConfig.expiresAt), BigInt(Date.now()))) {
        throw new Error('Config expired');
      }
    }

    // Verify integrity
    const isValid = await verifyIntegrity(encryptedConfig);
    if (!isValid) {
      throw new Error('Integrity check failed');
    }

    // Decrypt credentials locally (for script loading)
    const credentials = await decryptCredentials(encryptedConfig, currentDomain);

    // Register with service worker (try secure protocol first, fallback to legacy)
    const registerPayload = JSON.stringify({ configUrl, domain: currentDomain });

    let registerSuccess = false;

    try {
      // Try secure protocol
      const secureResponse = await sendSecureMessage(
        sw,
        ProtocolMessageType.REGISTER_CONFIG,
        registerPayload,
        operationId
      );
      const parsed = JSON.parse(secureResponse) as { success: boolean; error?: string };
      registerSuccess = parsed.success;
      if (!registerSuccess && parsed.error) {
        throw new Error(parsed.error);
      }
    } catch {
      // Fallback to legacy protocol
      const legacyResponse = await sendLegacyMessage(
        sw,
        { type: 'REGISTER_CONFIG', configUrl, domain: currentDomain },
        operationId + '-legacy'
      );
      registerSuccess = legacyResponse.success;
      if (!registerSuccess && legacyResponse.error) {
        throw new Error(legacyResponse.error);
      }
    }

    if (!registerSuccess) {
      throw new Error('Registration failed');
    }

    // Load the embed script
    await loadEmbed(provider, credentials, containerId, configUrl);

    // Clear credentials from memory
    clearCredentials(credentials);

    onLoad?.();
  } catch (error) {
    const err = error instanceof Error ? error : new Error('Unknown error');
    onError?.(err);
    throw err;
  }
}

/**
 * Decrypt credentials for script loading
 */
async function decryptCredentials(
  config: EncryptedConfig,
  _currentDomain: string
): Promise<CredentialPayload> {
  const primaryDomain = config.authorizedDomains[0];
  if (primaryDomain === undefined) {
    throw new Error('No authorized domains');
  }

  // Normalize domain
  let normalizedDomain = primaryDomain.toLowerCase();
  if (normalizedDomain.startsWith('https://')) {
    normalizedDomain = normalizedDomain.substring(8);
  } else if (normalizedDomain.startsWith('http://')) {
    normalizedDomain = normalizedDomain.substring(7);
  }
  while (normalizedDomain.endsWith('/')) {
    normalizedDomain = normalizedDomain.slice(0, -1);
  }
  if (normalizedDomain.startsWith('www.')) {
    normalizedDomain = normalizedDomain.substring(4);
  }
  const colonIdx = normalizedDomain.lastIndexOf(':');
  if (colonIdx > 0) {
    const afterColon = normalizedDomain.substring(colonIdx + 1);
    if (/^\d{1,5}$/.test(afterColon)) {
      normalizedDomain = normalizedDomain.substring(0, colonIdx);
    }
  }

  // Decode base64
  const salt = base64ToUint8Array(config.salt);
  const iv = base64ToUint8Array(config.iv);
  const encryptedData = base64ToUint8Array(config.encryptedPayload);

  // Derive key
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(normalizedDomain),
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
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
    key,
    encryptedData.buffer as ArrayBuffer
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(decryptedBuffer)) as CredentialPayload;
}

/**
 * Verify config integrity
 */
async function verifyIntegrity(config: EncryptedConfig): Promise<boolean> {
  if (config.integrity === undefined) {
    return true;
  }

  const { integrity, ...configWithoutIntegrity } = config;
  const encoder = new TextEncoder();
  const configBytes = encoder.encode(JSON.stringify(configWithoutIntegrity));
  const hashBuffer = await crypto.subtle.digest('SHA-384', configBytes);

  const hashArray = new Uint8Array(hashBuffer);
  let binary = '';
  for (let i = 0; i < hashArray.length; i++) {
    binary += String.fromCharCode(hashArray[i]!);
  }
  const computedIntegrity = 'sha384-' + btoa(binary);

  // Constant-time comparison
  if (wasmCore !== null) {
    return wasmCore.secureCompare(computedIntegrity, integrity);
  }

  return computedIntegrity === integrity;
}

/**
 * Base64 to Uint8Array
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
 * Load the embed script
 */
async function loadEmbed(
  provider: ProviderType,
  credentials: CredentialPayload,
  containerId: string | undefined,
  configUrl: string
): Promise<void> {
  const providerConfig = getProviderConfig(provider);

  // Build variables map
  const variables: Record<string, string> = {
    apiKey: credentials.apiKey,
    appId: credentials.apiKey,
    portalId: credentials.metadata?.['portalId'] ?? credentials.apiKey,
    embedId: credentials.metadata?.['embedId'] ?? '',
    ...(credentials.apiSecret !== undefined ? { apiSecret: credentials.apiSecret } : {}),
    ...(credentials.metadata ?? {}),
  };

  // Create script element
  const scriptUrl = interpolate(providerConfig.scriptUrl, variables);
  const script = document.createElement('script');
  script.src = scriptUrl;
  script.async = true;

  // Get container
  const container = containerId !== undefined
    ? document.getElementById(containerId)
    : document.body;

  if (container === null) {
    throw new Error('Container not found');
  }

  // Load script
  await new Promise<void>((resolve, reject) => {
    script.onload = () => resolve();
    script.onerror = () => reject(new Error('Failed to load embed script'));
    container.appendChild(script);
  });

  // Execute init script
  if (providerConfig.initScript !== undefined && providerConfig.initScript !== '') {
    const initCode = interpolate(providerConfig.initScript, variables);
    // Use indirect eval for global scope execution
    const globalEval = eval;
    globalEval(initCode);
  }

  // Track for cleanup
  registeredEmbeds.set(provider, {
    script,
    configUrl,
    cleanup: () => {
      script.remove();
      // Clear variables
      for (const key of Object.keys(variables)) {
        variables[key] = '';
      }
    },
  });
}

/**
 * Clear credentials from memory
 */
function clearCredentials(credentials: CredentialPayload): void {
  // Overwrite with empty values (best effort)
  const mutableCredentials = credentials as { apiKey: string; apiSecret?: string; metadata?: Record<string, string> };
  mutableCredentials.apiKey = '';
  if (mutableCredentials.apiSecret !== undefined) {
    mutableCredentials.apiSecret = '';
  }
  if (mutableCredentials.metadata !== undefined) {
    for (const key of Object.keys(mutableCredentials.metadata)) {
      mutableCredentials.metadata[key] = '';
    }
  }
}

/**
 * Remove an embed and cleanup
 */
export async function destroy(provider: ProviderType): Promise<void> {
  const embed = registeredEmbeds.get(provider);
  if (embed === undefined) {
    return;
  }

  // Run cleanup
  embed.cleanup();

  // Notify service worker
  const sw = navigator.serviceWorker.controller;
  if (sw !== null && wasmCore !== null) {
    const operationId = generateOperationId();
    const payload = JSON.stringify({ configUrl: embed.configUrl });

    try {
      await sendSecureMessage(sw, ProtocolMessageType.CLEAR_CONFIG, payload, operationId);
    } catch {
      // Fallback to legacy
      await sendLegacyMessage(
        sw,
        { type: 'CLEAR_CONFIG', configUrl: embed.configUrl },
        operationId + '-legacy'
      );
    }
  }

  registeredEmbeds.delete(provider);
}

/**
 * Health check
 */
export async function healthCheck(): Promise<boolean> {
  const sw = navigator.serviceWorker.controller;
  if (sw === null) {
    return false;
  }

  if (wasmCore === null) {
    // Not initialized, try legacy health check
    try {
      const response = await sendLegacyMessage(
        sw,
        { type: 'HEALTH_CHECK' },
        generateOperationId()
      );
      return response.success;
    } catch {
      return false;
    }
  }

  try {
    const operationId = generateOperationId();
    const response = await sendSecureMessage(
      sw,
      ProtocolMessageType.HEALTH_CHECK,
      '{}',
      operationId
    );
    const parsed = JSON.parse(response) as { success: boolean };
    return parsed.success;
  } catch {
    return false;
  }
}

/**
 * Get memory statistics (for debugging/monitoring)
 */
export function getMemoryStats(): { wasmStats?: string; registeredEmbeds: number; pendingOps: number } | null {
  if (wasmCore === null) {
    return null;
  }

  return {
    wasmStats: wasmCore.getMemoryStats().toString(),
    registeredEmbeds: registeredEmbeds.size,
    pendingOps: pendingOperations.size,
  };
}

/**
 * Abort all pending operations
 */
export function abortAllOperations(): void {
  for (const controller of pendingOperations.values()) {
    controller.abort();
  }
  pendingOperations.clear();
}

/**
 * Cleanup and release all resources
 */
export function cleanup(): void {
  // Abort pending operations
  abortAllOperations();

  // Cleanup embeds
  for (const [provider, embed] of registeredEmbeds.entries()) {
    embed.cleanup();
    registeredEmbeds.delete(provider);
  }

  // Release Wasm core
  if (wasmCore !== null) {
    releaseWasmCore();
    wasmCore = null;
  }

  isInitialized = false;
}

/**
 * Generate unique operation ID
 */
function generateOperationId(): string {
  const buffer = new Uint8Array(8);
  crypto.getRandomValues(buffer);
  return Array.from(buffer, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * SecureEmbed namespace export
 */
export const SecureEmbed = {
  init,
  destroy,
  healthCheck,
  getMemoryStats,
  abortAllOperations,
  cleanup,
} as const;
