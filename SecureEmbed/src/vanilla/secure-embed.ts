/**
 * Vanilla JavaScript API for SecureEmbed.
 * Use this when React is not available.
 */

import { decryptCredentials, verifyIntegrity } from '../crypto.js';
import { getProviderConfig, interpolate } from '../providers/index.js';
import type { CredentialPayload, EmbedConfig, EncryptedConfig, SWResponse } from '../types.js';

/** Service Worker registration state */
let swRegistration: ServiceWorkerRegistration | null = null;

/** Registered embeds for cleanup */
const registeredEmbeds = new Map<string, { script: HTMLScriptElement; configUrl: string }>();

/** Check if Service Workers are supported */
function isServiceWorkerSupported(): boolean {
  return 'serviceWorker' in navigator && navigator.serviceWorker !== undefined;
}

/**
 * Initialize a secure embed.
 * @param config - Embed configuration
 * @returns Promise that resolves when embed is loaded
 */
async function init(config: EmbedConfig): Promise<void> {
  const { provider, configUrl, containerId, onLoad, onError } = config;

  try {
    // Check browser support first
    if (!isServiceWorkerSupported()) {
      throw new Error(
        'Service Workers are not supported in this browser. ' +
        'SecureEmbed requires a modern browser with Service Worker support.'
      );
    }

    // Check for secure context (required for SW)
    if (!window.isSecureContext) {
      throw new Error(
        'SecureEmbed requires a secure context (HTTPS or localhost). ' +
        'Please serve your application over HTTPS.'
      );
    }

    // Ensure Service Worker is registered
    await ensureServiceWorker();

    // Fetch and decrypt config
    const response = await fetch(configUrl);
    if (!response.ok) {
      throw new Error('Failed to fetch config: ' + response.status.toString());
    }

    const encryptedConfig = (await response.json()) as EncryptedConfig;

    // Verify integrity
    const isValid = await verifyIntegrity(encryptedConfig);
    if (!isValid) {
      throw new Error('Config integrity verification failed');
    }

    // Verify provider matches
    if (encryptedConfig.provider !== provider) {
      throw new Error('Provider mismatch: expected ' + provider + ', got ' + encryptedConfig.provider);
    }

    // Decrypt credentials
    const currentDomain = window.location.hostname;
    const credentials = await decryptCredentials(encryptedConfig, currentDomain);

    // Register with Service Worker
    await registerWithServiceWorker(configUrl, currentDomain);

    // Load the embed
    await loadEmbed(provider, credentials, containerId);

    onLoad?.();
  } catch (error: unknown) {
    const err = error instanceof Error ? error : new Error('Unknown error');
    onError?.(err);
    throw err;
  }
}

/**
 * Ensures Service Worker is registered and controlling the page.
 * Handles first-load race condition by waiting for controller.
 */
async function ensureServiceWorker(): Promise<void> {
  if (swRegistration !== null && navigator.serviceWorker.controller !== null) {
    return;
  }

  if (!('serviceWorker' in navigator)) {
    throw new Error('Service Workers are not supported in this browser');
  }

  // Check if already registered
  const existing = await navigator.serviceWorker.getRegistration('/');
  if (existing !== undefined) {
    swRegistration = existing;
  } else {
    // Register new Service Worker
    swRegistration = await navigator.serviceWorker.register('/secure-embed-sw.js', {
      scope: '/',
    });
  }

  // Wait for activation
  const sw = swRegistration.installing ?? swRegistration.waiting ?? swRegistration.active;
  if (sw === null) {
    throw new Error('Service Worker not found after registration');
  }

  // Wait for the SW to be activated
  if (sw.state !== 'activated') {
    await new Promise<void>((resolve, reject) => {
      const handleStateChange = (): void => {
        if (sw.state === 'activated') {
          sw.removeEventListener('statechange', handleStateChange);
          resolve();
        } else if (sw.state === 'redundant') {
          sw.removeEventListener('statechange', handleStateChange);
          reject(new Error('Service Worker became redundant'));
        }
      };

      sw.addEventListener('statechange', handleStateChange);

      // Timeout after 10 seconds
      setTimeout(() => {
        sw.removeEventListener('statechange', handleStateChange);
        reject(new Error('Service Worker activation timeout'));
      }, 10000);
    });
  }

  // CRITICAL: Wait for the SW to control the page (first load issue)
  // On first load, the page isn't controlled even if SW is active
  if (navigator.serviceWorker.controller === null) {
    await new Promise<void>((resolve, reject) => {
      const handleControllerChange = (): void => {
        if (navigator.serviceWorker.controller !== null) {
          navigator.serviceWorker.removeEventListener('controllerchange', handleControllerChange);
          resolve();
        }
      };

      navigator.serviceWorker.addEventListener('controllerchange', handleControllerChange);

      // Also check immediately in case it changed
      if (navigator.serviceWorker.controller !== null) {
        navigator.serviceWorker.removeEventListener('controllerchange', handleControllerChange);
        resolve();
        return;
      }

      // Timeout after 5 seconds - force a page reload suggestion
      setTimeout(() => {
        navigator.serviceWorker.removeEventListener('controllerchange', handleControllerChange);
        reject(new Error('Service Worker not controlling page. Try refreshing the page.'));
      }, 5000);
    });
  }
}

/**
 * Registers a config with the Service Worker.
 */
async function registerWithServiceWorker(configUrl: string, domain: string): Promise<void> {
  const sw = navigator.serviceWorker.controller;
  if (sw === null) {
    throw new Error('Service Worker not controlling this page');
  }

  const channel = new MessageChannel();
  
  const response = await new Promise<SWResponse>((resolve) => {
    channel.port1.onmessage = (event: MessageEvent<SWResponse>) => {
      resolve(event.data);
    };

    sw.postMessage(
      { type: 'REGISTER_CONFIG', configUrl, domain },
      [channel.port2]
    );
  });

  if (!response.success) {
    throw new Error('SW registration failed: ' + (response.error ?? 'Unknown error'));
  }
}

/**
 * Loads the embed script and initializes it.
 */
async function loadEmbed(
  provider: EmbedConfig['provider'],
  credentials: CredentialPayload,
  containerId?: string
): Promise<void> {
  const providerConfig = getProviderConfig(provider);

  // Build variable map
  const variables: Record<string, string> = {
    apiKey: credentials.apiKey,
    appId: credentials.apiKey, // Alias for Intercom
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

  // Add to container or document
  const container = containerId !== undefined 
    ? document.getElementById(containerId) 
    : document.body;

  if (container === null) {
    throw new Error('Container element not found: ' + (containerId ?? 'body'));
  }

  // Load script
  await new Promise<void>((resolve, reject) => {
    script.onload = () => resolve();
    script.onerror = () => reject(new Error('Failed to load embed script'));
    container.appendChild(script);
  });

  // Execute init script if present
  if (providerConfig.initScript !== undefined && providerConfig.initScript !== '') {
    const initCode = interpolate(providerConfig.initScript, variables);
    // Use Function constructor to execute in global scope
    const initFn = new Function(initCode);
    initFn();
  }

  // Track for cleanup
  registeredEmbeds.set(provider, { script, configUrl: scriptUrl });
}

/**
 * Removes an embed and cleans up.
 * @param provider - The provider to remove
 */
async function destroy(provider: EmbedConfig['provider']): Promise<void> {
  const embed = registeredEmbeds.get(provider);
  if (embed === undefined) {
    return;
  }

  // Remove script element
  embed.script.remove();

  // Notify Service Worker
  const sw = navigator.serviceWorker.controller;
  if (sw !== null) {
    const channel = new MessageChannel();
    sw.postMessage(
      { type: 'CLEAR_CONFIG', configUrl: embed.configUrl },
      [channel.port2]
    );
  }

  registeredEmbeds.delete(provider);
}

/**
 * Checks if Service Worker is healthy.
 */
async function healthCheck(): Promise<boolean> {
  const sw = navigator.serviceWorker.controller;
  if (sw === null) {
    return false;
  }

  const channel = new MessageChannel();

  const response = await new Promise<SWResponse>((resolve) => {
    channel.port1.onmessage = (event: MessageEvent<SWResponse>) => {
      resolve(event.data);
    };

    sw.postMessage({ type: 'HEALTH_CHECK' }, [channel.port2]);
  });

  return response.success;
}

/** SecureEmbed namespace export */
export const SecureEmbed = {
  init,
  destroy,
  healthCheck,
} as const;

// Also export for direct imports
export { init, destroy, healthCheck };
