/**
 * Service Worker for SecureEmbed.
 * Intercepts fetch requests to embed providers and injects decrypted credentials.
 * 
 * IMPORTANT: This file should be served from the root of your domain.
 * Copy the compiled version to your public directory.
 */

import { decryptCredentials, verifyIntegrity } from './crypto.js';
import { getProviderConfig, interpolate, getInterceptRegexes } from './providers/index.js';
import type { CredentialPayload, EncryptedConfig, SWMessageType, SWResponse } from './types.js';

declare const self: ServiceWorkerGlobalScope;

/** Cache for decrypted configs to avoid repeated decryption */
interface ConfigCache {
  readonly config: EncryptedConfig;
  readonly credentials: CredentialPayload;
  readonly interceptRegexes: RegExp[];
  readonly registeredAt: number;
}

const configCache = new Map<string, ConfigCache>();

/** Maximum cache size to prevent memory exhaustion */
const MAX_CACHE_SIZE = 50;

/** Cache entry TTL in milliseconds (1 hour) */
const CACHE_TTL_MS = 60 * 60 * 1000;

/**
 * Message handler for communication with main thread.
 */
self.addEventListener('message', (event: ExtendableMessageEvent) => {
  const message = event.data as SWMessageType;

  switch (message.type) {
    case 'REGISTER_CONFIG':
      handleRegisterConfig(message.configUrl, message.domain)
        .then((response) => {
          event.ports[0]?.postMessage(response);
        })
        .catch((error: unknown) => {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          event.ports[0]?.postMessage({ success: false, error: errorMessage });
        });
      break;

    case 'CLEAR_CONFIG':
      configCache.delete(message.configUrl);
      event.ports[0]?.postMessage({ success: true } satisfies SWResponse);
      break;

    case 'HEALTH_CHECK':
      event.ports[0]?.postMessage({ success: true } satisfies SWResponse);
      break;
  }
});

/**
 * Registers and decrypts a configuration file.
 */
async function handleRegisterConfig(configUrl: string, domain: string): Promise<SWResponse> {
  try {
    const response = await fetch(configUrl);
    if (!response.ok) {
      throw new Error('Failed to fetch config: ' + response.status.toString());
    }

    const config = (await response.json()) as EncryptedConfig;

    // Verify integrity
    const isValid = await verifyIntegrity(config);
    if (!isValid) {
      throw new Error('Config integrity check failed');
    }

    // Decrypt credentials
    const credentials = await decryptCredentials(config, domain);

    // Evict stale entries before adding new one
    evictStaleCacheEntries();

    // If cache is full, evict oldest entry
    if (configCache.size >= MAX_CACHE_SIZE) {
      let oldestKey: string | undefined;
      let oldestTime = Infinity;
      for (const [key, entry] of configCache.entries()) {
        if (entry.registeredAt < oldestTime) {
          oldestTime = entry.registeredAt;
          oldestKey = key;
        }
      }
      if (oldestKey !== undefined) {
        configCache.delete(oldestKey);
      }
    }

    // Cache for request interception
    const interceptRegexes = getInterceptRegexes(config.provider);
    configCache.set(configUrl, {
      config,
      credentials,
      interceptRegexes,
      registeredAt: Date.now(),
    });

    return { success: true };
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return { success: false, error: errorMessage };
  }
}

/**
 * Fetch event handler - intercepts requests to inject credentials.
 */
self.addEventListener('fetch', (event: FetchEvent) => {
  const url = event.request.url;

  // Find matching cached config
  let matchedCache: ConfigCache | undefined;
  for (const cache of configCache.values()) {
    const isMatch = cache.interceptRegexes.some((regex) => regex.test(url));
    if (isMatch) {
      matchedCache = cache;
      break;
    }
  }

  if (matchedCache === undefined) {
    // No interception needed
    return;
  }

  event.respondWith(handleInterceptedRequest(event.request, matchedCache));
});

/**
 * Handles an intercepted request by injecting credentials.
 */
async function handleInterceptedRequest(
  request: Request,
  cache: ConfigCache
): Promise<Response> {
  const { config, credentials } = cache;
  const providerConfig = getProviderConfig(config.provider);

  // Build variable map for interpolation
  const variables: Record<string, string> = {
    apiKey: credentials.apiKey,
    ...(credentials.apiSecret !== undefined ? { apiSecret: credentials.apiSecret } : {}),
    ...(credentials.metadata ?? {}),
  };

  // Clone and modify the request
  const url = new URL(request.url);

  // Inject query parameters
  if (providerConfig.queryParams !== undefined) {
    for (const [key, template] of Object.entries(providerConfig.queryParams)) {
      const value = interpolate(template, variables);
      url.searchParams.set(key, value);
    }
  }

  // Build new headers
  const newHeaders = new Headers(request.headers);
  if (providerConfig.headers !== undefined) {
    for (const [key, template] of Object.entries(providerConfig.headers)) {
      const value = interpolate(template, variables);
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

  // Fetch with modified request
  return fetch(modifiedRequest);
}

/**
 * Install event - take control immediately.
 */
self.addEventListener('install', () => {
  void self.skipWaiting();
});

/**
 * Activate event - claim all clients.
 */
self.addEventListener('activate', (event: ExtendableEvent) => {
  event.waitUntil(self.clients.claim());
});

/**
 * Evicts stale cache entries that have exceeded TTL.
 */
function evictStaleCacheEntries(): void {
  const now = Date.now();
  for (const [key, entry] of configCache.entries()) {
    if (now - entry.registeredAt > CACHE_TTL_MS) {
      configCache.delete(key);
    }
  }
}
