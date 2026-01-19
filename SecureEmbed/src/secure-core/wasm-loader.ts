/**
 * WebAssembly Crypto Core Loader
 *
 * Loads and initializes the compiled Wasm module for secure operations.
 * All security-critical operations are delegated to the Wasm core.
 */

export interface WasmCryptoCore {
  // Initialization
  initCore(entropy0: bigint, entropy1: bigint, timestamp: bigint): void;

  // Domain operations
  normalizeDomain(domain: string): string;
  isDomainAuthorized(currentDomain: string, authorizedDomainsJson: string): boolean;
  deriveKeySalt(domain: string, configSalt: string): string;

  // Cache operations
  generateCacheKey(configUrl: string, domain: string): number;
  allocateCacheSlot(cacheKey: number): number;
  freeCacheSlot(slotIndex: number): void;
  isCacheSlotValid(slotIndex: number, maxAgeMs: bigint): boolean;
  getCacheSlotCount(): number;

  // Protocol operations
  encodeProtocolMessage(messageType: number, payload: string): Uint8Array;
  decodeProtocolMessage(data: Uint8Array): string;
  getProtocolMessageType(data: Uint8Array): number;

  // Validation
  isExpired(expiresAt: bigint, currentTimestamp: bigint): boolean;
  secureCompare(a: string, b: string): boolean;
  validateConfigStructure(configJson: string): boolean;

  // Memory management
  secureClear(): void;
  getMemoryStats(): bigint;

  // Provider operations (obfuscated in Wasm)
  getProviderId(providerName: string): number;
  getProviderScriptUrl(providerId: number): string;
  getProviderPatterns(providerId: number): string;
  getProviderInitScript(providerId: number): string;
  getProviderHeaders(providerId: number): string;
  getProviderQueryParams(providerId: number): string;
  interpolateTemplate(template: string, variablesJson: string): string;
}

// Singleton instance
let wasmCore: WasmCryptoCore | null = null;
let initPromise: Promise<WasmCryptoCore> | null = null;

/**
 * Protocol message types for SW communication
 */
export const ProtocolMessageType = {
  REGISTER_CONFIG: 0x01,
  CLEAR_CONFIG: 0x02,
  HEALTH_CHECK: 0x03,
  CONFIG_RESPONSE: 0x10,
  ERROR_RESPONSE: 0x11,
  CREDENTIAL_REQUEST: 0x20,
  CREDENTIAL_RESPONSE: 0x21,
} as const;

/**
 * Load and initialize the Wasm crypto core
 */
export async function loadWasmCore(): Promise<WasmCryptoCore> {
  if (wasmCore !== null) {
    return wasmCore;
  }

  if (initPromise !== null) {
    return initPromise;
  }

  initPromise = doLoadWasmCore();
  return initPromise;
}

async function doLoadWasmCore(): Promise<WasmCryptoCore> {
  // Load the Wasm module - NO FALLBACK
  // Wasm is required for security, fail if not available
  const wasmModule = await loadWasmModule();
  wasmCore = createWasmBinding(wasmModule);

  // Initialize with secure entropy
  const entropy0 = generateEntropy();
  const entropy1 = generateEntropy();
  const timestamp = BigInt(Date.now());

  wasmCore.initCore(entropy0, entropy1, timestamp);

  return wasmCore;
}

/**
 * Load the compiled Wasm module
 */
async function loadWasmModule(): Promise<WebAssembly.Instance> {
  // Try multiple paths for Wasm module
  const wasmPaths = [
    '/secure-embed-core.wasm',
    './secure-embed-core.wasm',
    '../wasm/build/crypto-core.wasm',
  ];

  for (const path of wasmPaths) {
    try {
      const response = await fetch(path);
      if (response.ok) {
        const buffer = await response.arrayBuffer();
        const module = await WebAssembly.compile(buffer);
        const instance = await WebAssembly.instantiate(module, {
          env: {
            abort: () => { throw new Error('Wasm abort'); },
          },
        });
        return instance;
      }
    } catch {
      continue;
    }
  }

  throw new Error('Failed to load Wasm module');
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type WasmExports = Record<string, any>;

/**
 * Create TypeScript bindings for Wasm module
 */
function createWasmBinding(instance: WebAssembly.Instance): WasmCryptoCore {
  const exports = instance.exports as WasmExports;
  const memory = exports['memory'] as WebAssembly.Memory;

  // String helpers for Wasm interop
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function allocString(str: string): number {
    const allocFn = exports['__new'] as (size: number, id: number) => number;
    const bytes = encoder.encode(str);
    const ptr = allocFn(bytes.length, 1); // String type ID
    const view = new Uint8Array(memory.buffer, ptr, bytes.length);
    view.set(bytes);
    return ptr;
  }

  function readString(ptr: number): string {
    if (ptr === 0) return '';
    const view = new DataView(memory.buffer);
    const length = view.getUint32(ptr - 4, true);
    const bytes = new Uint8Array(memory.buffer, ptr, length);
    return decoder.decode(bytes);
  }

  return {
    initCore(entropy0: bigint, entropy1: bigint, timestamp: bigint): void {
      exports['initCore'](entropy0, entropy1, timestamp);
    },

    normalizeDomain(domain: string): string {
      const ptr = allocString(domain);
      const resultPtr = exports['normalizeDomain'](ptr);
      return readString(resultPtr as number);
    },

    isDomainAuthorized(currentDomain: string, authorizedDomainsJson: string): boolean {
      const domainPtr = allocString(currentDomain);
      const authPtr = allocString(authorizedDomainsJson);
      return exports['isDomainAuthorized'](domainPtr, authPtr) !== 0;
    },

    deriveKeySalt(domain: string, configSalt: string): string {
      const domainPtr = allocString(domain);
      const saltPtr = allocString(configSalt);
      const resultPtr = exports['deriveKeySalt'](domainPtr, saltPtr);
      return readString(resultPtr as number);
    },

    generateCacheKey(configUrl: string, domain: string): number {
      const urlPtr = allocString(configUrl);
      const domainPtr = allocString(domain);
      return exports['generateCacheKey'](urlPtr, domainPtr) as number;
    },

    allocateCacheSlot(cacheKey: number): number {
      return exports['allocateCacheSlot'](cacheKey) as number;
    },

    freeCacheSlot(slotIndex: number): void {
      exports['freeCacheSlot'](slotIndex);
    },

    isCacheSlotValid(slotIndex: number, maxAgeMs: bigint): boolean {
      return exports['isCacheSlotValid'](slotIndex, maxAgeMs) !== 0;
    },

    getCacheSlotCount(): number {
      return exports['getCacheSlotCount']() as number;
    },

    encodeProtocolMessage(messageType: number, payload: string): Uint8Array {
      const payloadPtr = allocString(payload);
      const resultPtr = exports['encodeProtocolMessage'](messageType, payloadPtr) as number;
      // Read Uint8Array from Wasm memory
      const view = new DataView(memory.buffer);
      const length = view.getUint32(resultPtr - 4, true);
      const bytes = new Uint8Array(memory.buffer, resultPtr, length);
      return new Uint8Array(bytes); // Copy to avoid memory issues
    },

    decodeProtocolMessage(data: Uint8Array): string {
      const allocFn = exports['__new'] as (size: number, id: number) => number;
      const ptr = allocFn(data.length, 2); // ArrayBuffer type ID
      const view = new Uint8Array(memory.buffer, ptr, data.length);
      view.set(data);
      const resultPtr = exports['decodeProtocolMessage'](ptr);
      return readString(resultPtr as number);
    },

    getProtocolMessageType(data: Uint8Array): number {
      const allocFn = exports['__new'] as (size: number, id: number) => number;
      const ptr = allocFn(data.length, 2);
      const view = new Uint8Array(memory.buffer, ptr, data.length);
      view.set(data);
      return exports['getProtocolMessageType'](ptr) as number;
    },

    isExpired(expiresAt: bigint, currentTimestamp: bigint): boolean {
      return exports['isExpired'](expiresAt, currentTimestamp) !== 0;
    },

    secureCompare(a: string, b: string): boolean {
      const aPtr = allocString(a);
      const bPtr = allocString(b);
      return exports['secureCompare'](aPtr, bPtr) !== 0;
    },

    validateConfigStructure(configJson: string): boolean {
      const ptr = allocString(configJson);
      return exports['validateConfigStructure'](ptr) !== 0;
    },

    secureClear(): void {
      exports['secureClear']();
    },

    getMemoryStats(): bigint {
      return exports['getMemoryStats']() as bigint;
    },

    getProviderId(providerName: string): number {
      const ptr = allocString(providerName);
      return exports['getProviderId'](ptr) as number;
    },

    getProviderScriptUrl(providerId: number): string {
      const resultPtr = exports['getProviderScriptUrl'](providerId);
      return readString(resultPtr as number);
    },

    getProviderPatterns(providerId: number): string {
      const resultPtr = exports['getProviderPatterns'](providerId);
      return readString(resultPtr as number);
    },

    getProviderInitScript(providerId: number): string {
      const resultPtr = exports['getProviderInitScript'](providerId);
      return readString(resultPtr as number);
    },

    getProviderHeaders(providerId: number): string {
      const resultPtr = exports['getProviderHeaders'](providerId);
      return readString(resultPtr as number);
    },

    getProviderQueryParams(providerId: number): string {
      const resultPtr = exports['getProviderQueryParams'](providerId);
      return readString(resultPtr as number);
    },

    interpolateTemplate(template: string, variablesJson: string): string {
      const templatePtr = allocString(template);
      const varsPtr = allocString(variablesJson);
      const resultPtr = exports['interpolateTemplate'](templatePtr, varsPtr);
      return readString(resultPtr as number);
    },
  };
}


/**
 * Generate secure entropy for initialization
 */
function generateEntropy(): bigint {
  const buffer = new Uint8Array(8);
  crypto.getRandomValues(buffer);

  let result = BigInt(0);
  for (let i = 0; i < 8; i++) {
    result = (result << BigInt(8)) | BigInt(buffer[i]!);
  }

  return result;
}

/**
 * Get the loaded Wasm core instance
 */
export function getWasmCore(): WasmCryptoCore | null {
  return wasmCore;
}

/**
 * Cleanup and release resources
 */
export function releaseWasmCore(): void {
  if (wasmCore !== null) {
    wasmCore.secureClear();
    wasmCore = null;
  }
  initPromise = null;
}
