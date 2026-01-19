/**
 * SecureEmbed Crypto Core - WebAssembly Module
 *
 * This module handles security-critical operations in compiled Wasm
 * to prevent reverse engineering of the security logic.
 *
 * Operations handled:
 * - Domain normalization and validation
 * - Config key generation
 * - Protocol message encoding/decoding
 * - Secure string operations
 * - Cache management primitives
 */

// Memory management constants
const MAX_STRING_LENGTH: i32 = 2048;
const CACHE_SLOT_COUNT: i32 = 64;
const DOMAIN_MAX_LENGTH: i32 = 253;

// Internal state - obfuscated variable names
let _s0: u32 = 0; // slot counter
let _t0: u64 = 0; // timestamp base
let _k0: u32 = 0; // key counter

// Secure random state (xorshift128+)
let _rx: u64 = 0x853c49e6748fea9b;
let _ry: u64 = 0xda3e39cb94b95bdb;

// Cache slot tracking
const _slots: StaticArray<u64> = new StaticArray<u64>(64);
const _slotKeys: StaticArray<u32> = new StaticArray<u32>(64);

/**
 * Initialize the secure core with entropy
 */
export function initCore(entropy0: u64, entropy1: u64, timestamp: u64): void {
  _rx = entropy0 ^ 0x853c49e6748fea9b;
  _ry = entropy1 ^ 0xda3e39cb94b95bdb;
  _t0 = timestamp;
  _s0 = 0;
  _k0 = 0;

  // Initialize slot tracking
  for (let i: i32 = 0; i < CACHE_SLOT_COUNT; i++) {
    unchecked(_slots[i] = 0);
    unchecked(_slotKeys[i] = 0);
  }
}

/**
 * Generate secure random u64
 */
function secureRandom(): u64 {
  let x = _rx;
  const y = _ry;
  _rx = y;
  x ^= x << 23;
  x ^= x >> 17;
  x ^= y ^ (y >> 26);
  _ry = x;
  return x + y;
}

/**
 * Fast hash function for strings (FNV-1a variant)
 */
function fnv1aHash(str: string): u32 {
  let hash: u32 = 0x811c9dc5;
  const len = str.length;

  for (let i = 0; i < len; i++) {
    hash ^= str.charCodeAt(i) as u32;
    hash = (hash * 0x01000193) >>> 0;
  }

  return hash;
}

/**
 * Secure hash with mixing for cache keys
 */
function secureHash(input: u32, salt: u32): u32 {
  let h = input ^ salt;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

/**
 * Normalize domain for secure comparison
 * Returns empty string on validation failure
 */
export function normalizeDomain(domain: string): string {
  if (domain.length === 0 || domain.length > DOMAIN_MAX_LENGTH) {
    return "";
  }

  let result = domain;

  // Unicode NFC normalization approximation (lowercase)
  result = result.toLowerCase();

  // Remove protocol prefix
  if (result.startsWith("https://")) {
    result = result.substring(8);
  } else if (result.startsWith("http://")) {
    result = result.substring(7);
  }

  // Remove trailing slashes
  while (result.endsWith("/")) {
    result = result.substring(0, result.length - 1);
  }

  // Remove www prefix
  if (result.startsWith("www.")) {
    result = result.substring(4);
  }

  // Remove port number
  const colonIdx = result.lastIndexOf(":");
  if (colonIdx > 0) {
    const afterColon = result.substring(colonIdx + 1);
    let isPort = true;
    for (let i = 0; i < afterColon.length; i++) {
      const c = afterColon.charCodeAt(i);
      if (c < 48 || c > 57) { // not 0-9
        isPort = false;
        break;
      }
    }
    if (isPort && afterColon.length > 0 && afterColon.length <= 5) {
      result = result.substring(0, colonIdx);
    }
  }

  // Security: reject paths, queries, fragments
  if (result.includes("/") || result.includes("?") || result.includes("#")) {
    return "";
  }

  // Security: reject empty
  if (result.length === 0) {
    return "";
  }

  // Validate hostname characters
  if (!validateHostname(result)) {
    // Allow localhost and IPv4
    if (result !== "localhost" && !validateIPv4(result)) {
      return "";
    }
  }

  return result;
}

/**
 * Validate hostname format
 */
function validateHostname(host: string): bool {
  const len = host.length;
  if (len === 0 || len > 253) return false;

  let labelStart = 0;
  let i = 0;

  while (i <= len) {
    const c = i < len ? host.charCodeAt(i) : 46; // '.'

    if (c === 46) { // '.'
      const labelLen = i - labelStart;
      if (labelLen === 0 || labelLen > 63) return false;

      // First char must be alphanumeric
      const first = host.charCodeAt(labelStart);
      if (!isAlphaNumeric(first)) return false;

      // Last char must be alphanumeric
      if (labelLen > 1) {
        const last = host.charCodeAt(i - 1);
        if (!isAlphaNumeric(last)) return false;
      }

      labelStart = i + 1;
    } else if (!isAlphaNumeric(c) && c !== 45) { // not alphanumeric or '-'
      return false;
    }

    i++;
  }

  return true;
}

/**
 * Validate IPv4 address format
 */
function validateIPv4(ip: string): bool {
  let octetCount = 0;
  let currentOctet: u32 = 0;
  let digitCount = 0;

  for (let i = 0; i <= ip.length; i++) {
    const c = i < ip.length ? ip.charCodeAt(i) : 46;

    if (c === 46) {
      if (digitCount === 0 || digitCount > 3) return false;
      if (currentOctet > 255) return false;
      octetCount++;
      currentOctet = 0;
      digitCount = 0;
    } else if (c >= 48 && c <= 57) {
      currentOctet = currentOctet * 10 + (c - 48) as u32;
      digitCount++;
    } else {
      return false;
    }
  }

  return octetCount === 4;
}

function isAlphaNumeric(c: i32): bool {
  return (c >= 48 && c <= 57) ||  // 0-9
         (c >= 65 && c <= 90) ||  // A-Z
         (c >= 97 && c <= 122);   // a-z
}

/**
 * Check if domain is authorized (domain-bound decryption)
 */
export function isDomainAuthorized(
  currentDomain: string,
  authorizedDomainsJson: string
): bool {
  const normalizedCurrent = normalizeDomain(currentDomain);
  if (normalizedCurrent.length === 0) {
    return false;
  }

  // Parse simple JSON array format: ["domain1","domain2"]
  const domains = parseJsonStringArray(authorizedDomainsJson);

  for (let i = 0; i < domains.length; i++) {
    const authorizedNorm = normalizeDomain(unchecked(domains[i]));
    if (authorizedNorm === normalizedCurrent) {
      return true;
    }
  }

  return false;
}

/**
 * Parse simple JSON string array
 */
function parseJsonStringArray(json: string): string[] {
  const result: string[] = [];

  if (!json.startsWith("[") || !json.endsWith("]")) {
    return result;
  }

  const inner = json.substring(1, json.length - 1).trim();
  if (inner.length === 0) {
    return result;
  }

  let inString = false;
  let escaped = false;
  let current = "";

  for (let i = 0; i < inner.length; i++) {
    const c = inner.charAt(i);

    if (escaped) {
      current += c;
      escaped = false;
      continue;
    }

    if (c === "\\") {
      escaped = true;
      continue;
    }

    if (c === '"') {
      if (inString) {
        result.push(current);
        current = "";
      }
      inString = !inString;
      continue;
    }

    if (inString) {
      current += c;
    }
  }

  return result;
}

/**
 * Generate cache slot key for a config URL
 */
export function generateCacheKey(configUrl: string, domain: string): u32 {
  const urlHash = fnv1aHash(configUrl);
  const domainHash = fnv1aHash(domain);
  const combined = secureHash(urlHash ^ domainHash, _k0++);
  return combined;
}

/**
 * Allocate a cache slot and return its index
 * Returns -1 if cache is full
 */
export function allocateCacheSlot(cacheKey: u32): i32 {
  const now = _t0 + (secureRandom() & 0xFFFF); // Approximate timestamp

  // Look for existing slot with same key
  for (let i: i32 = 0; i < CACHE_SLOT_COUNT; i++) {
    if (unchecked(_slotKeys[i]) === cacheKey) {
      unchecked(_slots[i] = now);
      return i;
    }
  }

  // Find empty slot
  for (let i: i32 = 0; i < CACHE_SLOT_COUNT; i++) {
    if (unchecked(_slots[i]) === 0) {
      unchecked(_slots[i] = now);
      unchecked(_slotKeys[i] = cacheKey);
      _s0++;
      return i;
    }
  }

  // Evict oldest slot
  let oldestIdx: i32 = 0;
  let oldestTime: u64 = unchecked(_slots[0]);

  for (let i: i32 = 1; i < CACHE_SLOT_COUNT; i++) {
    if (unchecked(_slots[i]) < oldestTime) {
      oldestTime = unchecked(_slots[i]);
      oldestIdx = i;
    }
  }

  unchecked(_slots[oldestIdx] = now);
  unchecked(_slotKeys[oldestIdx] = cacheKey);
  return oldestIdx;
}

/**
 * Free a cache slot
 */
export function freeCacheSlot(slotIndex: i32): void {
  if (slotIndex >= 0 && slotIndex < CACHE_SLOT_COUNT) {
    unchecked(_slots[slotIndex as u32] = 0);
    unchecked(_slotKeys[slotIndex as u32] = 0);
    if (_s0 > 0) _s0--;
  }
}

/**
 * Check if a cache slot is valid and not expired
 */
export function isCacheSlotValid(slotIndex: i32, maxAgeMs: u64): bool {
  if (slotIndex < 0 || slotIndex >= CACHE_SLOT_COUNT) {
    return false;
  }

  const slotTime = unchecked(_slots[slotIndex as u32]);
  if (slotTime === 0) {
    return false;
  }

  // Approximate age check
  const age = (_t0 + (secureRandom() & 0xFFFF)) - slotTime;
  return age < maxAgeMs;
}

/**
 * Get current cache slot count
 */
export function getCacheSlotCount(): u32 {
  return _s0;
}

/**
 * Encode protocol message with obfuscation
 * Format: [type:1][nonce:4][length:2][data][checksum:4]
 */
export function encodeProtocolMessage(
  messageType: u32,
  payload: string
): Uint8Array {
  const nonce = (secureRandom() & 0xFFFFFFFF) as u32;
  const payloadBytes = String.UTF8.encode(payload);
  const payloadLen = payloadBytes.byteLength as u32;

  const totalLen = 1 + 4 + 2 + payloadLen + 4;
  const result = new Uint8Array(totalLen);

  // Type byte (obfuscated)
  result[0] = ((messageType ^ (nonce & 0xFF)) & 0xFF) as u8;

  // Nonce (4 bytes, little-endian)
  result[1] = (nonce & 0xFF) as u8;
  result[2] = ((nonce >> 8) & 0xFF) as u8;
  result[3] = ((nonce >> 16) & 0xFF) as u8;
  result[4] = ((nonce >> 24) & 0xFF) as u8;

  // Payload length (2 bytes, little-endian)
  result[5] = (payloadLen & 0xFF) as u8;
  result[6] = ((payloadLen >> 8) & 0xFF) as u8;

  // XOR-scrambled payload
  const payloadView = Uint8Array.wrap(payloadBytes);
  for (let i: u32 = 0; i < payloadLen; i++) {
    const scrambleKey = ((nonce >> ((i & 3) * 8)) & 0xFF) as u8;
    result[7 + i] = payloadView[i] ^ scrambleKey;
  }

  // Checksum (simple FNV-1a of scrambled data)
  let checksum: u32 = 0x811c9dc5;
  for (let i: u32 = 0; i < 7 + payloadLen; i++) {
    checksum ^= result[i] as u32;
    checksum = (checksum * 0x01000193) >>> 0;
  }

  result[7 + payloadLen] = (checksum & 0xFF) as u8;
  result[8 + payloadLen] = ((checksum >> 8) & 0xFF) as u8;
  result[9 + payloadLen] = ((checksum >> 16) & 0xFF) as u8;
  result[10 + payloadLen] = ((checksum >> 24) & 0xFF) as u8;

  return result;
}

/**
 * Decode protocol message
 * Returns empty string on failure (invalid checksum, etc.)
 */
export function decodeProtocolMessage(data: Uint8Array): string {
  if (data.length < 11) {
    return "";
  }

  // Extract nonce
  const nonce: u32 = (data[1] as u32) |
                     ((data[2] as u32) << 8) |
                     ((data[3] as u32) << 16) |
                     ((data[4] as u32) << 24);

  // Extract payload length
  const payloadLen: u32 = (data[5] as u32) | ((data[6] as u32) << 8);

  if (data.length !== 11 + payloadLen as i32) {
    return "";
  }

  // Verify checksum first
  let checksum: u32 = 0x811c9dc5;
  for (let i: u32 = 0; i < 7 + payloadLen; i++) {
    checksum ^= data[i] as u32;
    checksum = (checksum * 0x01000193) >>> 0;
  }

  const storedChecksum: u32 = (data[7 + payloadLen] as u32) |
                              ((data[8 + payloadLen] as u32) << 8) |
                              ((data[9 + payloadLen] as u32) << 16) |
                              ((data[10 + payloadLen] as u32) << 24);

  if (checksum !== storedChecksum) {
    return "";
  }

  // Descramble payload
  const payloadBytes = new Uint8Array(payloadLen);
  for (let i: u32 = 0; i < payloadLen; i++) {
    const scrambleKey = ((nonce >> ((i & 3) * 8)) & 0xFF) as u8;
    payloadBytes[i] = data[7 + i] ^ scrambleKey;
  }

  return String.UTF8.decode(payloadBytes.buffer);
}

/**
 * Get message type from encoded protocol message
 */
export function getProtocolMessageType(data: Uint8Array): u32 {
  if (data.length < 5) {
    return 0xFFFFFFFF; // Invalid
  }

  const nonce: u32 = (data[1] as u32) |
                     ((data[2] as u32) << 8) |
                     ((data[3] as u32) << 16) |
                     ((data[4] as u32) << 24);

  return (data[0] ^ (nonce & 0xFF)) as u32;
}

/**
 * Check expiry timestamp
 */
export function isExpired(expiresAt: u64, currentTimestamp: u64): bool {
  if (expiresAt === 0) {
    return false; // No expiry
  }
  return currentTimestamp > expiresAt;
}

/**
 * Secure string comparison (constant-time)
 */
export function secureCompare(a: string, b: string): bool {
  if (a.length !== b.length) {
    return false;
  }

  let diff: u32 = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return diff === 0;
}

/**
 * Generate key derivation salt from domain
 * This creates a unique salt component for PBKDF2
 */
export function deriveKeySalt(domain: string, configSalt: string): string {
  const normalizedDomain = normalizeDomain(domain);
  if (normalizedDomain.length === 0) {
    return "";
  }

  // Combine domain hash with config salt
  const domainHash = fnv1aHash(normalizedDomain);
  const saltHash = fnv1aHash(configSalt);
  const combined = secureHash(domainHash, saltHash);

  // Return hex-encoded combined hash
  return u32ToHex(combined);
}

function u32ToHex(value: u32): string {
  const hexChars = "0123456789abcdef";
  let result = "";

  for (let i = 7; i >= 0; i--) {
    const nibble = (value >> (i * 4)) & 0xF;
    result += hexChars.charAt(nibble as i32);
  }

  return result;
}

/**
 * Validate config structure (basic checks)
 */
export function validateConfigStructure(configJson: string): bool {
  // Check for required fields
  const requiredFields = [
    '"version"',
    '"provider"',
    '"encryptedPayload"',
    '"iv"',
    '"salt"',
    '"authorizedDomains"'
  ];

  for (let i = 0; i < requiredFields.length; i++) {
    if (!configJson.includes(unchecked(requiredFields[i]))) {
      return false;
    }
  }

  // Version must be 1
  if (!configJson.includes('"version":1') && !configJson.includes('"version": 1')) {
    return false;
  }

  return true;
}

/**
 * Clear all sensitive data from memory
 */
export function secureClear(): void {
  // Reset random state
  _rx = 0;
  _ry = 0;

  // Clear all cache slots
  for (let i: i32 = 0; i < CACHE_SLOT_COUNT; i++) {
    unchecked(_slots[i] = 0);
    unchecked(_slotKeys[i] = 0);
  }

  // Reset counters
  _s0 = 0;
  _k0 = 0;
  _t0 = 0;
}

/**
 * Get memory statistics for leak detection
 */
export function getMemoryStats(): u64 {
  // Pack stats into a single u64
  // [slotCount:16][keyCounter:16][timestamp:32]
  return (((_s0 as u64) & 0xFFFF) << 48) |
         (((_k0 as u64) & 0xFFFF) << 32) |
         (_t0 & 0xFFFFFFFF);
}

// ============================================================================
// Provider Configuration System (obfuscated)
// ============================================================================

// Provider type IDs (obfuscated values)
const _P_IC: u32 = 0x6943;  // intercom
const _P_CR: u32 = 0x7243;  // crisp
const _P_HS: u32 = 0x7348;  // hubspot
const _P_DR: u32 = 0x7244;  // drift
const _P_GA: u32 = 0x6147;  // google-analytics
const _P_MP: u32 = 0x704D;  // mixpanel
const _P_SG: u32 = 0x6753;  // segment
const _P_TF: u32 = 0x6654;  // typeform
const _P_JF: u32 = 0x664A;  // jotform
const _P_CU: u32 = 0x7543;  // custom

// XOR key for string deobfuscation
const _XK: u8 = 0x5A;

// Deobfuscate a string (simple XOR)
function _ds(encoded: StaticArray<u8>): string {
  let result = "";
  for (let i = 0; i < encoded.length; i++) {
    result += String.fromCharCode(unchecked(encoded[i]) ^ _XK);
  }
  return result;
}

/**
 * Get provider ID from provider name
 */
export function getProviderId(providerName: string): u32 {
  const name = providerName.toLowerCase();
  if (name == "intercom") return _P_IC;
  if (name == "crisp") return _P_CR;
  if (name == "hubspot") return _P_HS;
  if (name == "drift") return _P_DR;
  if (name == "google-analytics") return _P_GA;
  if (name == "mixpanel") return _P_MP;
  if (name == "segment") return _P_SG;
  if (name == "typeform") return _P_TF;
  if (name == "jotform") return _P_JF;
  if (name == "custom") return _P_CU;
  return 0;
}

/**
 * Get provider script URL by ID
 * Returns XOR-deobfuscated URL
 */
export function getProviderScriptUrl(providerId: u32): string {
  // URLs are XOR-encoded with _XK (0x5A)
  if (providerId == _P_IC) {
    // https://widget.intercom.io/widget/{{appId}}
    const e: StaticArray<u8> = [0x32,0x2e,0x2e,0x3a,0x29,0x1a,0x11,0x11,0x33,0x3f,0x38,0x37,0x35,0x2e,0x14,0x3f,0x3e,0x2e,0x35,0x28,0x39,0x3d,0x3b,0x14,0x3f,0x3d,0x11,0x33,0x3f,0x38,0x37,0x35,0x2e,0x11,0x06,0x06,0x3b,0x3a,0x3a,0x1f,0x38,0x07,0x07];
    return _ds(e);
  }
  if (providerId == _P_CR) {
    // https://client.crisp.chat/l.js
    const e: StaticArray<u8> = [0x32,0x2e,0x2e,0x3a,0x29,0x1a,0x11,0x11,0x39,0x3c,0x3f,0x35,0x3e,0x2e,0x14,0x39,0x28,0x3f,0x29,0x3a,0x14,0x39,0x32,0x3b,0x2e,0x11,0x3c,0x14,0x30,0x29];
    return _ds(e);
  }
  if (providerId == _P_HS) {
    // https://js.hs-scripts.com/{{portalId}}.js
    const e: StaticArray<u8> = [0x32,0x2e,0x2e,0x3a,0x29,0x1a,0x11,0x11,0x30,0x29,0x14,0x32,0x29,0x17,0x29,0x39,0x28,0x3f,0x3a,0x2e,0x29,0x14,0x39,0x3d,0x3b,0x11,0x06,0x06,0x3a,0x3d,0x28,0x2e,0x3b,0x3c,0x1f,0x38,0x07,0x07,0x14,0x30,0x29];
    return _ds(e);
  }
  if (providerId == _P_DR) {
    // https://js.driftt.com/include/{{embedId}}/{{apiKey}}.js
    const e: StaticArray<u8> = [0x32,0x2e,0x2e,0x3a,0x29,0x1a,0x11,0x11,0x30,0x29,0x14,0x3e,0x28,0x3f,0x36,0x2e,0x2e,0x14,0x39,0x3d,0x3b,0x11,0x3f,0x3e,0x39,0x3c,0x2f,0x3e,0x35,0x11,0x06,0x06,0x35,0x3b,0x3a,0x35,0x38,0x1f,0x38,0x07,0x07,0x11,0x06,0x06,0x3b,0x3a,0x3f,0x1b,0x35,0x2b,0x07,0x07,0x14,0x30,0x29];
    return _ds(e);
  }
  if (providerId == _P_GA) {
    // https://www.googletagmanager.com/gtag/js?id={{apiKey}}
    const e: StaticArray<u8> = [0x32,0x2e,0x2e,0x3a,0x29,0x1a,0x11,0x11,0x33,0x33,0x33,0x14,0x37,0x3d,0x3d,0x37,0x3c,0x35,0x2e,0x3b,0x37,0x3b,0x3b,0x3e,0x3b,0x37,0x35,0x28,0x14,0x39,0x3d,0x3b,0x11,0x37,0x2e,0x3b,0x37,0x11,0x30,0x29,0x15,0x3f,0x38,0x19,0x06,0x06,0x3b,0x3a,0x3f,0x1b,0x35,0x2b,0x07,0x07];
    return _ds(e);
  }
  if (providerId == _P_MP) {
    // https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js
    const e: StaticArray<u8> = [0x32,0x2e,0x2e,0x3a,0x29,0x1a,0x11,0x11,0x39,0x38,0x3e,0x14,0x3b,0x22,0x3a,0x3e,0x3c,0x14,0x39,0x3d,0x3b,0x11,0x3c,0x3f,0x3a,0x29,0x11,0x3b,0x3f,0x22,0x3a,0x3b,0x3e,0x35,0x3c,0x17,0x58,0x17,0x3c,0x3b,0x2e,0x35,0x29,0x2e,0x14,0x3b,0x3f,0x3e,0x14,0x30,0x29];
    return _ds(e);
  }
  if (providerId == _P_SG) {
    // https://cdn.segment.com/analytics.js/v1/{{apiKey}}/analytics.min.js
    const e: StaticArray<u8> = [0x32,0x2e,0x2e,0x3a,0x29,0x1a,0x11,0x11,0x39,0x38,0x3e,0x14,0x29,0x35,0x37,0x3b,0x35,0x3e,0x2e,0x14,0x39,0x3d,0x3b,0x11,0x3b,0x3e,0x3b,0x3c,0x2b,0x2e,0x3f,0x39,0x29,0x14,0x30,0x29,0x11,0x2c,0x59,0x11,0x06,0x06,0x3b,0x3a,0x3f,0x1b,0x35,0x2b,0x07,0x07,0x11,0x3b,0x3e,0x3b,0x3c,0x2b,0x2e,0x3f,0x39,0x29,0x14,0x3b,0x3f,0x3e,0x14,0x30,0x29];
    return _ds(e);
  }
  if (providerId == _P_TF) {
    // https://embed.typeform.com/next/embed.js
    const e: StaticArray<u8> = [0x32,0x2e,0x2e,0x3a,0x29,0x1a,0x11,0x11,0x35,0x3b,0x3a,0x35,0x38,0x14,0x2e,0x2b,0x3a,0x35,0x36,0x3d,0x28,0x3b,0x14,0x39,0x3d,0x3b,0x11,0x3e,0x35,0x22,0x2e,0x11,0x35,0x3b,0x3a,0x35,0x38,0x14,0x30,0x29];
    return _ds(e);
  }
  if (providerId == _P_JF) {
    // https://cdn.jotfor.ms/js/vendor/JotForm.js
    const e: StaticArray<u8> = [0x32,0x2e,0x2e,0x3a,0x29,0x1a,0x11,0x11,0x39,0x38,0x3e,0x14,0x30,0x3d,0x2e,0x36,0x3d,0x28,0x14,0x3b,0x29,0x11,0x30,0x29,0x11,0x2c,0x35,0x3e,0x38,0x3d,0x28,0x11,0x10,0x3d,0x2e,0x16,0x3d,0x28,0x3b,0x14,0x30,0x29];
    return _ds(e);
  }
  // Custom - return placeholder
  return "{{scriptUrl}}";
}

/**
 * Get provider intercept patterns by ID
 * Returns JSON array of regex patterns
 */
export function getProviderPatterns(providerId: u32): string {
  if (providerId == _P_IC) {
    return '["^https://api\\\\.intercom\\\\.io/.*","^https://widget\\\\.intercom\\\\.io/.*"]';
  }
  if (providerId == _P_CR) {
    return '["^https://client\\\\.crisp\\\\.chat/.*","^https://api\\\\.crisp\\\\.chat/.*"]';
  }
  if (providerId == _P_HS) {
    return '["^https://api\\\\.hubspot\\\\.com/.*","^https://js\\\\.hs-scripts\\\\.com/.*","^https://track\\\\.hubspot\\\\.com/.*"]';
  }
  if (providerId == _P_DR) {
    return '["^https://js\\\\.driftt\\\\.com/.*","^https://event\\\\.api\\\\.drift\\\\.com/.*"]';
  }
  if (providerId == _P_GA) {
    return '["^https://www\\\\.google-analytics\\\\.com/.*","^https://www\\\\.googletagmanager\\\\.com/.*"]';
  }
  if (providerId == _P_MP) {
    return '["^https://api\\\\.mixpanel\\\\.com/.*","^https://cdn\\\\.mxpnl\\\\.com/.*"]';
  }
  if (providerId == _P_SG) {
    return '["^https://cdn\\\\.segment\\\\.com/.*","^https://api\\\\.segment\\\\.io/.*"]';
  }
  if (providerId == _P_TF) {
    return '["^https://api\\\\.typeform\\\\.com/.*","^https://embed\\\\.typeform\\\\.com/.*"]';
  }
  if (providerId == _P_JF) {
    return '["^https://api\\\\.jotform\\\\.com/.*","^https://cdn\\\\.jotfor\\\\.ms/.*"]';
  }
  return "[]";
}

/**
 * Get provider init script by ID
 */
export function getProviderInitScript(providerId: u32): string {
  if (providerId == _P_IC) {
    return 'window.Intercom("boot", { app_id: "{{appId}}" });';
  }
  if (providerId == _P_CR) {
    return 'window.CRISP_WEBSITE_ID = "{{apiKey}}";';
  }
  if (providerId == _P_HS) {
    return 'window._hsq = window._hsq || [];';
  }
  if (providerId == _P_DR) {
    return 'drift.SNIPPET_VERSION = "0.3.1"; drift.config({ appId: "{{apiKey}}" });';
  }
  if (providerId == _P_GA) {
    return 'window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);} gtag("js", new Date()); gtag("config", "{{apiKey}}");';
  }
  if (providerId == _P_MP) {
    return 'mixpanel.init("{{apiKey}}", { track_pageview: true });';
  }
  if (providerId == _P_SG) {
    return 'analytics.load("{{apiKey}}"); analytics.page();';
  }
  if (providerId == _P_TF) {
    return '';
  }
  if (providerId == _P_JF) {
    return 'JF.init({ apiKey: "{{apiKey}}" });';
  }
  return "{{initScript}}";
}

/**
 * Get provider header configuration by ID
 * Returns JSON object of headers
 */
export function getProviderHeaders(providerId: u32): string {
  if (providerId == _P_IC) {
    return '{"Authorization":"Bearer {{apiKey}}"}';
  }
  if (providerId == _P_MP) {
    return '{"Authorization":"Basic {{apiKey}}"}';
  }
  if (providerId == _P_TF) {
    return '{"Authorization":"Bearer {{apiKey}}"}';
  }
  if (providerId == _P_JF) {
    return '{"APIKEY":"{{apiKey}}"}';
  }
  return "{}";
}

/**
 * Get provider query params by ID
 * Returns JSON object of query params
 */
export function getProviderQueryParams(providerId: u32): string {
  if (providerId == _P_HS) {
    return '{"hapikey":"{{apiKey}}"}';
  }
  return "{}";
}

/**
 * Interpolate template variables in a string
 */
export function interpolateTemplate(template: string, variablesJson: string): string {
  let result = template;
  const vars = parseJsonObject(variablesJson);

  for (let i = 0; i < vars.length; i += 2) {
    const key = unchecked(vars[i]);
    const value = unchecked(vars[i + 1]);
    const pattern = "{{" + key + "}}";

    while (result.includes(pattern)) {
      const idx = result.indexOf(pattern);
      result = result.substring(0, idx) + value + result.substring(idx + pattern.length);
    }
  }

  return result;
}

/**
 * Simple JSON object parser - returns flat array of [key, value, key, value, ...]
 */
function parseJsonObject(json: string): string[] {
  const result: string[] = [];

  if (!json.startsWith("{") || !json.endsWith("}")) {
    return result;
  }

  const inner = json.substring(1, json.length - 1).trim();
  if (inner.length === 0) {
    return result;
  }

  let inString = false;
  let escaped = false;
  let current = "";
  let isKey = true;
  let currentKey = "";

  for (let i = 0; i < inner.length; i++) {
    const c = inner.charAt(i);

    if (escaped) {
      current += c;
      escaped = false;
      continue;
    }

    if (c === "\\") {
      escaped = true;
      continue;
    }

    if (c === '"') {
      if (inString) {
        if (isKey) {
          currentKey = current;
        } else {
          result.push(currentKey);
          result.push(current);
        }
        current = "";
      }
      inString = !inString;
      continue;
    }

    if (!inString && c === ":") {
      isKey = false;
      continue;
    }

    if (!inString && c === ",") {
      isKey = true;
      continue;
    }

    if (inString) {
      current += c;
    }
  }

  return result;
}
