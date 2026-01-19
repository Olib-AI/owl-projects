# @olib-ai/secure-embed

[![Olib AI](https://img.shields.io/badge/Olib%20AI-www.olib.ai-blue)](https://www.olib.ai)

Securely embed third-party scripts (chat widgets, analytics, forms) without hardcoding API keys in your HTML/JavaScript. Uses Service Worker + WebAssembly encryption for runtime credential injection with maximum security.

## The Problem

Modern websites need third-party embeds that require API keys:

```html
<!-- DON'T DO THIS - API key visible to anyone -->
<script>
  window.intercomSettings = { app_id: "abc123secret" };
</script>
```

Anyone can view-source your page and steal your credentials.

## The Solution

SecureEmbed v2.0 uses **WebAssembly** to protect your security logic from reverse engineering:

1. **Credentials are encrypted** at build time with domain-bound keys
2. **Service Worker + Wasm** intercepts requests to embed providers
3. **Security logic is compiled to binary** - algorithms can't be read from source
4. **Decryption happens in memory** - credentials never appear in source code
5. **Domain verification** ensures credentials only work on your site

## Installation

```bash
npm install @olib-ai/secure-embed
```

## Quick Start

### 1. Create a config file

```json
// embed.json
{
  "provider": "intercom",
  "credentials": {
    "apiKey": "your-intercom-app-id"
  },
  "authorizedDomains": ["example.com", "www.example.com"]
}
```

### 2. Encrypt your credentials

```bash
npx @olib-ai/secure-embed encrypt --config embed.json --output public/.secure-embed
```

### 3. Copy the Service Worker and Wasm module

Copy these files to your public directory root:

```bash
# Service Worker (Wasm-protected)
cp node_modules/@olib-ai/secure-embed/dist/secure-sw.min.js public/secure-embed-sw.js

# WebAssembly crypto core
cp node_modules/@olib-ai/secure-embed/wasm/build/crypto-core.wasm public/secure-embed-core.wasm
```

### 4. Use in your app

**React:**

```tsx
import { SecureEmbed } from '@olib-ai/secure-embed/react';

function App() {
  return (
    <SecureEmbed
      provider="intercom"
      configUrl="/.secure-embed/intercom.enc"
      onLoad={() => console.log('Chat loaded!')}
      onError={(err) => console.error(err)}
    >
      <div>Loading chat widget...</div>
    </SecureEmbed>
  );
}
```

**Vanilla JavaScript:**

```js
import { SecureEmbed } from '@olib-ai/secure-embed';

SecureEmbed.init({
  provider: 'intercom',
  configUrl: '/.secure-embed/intercom.enc'
}).then(() => {
  console.log('Chat loaded!');
}).catch((err) => {
  console.error('Failed to load:', err);
});
```

## Supported Providers

### Chat Widgets
- **Intercom** - `intercom`
- **Crisp** - `crisp`
- **HubSpot** - `hubspot`
- **Drift** - `drift`

### Analytics
- **Google Analytics** - `google-analytics`
- **Mixpanel** - `mixpanel`
- **Segment** - `segment`

### Forms
- **Typeform** - `typeform`
- **JotForm** - `jotform`

### Custom
Use `custom` provider for any third-party script.

## Configuration Options

### CLI Config File

```json
{
  "provider": "intercom",
  "credentials": {
    "apiKey": "required-api-key",
    "apiSecret": "optional-secret",
    "metadata": {
      "portalId": "for-hubspot",
      "embedId": "for-drift"
    }
  },
  "authorizedDomains": ["example.com"],
  "expiresAt": "2025-12-31T23:59:59Z"
}
```

### React Component Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `provider` | `ProviderType` | Yes | The embed provider |
| `configUrl` | `string` | Yes | URL to encrypted config |
| `containerId` | `string` | No | Custom container element ID |
| `onLoad` | `() => void` | No | Callback when loaded |
| `onError` | `(error: Error) => void` | No | Error callback |
| `className` | `string` | No | CSS class for container |
| `style` | `CSSProperties` | No | Inline styles |
| `children` | `ReactNode` | No | Loading state content |
| `fallback` | `ReactNode` | No | Error state content |

### React Hook

```tsx
import { useSecureEmbed } from '@olib-ai/secure-embed/react';

function MyComponent() {
  const { init, destroy, isLoaded, isLoading, error, healthCheck } = useSecureEmbed();

  useEffect(() => {
    init({
      provider: 'intercom',
      configUrl: '/.secure-embed/intercom.enc',
    });
    return () => destroy('intercom');
  }, [init, destroy]);

  if (error) return <div>Error: {error.message}</div>;
  if (isLoading) return <div>Loading...</div>;
  return null;
}
```

## Security Features

### WebAssembly Protection

All security-critical operations are compiled to WebAssembly binary code:
- Cryptographic algorithms
- Domain validation logic
- Cache key generation
- Protocol message encoding
- Provider configurations

This makes reverse engineering extremely difficult compared to JavaScript.

### Domain-Bound Encryption

Credentials are encrypted using a key derived from your domain. They can only be decrypted when running on an authorized domain.

### AES-256-GCM

Industry-standard authenticated encryption ensures both confidentiality and integrity.

### PBKDF2 Key Derivation

100,000 iterations of PBKDF2-SHA256 make brute-force attacks impractical.

### Expiry Timestamps

Optional credential expiration prevents stolen configs from working indefinitely.

### Subresource Integrity

SHA-384 hashes verify config files haven't been tampered with.

### Memory-Safe Design

- Bounded cache (64 slots max)
- Automatic TTL-based eviction (1 hour)
- Explicit cleanup functions
- No memory leaks

## Architecture

```
┌─────────────────┐     ┌──────────────────────────────┐     ┌─────────────────┐
│   Build Time    │     │          Runtime             │     │    Provider     │
├─────────────────┤     ├──────────────────────────────┤     ├─────────────────┤
│                 │     │                              │     │                 │
│  embed.json     │     │  Browser loads               │     │  Intercom API   │
│       │         │     │  encrypted .enc              │     │                 │
│       ▼         │     │       │                      │     │                 │
│  CLI encrypts   │     │       ▼                      │     │                 │
│  with domain    │────▶│  ┌────────────────────┐      │     │                 │
│  key + salt     │     │  │  Service Worker    │      │     │                 │
│       │         │     │  │  (9KB JS loader)   │      │────▶│  Receives       │
│       ▼         │     │  └─────────┬──────────┘      │     │  authenticated  │
│  .enc file      │     │            │                 │     │  request        │
│                 │     │            ▼                 │     │                 │
│                 │     │  ┌────────────────────┐      │     │                 │
│                 │     │  │  Wasm Crypto Core  │      │     │                 │
│                 │     │  │  (21KB binary)     │      │     │                 │
│                 │     │  │  - Decryption      │      │     │                 │
│                 │     │  │  - Domain check    │      │     │                 │
│                 │     │  │  - Cred injection  │      │     │                 │
│                 │     │  └────────────────────┘      │     │                 │
│                 │     │                              │     │                 │
└─────────────────┘     └──────────────────────────────┘     └─────────────────┘
```

## Browser Support

- Chrome 68+
- Firefox 61+
- Safari 11.1+
- Edge 79+

Requires Service Worker and WebAssembly support.

## TypeScript

Full TypeScript support with strict types:

```ts
import type {
  ProviderType,
  EncryptedConfig,
  CredentialPayload,
  EmbedConfig,
} from '@olib-ai/secure-embed';
```

## API Reference

### Core API

```ts
import { SecureEmbed, init, destroy, healthCheck } from '@olib-ai/secure-embed';

// Initialize an embed
await init({ provider: 'intercom', configUrl: '/config.enc' });

// Destroy an embed
await destroy('intercom');

// Check if service worker is healthy
const isHealthy = await healthCheck();
```

### Crypto Utilities

```ts
import { encryptCredentials, decryptCredentials, verifyIntegrity } from '@olib-ai/secure-embed';

// Encrypt credentials for deployment
const encrypted = await encryptCredentials(payload, domains, provider, expiresAt);

// Decrypt credentials (used internally by Service Worker)
const decrypted = await decryptCredentials(config, currentDomain);

// Verify the SHA-384 integrity hash
const isValid = await verifyIntegrity(config);
```

### Wasm Core (Advanced)

```ts
import { loadWasmCore, getWasmCore, releaseWasmCore } from '@olib-ai/secure-embed';

// Load the Wasm module manually
const core = await loadWasmCore();

// Get the loaded instance
const instance = getWasmCore();

// Release resources
releaseWasmCore();
```

## File Sizes

| File | Size | Purpose |
|------|------|---------|
| `secure-sw.min.js` | ~9 KB | Service Worker loader |
| `crypto-core.wasm` | ~21 KB | Security logic (binary) |
| **Total** | **~30 KB** | Complete security layer |

## Limitations

- Service Workers require HTTPS (except localhost)
- WebAssembly must be supported by the browser
- Initial page load fetches encrypted config (small overhead)
- Some providers may detect Service Worker interception

## Development

```bash
# Build everything
npm run build

# Build Wasm only
npm run build:wasm

# Run demo server
npm run demo

# Type check
npm run typecheck
```

## License

MIT - [Olib AI](https://www.olib.ai)
