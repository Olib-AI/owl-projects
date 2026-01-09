# @olib-ai/secure-embed

Securely embed third-party scripts (chat widgets, analytics, forms) without hardcoding API keys in your HTML/JavaScript. Uses Service Worker encryption for runtime credential injection.

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

SecureEmbed encrypts your credentials and uses a Service Worker to decrypt them at runtime:

1. **Credentials are encrypted** at build time with domain-bound keys
2. **Service Worker intercepts** requests to embed providers
3. **Decryption happens in memory** - credentials never appear in source code
4. **Domain verification** ensures credentials only work on your site

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

### 3. Copy the Service Worker

Copy `node_modules/@olib-ai/secure-embed/dist/service-worker.js` to your public directory as `secure-embed-sw.js`.

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
import { SecureEmbed } from '@olib-ai/secure-embed/vanilla';

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

### No Memory Leaks

The Service Worker uses streaming where possible and properly cleans up decrypted credentials.

## How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Build Time    │     │     Runtime      │     │    Provider     │
├─────────────────┤     ├──────────────────┤     ├─────────────────┤
│                 │     │                  │     │                 │
│  embed.json     │     │  Browser loads   │     │  Intercom API   │
│       │         │     │  encrypted .enc  │     │                 │
│       ▼         │     │       │          │     │                 │
│  CLI encrypts   │     │       ▼          │     │                 │
│  with domain    │────▶│  Service Worker  │────▶│  Receives       │
│  key + salt     │     │  decrypts +      │     │  authenticated  │
│       │         │     │  injects creds   │     │  request        │
│       ▼         │     │                  │     │                 │
│  .enc file      │     │                  │     │                 │
│                 │     │                  │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Browser Support

- Chrome 68+
- Firefox 61+
- Safari 11.1+
- Edge 79+

Requires Service Worker support.

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

### `encryptCredentials(payload, domains, provider, expiresAt?)`

Encrypt credentials for deployment.

### `decryptCredentials(config, currentDomain)`

Decrypt credentials (used internally by Service Worker).

### `verifyIntegrity(config)`

Verify the SHA-384 integrity hash of an encrypted config.

### `getProviderConfig(provider)`

Get the configuration for a specific provider.

## Limitations

- Service Workers require HTTPS (except localhost)
- Initial page load fetches encrypted config (small overhead)
- Some providers may detect Service Worker interception

## License

MIT - Olib AI
