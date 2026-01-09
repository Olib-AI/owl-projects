/**
 * Provider configurations for supported embed types.
 * Each provider defines how to inject credentials and intercept requests.
 */

import type { ProviderConfig, ProviderType } from '../types.js';

/** Provider configuration registry */
const providers: Record<ProviderType, ProviderConfig> = {
  // Chat Widgets
  intercom: {
    scriptUrl: 'https://widget.intercom.io/widget/{{appId}}',
    initScript: 'window.Intercom("boot", { app_id: "{{appId}}" });',
    interceptPatterns: [
      '^https://api\\.intercom\\.io/.*',
      '^https://widget\\.intercom\\.io/.*',
    ],
    headers: {
      'Authorization': 'Bearer {{apiKey}}',
    },
  },

  crisp: {
    scriptUrl: 'https://client.crisp.chat/l.js',
    initScript: 'window.CRISP_WEBSITE_ID = "{{apiKey}}";',
    interceptPatterns: [
      '^https://client\\.crisp\\.chat/.*',
      '^https://api\\.crisp\\.chat/.*',
    ],
  },

  hubspot: {
    scriptUrl: 'https://js.hs-scripts.com/{{portalId}}.js',
    initScript: 'window._hsq = window._hsq || [];',
    interceptPatterns: [
      '^https://api\\.hubspot\\.com/.*',
      '^https://js\\.hs-scripts\\.com/.*',
      '^https://track\\.hubspot\\.com/.*',
    ],
    queryParams: {
      'hapikey': '{{apiKey}}',
    },
  },

  drift: {
    scriptUrl: 'https://js.driftt.com/include/{{embedId}}/{{apiKey}}.js',
    initScript: 'drift.SNIPPET_VERSION = "0.3.1"; drift.config({ appId: "{{apiKey}}" });',
    interceptPatterns: [
      '^https://js\\.driftt\\.com/.*',
      '^https://event\\.api\\.drift\\.com/.*',
    ],
  },

  // Analytics
  'google-analytics': {
    scriptUrl: 'https://www.googletagmanager.com/gtag/js?id={{apiKey}}',
    initScript: 'window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);} gtag("js", new Date()); gtag("config", "{{apiKey}}");',
    interceptPatterns: [
      '^https://www\\.google-analytics\\.com/.*',
      '^https://www\\.googletagmanager\\.com/.*',
    ],
  },

  mixpanel: {
    scriptUrl: 'https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js',
    initScript: 'mixpanel.init("{{apiKey}}", { track_pageview: true });',
    interceptPatterns: [
      '^https://api\\.mixpanel\\.com/.*',
      '^https://cdn\\.mxpnl\\.com/.*',
    ],
    headers: {
      'Authorization': 'Basic {{apiKey}}',
    },
  },

  segment: {
    scriptUrl: 'https://cdn.segment.com/analytics.js/v1/{{apiKey}}/analytics.min.js',
    initScript: 'analytics.load("{{apiKey}}"); analytics.page();',
    interceptPatterns: [
      '^https://cdn\\.segment\\.com/.*',
      '^https://api\\.segment\\.io/.*',
    ],
  },

  // Forms
  typeform: {
    scriptUrl: 'https://embed.typeform.com/next/embed.js',
    initScript: '',
    interceptPatterns: [
      '^https://api\\.typeform\\.com/.*',
      '^https://embed\\.typeform\\.com/.*',
    ],
    headers: {
      'Authorization': 'Bearer {{apiKey}}',
    },
  },

  jotform: {
    scriptUrl: 'https://cdn.jotfor.ms/js/vendor/JotForm.js',
    initScript: 'JF.init({ apiKey: "{{apiKey}}" });',
    interceptPatterns: [
      '^https://api\\.jotform\\.com/.*',
      '^https://cdn\\.jotfor\\.ms/.*',
    ],
    headers: {
      'APIKEY': '{{apiKey}}',
    },
  },

  // Custom - user provides their own configuration
  custom: {
    scriptUrl: '{{scriptUrl}}',
    initScript: '{{initScript}}',
    interceptPatterns: [],
  },
};

/**
 * Gets the configuration for a specific provider.
 * @param provider - The provider type
 * @returns Provider configuration
 */
export function getProviderConfig(provider: ProviderType): ProviderConfig {
  return providers[provider];
}

/**
 * Interpolates template variables in a string.
 * @param template - String with {{variable}} placeholders
 * @param variables - Key-value pairs to interpolate
 * @returns Interpolated string
 */
export function interpolate(
  template: string,
  variables: Readonly<Record<string, string>>
): string {
  let result = template;
  for (const [key, value] of Object.entries(variables)) {
    const pattern = new RegExp('\\{\\{' + key + '\\}\\}', 'g');
    result = result.replace(pattern, value);
  }
  return result;
}

/**
 * Creates regex patterns from provider intercept patterns.
 * @param provider - The provider type
 * @returns Array of RegExp objects
 */
export function getInterceptRegexes(provider: ProviderType): RegExp[] {
  const config = providers[provider];
  return config.interceptPatterns.map((pattern) => new RegExp(pattern));
}

export { providers };
