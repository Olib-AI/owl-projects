/**
 * React component for SecureEmbed.
 * Provides a declarative API for embedding third-party scripts.
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import type { ReactElement } from 'react';
import { SecureEmbed as VanillaSecureEmbed } from '../vanilla/secure-embed.js';
import type { EmbedConfig, ProviderType } from '../types.js';

/** Props for SecureEmbed component */
export interface SecureEmbedProps {
  /** The embed provider type */
  readonly provider: ProviderType;
  /** URL to the encrypted config file */
  readonly configUrl: string;
  /** Optional custom container ID (creates one if not provided) */
  readonly containerId?: string;
  /** Callback when embed is loaded */
  readonly onLoad?: () => void;
  /** Callback on error */
  readonly onError?: (error: Error) => void;
  /** Additional className for the container */
  readonly className?: string;
  /** Inline styles for the container */
  readonly style?: React.CSSProperties;
  /** Children to render while loading */
  readonly children?: React.ReactNode;
  /** Fallback content on error */
  readonly fallback?: React.ReactNode;
}

/** Component state */
type LoadState = 'idle' | 'loading' | 'loaded' | 'error';

/**
 * SecureEmbed React component.
 * Securely loads third-party embeds with encrypted credentials.
 * 
 * @example
 * ```tsx
 * <SecureEmbed
 *   provider="intercom"
 *   configUrl="/.secure-embed/intercom.enc"
 *   onLoad={() => console.log('Loaded!')}
 *   onError={(err) => console.error(err)}
 * >
 *   <div>Loading chat widget...</div>
 * </SecureEmbed>
 * ```
 */
export function SecureEmbed({
  provider,
  configUrl,
  containerId,
  onLoad,
  onError,
  className,
  style,
  children,
  fallback,
}: SecureEmbedProps): ReactElement {
  const [loadState, setLoadState] = useState<LoadState>('idle');
  const [error, setError] = useState<Error | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const generatedId = useRef<string>('secure-embed-' + Math.random().toString(36).slice(2, 11));

  const effectiveContainerId = containerId ?? generatedId.current;

  // Use refs to avoid recreating callbacks on prop changes
  const onLoadRef = useRef(onLoad);
  const onErrorRef = useRef(onError);
  onLoadRef.current = onLoad;
  onErrorRef.current = onError;

  const handleLoad = useCallback(() => {
    setLoadState('loaded');
    onLoadRef.current?.();
  }, []);

  const handleError = useCallback((err: Error) => {
    setLoadState('error');
    setError(err);
    onErrorRef.current?.(err);
  }, []);

  useEffect(() => {
    let mounted = true;

    const initEmbed = async (): Promise<void> => {
      if (!mounted) return;
      setLoadState('loading');

      const config: EmbedConfig = {
        provider,
        configUrl,
        containerId: effectiveContainerId,
        onLoad: () => {
          if (mounted) handleLoad();
        },
        onError: (err) => {
          if (mounted) handleError(err);
        },
      };

      try {
        await VanillaSecureEmbed.init(config);
      } catch (err: unknown) {
        if (mounted) {
          handleError(err instanceof Error ? err : new Error('Unknown error'));
        }
      }
    };

    void initEmbed();

    return () => {
      mounted = false;
      void VanillaSecureEmbed.destroy(provider);
    };
  }, [provider, configUrl, effectiveContainerId, handleLoad, handleError]);

  // Render error fallback
  if (loadState === 'error') {
    if (fallback !== undefined) {
      return <>{fallback}</>;
    }
    return (
      <div
        id={effectiveContainerId}
        ref={containerRef}
        className={className}
        style={style}
        role="alert"
        aria-live="polite"
      >
        <p>Failed to load embed: {error?.message ?? 'Unknown error'}</p>
      </div>
    );
  }

  return (
    <div
      id={effectiveContainerId}
      ref={containerRef}
      className={className}
      style={style}
      data-provider={provider}
      data-state={loadState}
    >
      {loadState === 'loading' && children}
    </div>
  );
}

/**
 * Hook for imperative SecureEmbed control.
 * Use this when you need more control than the component provides.
 * 
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { init, destroy, isLoaded, error } = useSecureEmbed();
 *   
 *   useEffect(() => {
 *     init({
 *       provider: 'intercom',
 *       configUrl: '/.secure-embed/intercom.enc',
 *     });
 *     return () => destroy('intercom');
 *   }, [init, destroy]);
 *   
 *   if (error) return <div>Error: {error.message}</div>;
 *   if (!isLoaded) return <div>Loading...</div>;
 *   return null;
 * }
 * ```
 */
export function useSecureEmbed(): {
  readonly init: (config: EmbedConfig) => Promise<void>;
  readonly destroy: (provider: ProviderType) => Promise<void>;
  readonly healthCheck: () => Promise<boolean>;
  readonly isLoaded: boolean;
  readonly isLoading: boolean;
  readonly error: Error | null;
} {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const init = useCallback(async (config: EmbedConfig): Promise<void> => {
    setIsLoading(true);
    setError(null);

    try {
      await VanillaSecureEmbed.init({
        ...config,
        onLoad: () => {
          setIsLoaded(true);
          setIsLoading(false);
          config.onLoad?.();
        },
        onError: (err) => {
          setError(err);
          setIsLoading(false);
          config.onError?.(err);
        },
      });
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error('Unknown error');
      setError(error);
      setIsLoading(false);
      throw error;
    }
  }, []);

  const destroy = useCallback(async (provider: ProviderType): Promise<void> => {
    await VanillaSecureEmbed.destroy(provider);
    setIsLoaded(false);
  }, []);

  const healthCheck = useCallback(async (): Promise<boolean> => {
    return VanillaSecureEmbed.healthCheck();
  }, []);

  return {
    init,
    destroy,
    healthCheck,
    isLoaded,
    isLoading,
    error,
  } as const;
}

export default SecureEmbed;
