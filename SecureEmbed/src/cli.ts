#!/usr/bin/env node
/**
 * CLI tool for SecureEmbed.
 * Encrypts credentials for secure embedding.
 * 
 * Usage:
 *   npx @olib-ai/secure-embed encrypt --config embed.json --output .secure-embed
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { webcrypto } from 'node:crypto';
import { encryptCredentials } from './crypto.js';
import type { CLIInputConfig, EncryptedConfig, ProviderType } from './types.js';

// Polyfill crypto for Node.js
const cryptoImpl = webcrypto as unknown as Crypto;

/** CLI argument parsing result */
type ParsedArgs =
  | { readonly command: 'help' | 'version' }
  | { readonly command: 'encrypt'; readonly configPath: string | undefined; readonly outputDir: string | undefined };

/** Parses CLI arguments */
function parseArgs(args: readonly string[]): ParsedArgs {
  const argsList = args.slice(2); // Skip node and script path

  if (argsList.length === 0 || argsList.includes('--help') || argsList.includes('-h')) {
    return { command: 'help' };
  }

  if (argsList.includes('--version') || argsList.includes('-v')) {
    return { command: 'version' };
  }

  const command = argsList[0];
  if (command !== 'encrypt') {
    console.error('Unknown command: ' + (command ?? ''));
    return { command: 'help' };
  }

  let configPath: string | undefined;
  let outputDir: string | undefined;

  for (let i = 1; i < argsList.length; i++) {
    const arg = argsList[i];
    const nextArg = argsList[i + 1];

    if ((arg === '--config' || arg === '-c') && nextArg !== undefined) {
      configPath = nextArg;
      i++;
    } else if ((arg === '--output' || arg === '-o') && nextArg !== undefined) {
      outputDir = nextArg;
      i++;
    }
  }

  return { command: 'encrypt', configPath, outputDir };
}

/** Prints help message */
function printHelp(): void {
  console.log(`
@olib-ai/secure-embed CLI

Usage:
  secure-embed <command> [options]

Commands:
  encrypt    Encrypt credentials from a config file

Options:
  --config, -c <path>   Path to input config file (JSON)
  --output, -o <dir>    Output directory for encrypted files
  --help, -h            Show this help message
  --version, -v         Show version number

Example:
  secure-embed encrypt --config embed.json --output .secure-embed

Config file format (embed.json):
{
  "provider": "intercom",
  "credentials": {
    "apiKey": "your-api-key",
    "apiSecret": "optional-secret",
    "metadata": {
      "appId": "optional-app-id"
    }
  },
  "authorizedDomains": ["example.com", "www.example.com"],
  "expiresAt": "2025-12-31T23:59:59Z"
}

Supported providers:
  - intercom, crisp, hubspot, drift (chat widgets)
  - google-analytics, mixpanel, segment (analytics)
  - typeform, jotform (forms)
  - custom (user-defined)
`);
}

/** Prints version */
function printVersion(): void {
  console.log('@olib-ai/secure-embed v1.0.0');
}

/** Validates the input config */
function validateConfig(config: unknown): config is CLIInputConfig {
  if (typeof config !== 'object' || config === null) {
    return false;
  }

  const obj = config as Record<string, unknown>;

  // Check provider
  const validProviders: readonly ProviderType[] = [
    'intercom', 'crisp', 'hubspot', 'drift',
    'google-analytics', 'mixpanel', 'segment',
    'typeform', 'jotform', 'custom',
  ];
  if (!validProviders.includes(obj['provider'] as ProviderType)) {
    console.error('Invalid provider. Must be one of: ' + validProviders.join(', '));
    return false;
  }

  // Check credentials
  const creds = obj['credentials'];
  if (typeof creds !== 'object' || creds === null) {
    console.error('Missing or invalid credentials object');
    return false;
  }

  const credsObj = creds as Record<string, unknown>;
  if (typeof credsObj['apiKey'] !== 'string' || credsObj['apiKey'] === '') {
    console.error('Missing or invalid apiKey in credentials');
    return false;
  }

  // Check authorized domains
  const domains = obj['authorizedDomains'];
  if (!Array.isArray(domains) || domains.length === 0) {
    console.error('Missing or empty authorizedDomains array');
    return false;
  }

  for (const domain of domains) {
    if (typeof domain !== 'string' || domain === '') {
      console.error('Invalid domain in authorizedDomains');
      return false;
    }
  }

  return true;
}

/** Main encrypt command */
async function encryptCommand(configPath: string, outputDir: string): Promise<void> {
  // Resolve paths
  const absoluteConfigPath = resolve(process.cwd(), configPath);
  const absoluteOutputDir = resolve(process.cwd(), outputDir);

  // Read config file
  console.log('Reading config from: ' + absoluteConfigPath);

  let configContent: string;
  try {
    configContent = await readFile(absoluteConfigPath, 'utf-8');
  } catch {
    console.error('Failed to read config file: ' + absoluteConfigPath);
    process.exit(1);
  }

  // Parse JSON
  let config: unknown;
  try {
    config = JSON.parse(configContent);
  } catch {
    console.error('Invalid JSON in config file');
    process.exit(1);
  }

  // Validate config
  if (!validateConfig(config)) {
    process.exit(1);
  }

  // Parse expiry date if provided
  let expiresAt: number | undefined;
  if (config.expiresAt !== undefined) {
    const date = new Date(config.expiresAt);
    if (isNaN(date.getTime())) {
      console.error('Invalid expiresAt date format. Use ISO 8601 format.');
      process.exit(1);
    }
    expiresAt = date.getTime();
  }

  // Encrypt credentials
  console.log('Encrypting credentials for provider: ' + config.provider);

  const encryptedConfig: EncryptedConfig = await encryptCredentials(
    config.credentials,
    config.authorizedDomains,
    config.provider,
    expiresAt,
    cryptoImpl
  );

  // Create output directory if needed
  if (!existsSync(absoluteOutputDir)) {
    await mkdir(absoluteOutputDir, { recursive: true });
    console.log('Created output directory: ' + absoluteOutputDir);
  }

  // Write encrypted config
  const outputFileName = config.provider + '.enc';
  const outputPath = join(absoluteOutputDir, outputFileName);

  await writeFile(outputPath, JSON.stringify(encryptedConfig, null, 2), 'utf-8');

  console.log('Encrypted config written to: ' + outputPath);
  console.log('');
  console.log('Next steps:');
  console.log('1. Copy secure-embed-sw.js to your web server root');
  console.log('2. Serve the .enc file from your web server');
  console.log('3. Use SecureEmbed in your application:');
  console.log('');
  console.log('   React:');
  console.log('   <SecureEmbed provider="' + config.provider + '" configUrl="/' + outputDir + '/' + outputFileName + '" />');
  console.log('');
  console.log('   Vanilla JS:');
  console.log('   SecureEmbed.init({ provider: "' + config.provider + '", configUrl: "/' + outputDir + '/' + outputFileName + '" });');
}

/** Main entry point */
async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  switch (args.command) {
    case 'help':
      printHelp();
      break;

    case 'version':
      printVersion();
      break;

    case 'encrypt':
      if (args.configPath === undefined) {
        console.error('Missing --config option');
        printHelp();
        process.exit(1);
      }
      if (args.outputDir === undefined) {
        console.error('Missing --output option');
        printHelp();
        process.exit(1);
      }
      await encryptCommand(args.configPath, args.outputDir);
      break;
  }
}

// Run
main().catch((error: unknown) => {
  console.error('Fatal error:', error instanceof Error ? error.message : error);
  process.exit(1);
});
