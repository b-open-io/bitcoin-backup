/**
 * Touch ID password cache for bbackup.
 *
 * Caches passphrases in the macOS Secure Enclave via @1sat/vault.
 * Each .bep file gets its own vault entry, keyed by a hash of its absolute path.
 * The passphrase is encrypted with a P-256 key that never leaves the SE chip.
 * Decryption (retrieval) triggers Touch ID.
 *
 * This module is a convenience layer -- the .bep file format is unchanged.
 * Backups remain portable; only the cached password is hardware-bound.
 */

import { arch, platform } from 'node:os';
import { resolve } from 'node:path';

/**
 * Derive a deterministic vault label from a file path.
 * Uses first 16 hex chars of SHA-256(absolutePath).
 */
export function getLabelForFile(filePath: string): string {
  const absolutePath = resolve(filePath);
  const hash = new Bun.CryptoHasher('sha256').update(absolutePath).digest('hex');
  return `bbackup-${hash.slice(0, 16)}`;
}

/** Check if Touch ID password caching is available on this platform. */
export function isTouchIDAvailable(): boolean {
  return platform() === 'darwin' && arch() === 'arm64';
}

/** Lazily load @1sat/vault. Throws if not installed. */
async function loadVault() {
  try {
    return await import('@1sat/vault');
  } catch {
    throw new Error('@1sat/vault is not installed. Install it with: bun add @1sat/vault');
  }
}

/**
 * Cache a passphrase for a .bep file in the Secure Enclave.
 * No Touch ID required (encryption uses public key only).
 */
export async function cachePassword(filePath: string, passphrase: string): Promise<void> {
  const vault = await loadVault();
  const label = getLabelForFile(filePath);
  await vault.protectSecret(label, passphrase, {
    file: resolve(filePath),
  });
}

/**
 * Retrieve a cached passphrase for a .bep file.
 * Triggers Touch ID -- the ECDH happens inside the Secure Enclave.
 * Returns null if no cached password exists.
 */
export async function getCachedPassword(filePath: string): Promise<string | null> {
  const vault = await loadVault();
  const label = getLabelForFile(filePath);
  try {
    const { plaintext } = await vault.unlockSecret(label);
    return plaintext;
  } catch {
    return null;
  }
}

/**
 * Remove a cached passphrase for a .bep file.
 */
export async function forgetPassword(filePath: string): Promise<void> {
  const vault = await loadVault();
  const label = getLabelForFile(filePath);
  try {
    await vault.removeSecret(label);
  } catch {
    // No cached password to remove
  }
}
