/**
 * Touch ID password cache for bbackup.
 *
 * Caches passphrases in the macOS Secure Enclave. Each .bep file gets its own
 * vault entry, keyed by a hash of its absolute path. The passphrase is encrypted
 * with a P-256 key that never leaves the SE chip. Decryption (retrieval) triggers
 * Touch ID.
 *
 * Uses the provider-based @1sat/vault (>=0.0.6): the platform-agnostic vault
 * interface from @1sat/vault plus the macOS SecureEnclaveProvider from
 * @1sat/wallet-mac. The ciphertext is stored on disk by FileVaultStorage at
 * ~/.secure-enclave-vault/<label>.vault.json.
 *
 * This module is a convenience layer -- the .bep file format is unchanged.
 * Backups remain portable; only the cached password is hardware-bound.
 */

import { arch, homedir, platform } from 'node:os';
import { resolve } from 'node:path';
import type { Vault } from '@1sat/vault';

/** Directory where the Secure Enclave ciphertext entries are stored. */
const VAULT_DIR = resolve(homedir(), '.secure-enclave-vault');

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

let vaultPromise: Promise<Vault> | undefined;

/**
 * Lazily build the Secure Enclave vault from the platform-agnostic @1sat/vault
 * interface and the macOS provider in @1sat/wallet-mac. Throws if either is
 * missing (e.g. dependencies not installed).
 */
function getVault(): Promise<Vault> {
  if (!vaultPromise) {
    vaultPromise = (async () => {
      let vaultMod: typeof import('@1sat/vault');
      let macMod: typeof import('@1sat/wallet-mac');
      try {
        vaultMod = await import('@1sat/vault');
        macMod = await import('@1sat/wallet-mac');
      } catch {
        throw new Error(
          'Touch ID support requires @1sat/vault and @1sat/wallet-mac. Install them with: bun add @1sat/vault @1sat/wallet-mac'
        );
      }
      return vaultMod.createVault(
        new macMod.SecureEnclaveProvider({ name: 'bbackup' }),
        new vaultMod.FileVaultStorage(VAULT_DIR)
      );
    })();
  }
  return vaultPromise;
}

/**
 * Cache a passphrase for a .bep file in the Secure Enclave.
 * No Touch ID required (encryption uses public key only).
 */
export async function cachePassword(filePath: string, passphrase: string): Promise<void> {
  const vault = await getVault();
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
  const vault = await getVault();
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
  const vault = await getVault();
  const label = getLabelForFile(filePath);
  try {
    await vault.removeSecret(label);
  } catch {
    // No cached password to remove
  }
}
