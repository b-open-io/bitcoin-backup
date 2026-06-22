import { decode as decodeMsgpack } from '@msgpack/msgpack';
import { unzipSync } from 'fflate';
import type {
  YoursWalletBackup,
  YoursWalletBackupManifest,
  YoursWalletZipBackup,
} from './interfaces';

/**
 * Extracts keys from Yours Wallet Chrome storage format
 */
export function extractKeysFromChromeStorage(chromeStorage: any): YoursWalletBackup | null {
  try {
    // Find the selected account
    const selectedAccount = chromeStorage.selectedAccount;
    if (!selectedAccount || !chromeStorage.accounts?.[selectedAccount]) {
      return null;
    }

    const account = chromeStorage.accounts[selectedAccount];

    // Check if we have encrypted keys - these need to be decrypted with the wallet password
    if (account.encryptedKeys) {
      // For now, return null as we cannot decrypt without the wallet password
      // In a real implementation, this would need the wallet's internal password
      return null;
    }

    // If keys are available in plain text (unlikely in production)
    if (account.privateKeys) {
      return {
        mnemonic: account.mnemonic || '',
        payPk: account.privateKeys.payPk || '',
        payDerivationPath: account.derivationPaths?.pay || "m/44'/236'/0'/1/0",
        ordPk: account.privateKeys.ordPk || '',
        ordDerivationPath: account.derivationPaths?.ord || "m/44'/236'/1'/0/0",
        identityPk: account.privateKeys.identityPk || '',
        identityDerivationPath: account.derivationPaths?.identity || "m/0'/236'/0'/0/0",
      };
    }

    return null;
  } catch (error) {
    console.error('Error extracting keys from Chrome storage:', error);
    return null;
  }
}

/** True for ZIP entries holding a msgpack-encoded wallet-toolbox sync chunk. */
function isChunkEntry(name: string): boolean {
  return name.includes('chunk-') && name.endsWith('.bin');
}

/**
 * Parses a Yours Wallet master backup ZIP into its structured contents.
 *
 * The ZIP (fflate/deflate) holds chromeStorage.json (required), an optional
 * manifest.json (absent for legacy keys-only backups), an optional
 * msgpack-encoded settings.bin, and msgpack-encoded sync chunks. JSON entries
 * are parsed; binary (.bin) entries are msgpack-decoded.
 *
 * @param zip Raw ZIP bytes (e.g. from `await file.arrayBuffer()` wrapped in a Uint8Array).
 * @returns The parsed backup contents.
 * @throws If the ZIP cannot be decompressed or is missing chromeStorage.json.
 */
export function parseYoursWalletZip(zip: Uint8Array): YoursWalletZipBackup {
  const entries = unzipSync(zip);
  const decoder = new TextDecoder();

  const chromeStorageRaw = entries['chromeStorage.json'];
  if (!chromeStorageRaw) {
    throw new Error('Invalid Yours Wallet backup: missing chromeStorage.json');
  }

  const backup: YoursWalletZipBackup = {
    chromeStorage: JSON.parse(decoder.decode(chromeStorageRaw)) as Record<string, unknown>,
  };

  const manifestRaw = entries['manifest.json'];
  if (manifestRaw) {
    backup.manifest = JSON.parse(decoder.decode(manifestRaw)) as YoursWalletBackupManifest;
  }

  const settingsRaw = entries['settings.bin'];
  if (settingsRaw) {
    backup.settings = decodeMsgpack(settingsRaw);
  }

  const chunks: Record<string, unknown> = {};
  for (const name of Object.keys(entries)) {
    if (isChunkEntry(name)) {
      chunks[name] = decodeMsgpack(entries[name]);
    }
  }
  if (Object.keys(chunks).length > 0) {
    backup.chunks = chunks;
  }

  return backup;
}

/**
 * Type guard for YoursWalletBackup
 */
export function isYoursWalletBackup(backup: any): backup is YoursWalletBackup {
  return (
    backup &&
    typeof backup === 'object' &&
    'payPk' in backup &&
    typeof backup.payPk === 'string' &&
    'ordPk' in backup &&
    typeof backup.ordPk === 'string' &&
    // Must have at least one Yours-specific field to distinguish from OneSatBackup
    ('mnemonic' in backup || 'payDerivationPath' in backup || 'ordDerivationPath' in backup)
  );
}

/**
 * Type guard for a parsed YoursWalletZipBackup.
 * The chromeStorage object is the discriminator; manifest/settings/chunks are optional.
 */
export function isYoursWalletZipBackup(backup: any): backup is YoursWalletZipBackup {
  return (
    backup &&
    typeof backup === 'object' &&
    'chromeStorage' in backup &&
    typeof backup.chromeStorage === 'object' &&
    backup.chromeStorage !== null
  );
}
