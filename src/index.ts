import { decryptData, encryptData, isValidPayload } from './crypto';
import { decodeBase64Envelope, hasV2Magic, openV2WithPassphrase } from './envelope';
import type { DecryptedBackup, EncryptedBackup } from './interfaces';

export {
  addSlot,
  type DeviceP256Slot,
  type EnvelopeHeader,
  type InspectResult,
  inspectEnvelope,
  isEnvelopeV2,
  openBackup,
  type Pbkdf2Slot,
  removeSlot,
  rewrapBackup,
  type Slot,
  type SlotSpec,
  sealBackup,
  type Unlock,
  updateBackupPayload,
} from './envelope';

/**
 * Validates the structure of a payload intended for encryption.
 * @param payload The payload to validate.
 * @returns True if the payload is valid, false otherwise.
 */

/**
 * Encrypts a backup payload object into an encrypted string.
 * The type of backup is inferred from its structure.
 * @param payload The backup payload to encrypt.
 * @param passphrase The passphrase to use for encryption.
 * @param iterations Optional PBKDF2 iteration count. Defaults to `DEFAULT_PBKDF2_ITERATIONS` from crypto module.
 * @returns A promise that resolves to the encrypted backup string (Base64 encoded).
 * @throws Will throw an error if the payload or passphrase is invalid.
 */
export async function encryptBackup(
  payload: DecryptedBackup,
  passphrase: string,
  iterations?: number
): Promise<EncryptedBackup> {
  if (!isValidPayload(payload)) {
    throw new Error(
      'Invalid payload: Payload must be an object matching SigmaSeedBackup, BapMasterBackup, BapAccountBackup, WifBackup, OneSatBackup, VaultBackup, YoursWalletBackup, or YoursWalletZipBackup structure.'
    );
  }
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('Invalid passphrase: Passphrase must be a non-empty string.');
  }
  if (passphrase.length < 8) {
    throw new Error('Invalid passphrase: Passphrase must be at least 8 characters long.');
  }
  return encryptData(payload, passphrase, iterations);
}

/**
 * Decrypts an encrypted backup string back into a backup payload object.
 * Handles both new JSON-structured encrypted backups and legacy raw WIF encrypted backups.
 * Attempts decryption with default and legacy iteration counts if not specified.
 * @param encryptedString The encrypted backup string (Base64 encoded).
 * @param passphrase The passphrase used for encryption.
 * @param attemptIterations Optional. A specific iteration count, or an array of counts to try.
 *                        If undefined, defaults to trying [DEFAULT_PBKDF2_ITERATIONS, LEGACY_PBKDF2_ITERATIONS].
 * @returns A promise that resolves to the decrypted backup payload.
 * @throws Will throw an error if decryption fails or the format is invalid.
 */
export async function decryptBackup(
  encryptedString: EncryptedBackup,
  passphrase: string,
  attemptIterations?: number | number[]
): Promise<DecryptedBackup> {
  if (typeof encryptedString !== 'string' || encryptedString.length === 0) {
    throw new Error('Invalid encryptedString: Must be a non-empty string.');
  }
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('Invalid passphrase: Passphrase must be a non-empty string.');
  }
  let decoded: Uint8Array | null = null;
  try {
    decoded = decodeBase64Envelope(encryptedString);
  } catch {
    decoded = null;
  }
  if (decoded && hasV2Magic(decoded)) {
    return openV2WithPassphrase(encryptedString, passphrase, attemptIterations);
  }
  return decryptData(encryptedString, passphrase, attemptIterations);
}

// Optionally re-export constants if they are part of the public API
export {
  DEFAULT_PBKDF2_ITERATIONS,
  LEGACY_PBKDF2_ITERATIONS,
  RECOMMENDED_PBKDF2_ITERATIONS,
} from './crypto';
// Re-export ECIES helpers for device-key slots
export { eciesDecrypt, eciesEncrypt } from './ecies';
// Re-export type guards for backup type detection
export * from './guards';
// Re-export interfaces for library consumers
export * from './interfaces';
// Re-export Yours Wallet helpers (guards live in ./guards to avoid duplicate exports)
export { extractKeysFromChromeStorage, parseYoursWalletZip } from './yours-wallet';
