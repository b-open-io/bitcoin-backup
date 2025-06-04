import { encryptData, decryptData } from './crypto';
import type {
  DecryptedBackup,
  EncryptedBackup
  // BapMasterBackup, // Removed as it's covered by export *
  // BapMemberBackup, // Removed as it's covered by export *
  // WifBackup        // Removed as it's covered by export *
} from './interfaces';

/**
 * Validates the structure of a payload intended for encryption.
 * @param payload The payload to validate.
 * @returns True if the payload is valid, false otherwise.
 */
function isValidPayload(payload: unknown): payload is DecryptedBackup {
  if (!payload || typeof payload !== 'object') return false;

  // Narrow down type for property checks
  const p = payload as Record<string, unknown>;

  // Check for BapMasterBackup structure (legacy XPRV format)
  if (
    'xprv' in p && typeof p.xprv === 'string' &&
    'ids' in p && typeof p.ids === 'string' &&
    'mnemonic' in p && typeof p.mnemonic === 'string'
  ) {
    return true;
  }

  // Check for BapMasterBackup structure (Type 42 format)
  if (
    'rootPk' in p && typeof p.rootPk === 'string' &&
    'ids' in p && typeof p.ids === 'string' &&
    !('xprv' in p) // Ensure it's not a legacy format
  ) {
    return true;
  }

  // Check for BapMemberBackup structure
  if (
    'wif' in p && typeof p.wif === 'string' &&
    'id' in p && typeof p.id === 'string'
  ) {
    return true;
  }

  // Check for WifBackup structure
  if (
    'wif' in p && typeof p.wif === 'string' &&
    !('id' in p) && // Differentiates from BapMemberBackup
    !('xprv' in p) && // Differentiates from BapMasterBackupLegacy
    !('rootPk' in p) // Differentiates from MasterBackupType42
  ) {
    return true;
  }

  // Check for OneSatBackup structure
  if (
    'ordPk' in p && typeof p.ordPk === 'string' &&
    'payPk' in p && typeof p.payPk === 'string' &&
    'identityPk' in p && typeof p.identityPk === 'string'
  ) {
    return true;
  }

  return false;
}


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
      'Invalid payload: Payload must be an object matching BapMasterBackup, BapMemberBackup, WifBackup, or OneSatBackup structure.'
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
  return decryptData(encryptedString, passphrase, attemptIterations);
}

// Re-export interfaces for library consumers
export * from './interfaces';
// Optionally re-export constants if they are part of the public API
export { DEFAULT_PBKDF2_ITERATIONS, LEGACY_PBKDF2_ITERATIONS, RECOMMENDED_PBKDF2_ITERATIONS } from './crypto';
