import { Utils } from '@bsv/sdk';
import type {
  BapMasterBackup,
  BapMemberBackup,
  DecryptedBackup,
  EncryptedBackup,
  OneSatBackup,
  WifBackup,
} from './interfaces';

const { toArray, toBase64 } = Utils;

export const RECOMMENDED_PBKDF2_ITERATIONS = 600000;
export const LEGACY_PBKDF2_ITERATIONS = 100000;

// This export will be what users see as the "current default"
export const DEFAULT_PBKDF2_ITERATIONS = RECOMMENDED_PBKDF2_ITERATIONS;

const SALT_LENGTH_BYTES = 16;
const IV_LENGTH_BYTES = 12;
const AES_KEY_LENGTH_BITS = 256;

/**
 * Derives a cryptographic key from a passphrase and salt using PBKDF2 and AES-GCM.
 * @param passphrase The passphrase to derive the key from.
 * @param salt The salt to use for key derivation.
 * @param iterations The number of PBKDF2 iterations to use. Defaults to DEFAULT_PBKDF2_ITERATIONS.
 * @returns A promise that resolves to the derived CryptoKey.
 */
async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = RECOMMENDED_PBKDF2_ITERATIONS // Default to new recommended standard
): Promise<CryptoKey> {
  const passphraseBytes = Uint8Array.from(toArray(passphrase, 'utf8'));

  const keyMaterial = await globalThis.crypto.subtle.importKey(
    'raw',
    passphraseBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return globalThis.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations, // Use provided or defaulted iterations
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: AES_KEY_LENGTH_BITS },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a backup payload object into a Base64 encoded string.
 * The string concatenates salt, IV, and the encrypted content.
 * @param iterations Optional number of PBKDF2 iterations. Defaults to DEFAULT_PBKDF2_ITERATIONS.
 */
export async function encryptData(
  payload: DecryptedBackup,
  passphrase: string,
  iterations?: number // Optional iterations for encryption
): Promise<EncryptedBackup> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));

  // deriveKey will use its default (DEFAULT_PBKDF2_ITERATIONS) if iterations is undefined
  const key = await deriveKey(passphrase, salt, iterations);

  const payloadToEncrypt = {
    ...payload,
    createdAt: payload.createdAt || new Date().toISOString(),
  };

  const jsonPayload = JSON.stringify(payloadToEncrypt);
  const dataToEncrypt = new TextEncoder().encode(jsonPayload);

  const encryptedContent = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    dataToEncrypt
  );

  const combined = new Uint8Array(salt.length + iv.length + encryptedContent.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encryptedContent), salt.length + iv.length);

  return toBase64(Array.from(combined));
}

/**
 * Decrypts an encrypted backup string back into a backup payload object.
 * Handles JSON-structured and legacy raw WIF backups.
 * @param attemptIterations Optional. A specific iteration count, or an array of counts to try in order.
 *                        Defaults to trying [DEFAULT_PBKDF2_ITERATIONS, LEGACY_PBKDF2_ITERATIONS].
 */
export async function decryptData(
  encryptedBackup: EncryptedBackup,
  passphrase: string,
  attemptIterations?: number | number[]
): Promise<DecryptedBackup> {
  let combinedBytesNumbers: number[];
  try {
    combinedBytesNumbers = toArray(encryptedBackup, 'base64');
  } catch (error) {
    console.error('Failed to decode base64 string (toArray threw):', error);
    throw new Error('Decryption failed: Invalid Base64 input.');
  }

  if (encryptedBackup.length > 0 && combinedBytesNumbers.length === 0) {
    throw new Error('Decryption failed: Invalid Base64 input (decoded to empty).');
  }

  const combinedBytes = Uint8Array.from(combinedBytesNumbers);

  if (combinedBytes.length < SALT_LENGTH_BYTES + IV_LENGTH_BYTES) {
    throw new Error('Decryption failed: Encrypted data is too short.');
  }

  const salt = combinedBytes.slice(0, SALT_LENGTH_BYTES);
  const iv = combinedBytes.slice(SALT_LENGTH_BYTES, SALT_LENGTH_BYTES + IV_LENGTH_BYTES);
  const encryptedCiphertext = combinedBytes.slice(SALT_LENGTH_BYTES + IV_LENGTH_BYTES);

  const iterationCountsToTry: number[] =
    typeof attemptIterations === 'number'
      ? [attemptIterations]
      : Array.isArray(attemptIterations)
        ? attemptIterations
        : [RECOMMENDED_PBKDF2_ITERATIONS, LEGACY_PBKDF2_ITERATIONS]; // Updated default order

  let lastError: Error | null = null;

  for (const iterations of iterationCountsToTry) {
    try {
      const key = await deriveKey(passphrase, salt, iterations);
      const decryptedArrayBuffer = await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encryptedCiphertext
      );
      const decryptedString = new TextDecoder().decode(decryptedArrayBuffer);
      try {
        const parsedJson = JSON.parse(decryptedString);
        if (typeof parsedJson === 'object' && parsedJson !== null) {
          if ('xprv' in parsedJson && 'ids' in parsedJson && 'mnemonic' in parsedJson)
            return parsedJson as BapMasterBackup;
          if ('rootPk' in parsedJson && 'ids' in parsedJson) return parsedJson as BapMasterBackup;
          if ('wif' in parsedJson && 'id' in parsedJson) return parsedJson as BapMemberBackup;
          if ('ordPk' in parsedJson && 'payPk' in parsedJson && 'identityPk' in parsedJson)
            return parsedJson as OneSatBackup;
          if (
            'wif' in parsedJson &&
            !('id' in parsedJson) &&
            !('xprv' in parsedJson) &&
            !('rootPk' in parsedJson)
          )
            return parsedJson as WifBackup;
        }
        throw new Error('Invalid backup structure after JSON parse.');
      } catch (jsonError) {
        if (jsonError instanceof SyntaxError) return { wif: decryptedString } as WifBackup;
        throw jsonError;
      }
    } catch (decryptionError) {
      lastError = decryptionError as Error;
      // console.log(`Decryption attempt failed with ${iterations} iterations.`); // Optional: for debugging
      if (decryptionError instanceof DOMException && decryptionError.name === 'OperationError') {
        // This is the expected error for wrong key / corrupted data, continue to next iteration count
        continue;
      }
      throw decryptionError; // Rethrow unexpected errors immediately
    }
  }
  // If all iteration counts failed
  console.error('All decryption attempts failed. Last error:', lastError);
  if (lastError && lastError.name === 'OperationError') {
    throw new Error(
      'Decryption failed: Invalid passphrase or corrupted data across all attempted iteration counts.'
    );
  }
  throw (
    lastError ||
    new Error(
      'Decryption failed: Invalid passphrase or corrupted data across all attempted iteration counts.'
    )
  );
}
