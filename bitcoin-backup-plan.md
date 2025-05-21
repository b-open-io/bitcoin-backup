# `bitcoin-backup` Library Development Plan

This document outlines the detailed steps and specifications for creating the `bitcoin-backup` library.

## 1. Project Goal

To develop a robust JavaScript/TypeScript library for managing and securing Bitcoin-related identity backups. The library will handle the creation, encryption, and decryption of structured backup objects, supporting multiple formats including legacy single WIF backups and new HD master key backups. The encryption methods employed (AES-GCM with PBKDF2) align with industry best practices for secure backup encryption.

## 2. Core Features

*   Define clear TypeScript interfaces for different backup payload types.
*   Implement strong encryption (AES-GCM with PBKDF2) for backup data.
*   Support decryption of both new JSON-structured encrypted backups and legacy raw WIF encrypted backups.
*   Provide a simple API for encrypting and decrypting backup data.
*   Ensure compatibility with both browser and Node.js environments.
*   Be well-tested.

## 3. Detailed Implementation Specifications

### 3.1. TypeScript Interface Definitions (`src/interfaces.ts`)

```typescript
export type BackupFormat = "Master" | "Single" | "Simple";

export interface MasterBackupPayload {
  format: "Master";
  ids: string;          // Serialized data from bsv-bap's bap.exportIds()
  xprv: string;         // Master extended private key
  mnemonic: string;     // BIP39 mnemonic phrase
  createdAt?: string;   // ISO 8601 timestamp (optional)
}

export interface SingleIdentityBackupPayload {
  format: "Single";
  wif: string;          // Private key in WIF format
  id: string;           // BAP ID or other identifier (e.g., from memberId.getIdentityKey())
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (optional)
}

export interface SimpleWifBackupPayload {
  format: "Simple";
  wif: string;
  label?: string;               // User-defined label (optional)
  associatedBapId?: string;     // Optional BAP ID if linked (optional)
  createdAt?: string;           // ISO 8601 timestamp (optional)
}

export type DecryptedBackupPayload =
  | MasterBackupPayload
  | SingleIdentityBackupPayload
  | SimpleWifBackupPayload;

// Represents the final encrypted string, typically Base64 encoded
export type EncryptedBackupString = string;
```

### 3.2. Cryptographic Operations (`src/crypto.ts`)

This module will use the Web Crypto API (`crypto.subtle`).

*   **Constants:**
    *   `PBKDF2_ITERATIONS = 100000` (or higher, e.g., 250000)
    *   `SALT_LENGTH_BYTES = 16`
    *   `IV_LENGTH_BYTES = 12` (for AES-GCM)
    *   `AES_KEY_LENGTH_BITS = 256`

*   **Helper Functions (in `src/utils.ts` or directly in `crypto.ts`):**
    *   `stringToArrayBuffer(str: string): Uint8Array` (UTF-8 encode)
    *   `arrayBufferToString(buffer: ArrayBuffer): string` (UTF-8 decode)
    *   `arrayBufferToBase64(buffer: ArrayBuffer): string`
    *   `base64ToArrayBuffer(base64: string): ArrayBuffer`

*   **`deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey>`**
    *   Uses `crypto.subtle.importKey` for the password.
    *   Uses `crypto.subtle.deriveKey` with PBKDF2 algorithm.
        *   `name: "PBKDF2"`
        *   `hash: "SHA-256"`
        *   `iterations: PBKDF2_ITERATIONS`
        *   `salt: salt`
    *   Derived key usage: `["encrypt", "decrypt"]` for AES-GCM.
    *   `extractable: false`

*   **`encryptData(payload: DecryptedBackupPayload, passphrase: string): Promise<EncryptedBackupString>`**
    1.  Generate a random salt: `crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES))`.
    2.  Derive encryption key using `deriveKey(passphrase, salt)`.
    3.  Generate a random IV: `crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES))`.
    4.  Convert `payload` to JSON string: `JSON.stringify(payload)`.
    5.  Convert JSON string to `Uint8Array` (UTF-8): `stringToArrayBuffer()`.
    6.  Encrypt the data using `crypto.subtle.encrypt`:
        *   `name: "AES-GCM"`
        *   `iv: iv`
        *   `key: derivedKey`
        *   `data: dataToEncrypt (Uint8Array)`
    7.  Concatenate `salt`, `iv`, and `encryptedContent (ArrayBuffer)` into a single `Uint8Array`.
    8.  Convert the combined `Uint8Array` to a Base64 string: `arrayBufferToBase64()`.
    9.  Return the Base64 string.

*   **`decryptData(encryptedBackupString: EncryptedBackupString, passphrase: string): Promise<DecryptedBackupPayload>`**
    1.  Convert Base64 `encryptedBackupString` to `ArrayBuffer`: `base64ToArrayBuffer()`.
    2.  Convert `ArrayBuffer` to `Uint8Array`.
    3.  Extract `salt` (first `SALT_LENGTH_BYTES`), `iv` (next `IV_LENGTH_BYTES`), and `encryptedContent` (the rest).
    4.  Derive decryption key using `deriveKey(passphrase, salt)`.
    5.  Attempt to decrypt `encryptedContent` using `crypto.subtle.decrypt`:
        *   `name: "AES-GCM"`
        *   `iv: iv`
        *   `key: derivedKey`
        *   `data: encryptedContent`
    6.  Convert the decrypted `ArrayBuffer` to a string (UTF-8): `arrayBufferToString()`.
    7.  **Handle different formats:**
        *   Try `JSON.parse(decryptedString)`.
            *   If successful, validate that the parsed object has a `format` field matching one of the `BackupFormat` types. Cast to `DecryptedBackupPayload` and return.
            *   If `JSON.parse` fails (throws an error):
                *   Assume it's a legacy raw WIF string (the "Simple" format before it was JSON structured).
                *   Return `({ format: "Simple", wif: decryptedString } as SimpleWifBackupPayload)`.
        *   If any step fails (e.g., decryption error, invalid JSON structure after successful parse but no `format` field), throw an appropriate error (e.g., "Decryption failed: Invalid passphrase or corrupted data", "Invalid backup format").

### 3.3. Public API (`src/index.ts`)

```typescript
import { encryptData, decryptData } from './crypto';
import type { DecryptedBackupPayload, EncryptedBackupString } from './interfaces';

/**
 * Encrypts a backup payload object into an encrypted string.
 * @param payload The backup payload to encrypt.
 * @param passphrase The passphrase to use for encryption.
 * @returns A promise that resolves to the encrypted backup string (Base64 encoded).
 */
export async function encryptBackup(
  payload: DecryptedBackupPayload,
  passphrase: string
): Promise<EncryptedBackupString> {
  if (!payload || typeof payload !== 'object' || !payload.format) {
    throw new Error('Invalid payload: Payload must be an object with a format property.');
  }
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('Invalid passphrase: Passphrase must be a non-empty string.');
  }
  return encryptData(payload, passphrase);
}

/**
 * Decrypts an encrypted backup string back into a backup payload object.
 * Handles both new JSON-structured encrypted backups and legacy raw WIF encrypted backups.
 * @param encryptedString The encrypted backup string (Base64 encoded).
 * @param passphrase The passphrase used for encryption.
 * @returns A promise that resolves to the decrypted backup payload.
 * @throws Will throw an error if decryption fails or the format is invalid.
 */
export async function decryptBackup(
  encryptedString: EncryptedBackupString,
  passphrase: string
): Promise<DecryptedBackupPayload> {
  if (typeof encryptedString !== 'string' || encryptedString.length === 0) {
    throw new Error('Invalid encryptedString: Must be a non-empty string.');
  }
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('Invalid passphrase: Passphrase must be a non-empty string.');
  }
  return decryptData(encryptedString, passphrase);
}

// Re-export interfaces for library consumers
export * from './interfaces';
```

## 4. Development Steps

1.  **Define Interfaces:** Create `src/interfaces.ts` with all the payload and type definitions.
2.  **Implement Utility Functions:** Create `src/utils.ts` (or helpers in `crypto.ts`) for `stringToArrayBuffer`, `arrayBufferToString`, `arrayBufferToBase64`, `base64ToArrayBuffer`.
3.  **Implement `deriveKey`:** Implement the PBKDF2 key derivation logic in `src/crypto.ts`.
4.  **Implement `encryptData`:**
    *   Implement the encryption flow in `src/crypto.ts`.
    *   Write unit tests for `encryptData` (e.g., ensure output is a Base64 string, try with different payload types).
5.  **Implement `decryptData`:**
    *   Implement the decryption flow in `src/crypto.ts`.
    *   Crucially, implement the logic to try `JSON.parse` and fall back to treating the decrypted content as a raw WIF if parsing fails.
    *   Write unit tests for `decryptData`:
        *   Test decryption of `MasterBackupPayload`.
        *   Test decryption of `SingleIdentityBackupPayload`.
        *   Test decryption of `SimpleWifBackupPayload` (JSON structured).
        *   Test decryption of a legacy encrypted raw WIF (should result in a `SimpleWifBackupPayload` with just the `wif` field and `format: "Simple"`).
        *   Test with incorrect passphrases (should throw).
        *   Test with corrupted data (should throw).
6.  **Implement Public API:** Create `src/index.ts` and export the `encryptBackup` and `decryptBackup` functions and interfaces. Add basic input validation.
7.  **Write Integration Tests:** Test the end-to-end flow of encrypting and then decrypting various payloads.
8.  **Documentation:** Write a `README.md` for the library, explaining its purpose, API, and usage examples.
9.  **Build and Package:** (Details for `package.json` and build scripts will be handled during actual library setup).

## 5. Testing Strategy

*   **Unit Tests:**
    *   Test individual cryptographic helper functions.
    *   Test `deriveKey` separately if possible (mocking Web Crypto might be complex, focus on testing its usage within encrypt/decrypt).
    *   Test the core `encryptData` logic with various inputs.
    *   Test the core `decryptData` logic with various inputs, including all supported formats and error conditions (wrong password, corrupted data, legacy WIF).
*   **Integration Tests:**
    *   Test the full `encryptBackup` -> `decryptBackup` cycle for each payload type.
    *   Test that legacy WIF encryption (if you create a temporary function to simulate old encryption for testing purposes) can be decrypted by the new `decryptBackup`.

## 6. Considerations

*   **Error Handling:** Provide clear and informative error messages.
*   **Performance:** While security is paramount, be mindful of PBKDF2 iterations impacting performance, especially in browsers. `100,000` is a common baseline; adjust if needed after testing.
*   **Environment Compatibility:** Ensure Web Crypto API usage is compatible with target browsers and Node.js versions (Node.js has `globalThis.crypto` available in recent versions). Polyfills might be needed for older environments, but aim for modern standards.

## 7. Future Enhancements

*   **Heimdal Backup Support:** Investigate and implement support for importing/decrypting Heimdal backup formats. Heimdal backups appear as a data URI with a Base64 encoded payload, for example:
    `data:application/heimdal;base64,QklFMQKxMooP1mUTFPNXght/sNmTSUp9DrjspdICACBHl2jkiFAgtgxtrIzDXJL0oBhj+D9kCFxw0cFZE7R4y1RxCrD86+iZQRoFLLhImYud5RKE6yvEhAqvi1tMNO+VciiCN0VxvC9R0YpLZ+epvrA8it5rK9FpY4UpdiCMgDRNMuHy/mw/8SNcJklqUXjETpbTitv1r+oCW/5vJeU4zRDj5PPapheHHY+NBrwxJPu3333hrC3J1vwjHIV2H1WEtbtHvP1Rwlpo+yOiNCTqCH392zfp1TmM2UZR6s4HNk4OvNyUrcsEB3pd9qz7e5yNFvAh7Pu541IwvLMbuGRfIBbii3YmsBcZ6pm9bIUYVuucfq0LLXfWl3tRa4iU8LmJGIVDFIdoxU2AeLiVq5a5/HAPwtEKIZR/R88rTJw4HLAwsWbbL+AZJdeRRk9wETAArG29rv8BaFuQzsYxGWhPsX5bCakLiAWixLBojXhNLtENqXvupjOYhdz+QNwSY2Aie+BqKFdcorkiDuza4ICo2yCpLe9ZcHEiWeu5mjrvWuYKlfTKXw62Qol6vZT8voXxiYroSMBFfFCtfi1m+AkBmNF2UigS0NQ4/f8RzodUIewGoJAX2lh5A/J7PEk0som+NerssbyTlOMFmDZUDbvjyjxIlrYn8u93d8dtqOhMZd0748gUjUdfTNEJ+xAF35Iwv8Zinh5Cwa/SKXhuUsl5ZVl1rwoAgL4kLABJ7yUA+jbySX/RrCnESJgmXpGqp1Fx2DkWvaUD+tpHfBGQGIsuIB9xPvZ/DFiSDj5AjyY5DEUboNkQa7CL+bgylPVH4BYaQZh3gT4+vnLccTZ/FJkAEv+vR6vU2qAyeP8mLSXl7Cn2HDkNztWSv4mURPqPyDuXICMzDaSuLQtypBdij46xPhiZ7KPMKqLVHqXde5jk+okETH9fIsQLcM9LTT6mlryIkEYEKcfoTPZJmkpjtJXqzeo5YjAkLUrPEgMRVhHiXjf+wvzQ+QXx0VPGEq+GYoUZVZNyudZ1/bs3IVlKRP8MY6obVuczjaYrAMihyCaNkWMhn7Fg5bjYD9P3CNdDA/x7THwclQs=`
    The specifics of the internal binary structure once Base64 decoded would need to be understood to extract meaningful data (e.g., WIF, xprv, mnemonic).

This plan provides a comprehensive guide for the library's implementation. You can tackle these sections incrementally. Good luck! 