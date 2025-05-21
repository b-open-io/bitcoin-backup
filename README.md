# `bitcoin-backup`

A robust TypeScript library and CLI tool for managing and securing sensitive data backups, such as private keys, mnemonics, or any structured data. While it can be used for Bitcoin-related identity backups, its core encryption and data handling are **chain-agnostic**, making it suitable for a wide variety of blockchain or cryptographic key backups.

## Features

*   **Chain-Agnostic Core:** Securely encrypt and decrypt WIF private keys, xprv/mnemonic phrases for HD wallets, or custom data structures from any blockchain (e.g., Ethereum, Solana, etc.) or cryptographic application.
*   **Strong Encryption:** Secures backup data using AES-GCM with PBKDF2 key derivation.
*   **Multiple Backup Formats:** While originally designed with Bitcoin BAP in mind (supporting `BapMasterBackup`, `BapMemberBackup`), the flexible `WifBackup` and `OneSatBackup` (example for custom structured data) demonstrate its adaptability. The type of backup is inferred from payload structure.
*   **Handles Unencrypted Data:** Easily encrypt existing unencrypted backup objects (e.g., from JSON files).
*   **Legacy Support:** Capable of decrypting older, raw WIF-string based encrypted backups (that were encrypted using 100,000 PBKDF2 iterations).
*   **Type-Safe:** Fully written in TypeScript with clear interfaces for payloads.
*   **Environment Agnostic:** Designed to work in both Node.js and browser environments.
*   **Automatic Timestamps:** Adds a `createdAt` timestamp (ISO 8601) to payloads during encryption if not already provided.

## Security

*   **PBKDF2 Iterations:**
    *   **Recommended:** New backups are encrypted using **600,000** PBKDF2-SHA256 iterations by default.
    *   **Legacy Decryption:** The library can automatically decrypt older backups that were encrypted using **100,000** iterations.
*   **Passphrase Length:** A minimum passphrase length of **8 characters** is enforced during encryption.

## Installation

```bash
bun add bitcoin-backup @bsv/sdk
# or
npm install bitcoin-backup @bsv/sdk
# or
yarn add bitcoin-backup @bsv/sdk
```

**Note on `@bsv/sdk`:** This library uses utility functions from `@bsv/sdk` for operations like string-to-buffer conversions. Therefore, `@bsv/sdk` is a required peer dependency and must be installed alongside `bitcoin-backup` for it to function correctly. While the core backup logic is chain-agnostic, this specific utility usage ties its runtime to `@bsv/sdk`.

## API

### Types

```typescript
// Backup type is inferred from the payload structure.

export interface BapMasterBackup {
  ids: string;          // Encrypted data from bsv-bap's bap.exportIds()
  xprv: string;         // Master extended private key
  mnemonic: string;     // BIP39 mnemonic phrase
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

export interface BapMemberBackup {
  wif: string;          // Private key in WIF format
  id: string;           // BAP ID or other identifier
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

export interface WifBackup {
  wif: string;
  label?: string;               // User-defined label (optional)
  createdAt?: string;           // ISO 8601 timestamp (populated by encryptBackup if a new WifBackup object is passed)
}

export interface OneSatBackup {
  ordPk: string;        // Ordinals Private Key WIF
  payPk: string;        // Payment Private Key WIF
  identityPk: string;   // Identity Private Key WIF (associated with a user identity)
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

export type DecryptedBackupPayload =
  | BapMasterBackup
  | BapMemberBackup
  | WifBackup
  | OneSatBackup;

// Represents the final encrypted string, typically Base64 encoded
export type EncryptedBackupString = string;
```

### Functions

#### `encryptBackup(payload: DecryptedBackupPayload, passphrase: string): Promise<EncryptedBackupString>`

Encrypts a backup payload object into an encrypted string.

*   `payload`: The `DecryptedBackupPayload` object to encrypt. The type of backup is inferred from its structure (presence of `xprv`, `wif` and `id`, just `wif`, or `ordPk`, `payPk`, and `identityPk`). If `createdAt` is not provided, it will be added automatically.
*   `passphrase`: The passphrase to use for encryption. Must be a non-empty string of at least 8 characters.
*   `iterations` (optional): The number of PBKDF2 iterations to use. Defaults to `RECOMMENDED_PBKDF2_ITERATIONS` (600,000).
*   Returns: A promise that resolves to the Base64 encoded encrypted backup string.
*   Throws: An error if the payload structure is unrecognized/invalid or passphrase is invalid.

#### `decryptBackup(encryptedString: EncryptedBackupString, passphrase: string): Promise<DecryptedBackupPayload>`

Decrypts an encrypted backup string back into a backup payload object. Handles both new JSON-structured encrypted backups (inferring type from structure) and legacy raw WIF encrypted backups.

*   `encryptedString`: The Base64 encoded encrypted backup string. Must be a non-empty string.
*   `passphrase`: The passphrase used for encryption. Must be a non-empty string.
*   `attemptIterations` (optional): A specific iteration count or an array of counts to try. If undefined, defaults to trying `RECOMMENDED_PBKDF2_ITERATIONS` (600,000) and then `LEGACY_PBKDF2_ITERATIONS` (100,000).
*   Returns: A promise that resolves to the `DecryptedBackupPayload`.
    *   For JSON-structured backups, the type (`BapMasterBackup`, `BapMemberBackup`, `WifBackup`, or `OneSatBackup`) is inferred based on the decrypted object's properties:
        *   `xprv`, `ids`, `mnemonic` present => `BapMasterBackup`
        *   `wif`, `id` present (and no `xprv`) => `BapMemberBackup`
        *   `ordPk`, `payPk`, `identityPk` present => `OneSatBackup`
        *   `wif` present (and no `xprv`, no `id`, no `ordPk`) => `WifBackup`
*   Throws: An error if decryption fails (e.g., invalid passphrase, corrupted data) or if a parsed JSON structure does not match a known backup payload structure.
*   **Legacy WIF Handling**: If decryption of `encryptedString` results in a raw WIF string (i.e., it's not JSON), `decryptBackup` will return a `WifBackup` like: `{ wif: "decryptedWifString" }`. The `createdAt` and `label` fields will not be present in this case.

## Usage Examples

```typescript
import {
  encryptBackup,
  decryptBackup,
  BapMasterBackup,
  BapMemberBackup,
  WifBackup,
  OneSatBackup,
  DecryptedBackupPayload,
  EncryptedBackupString
} from 'bitcoin-backup';

const passphrase = 'supersecretpassword123';

async function main() {
  // Example 1: Encrypting a Master Backup
  const masterBackup: BapMasterBackup = {
    ids: "serializedBapIdsString...", // Replace with actual serialized IDs
    xprv: "xprv9s21ZrQH143K3QjYCBAd...", // Replace with actual master extended private key
    mnemonic: "word1 word2 word3 ... word12", // Replace with actual mnemonic
    label: "My Main HD Wallet"
    // createdAt will be added by encryptBackup
  };

  try {
    const encryptedMaster: EncryptedBackupString = await encryptBackup(masterBackup, passphrase);
    console.log('Encrypted Master Backup:', encryptedMaster);

    const decryptedMaster: DecryptedBackupPayload = await decryptBackup(encryptedMaster, passphrase);
    console.log('Decrypted Master Backup:', decryptedMaster);
    // Type guard or check properties to safely access specific fields
    if ('mnemonic' in decryptedMaster) { // Example of a type guard for BapMasterBackup
      console.log('Master Mnemonic:', decryptedMaster.mnemonic);
      console.log('Master Label:', decryptedMaster.label);
    }

  } catch (error) {
    console.error('Master Backup Error:', error.message);
  }

  console.log('\n--- --- ---\n');

  // Example 2: Encrypting a Single Identity Backup
  const memberBackup: BapMemberBackup = {
    wif: "L1uyy5qTuGrPp5kKs9Dq32...", // Replace with actual WIF
    id: "someIdentityKeyString",    // Replace with actual ID
    label: "Alice's Main Bitcoin Identity"
  };

  try {
    const encryptedSingle: EncryptedBackupString = await encryptBackup(memberBackup, passphrase);
    console.log('Encrypted Single Identity Backup:', encryptedSingle);

    const decryptedSingle: DecryptedBackupPayload = await decryptBackup(encryptedSingle, passphrase);
    console.log('Decrypted Single Identity Backup:', decryptedSingle);
    if ('id' in decryptedSingle && 'wif' in decryptedSingle && !('xprv' in decryptedSingle)) { // Example of a type guard for BapMemberBackup
      console.log('Member ID Label:', decryptedSingle.label);
    }
  } catch (error) {
    console.error('Single Identity Backup Error:', error.message);
  }

  console.log('\n--- --- ---\n');

  // Example 3: Encrypting a Simple WIF Backup
  const wifBackup: WifBackup = {
    wif: "KwDiBf89QgGbjEhKnhXJuH7...", // Replace with actual WIF
    label: "Old Savings Wallet"
    // createdAt will be added by encryptBackup if not present
  };

  try {
    const encryptedSimple: EncryptedBackupString = await encryptBackup(wifBackup, passphrase);
    console.log('Encrypted Simple WIF Backup:', encryptedSimple);

    const decryptedSimple: DecryptedBackupPayload = await decryptBackup(encryptedSimple, passphrase);
    console.log('Decrypted Simple WIF Backup:', decryptedSimple);
    // Check for wif and absence of id/xprv for WifBackup
    if ('wif' in decryptedSimple && !('id' in decryptedSimple) && !('xprv' in decryptedSimple)) {
      console.log('WIF Backup Label:', decryptedSimple.label);
      console.log('WIF:', decryptedSimple.wif);
      if (decryptedSimple.createdAt) {
        console.log('Created At:', decryptedSimple.createdAt);
      }
    }
  } catch (error) {
    console.error('Simple WIF Backup Error:', error.message);
  }

  console.log('\n--- --- ---\n');

  // Example 4: Decrypting a legacy raw WIF backup
  // This is a hypothetical encrypted string that, when decrypted with the passphrase,
  // would result directly in a WIF string (e.g., "Kxotg5dKx1PKvb5fJ1zQxY2nQ5dG8fL9m...")
  // For testing, you would need a string that was encrypted this way (e.g., using an older tool that just encrypted the WIF string directly).
  // Let's assume `legacyEncryptedWif` is such a string that, when decrypted, yields only the WIF.
  const legacyEncryptedWif: EncryptedBackupString = "BASE64_ENCODED_RAW_ENCRYPTED_WIF_STRING"; // Replace with a real one for testing

  try {
    console.log('\nAttempting to decrypt legacy WIF backup...');
    const decryptedLegacy: DecryptedBackupPayload = await decryptBackup(legacyEncryptedWif, passphrase);
    console.log('Decrypted Legacy WIF Backup:', decryptedLegacy);
    // For legacy, it will be WifBackup with only wif.
    if ('wif' in decryptedLegacy && !('id' in decryptedLegacy) && !('xprv' in decryptedLegacy) && !decryptedLegacy.label) {
      console.log('Legacy WIF:', decryptedLegacy.wif);
    }
  } catch (error) {
    console.error('Legacy WIF Backup Decryption Error:', (error as Error).message);
  }

  console.log('\n--- --- ---\n');

  // Example 5: Encrypting an Existing Unencrypted JSON Backup
  // Assume `unencryptedBackupJsonString` is read from a file or obtained elsewhere
  const unencryptedBackupJsonString = `{
    "wif": "L52NqJjXz9Y1TjE7S9U8pZ5rA3sH6VcF5xR4gD2zBnK8sJ7fP9qW",
    "id": "someBAPIDStringHere",
    "label": "Imported Wallet"
  }`;

  try {
    const unencryptedPayload: BapMemberBackup = JSON.parse(unencryptedBackupJsonString);
    
    // You can now encrypt this payload
    const encryptedImported: EncryptedBackupString = await encryptBackup(unencryptedPayload, passphrase);
    console.log('Encrypted Imported Backup:', encryptedImported);

    // And decrypt it back
    const decryptedImported: DecryptedBackupPayload = await decryptBackup(encryptedImported, passphrase);
    console.log('Decrypted Imported Backup:', decryptedImported);

    if ('id' in decryptedImported && decryptedImported.id === unencryptedPayload.id) {
      console.log('Successfully encrypted and decrypted an existing unencrypted backup.');
      console.log('Imported Label:', decryptedImported.label);
    }
  } catch (error) {
    console.error('Error handling unencrypted JSON backup:', (error as Error).message);
  }

  console.log('\n--- --- ---\n');

  // Example 6: Encrypting a OneSat Backup
  const oneSatBackup: OneSatBackup = {
    ordPk: "L1uyy5qTuGrPp5kKs9Dq32...", // Replace with actual ordPk
    payPk: "KwDiBf89QgGbjEhKnhXJuH7...", // Replace with actual payPk
    identityPk: "L52NqJjXz9Y1TjE7S9U8pZ5rA3sH6VcF5xR4gD2zBnK8sJ7fP9qW", // Replace with actual identityPk
    label: "Alice's Main Bitcoin Identity"
  };

  try {
    const encryptedOneSat: EncryptedBackupString = await encryptBackup(oneSatBackup, passphrase);
    console.log('Encrypted OneSat Backup:', encryptedOneSat);

    const decryptedOneSat: DecryptedBackupPayload = await decryptBackup(encryptedOneSat, passphrase);
    console.log('Decrypted OneSat Backup:', decryptedOneSat);
    if ('ordPk' in decryptedOneSat && 'payPk' in decryptedOneSat && 'identityPk' in decryptedOneSat) {
      console.log('OneSat Backup Label:', decryptedOneSat.label);
    }
  } catch (error) {
    console.error('OneSat Backup Error:', error.message);
  }
}

main().catch(console.error);
```

## CLI Tool (`bbackup`)

This library includes a command-line interface (CLI) tool named `bbackup` for encrypting, decrypting, and upgrading backup files directly from your terminal. If the library is installed globally (e.g., `npm install -g bitcoin-backup` or `bun install -g bitcoin-backup`), you can use the `bbackup` command directly. Otherwise, you can run it via `bun dist/cli/bbackup.js <command> ...` from the project root after building.

**General Usage:**

```bash
bbackup <command> <inputFile> -p "your-passphrase" [options]
```

**Common Options:**

*   `<inputFile>`: The primary input file for the command.
*   `-p, --password <password>`: The passphrase (required for all commands).
*   `-o, --output <outputFile>`: Specifies the output file path (optional for most commands, with sensible defaults).

For detailed options for each command, use `bbackup <command> --help`.

### 1. Encrypt (`enc`)

Encrypts a JSON file containing a `DecryptedBackupPayload`.

**Usage:**

```bash
bbackup enc <inputFile.json> -p "your-passphrase" [-o <outputFile.bep>] [-t <iterations>]
```

*   `-t, --iterations <count>` (Optional): Number of PBKDF2 iterations. Defaults to 600,000.
*   Default output: `<inputFile_encrypted.bep>`.

**Example:**

```bash
# Encrypt my_wallet.json with a password
bbackup enc ./my_wallet.json -p "!S3cureP@ssw0rd"

# Encrypt with a specific output path and iterations
bbackup enc ./decrypted/main.json -p "s3cr3t" -o ./encrypted/main.bep -t 100000
```

### 2. Decrypt (`dec`)

Decrypts an encrypted backup file.

**Usage:**

```bash
bbackup dec <inputFile.bep> -p "your-passphrase" [-o <outputFile.json>]
```

*   If `-o` is omitted, the decrypted JSON is printed to the console.

**Example:**

```bash
# Decrypt my_wallet_encrypted.bep and print to console
bbackup dec ./my_wallet_encrypted.bep -p "!S3cureP@ssw0rd"

# Decrypt and save to a file
bbackup dec ./encrypted/old_backup.bep -p "oldPass123" -o ./decrypted/old_recovered.json
```

### 3. Upgrade (`upg`)

Upgrades an encrypted backup file to use the recommended PBKDF2 iterations (600,000).

**Usage:**

```bash
bbackup upg <inputFile.bep> -p "your-passphrase" [-o <outputFile_upgraded.bep>]
```

*   Default output: `<inputFile_basename>_upgraded.<ext>`.

**Example:**

```bash
# Upgrade my_legacy_backup.bep
bbackup upg ./legacy.bep -p "myOldWeakPassword"

# Upgrade and specify a different output location
bbackup upg ./archive/backup_v1.bep -p "archivePass" -o ./upgraded/backup_v1_new.bep
```

## Build Process

```bash
bun run build
```