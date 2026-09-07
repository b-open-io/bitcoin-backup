# `bitcoin-backup`

[![npm version](https://badge.fury.io/js/bitcoin-backup.svg)](https://badge.fury.io/js/bitcoin-backup)
[![Build Status](https://github.com/opldotdev/bitcoin-backup/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/opldotdev/bitcoin-backup/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A robust TypeScript library and CLI tool for managing and securing sensitive data backups, such as private keys, mnemonics, or any structured data.

## Purpose

`bitcoin-backup` provides a secure and straightforward way to encrypt and decrypt structured backup data, primarily targeting cryptographic keys and identity information. While its core is chain-agnostic, it includes utilities and examples relevant to Bitcoin and BAP (Bitcoin Attestation Protocol) identities.

## Quick Start

### Library Usage
```bash
bun add bitcoin-backup @bsv/sdk
# or
npm install bitcoin-backup @bsv/sdk
# or
yarn add bitcoin-backup @bsv/sdk
```

```typescript
import { encryptBackup, decryptBackup, WifBackup } from 'bitcoin-backup';

async function run() {
  const myWif: WifBackup = { wif: "L1uyy5qTuGrPp5kKs9Dq32KdXz22hJ1L8cDPexN17v2sAn8XGjY5" }; // Demo only - replace
  const passphrase = "your-strong-password-here"; // Use a strong, unique passphrase

  try {
    const encrypted = await encryptBackup(myWif, passphrase);
    console.log("Encrypted:", encrypted);

    const decrypted = await decryptBackup(encrypted, passphrase);
    console.log("Decrypted:", decrypted);
  } catch (error) {
    console.error("Backup error:", error);
  }
}
run();
```

### CLI Usage (bbackup)
```bash
# Ensure the CLI is built (see Build section) or installed globally
# Example: Encrypt a JSON file containing a WifBackup object
# Create wallet.json: echo '{"wif":"L1uyy5qTuGrPp5kKs9Dq32KdXz22hJ1L8cDPexN17v2sAn8XGjY5"}' > wallet.json

npx bbackup enc wallet.json -p "your-strong-password-here" -o wallet.bep
npx bbackup dec wallet.bep -p "your-strong-password-here"
```
(See full CLI documentation below)


## Features

*   **Chain-Agnostic Core:** Securely encrypt and decrypt WIF private keys, xprv/mnemonic phrases for HD wallets, or custom data structures from any blockchain or cryptographic application.
*   **Envelope v2 key slots:** Seal one encrypted file for multiple credentials (passphrase slots plus device-bound P-256 slots) while existing `.bep` files keep decrypting unchanged.
*   **Strong Encryption:** Secures backup data using AES-256-GCM with PBKDF2 key derivation (see Security Model).
*   **Multiple Backup Formats:** Supports various backup structures like `BapMasterBackup`, `BapMemberBackup`, `WifBackup`, `OneSatBackup`, and `VaultBackup`. The type of backup is inferred from payload structure. (See [API Documentation](./API.md) for full type details).
*   **Handles Unencrypted Data:** Easily encrypt existing unencrypted backup objects.
*   **Legacy Support:** Capable of decrypting older, raw WIF-string based encrypted backups.
*   **Type-Safe:** Fully written in TypeScript.
*   **Environment Agnostic:** Designed to work in Node.js and browser environments.
*   **Automatic Timestamps:** Adds a `createdAt` timestamp (ISO 8601) to payloads during encryption if not already provided.

## Security Model

This library employs AES-256-GCM for authenticated encryption. The encryption key is derived from the user-provided passphrase using PBKDF2 (Password-Based Key Derivation Function 2) with SHA-256.

*   **PBKDF2 Iterations:**
    *   **Recommended:** New backups are encrypted using **600,000** PBKDF2-SHA256 iterations by default. This number is chosen as a balance between security and performance, aligning with general industry guidance (e.g., see [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) recommendations on iterated hashing for memorized secrets).
    *   **Legacy Decryption:** The library can automatically decrypt older backups that were encrypted using **100,000** iterations.
*   **Passphrase Length:** A minimum passphrase length of **8 characters** is enforced. For high-value secrets, consider using passphrases of 12 characters or more, aligning with general recommendations such as those from [OWASP (Password Storage Cheat Sheet)](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). The choice of 8 characters is a minimum baseline.
*   **Salt and IV:** Unique, cryptographically random salts (16 bytes) and initialization vectors (IVs, 12 bytes for AES-GCM) are generated for each encryption operation to ensure that identical payloads with the same passphrase encrypt to different ciphertexts.

## API Overview

The primary API consists of two main functions: `encryptBackup` and `decryptBackup`.

Detailed type definitions for `BapMasterBackup`, `BapMemberBackup`, `WifBackup`, `OneSatBackup`, `VaultBackup`, and `DecryptedBackupPayload` can be found in [./API.md](./API.md).

### `encryptBackup(payload: DecryptedBackupPayload, passphrase: string, iterations?: number): Promise<EncryptedBackupString>`

Encrypts a backup payload object.
*   `payload`: The `DecryptedBackupPayload` object. Type is inferred.
*   `passphrase`: Encryption passphrase (min 8 characters).
*   `iterations` (optional): PBKDF2 iterations. Defaults to 600,000.
*   Returns: Base64 encoded encrypted string.

### `decryptBackup(encryptedString: EncryptedBackupString, passphrase: string): Promise<DecryptedBackupPayload>`

Decrypts an encrypted backup string.
*   `encryptedString`: Base64 encoded encrypted backup.
*   `passphrase`: Decryption passphrase.
*   Returns: The `DecryptedBackupPayload`. Type is inferred.
*   Handles legacy WIFs and tries recommended then legacy iterations.
*   Transparently opens v2 envelopes via their pbkdf2 slots; v1 files are unchanged.

### Envelope v2 (`sealBackup` / `openBackup`)

```typescript
const encrypted = await sealBackup(payload, [
  { type: 'pbkdf2', id: 'main', passphrase },
  { type: 'device-p256', id: 'phone', publicKey: devicePubHex },
]);
const decrypted = await openBackup(encrypted, { passphrase });
// or: await openBackup(encrypted, { slotId: 'phone', unwrap: async (wrapped) => hardwareUnwrap(wrapped) });
```

Helpers: `inspectEnvelope`, `isEnvelopeV2`, `addSlot`, `removeSlot` (refuses the last slot), `rewrapBackup` (new content key), `eciesEncrypt`/`eciesDecrypt`. Optional `derivation` descriptors on key payloads are copied to the v2 header for locked inspection.

*(For more detailed examples and advanced usage, please refer to the `test/` directory or consider creating an `examples/` directory in your project.)*

## CLI Tool (`bbackup`)

The `bitcoin-backup` library includes a command-line interface (CLI) tool named `bbackup` for easy file encryption, decryption, and upgrading of backup files.

### Installation (CLI)

The CLI is built as part of the project (see `Build` section). Once built, you can run it directly (e.g., `node dist/cli/bbackup.js`) or, if the package is installed globally or via `npx`, you can use `bbackup`.

```bash
# Assuming package is published and installable, or using npx with local build:
npx bbackup --help
```

### Commands

| Command                       | Purpose                                                                 | Example                                                              |
| ----------------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `bbackup enc <inputFile>`     | Encrypts a JSON input file.                                             | `bbackup enc wallet.json -p "secret" -o wallet.bep`                  |
| `bbackup dec <inputFile>`     | Decrypts a `.bep` file.                                                 | `bbackup dec wallet.bep -p "secret" -o wallet.json`                  |
| `bbackup upg <inputFile>`     | Upgrades an encrypted file to recommended PBKDF2 iterations.          | `bbackup upg old_wallet.bep -p "secret" -o upgraded_wallet.bep`      |
| `bbackup enc <input> --device-pubkey <hex>` | Seal a v2 envelope to the passphrase and one or more device keys. | `bbackup enc wallet.json -p "secret" --device-pubkey 04ab…` |
| `bbackup slot add <file>` | Add a pbkdf2 or device slot, unlocking with `-p`.               | `bbackup slot add wallet.bep -p "secret" --device-pubkey 04ab…` |
| `bbackup slot remove <file> <id>` | Remove a slot; refuses the last one.                     | `bbackup slot remove wallet.bep device-1 -p "secret"` |
| `bbackup slots <file>`        | Prints envelope version and key slots as JSON (no passphrase).        | `bbackup slots wallet.bep`                                           |

**Common Options:**
*   `-p, --password <password>`: (Required) The passphrase for encryption/decryption.
*   `-o, --output <outputFile>`: (Optional) Path for the output file. Defaults are sensible (e.g., `<input>.bep` for encrypt, `<input>.json` for decrypt).
*   `-t, --iterations <iterations>`: (Optional) PBKDF2 iterations: output count for `enc`, input count for `dec` and `upg`. Without it, readers try 600,000 then 100,000. `upg` always writes 600,000. Custom counts must be supplied when reading those files.

For detailed options for each command, run:
```bash
bbackup enc --help
bbackup dec --help
bbackup upg --help
```
*(Sample output or screenshots of `--help` could be added here for enhanced clarity).*

### Touch ID Password Cache (macOS Apple Silicon)

On supported hardware, `bbackup` can cache your passphrase in the Secure Enclave so you don't have to type it every time.

**First decrypt -- password required, gets cached:**

```
bbackup dec wallet.bep -p "my-password" --touchid
```

**Every time after -- just Touch ID:**

```
bbackup dec wallet.bep --touchid
```

**Works with all commands:**

```
bbackup enc backup.json -p "my-password" --touchid -o wallet.bep
bbackup dec wallet.bep --touchid
bbackup upg old.bep --touchid
bbackup forget wallet.bep
```

**Important:**

- Cached passwords are hardware-bound to your Mac's Secure Enclave
- The `.bep` file format is unchanged -- backups remain portable
- Touch ID is a convenience layer, not a replacement for your passphrase
- Without `--touchid`, all commands work exactly as before
- Requires `@1sat/vault` package: `bun add @1sat/vault`
- Requires macOS on Apple Silicon (arm64)

## Installation (Library)

```bash
bun add bitcoin-backup @bsv/sdk
# or
npm install bitcoin-backup @bsv/sdk
# or
yarn add bitcoin-backup @bsv/sdk
```

**Note on `@bsv/sdk` Peer Dependency:**
This library uses utility functions (specifically for string-to-byte and byte-to-Base64 conversions) from `@bsv/sdk`. Therefore, `@bsv/sdk` is a **required peer dependency**.

*   **Why?** While the core cryptographic logic of `bitcoin-backup` is chain-agnostic and doesn't rely on Bitcoin-specific protocols, `@bsv/sdk` provides efficient and well-tested buffer manipulation utilities. Re-implementing these would add unnecessary complexity and potential for errors. Using a peer dependency allows `bitcoin-backup` to remain lightweight and leverage an existing robust library for these common operations.
*   **Implication:** You must include `@bsv/sdk` in your project's dependencies. For more information on peer dependencies, see the [npm documentation](https://nodejs.org/es/blog/npm/peer-dependencies/).

The `OneSatBackup` interface is provided as an example of how you can define custom structured data for backup. It is treated as a first-class type by the inference logic if its characteristic properties (`ordPk`, `payPk`, `identityPk`) are present in a payload.

The term "BAP" (Bitcoin Attestation Protocol) is used in type names like `BapMasterBackup` and in descriptions.

## Build

To build the library and the CLI tool from source:
```bash
bun install
bun run build
```
This will output a `dist/` directory containing:
*   `dist/lib/`: ESM, CJS, and type declaration files for the library.
*   `dist/cli/`: The executable `bbackup.js` CLI tool.

## Semantic Versioning

This project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## Development

```bash
bun lint          # Check code quality
bun lint:fix      # Auto-fix safe issues  
bun lint:unsafe   # Auto-fix all issues
bun check         # Lint + test + build
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request. (A more detailed `CONTRIBUTING.md` could be added).

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Backup Format Types

### Master Backup
The `BapMasterBackup` interface supports both modern Type 42 key derivation and legacy BIP32 formats:

**Type 42 Format (Recommended):**
```typescript
interface BapMasterBackup {
  ids: string;          // Encrypted BAP identity data
  rootPk: string;    // Master private key in WIF format
  label?: string;       // Optional user label
  createdAt?: string;   // ISO 8601 timestamp
}
```

**Legacy Format (BIP32):**
```typescript
interface BapMasterBackup {
  ids: string;          // Encrypted BAP identity data
  xprv: string;         // Master extended private key
  mnemonic: string;     // BIP39 mnemonic phrase
  label?: string;       // Optional user label
  createdAt?: string;   // ISO 8601 timestamp
}
```

### Other Supported Formats
- **BapMemberBackup**: Individual member key backups
- **WifBackup**: Simple WIF key backups
- **OneSatBackup**: 1Sat ordinals wallet backups
- **VaultBackup**: Generic encrypted key vault backups (compatible with VSCode Bitcoin Extension and other key management systems)

## Usage

### Basic Usage

```typescript
import { encryptBackup, decryptBackup, type BapMasterBackup } from 'bitcoin-backup';

// Type 42 backup (recommended)
const type42Backup: BapMasterBackup = {
  ids: 'encrypted-bap-data',
  rootPk: 'L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6',
  label: 'My Main Wallet'
};

// Legacy backup (still supported)
const legacyBackup: BapMasterBackup = {
  ids: 'encrypted-bap-data',
  xprv: 'xprv9s21ZrQH143K...',
  mnemonic: 'abandon abandon abandon...'
};

// Encrypt any backup format
const encrypted = await encryptBackup(type42Backup, 'your-secure-passphrase');

// Decrypt automatically detects format
const decrypted = await decryptBackup(encrypted, 'your-secure-passphrase');
```

### Type 42 Key Derivation
Type 42 provides enhanced privacy through deterministic key derivation between parties:

```typescript
import { PrivateKey } from '@bsv/sdk';

// Example: Alice and Bob derive shared keys using Type 42
const alice = PrivateKey.fromWif('L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6');
const bobPub = PrivateKey.fromRandom().toPublicKey();

// Alice derives a child key for a specific purpose/invoice
const invoiceNumber = 'payment-2024-001';
const derivedKey = alice.deriveChild(bobPub, invoiceNumber);
```

## Advantages of Type 42 vs Legacy

| Feature | Type 42 | Legacy (BIP32) |
|---------|---------|----------------|
| **Privacy** | High - Private key derivation | Limited - Public derivation possible |
| **Key Space** | Unlimited invoice numbers | Limited to 2^31 child keys |
| **Flexibility** | Custom invoice numbering | Sequential integer paths only |
| **Shared Derivation** | Yes - Secure shared key universes | No |
| **Format Detection** | Automatic via `rootPk` field | Automatic via `xprv` field |

## CLI Usage

```bash
# Encrypt a backup file
bbackup enc input.json -p "passphrase" -o encrypted.backup

# Decrypt a backup file  
bbackup dec encrypted.backup -p "passphrase" -o decrypted.json
```

## Security Features

- **AES-GCM Encryption**: 256-bit keys with authenticated encryption
- **PBKDF2 Key Derivation**: 600,000 iterations (configurable)
- **Secure Random**: Cryptographically secure salt and IV generation
- **Legacy Support**: Automatic detection and handling of older formats

## API Reference

### Functions

- `encryptBackup(payload, passphrase, iterations?)`: Encrypt any supported backup format
- `decryptBackup(encrypted, passphrase, iterations?)`: Decrypt and auto-detect format

### Types

- `BapMasterBackup`: Type 42 master backup format
- `BapMemberBackup`: Member key backup format
- `WifBackup`: Simple WIF backup format
- `OneSatBackup`: 1Sat ordinals backup format
- `VaultBackup`: Encrypted key vault backups

## Migration Guide

To migrate from legacy to Type 42 format:

1. **Extract your master key**: Convert XPRV to WIF format using BSV SDK
2. **Choose a key name**: Select a meaningful identifier for your master key
3. **Create new backup**: Use `BapMasterBackup` interface
4. **Test thoroughly**: Verify encryption/decryption works as expected

## Sigma Peer Profiles seed backups

`SigmaSeedBackup` is a separate member of `DecryptedBackup`, never a
`BapMasterBackup`. Use `isSigmaSeedBackup(value)` to validate its structure;
`getBackupType` returns `SigmaSeed`. Existing encryption and legacy key formats
are unchanged. Older readers reject this envelope as an unknown JSON structure.

```ts
const backup: SigmaSeedBackup = {
  format: 'sigma-seed',
  version: 1,
  mnemonic,
  profiles: [{ index: 0, bapId }],
  nextProfileIndex: 1,
  createdAt: Date.now(),
};
const ciphertext = await encryptBackup(backup, backupPassword);
```

Version 1 permanently defines BRC157 peer profiles and an empty BIP39 passphrase; `backupPassword` protects the encrypted
file and is independent of that policy. Profiles are hardened peers at
`m/0'/N'`, where `N` is the profile index. Optional profile `metadata` must be a
JSON object, and the envelope supports an optional string `label`.

Validation requires version 1, 12/15/18/21/24 mnemonic word counts, a nonempty profile list,
unique indices and BAP
IDs, and a safe integer `nextProfileIndex` greater than every used index. All
profile indices are in 0–2147483647; `nextProfileIndex` may be 2147483648
to record exhaustion, at which point allocation must stop. `createdAt` is a
nonnegative safe integer timestamp in milliseconds.
The mnemonic word count encodes its entropy length; redundant `scheme`,
`entropyBytes`, and `passphrasePolicy` fields are rejected as unknown.
Unknown fields and mixed legacy discriminators (including top-level `rootPk`,
`xprv`, `wif`, or `ids`) are rejected. Numeric timestamps are preserved, including
zero. Legacy formats retain their existing ISO timestamp behavior.

This package checks structure and word count only. The Sigma seed module must
verify the mnemonic checksum, derive keys, and verify BAP ID bindings before
using a restored seed. This format does not migrate or rekey existing accounts.

The optional `inventoryComplete: false` marks phrase-only recovery with an unknown full profile inventory. Absence means complete; `true` and other values are invalid. For partial inventories, `nextProfileIndex` is only a structural bound over listed profiles, not proof that the next index is unused. Consumers must reconcile a complete backup before appending or deleting profiles or replacing a complete cloud inventory.

### Seed backups in the CLI

The same `enc`, `dec`, and `upg` commands accept complete and partial Sigma seed
backups. Format detection is automatic; no conversion flag is needed. Profile
indices, metadata, labels, numeric timestamps, and `inventoryComplete: false`
are preserved. `upg` changes encryption strength only; it never completes an
inventory or derives keys. Unknown versions, removed fields, and mixed legacy
markers fail without writing an output file.

`dec -o backup.json` writes plaintext with owner-only permissions (0600),
including when overwriting an existing file. Without `-o`, `dec` deliberately
prints the entire decrypted backup, including mnemonic/private keys, to stdout.
Passwords passed with `-p` may appear in shell history and process arguments;
Touch ID can retrieve an already cached password on supported Macs.

The CLI validates structure and supported mnemonic word count only. It does not
verify BIP39 checksum, derive or bind BAP IDs, generate seeds, or discover
profiles. Use a compatible Sigma application for those operations. An absent
`inventoryComplete` marker describes the inventory recorded when that backup
was saved; it does not prove no profiles were created later. Upgrading an old
backup does not discover or add those later profiles.
