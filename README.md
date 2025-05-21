# `bitcoin-backup`

[![npm version](https://badge.fury.io/js/bitcoin-backup.svg)](https://badge.fury.io/js/bitcoin-backup)
// [![Build Status](https://img.shields.io/your_ci_provider/your_username/bitcoin-backup.svg)](https://your_ci_provider_link) // Placeholder, CI not yet configured
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
*(Note: Replace npm version badge with actual link if/when published)*

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
*   **Strong Encryption:** Secures backup data using AES-256-GCM with PBKDF2 key derivation (see Security Model).
*   **Multiple Backup Formats:** Supports various backup structures like `BapMasterBackup`, `BapMemberBackup`, `WifBackup`, and `OneSatBackup`. The type of backup is inferred from payload structure. (See [API Documentation](./API.md) for full type details).
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

Detailed type definitions for `BapMasterBackup`, `BapMemberBackup`, `WifBackup`, `OneSatBackup`, and `DecryptedBackupPayload` can be found in [./API.md](./API.md).

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

**Common Options:**
*   `-p, --password <password>`: (Required) The passphrase for encryption/decryption.
*   `-o, --output <outputFile>`: (Optional) Path for the output file. Defaults are sensible (e.g., `<input>.bep` for encrypt, `<input>.json` for decrypt).
*   `-t, --iterations <iterations>`: (Optional, for `enc` command) Number of PBKDF2 iterations.

For detailed options for each command, run:
```bash
bbackup enc --help
bbackup dec --help
bbackup upg --help
```
*(Sample output or screenshots of `--help` could be added here for enhanced clarity).*

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

## Contributing

Contributions are welcome! Please open an issue or submit a pull request. (A more detailed `CONTRIBUTING.md` could be added).

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.