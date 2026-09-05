# API Documentation for `bitcoin-backup`

This document provides detailed information about the TypeScript types used by the `bitcoin-backup` library.

## Core Types

### `EncryptedBackupString`

Represents the final encrypted string, typically Base64 encoded.

```typescript
export type EncryptedBackupString = string;
```

### `DecryptedBackupPayload`

This is a union type representing all possible structures of decrypted backup data. The library infers the specific type based on the properties present in the decrypted object.

```typescript
export type DecryptedBackupPayload =
  | BapMasterBackup
  | BapMemberBackup
  | WifBackup
  | OneSatBackup
  | VaultBackup;
```

## Backup Payload Interfaces

The following interfaces define the structure of the data that can be encrypted and decrypted by this library. The `createdAt` field is automatically added by `encryptBackup` if not provided by the user, containing an ISO 8601 timestamp.

### `BapMasterBackup`

Represents a backup for a BAP (Bitcoin Attestation Protocol) master identity. Supports both legacy BIP32 format and modern Type 42 format.

```typescript
// Legacy BIP32 format
export interface BapMasterBackupLegacy {
  ids: string;          // Encrypted data from bsv-bap's bap.exportIds()
  xprv: string;         // Master extended private key
  mnemonic: string;     // BIP39 mnemonic phrase
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

// Type 42 format (recommended for new implementations)
export interface MasterBackupType42 {
  ids: string;          // Encrypted data from bsv-bap's bap.exportIds()
  rootPk: string;       // Master private key in WIF format (Type 42)
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

// Main type that supports both formats
export type BapMasterBackup = BapMasterBackupLegacy | MasterBackupType42;
```

### `BapMemberBackup`

Represents a backup for a BAP member identity, typically identified by a WIF and a BAP ID.

```typescript
export interface BapMemberBackup {
  wif: string;          // Private key in WIF format
  id: string;           // BAP ID or other identifier (e.g., from memberId.getIdentityKey())
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}
```

### `WifBackup`

Represents a simple backup of a single WIF (Wallet Import Format) private key.

```typescript
export interface WifBackup {
  wif: string;
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}
```

### `OneSatBackup`

An example interface demonstrating how to structure a backup for custom data, in this case, related to Ordinals/1Sat  private keys.
This shows the flexibility of the library to handle various structured payloads. It is treated as a first-class type if `ordPk`, `payPk`, and `identityPk` are present.

```typescript
export interface OneSatBackup {
  ordPk: string;        // Ordinal private key WIF
  payPk: string;        // Payment private key WIF
  identityPk: string;   // Identity private key WIF (associated with a user identity)
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}
```

### `VaultBackup`

Represents a backup of an encrypted key vault. The application encrypts the vault with its own encryption, and bitcoin-backup encrypts the entire `VaultBackup` object - just like all other formats in this library.

```typescript
export interface VaultBackup {
  encryptedVault: string;  // Application's encrypted vault blob
  scheme?: string;         // Vault encryption scheme identifier (e.g., "vscode-bitcoin-v1", "custom-vault-v2")
  label?: string;          // User-defined label (optional)
  createdAt?: string;      // ISO 8601 timestamp (populated by encryptBackup if not provided)
}
```

**Detection**: VaultBackup is identified by the presence of the `encryptedVault` field.

**Double Encryption**: The vault is already encrypted by the application, and bitcoin-backup encrypts the whole backup with strong, universal encryption (600k PBKDF2 iterations, AES-256-GCM).

**Scheme Field**: The optional `scheme` field identifies HOW the vault was assembled and encrypted by the application (not by bitcoin-backup, which uses universal encryption). This enables interoperability between different vault implementations.

- **Default scheme**: `"vscode-bitcoin-v1"` (VSCode Bitcoin Extension format)
- **Custom schemes**: Applications can define their own scheme identifiers (e.g., `"my-wallet-v1"`, `"mobile-app-v2"`)
- **Extensibility**: The scheme field allows applications to understand each other's vault formats while maintaining bitcoin-backup's universal encryption layer

## Constants

The library exports the following constants related to PBKDF2 iterations:

```typescript
export const RECOMMENDED_PBKDF2_ITERATIONS = 600000;
export const LEGACY_PBKDF2_ITERATIONS = 100000;
```
## Sigma Peer Profiles seed backups

`SigmaSeedBackup` is a separate member of `DecryptedBackup`, never a
`BapMasterBackup`. Use `isSigmaSeedBackup(value)` to validate its structure;
`getBackupType` returns `SigmaSeed`. Existing encryption and legacy key formats
are unchanged. Older readers reject this envelope as an unknown JSON structure.

```ts
const backup: SigmaSeedBackup = {
  format: 'sigma-seed',
  version: 1,
  scheme: 'brc157-peer-profiles',
  mnemonic,
  entropyBytes: 16,
  passphrasePolicy: 'empty',
  profiles: [{ index: 0, bapId }],
  nextProfileIndex: 1,
  createdAt: Date.now(),
};
const ciphertext = await encryptBackup(backup, backupPassword);
```

The seed uses an empty BIP39 passphrase; `backupPassword` protects the encrypted
file and is independent of that policy. Profiles are hardened peers at
`m/0'/N'`, where `N` is the profile index. Optional profile `metadata` must be a
JSON object, and the envelope supports an optional string `label`.

Validation requires version 1, the exact scheme, entropy sizes 16/20/24/28/32
bytes with matching 12/15/18/21/24 mnemonic word counts, a nonempty profile list,
unique indices and BAP
IDs, and a safe integer `nextProfileIndex` greater than every used index. All
profile indices are in 0–2147483647; `nextProfileIndex` may be 2147483648
to record exhaustion, at which point allocation must stop. `createdAt` is a
nonnegative safe integer timestamp in milliseconds.
Unknown fields and mixed legacy discriminators (including top-level `rootPk`,
`xprv`, `wif`, or `ids`) are rejected. Numeric timestamps are preserved, including
zero. Legacy formats retain their existing ISO timestamp behavior.

This package checks structure and word count only. The Sigma seed module must
verify the mnemonic checksum, derive keys, and verify BAP ID bindings before
using a restored seed. This format does not migrate or rekey existing accounts.

The optional `inventoryComplete: false` marks phrase-only recovery with an unknown full profile inventory. Absence means complete; `true` and other values are invalid. For partial inventories, `nextProfileIndex` is only a structural bound over listed profiles, not proof that the next index is unused. Consumers must reconcile a complete backup before appending or deleting profiles or replacing a complete cloud inventory.
