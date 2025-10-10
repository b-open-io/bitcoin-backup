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