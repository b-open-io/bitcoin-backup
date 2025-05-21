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
  | OneSatBackup;
```

## Backup Payload Interfaces

The following interfaces define the structure of the data that can be encrypted and decrypted by this library. The `createdAt` field is automatically added by `encryptBackup` if not provided by the user, containing an ISO 8601 timestamp.

### `BapMasterBackup`

Represents a backup for a BAP (Bitcoin Attestation Protocol) master identity, typically including an xprv and mnemonic.

```typescript
export interface BapMasterBackup {
  ids: string;          // Serialized data from bsv-bap's bap.exportIds()
  xprv: string;         // Master extended private key
  mnemonic: string;     // BIP39 mnemonic phrase
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}
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

## Constants

The library exports the following constants related to PBKDF2 iterations:

```typescript
export const RECOMMENDED_PBKDF2_ITERATIONS = 600000;
export const LEGACY_PBKDF2_ITERATIONS = 100000;
``` 