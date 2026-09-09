# Changelog

## 0.2.0

### Added
- v2 `argon2id` passphrase slots (RFC 9106 interactive parameters: 64 MiB, t=3, p=1). New Vault files should use these instead of PBKDF2.
- `assertPassphrase` wallet-grade policy (12+ characters; 16+ or mixed character classes; common-password denylist). Do not trim passphrases.
- `deriveArgon2idRaw` / `deriveArgon2idKey` for consumers that wrap keys themselves.

### Changed
- `openBackup` / `decryptBackup` try argon2id and pbkdf2 passphrase slots. Existing pbkdf2 envelopes still open.

## 0.1.0

### Added
- Versioned `BEP2` envelope (v2) with key slots: one encrypted file can be unlocked by multiple credentials (`pbkdf2` passphrase slots and `device-p256` P-256 ECIES slots).
- New API: `sealBackup`, `openBackup`, `inspectEnvelope`, `addSlot`, `removeSlot`, `rewrapBackup`, `isEnvelopeV2`, plus `eciesEncrypt`/`eciesDecrypt` and `SlotSpec`/`Unlock` types.
- Optional `DerivationDescriptor` (`scheme`, `path`, `parentIdentityKey`, `index`, `cohort`) on `WifBackup`, `BapAccountBackup`, `MasterBackupType42`, and `BapMasterBackupLegacy`, with `isDerivationDescriptor` guard. Header copies it for locked inspection.
- `updateBackupPayload` re-encrypts a new payload under an envelope's existing content key, keeping every slot.
- CLI: `bbackup enc --device-pubkey <hex>` (repeatable) writes a v2 envelope sealed to the passphrase and each device key; `bbackup slot add|remove` manages slots; `bbackup slots <file>` inspects slots without a passphrase.
- `decryptBackup` transparently opens v2 pbkdf2 slots; `encryptBackup` still writes v1. Existing `.bep` files decrypt unchanged.

## 0.0.14

### Fixed
- Snapshot validated backup data before asynchronous encryption so caller mutation cannot change the encrypted inventory.
- Keep CLI version synchronized with the package. Read custom PBKDF2 iteration counts in `dec` and `upg`, reject malformed counts, protect decrypted files with owner-only permissions, and avoid echoing malformed input JSON in errors.

### Added
- Versioned Sigma seed backup envelopes, structural validation, and encrypted profile inventories, including partial-inventory tracking for phrase recovery.

### Changed
- Version 1 defines the derivation and empty passphrase policy; mnemonic word count determines entropy length. Existing backup formats remain unchanged.
- Pin the integration suite to the published `bsv-bap` package instead of an undeclared sibling checkout.

## 0.0.13

### Fixed
- **Externalize `fflate` in the bundle** (build) — v0.0.12 inlined fflate's Node ESM, whose worker-pool path statically imports `createRequire` from `module`, breaking consumer browser/edge bundles (Turbopack: "Can't resolve 'module'"). `fflate` is now external like `@bsv/sdk`/`@1sat/vault`, so consumers resolve fflate's own browser-safe entry. (OPL-2516)

## 0.0.12

### Breaking Changes
- **`@bsv/sdk` peer dependency tightened to `^2.0.0`** (was `^1.5.2 || ^2.0.0`). Only the long-stable `Utils.toArray`/`toBase64` helpers are used, but the supported/tested range is now v2.

### Added
- **Full Yours Wallet master backup ZIP parser** — `parseYoursWalletZip(zip: Uint8Array)` unzips (via `fflate`) and parses the real Yours Wallet backup format: `manifest.json` (v1/v2), `chromeStorage.json`, msgpack `settings.bin`, and per-account msgpack `chunk-XXXX.bin` files. Exported from the package root alongside `extractKeysFromChromeStorage`.
- `YoursWalletZipBackup` interface rewritten to match the real format, with `YoursWalletBackupManifest` (v1/v2 union) and `YoursWalletBackupAccountEntry` types.

### Changed
- **Migrated to provider-based `@1sat/vault` (>=0.0.6 architecture).** Touch ID now uses `@1sat/vault` `^0.0.8` (platform-agnostic vault interface) plus `@1sat/wallet-mac` `^0.0.5` (`SecureEnclaveProvider`), wired via `createVault(provider, storage)`. `@1sat/wallet-mac` added to `trustedDependencies` so its Secure Enclave binary compiles on install.
- Dependencies updated to latest: `typescript` 5.9 → 6.0, `commander` 14 → 15, `@biomejs/biome` → 2.5, `@bsv/sdk` → 2.1.6, `@types/bun` → 1.3.14. Added `fflate` and `@msgpack/msgpack`.
- `tsconfig` `moduleResolution` `node` → `bundler` (the deprecated `node`/node10 value errors under TypeScript 6).

### Fixed
- Removed Node `Buffer` type usage (replaced with standard types) — resolves a TypeScript 6 build error and aligns with the project's no-`Buffer` convention.

## 0.0.11

### Fixed
- CLI shebang changed from `#!/usr/bin/env node` to `#!/usr/bin/env bun` -- fixes `@1sat/vault` dynamic import resolution and `Bun.CryptoHasher` availability
- `@1sat/vault` moved from optional peer dep to regular dependency so Touch ID works out of the box on `bun install -g bitcoin-backup`

## 0.0.9

### Added
- Touch ID password cache via `--touchid` flag on enc, dec, and upg commands
- `bbackup forget <file>` command to remove cached passwords
- `src/touchid.ts` module for programmatic SE password caching
- `@1sat/vault` as dependency for Secure Enclave support

## 0.0.8

### Changed
- **Rename `BapMemberBackup` → `BapAccountBackup`** — Master → many Accounts, not "Members". Same `{ wif, id }` shape, correct naming to match bsv-bap 0.2.0 architecture.
- **Rename `isMemberBackup()` → `isAccountBackup()`** — type guard updated to match.
- **Rename `"Member"` → `"Account"`** in `BackupTypeName` and `getBackupType()`.

### Updated
- `@bsv/sdk` 2.0.1 → 2.0.7
- `@types/bun` 1.3.3 → 1.3.10
- `commander` 14.0.2 → 14.0.3

## 0.0.7

### Added
- Type guard functions for all backup formats (`isLegacyBackup`, `isType42Backup`, `isMasterBackup`, `isWifBackup`, `isOneSatBackup`, `isVaultBackup`, `isYoursWalletBackup`, `isYoursWalletZipBackup`)
- `getBackupType()` returns human-readable backup type name

## 0.0.6

### Changed
- Accept `@bsv/sdk` v2 in peer dependencies
