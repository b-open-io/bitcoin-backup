# Changelog

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
