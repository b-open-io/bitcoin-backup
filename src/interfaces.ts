export interface BapMasterBackupLegacy {
  ids: string; // Encrypted data from bsv-bap's bap.exportIds()
  xprv: string; // Master extended private key
  mnemonic: string; // BIP39 mnemonic phrase
  label?: string; // User-defined label (optional)
  createdAt?: string; // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

export interface MasterBackupType42 {
  ids: string; // Encrypted data from bsv-bap's bap.exportIds()
  rootPk: string; // Master private key in WIF format (Type 42)
  label?: string; // User-defined label (optional)
  createdAt?: string; // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

// Main interface that users import - supports both legacy and Type 42 formats
export type BapMasterBackup = BapMasterBackupLegacy | MasterBackupType42;

export interface BapAccountBackup {
  wif: string; // Account private key in WIF format
  id: string; // BAP ID for this account
  label?: string; // User-defined label (optional)
  createdAt?: string; // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

export interface WifBackup {
  wif: string;
  label?: string; // User-defined label (optional)
  createdAt?: string; // ISO 8601 timestamp (populated by encryptBackup if a new WifBackup object is passed)
}

export interface OneSatBackup {
  ordPk: string; // Ordinals Private Key WIF
  payPk: string; // Payment Private Key WIF
  identityPk: string; // Identity Private Key WIF (associated with a user identity)
  label?: string; // User-defined label (optional)
  createdAt?: string; // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

/**
 * Encrypted key vault backup. The vault is already encrypted by the application
 * with its own encryption, and bitcoin-backup encrypts the entire VaultBackup object
 * for secure backup storage - just like all other backup formats in this library.
 *
 * The 'scheme' field identifies HOW the vault was assembled and encrypted by the
 * application (not by bitcoin-backup, which uses universal encryption for all backups).
 * This enables interoperability between different vault implementations.
 *
 * Default scheme: "vscode-bitcoin-v1" (VSCode Bitcoin Extension format)
 */
export interface VaultBackup {
  encryptedVault: string; // Application's encrypted vault blob (any format the app uses)
  scheme?: string; // Vault encryption scheme identifier (e.g., "vscode-bitcoin-v1", "custom-vault-v2")
  label?: string; // User-defined label (optional)
  createdAt?: string; // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

/**
 * YoursWallet JSON backup format - WIF keys with optional mnemonic and derivation paths
 * Compatible with Yours Wallet's JSON import/export
 */
export interface YoursWalletBackup {
  mnemonic?: string; // BIP39 mnemonic phrase (optional - not present in WIF-only exports)
  payPk: string; // Payment Private Key WIF
  payDerivationPath?: string; // Payment key derivation path (e.g., "m/44'/236'/0'/1/0")
  ordPk: string; // Ordinals Private Key WIF
  ordDerivationPath?: string; // Ordinals key derivation path (e.g., "m/44'/236'/1'/0/0")
  identityPk?: string; // Identity Private Key WIF (optional for compatibility)
  identityDerivationPath?: string; // Identity key derivation path (e.g., "m/0'/236'/0'/0/0")
  label?: string; // User-defined label (optional)
  createdAt?: string; // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

/** Per-account entry in a v2 (multi-account) Yours Wallet backup manifest. */
export interface YoursWalletBackupAccountEntry {
  identityKey: string; // Account identity public key
  identityAddress: string; // Account identity address (ZIP folder prefix for this account's chunks)
  name: string; // User-facing account name
  chunkCount: number; // Number of wallet-toolbox sync chunks for this account
}

/** v1 (single-account) Yours Wallet / wallet-toolbox backup manifest. */
export interface YoursWalletBackupManifestV1 {
  version: 1;
  createdAt: string; // ISO 8601 timestamp
  chain: 'main' | 'test';
  identityKey: string; // Wallet identity public key
  chunkCount: number; // Number of sync chunks in the backup
}

/** v2 (multi-account) Yours Wallet backup manifest. */
export interface YoursWalletBackupManifestV2 {
  version: 2;
  createdAt: string; // ISO 8601 timestamp
  chain: 'main' | 'test';
  accounts: YoursWalletBackupAccountEntry[]; // Per-account metadata
}

/**
 * Parsed manifest.json from a Yours Wallet master backup ZIP. Legacy
 * (pre-BRC-100, keys-only) backups have no manifest at all.
 */
export type YoursWalletBackupManifest = YoursWalletBackupManifestV1 | YoursWalletBackupManifestV2;

/**
 * Parsed contents of a Yours Wallet master backup ZIP (produced by parseYoursWalletZip).
 *
 * The on-disk ZIP (fflate, deflate) contains:
 *   - manifest.json        — v1/v2 manifest (absent for legacy keys-only backups)
 *   - chromeStorage.json   — accounts (with encrypted keys), selectedAccount, salt, settings
 *   - settings.bin         — msgpack-encoded wallet-toolbox storage settings (v1/v2)
 *   - chunk-XXXX.bin        — msgpack-encoded sync chunks (v1: flat; v2: under <identityAddress>/)
 */
export interface YoursWalletZipBackup {
  chromeStorage: Record<string, unknown>; // Parsed chromeStorage.json (required)
  manifest?: YoursWalletBackupManifest; // Parsed manifest.json (absent for legacy backups)
  settings?: unknown; // Decoded settings.bin (msgpack), present for v1/v2 backups
  chunks?: Record<string, unknown>; // Decoded sync chunks (msgpack), keyed by ZIP entry name
  label?: string; // User-defined label (optional)
  createdAt?: string; // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

export type DecryptedBackup =
  | BapMasterBackup
  | BapAccountBackup
  | WifBackup
  | OneSatBackup
  | VaultBackup
  | YoursWalletBackup
  | YoursWalletZipBackup;

// Represents the final encrypted string, typically Base64 encoded
export type EncryptedBackup = string;
