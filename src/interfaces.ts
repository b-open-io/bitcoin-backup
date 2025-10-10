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

export interface BapMemberBackup {
  wif: string; // Private key in WIF format
  id: string; // BAP ID or other identifier
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

export type DecryptedBackup =
  | BapMasterBackup
  | BapMemberBackup
  | WifBackup
  | OneSatBackup
  | VaultBackup;

// Represents the final encrypted string, typically Base64 encoded
export type EncryptedBackup = string;
