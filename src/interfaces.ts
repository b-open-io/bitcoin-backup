export interface BapMasterBackupLegacy {
  ids: string;          // Encrypted data from bsv-bap's bap.exportIds()
  xprv: string;         // Master extended private key
  mnemonic: string;     // BIP39 mnemonic phrase
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

export interface MasterBackupType42 {
  ids: string;          // Encrypted data from bsv-bap's bap.exportIds()
  rootPk: string;    // Master private key in WIF format (Type 42)
  label?: string;       // User-defined label (optional)
  createdAt?: string;   // ISO 8601 timestamp (populated by encryptBackup if not provided)
}

// Main interface that users import - supports both legacy and Type 42 formats
export type BapMasterBackup = BapMasterBackupLegacy | MasterBackupType42;

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

export type DecryptedBackup =
  | BapMasterBackup
  | BapMemberBackup
  | WifBackup
  | OneSatBackup;

// Represents the final encrypted string, typically Base64 encoded
export type EncryptedBackup = string; 