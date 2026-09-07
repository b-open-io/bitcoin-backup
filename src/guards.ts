import { hasSigmaSeedMarker, isSigmaSeedBackup } from './seed';

export { isSigmaSeedBackup } from './seed';

import type {
  BapAccountBackup,
  BapMasterBackup,
  BapMasterBackupLegacy,
  DecryptedBackup,
  DerivationDescriptor,
  MasterBackupType42,
  OneSatBackup,
  VaultBackup,
  WifBackup,
  YoursWalletBackup,
  YoursWalletZipBackup,
} from './interfaces';

/**
 * Type guard: checks if the value is a valid DerivationDescriptor.
 */
export function isDerivationDescriptor(value: unknown): value is DerivationDescriptor {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  const allowed = new Set(['scheme', 'path', 'parentIdentityKey', 'index', 'cohort']);
  for (const key of Object.keys(v)) {
    if (!allowed.has(key)) return false;
  }
  const schemes = new Set(['brc157', 'bip32', 'type42', 'brc42', 'legacy-bip32-unhardened']);
  if (typeof v.scheme !== 'string' || !schemes.has(v.scheme)) return false;
  if ('path' in v && typeof v.path !== 'string') return false;
  if ('parentIdentityKey' in v && typeof v.parentIdentityKey !== 'string') return false;
  if ('index' in v) {
    if (typeof v.index !== 'number' || !Number.isSafeInteger(v.index) || v.index < 0) return false;
  }
  if ('cohort' in v && typeof v.cohort !== 'string') return false;
  return true;
}

/**
 * Type guard: checks if the backup is a legacy BAP master backup (xprv + mnemonic).
 */
export function isLegacyBackup(backup: DecryptedBackup): backup is BapMasterBackupLegacy {
  if (hasSigmaSeedMarker(backup)) return false;
  return 'xprv' in backup && 'mnemonic' in backup && 'ids' in backup;
}

/**
 * Type guard: checks if the backup is a Type 42 BAP master backup (rootPk).
 */
export function isType42Backup(backup: DecryptedBackup): backup is MasterBackupType42 {
  if (hasSigmaSeedMarker(backup)) return false;
  return 'rootPk' in backup && 'ids' in backup && !('xprv' in backup);
}

/**
 * Type guard: checks if the backup is any BAP master backup (legacy or Type 42).
 */
export function isMasterBackup(backup: DecryptedBackup): backup is BapMasterBackup {
  return isLegacyBackup(backup) || isType42Backup(backup);
}

/**
 * Type guard: checks if the backup is a BAP account backup (wif + id).
 */
export function isAccountBackup(backup: DecryptedBackup): backup is BapAccountBackup {
  if (hasSigmaSeedMarker(backup)) return false;
  return 'wif' in backup && 'id' in backup && !('xprv' in backup) && !('rootPk' in backup);
}

/**
 * Type guard: checks if the backup is a bare WIF backup (wif only, no id/xprv/rootPk).
 */
export function isWifBackup(backup: DecryptedBackup): backup is WifBackup {
  if (hasSigmaSeedMarker(backup)) return false;
  return 'wif' in backup && !('id' in backup) && !('xprv' in backup) && !('rootPk' in backup);
}

/**
 * Type guard: checks if the backup is a 1Sat Ordinals backup.
 */
export function isOneSatBackup(backup: DecryptedBackup): backup is OneSatBackup {
  if (hasSigmaSeedMarker(backup)) return false;
  return (
    'ordPk' in backup &&
    'payPk' in backup &&
    'identityPk' in backup &&
    !('mnemonic' in backup) &&
    !('payDerivationPath' in backup)
  );
}

/**
 * Type guard: checks if the backup is an encrypted vault backup.
 */
export function isVaultBackup(backup: DecryptedBackup): backup is VaultBackup {
  if (hasSigmaSeedMarker(backup)) return false;
  return 'encryptedVault' in backup;
}

/**
 * Type guard: checks if the backup is a Yours Wallet JSON backup.
 */
export function isYoursWalletBackup(backup: DecryptedBackup): backup is YoursWalletBackup {
  if (hasSigmaSeedMarker(backup)) return false;
  return (
    'payPk' in backup &&
    'ordPk' in backup &&
    ('mnemonic' in backup || 'payDerivationPath' in backup || 'ordDerivationPath' in backup)
  );
}

/**
 * Type guard: checks if the backup is a parsed Yours Wallet ZIP backup.
 * The chromeStorage object is the discriminator; manifest/settings/chunks are optional.
 */
export function isYoursWalletZipBackup(backup: DecryptedBackup): backup is YoursWalletZipBackup {
  if (hasSigmaSeedMarker(backup)) return false;
  return (
    'chromeStorage' in backup &&
    typeof (backup as { chromeStorage: unknown }).chromeStorage === 'object' &&
    (backup as { chromeStorage: unknown }).chromeStorage !== null
  );
}

/** Backup type name for display/logging purposes */
export type BackupTypeName =
  | 'SigmaSeed'
  | 'Legacy'
  | 'Type42'
  | 'Account'
  | 'WIF'
  | 'OneSat'
  | 'Vault'
  | 'YoursWallet'
  | 'YoursWalletZip'
  | 'Unknown';

/**
 * Returns a human-readable name for the backup type.
 */
export function getBackupType(backup: DecryptedBackup): BackupTypeName {
  if (isSigmaSeedBackup(backup)) return 'SigmaSeed';
  if (isLegacyBackup(backup)) return 'Legacy';
  if (isType42Backup(backup)) return 'Type42';
  if (isAccountBackup(backup)) return 'Account';
  if (isWifBackup(backup)) return 'WIF';
  if (isOneSatBackup(backup)) return 'OneSat';
  if (isVaultBackup(backup)) return 'Vault';
  if (isYoursWalletZipBackup(backup)) return 'YoursWalletZip';
  if (isYoursWalletBackup(backup)) return 'YoursWallet';
  return 'Unknown';
}
