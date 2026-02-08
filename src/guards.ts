import type {
	BapMasterBackup,
	BapMasterBackupLegacy,
	BapMemberBackup,
	DecryptedBackup,
	MasterBackupType42,
	OneSatBackup,
	VaultBackup,
	WifBackup,
	YoursWalletBackup,
	YoursWalletZipBackup,
} from "./interfaces";

/**
 * Type guard: checks if the backup is a legacy BAP master backup (xprv + mnemonic).
 */
export function isLegacyBackup(
	backup: DecryptedBackup
): backup is BapMasterBackupLegacy {
	return "xprv" in backup && "mnemonic" in backup && "ids" in backup;
}

/**
 * Type guard: checks if the backup is a Type 42 BAP master backup (rootPk).
 */
export function isType42Backup(
	backup: DecryptedBackup
): backup is MasterBackupType42 {
	return "rootPk" in backup && "ids" in backup && !("xprv" in backup);
}

/**
 * Type guard: checks if the backup is any BAP master backup (legacy or Type 42).
 */
export function isMasterBackup(
	backup: DecryptedBackup
): backup is BapMasterBackup {
	return isLegacyBackup(backup) || isType42Backup(backup);
}

/**
 * Type guard: checks if the backup is a BAP member backup (wif + id).
 */
export function isMemberBackup(
	backup: DecryptedBackup
): backup is BapMemberBackup {
	return (
		"wif" in backup &&
		"id" in backup &&
		!("xprv" in backup) &&
		!("rootPk" in backup)
	);
}

/**
 * Type guard: checks if the backup is a bare WIF backup (wif only, no id/xprv/rootPk).
 */
export function isWifBackup(backup: DecryptedBackup): backup is WifBackup {
	return (
		"wif" in backup &&
		!("id" in backup) &&
		!("xprv" in backup) &&
		!("rootPk" in backup)
	);
}

/**
 * Type guard: checks if the backup is a 1Sat Ordinals backup.
 */
export function isOneSatBackup(
	backup: DecryptedBackup
): backup is OneSatBackup {
	return (
		"ordPk" in backup &&
		"payPk" in backup &&
		"identityPk" in backup &&
		!("mnemonic" in backup) &&
		!("payDerivationPath" in backup)
	);
}

/**
 * Type guard: checks if the backup is an encrypted vault backup.
 */
export function isVaultBackup(backup: DecryptedBackup): backup is VaultBackup {
	return "encryptedVault" in backup;
}

/**
 * Type guard: checks if the backup is a Yours Wallet JSON backup.
 */
export function isYoursWalletBackup(
	backup: DecryptedBackup
): backup is YoursWalletBackup {
	return (
		"payPk" in backup &&
		"ordPk" in backup &&
		("mnemonic" in backup ||
			"payDerivationPath" in backup ||
			"ordDerivationPath" in backup)
	);
}

/**
 * Type guard: checks if the backup is a Yours Wallet ZIP backup.
 */
export function isYoursWalletZipBackup(
	backup: DecryptedBackup
): backup is YoursWalletZipBackup {
	return "chromeStorage" in backup && "accountData" in backup;
}

/** Backup type name for display/logging purposes */
export type BackupTypeName =
	| "Legacy"
	| "Type42"
	| "Member"
	| "WIF"
	| "OneSat"
	| "Vault"
	| "YoursWallet"
	| "YoursWalletZip"
	| "Unknown";

/**
 * Returns a human-readable name for the backup type.
 */
export function getBackupType(backup: DecryptedBackup): BackupTypeName {
	if (isLegacyBackup(backup)) return "Legacy";
	if (isType42Backup(backup)) return "Type42";
	if (isMemberBackup(backup)) return "Member";
	if (isWifBackup(backup)) return "WIF";
	if (isOneSatBackup(backup)) return "OneSat";
	if (isVaultBackup(backup)) return "Vault";
	if (isYoursWalletZipBackup(backup)) return "YoursWalletZip";
	if (isYoursWalletBackup(backup)) return "YoursWallet";
	return "Unknown";
}
