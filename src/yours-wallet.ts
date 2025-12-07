import type { YoursWalletBackup, YoursWalletZipBackup } from './interfaces';

/**
 * Extracts keys from Yours Wallet Chrome storage format
 */
export function extractKeysFromChromeStorage(chromeStorage: any): YoursWalletBackup | null {
  try {
    // Find the selected account
    const selectedAccount = chromeStorage.selectedAccount;
    if (!selectedAccount || !chromeStorage.accounts?.[selectedAccount]) {
      return null;
    }

    const account = chromeStorage.accounts[selectedAccount];
    
    // Check if we have encrypted keys - these need to be decrypted with the wallet password
    if (account.encryptedKeys) {
      // For now, return null as we cannot decrypt without the wallet password
      // In a real implementation, this would need the wallet's internal password
      return null;
    }

    // If keys are available in plain text (unlikely in production)
    if (account.privateKeys) {
      return {
        mnemonic: account.mnemonic || '',
        payPk: account.privateKeys.payPk || '',
        payDerivationPath: account.derivationPaths?.pay || "m/44'/236'/0'/1/0",
        ordPk: account.privateKeys.ordPk || '',
        ordDerivationPath: account.derivationPaths?.ord || "m/44'/236'/1'/0/0",
        identityPk: account.privateKeys.identityPk || '',
        identityDerivationPath: account.derivationPaths?.identity || "m/0'/236'/0'/0/0"
      };
    }

    return null;
  } catch (error) {
    console.error('Error extracting keys from Chrome storage:', error);
    return null;
  }
}

/**
 * Parses a YoursWallet ZIP backup file
 * Note: This requires the 'unzipper' or similar package to handle ZIP files
 */
export async function parseYoursWalletZip(zipBuffer: Buffer): Promise<YoursWalletZipBackup> {
  // This would need an unzip library like 'unzipper' or 'node-stream-zip'
  // For now, we'll just document the expected structure
  throw new Error('ZIP parsing not yet implemented. Use unzip command line tool to extract and process files individually.');
}

/**
 * Type guard for YoursWalletBackup
 */
export function isYoursWalletBackup(backup: any): backup is YoursWalletBackup {
  return (
    backup &&
    typeof backup === 'object' &&
    'payPk' in backup &&
    typeof backup.payPk === 'string' &&
    'ordPk' in backup &&
    typeof backup.ordPk === 'string' &&
    // Must have at least one Yours-specific field to distinguish from OneSatBackup
    ('mnemonic' in backup || 'payDerivationPath' in backup || 'ordDerivationPath' in backup)
  );
}

/**
 * Type guard for YoursWalletZipBackup
 */
export function isYoursWalletZipBackup(backup: any): backup is YoursWalletZipBackup {
  return (
    backup &&
    typeof backup === 'object' &&
    'chromeStorage' in backup &&
    typeof backup.chromeStorage === 'object' &&
    'accountData' in backup
  );
}