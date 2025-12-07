import { describe, expect, it } from 'bun:test';
import { encryptBackup, decryptBackup } from '../src/index';
import type { YoursWalletBackup, YoursWalletZipBackup, OneSatBackup } from '../src/interfaces';
import { isYoursWalletBackup, isYoursWalletZipBackup } from '../src/yours-wallet';

describe('YoursWallet Backup', () => {
  const passphrase = 'testPassphrase123!';

  describe('YoursWalletBackup (JSON format)', () => {
    // Full format with mnemonic and derivation paths
    const fullYoursWalletBackup: YoursWalletBackup = {
      mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      payPk: 'L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
      payDerivationPath: "m/44'/236'/0'/1/0",
      ordPk: 'L2RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
      ordDerivationPath: "m/44'/236'/1'/0/0",
      identityPk: 'L3RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
      identityDerivationPath: "m/0'/236'/0'/0/0",
      label: 'Test Yours Wallet',
    };

    // Minimal format (WIF-only, no mnemonic)
    const minimalYoursWalletBackup: YoursWalletBackup = {
      payPk: 'L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
      ordPk: 'L2RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
      payDerivationPath: "m/44'/236'/0'/1/0", // At least one derivation path to distinguish from OneSat
    };

    it('should validate a full YoursWalletBackup with mnemonic', () => {
      expect(isYoursWalletBackup(fullYoursWalletBackup)).toBe(true);
    });

    it('should validate a minimal YoursWalletBackup without mnemonic', () => {
      expect(isYoursWalletBackup(minimalYoursWalletBackup)).toBe(true);
    });

    it('should reject YoursWalletBackup missing required fields', () => {
      const invalidBackup = {
        mnemonic: 'test mnemonic',
        payPk: 'L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        // Missing ordPk
      };
      expect(isYoursWalletBackup(invalidBackup)).toBe(false);
    });

    it('should encrypt and decrypt full YoursWalletBackup', async () => {
      const encrypted = await encryptBackup(fullYoursWalletBackup, passphrase);
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(0);

      const decrypted = await decryptBackup(encrypted, passphrase) as YoursWalletBackup;
      // The createdAt field is added automatically if not present
      expect(decrypted.createdAt).toBeDefined();
      const { createdAt, ...decryptedWithoutTimestamp } = decrypted;
      const { createdAt: originalCreatedAt, ...originalWithoutTimestamp } = fullYoursWalletBackup;
      expect(decryptedWithoutTimestamp).toEqual(originalWithoutTimestamp);
    });

    it('should encrypt and decrypt minimal YoursWalletBackup', async () => {
      const encrypted = await encryptBackup(minimalYoursWalletBackup, passphrase);
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(0);

      const decrypted = await decryptBackup(encrypted, passphrase) as YoursWalletBackup;
      // The createdAt field is added automatically if not present
      expect(decrypted.createdAt).toBeDefined();
      const { createdAt, ...decryptedWithoutTimestamp } = decrypted;
      const { createdAt: originalCreatedAt, ...originalWithoutTimestamp } = minimalYoursWalletBackup;
      expect(decryptedWithoutTimestamp).toEqual(originalWithoutTimestamp);
    });

    it('should fail decryption with wrong passphrase', async () => {
      const encrypted = await encryptBackup(fullYoursWalletBackup, passphrase);
      await expect(decryptBackup(encrypted, 'wrongPassphrase')).rejects.toThrow();
    });

    it('should add createdAt timestamp if not provided', async () => {
      const backupWithoutTimestamp = { ...fullYoursWalletBackup };
      delete backupWithoutTimestamp.createdAt;

      const encrypted = await encryptBackup(backupWithoutTimestamp, passphrase);
      const decrypted = (await decryptBackup(encrypted, passphrase)) as YoursWalletBackup;

      expect(decrypted.createdAt).toBeDefined();
      expect(typeof decrypted.createdAt).toBe('string');
      // Verify it's a valid ISO date
      expect(() => new Date(decrypted.createdAt!)).not.toThrow();
    });

    it('should handle YoursWallet format without identityPk', async () => {
      const backupWithoutIdentity: YoursWalletBackup = {
        payPk: 'L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        ordPk: 'L2RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        mnemonic: 'test mnemonic phrase here',
      };

      const encrypted = await encryptBackup(backupWithoutIdentity, passphrase);
      const decrypted = await decryptBackup(encrypted, passphrase) as YoursWalletBackup;
      // The createdAt field is added automatically if not present
      expect(decrypted.createdAt).toBeDefined();
      const { createdAt, ...decryptedWithoutTimestamp } = decrypted;
      expect(decryptedWithoutTimestamp).toEqual(backupWithoutIdentity);
    });
  });

  describe('YoursWalletZipBackup', () => {
    const validZipBackup: YoursWalletZipBackup = {
      chromeStorage: {
        accounts: {
          '1FdKLZsksDDRukRtUSwv8b2TVXEngdDHya': {
            addresses: {
              bsvAddress: '1Cr5gSHf5tzFBvGuSa21VRoV9pRuRBmum9',
              identityAddress: '1FdKLZsksDDRukRtUSwv8b2TVXEngdDHya',
              ordAddress: '1EkeEuz1ZHqzD2Q8sueRjziBpf59KbNoMC',
            },
            balance: { bsv: 0.85307057, satoshis: 85307057, usdInCents: 6074 },
            encryptedKeys: 'encrypted_keys_here',
            settings: {
              isPasswordRequired: true,
              noApprovalLimit: 0.01,
            },
          },
        },
        selectedAccount: '1FdKLZsksDDRukRtUSwv8b2TVXEngdDHya',
        version: 1,
      },
      accountData: [
        {
          txid: '657f89f2f538a9c1bb4e6637dc0aa4d4587a57fb6c80c60530d0e463fccb64db',
          height: 737660,
          idx: 7783,
          outputs: [4],
          parseMode: 2,
        },
      ],
      label: 'Yours Wallet Full Backup',
    };

    it('should validate a valid YoursWalletZipBackup', () => {
      expect(isYoursWalletZipBackup(validZipBackup)).toBe(true);
    });

    it('should reject invalid YoursWalletZipBackup', () => {
      const invalidBackup = {
        chromeStorage: 'not an object',
        // Missing accountData
      };
      expect(isYoursWalletZipBackup(invalidBackup)).toBe(false);
    });

    it('should encrypt and decrypt YoursWalletZipBackup', async () => {
      const encrypted = await encryptBackup(validZipBackup, passphrase);
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(0);

      const decrypted = await decryptBackup(encrypted, passphrase) as YoursWalletZipBackup;
      // The createdAt field is added automatically if not present
      expect(decrypted.createdAt).toBeDefined();
      const { createdAt, ...decryptedWithoutTimestamp } = decrypted;
      const { createdAt: originalCreatedAt, ...originalWithoutTimestamp } = validZipBackup;
      expect(decryptedWithoutTimestamp).toEqual(originalWithoutTimestamp);
    });
  });

  describe('Compatibility between formats', () => {
    it('should distinguish between YoursWalletBackup and OneSatBackup', async () => {
      // OneSatBackup format - no mnemonic or derivation paths
      const oneSatBackup: OneSatBackup = {
        ordPk: 'L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        payPk: 'L2RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        identityPk: 'L3RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        label: 'OneSat Backup',
      };

      // YoursWalletBackup with mnemonic
      const yoursWalletWithMnemonic: YoursWalletBackup = {
        mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
        payPk: 'L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        ordPk: 'L2RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        identityPk: 'L3RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        label: 'Yours Wallet Backup',
      };

      // YoursWalletBackup with derivation paths but no mnemonic
      const yoursWalletWithPaths: YoursWalletBackup = {
        payPk: 'L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        payDerivationPath: "m/44'/236'/0'/1/0",
        ordPk: 'L2RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        ordDerivationPath: "m/44'/236'/1'/0/0",
        identityPk: 'L3RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        identityDerivationPath: "m/0'/236'/0'/0/0",
        label: 'Yours Wallet with Paths',
      };

      // All should encrypt successfully
      const encryptedOneSat = await encryptBackup(oneSatBackup, passphrase);
      const encryptedYoursMnemonic = await encryptBackup(yoursWalletWithMnemonic, passphrase);
      const encryptedYoursPaths = await encryptBackup(yoursWalletWithPaths, passphrase);

      // Decrypt and verify they maintain their types
      const decryptedOneSat = await decryptBackup(encryptedOneSat, passphrase);
      const decryptedYoursMnemonic = await decryptBackup(encryptedYoursMnemonic, passphrase);
      const decryptedYoursPaths = await decryptBackup(encryptedYoursPaths, passphrase);

      // OneSat backup should not have mnemonic or derivation paths
      expect('mnemonic' in decryptedOneSat).toBe(false);
      expect('payDerivationPath' in decryptedOneSat).toBe(false);
      expect('ordDerivationPath' in decryptedOneSat).toBe(false);

      // Yours Wallet with mnemonic should have mnemonic
      expect('mnemonic' in decryptedYoursMnemonic).toBe(true);
      expect((decryptedYoursMnemonic as YoursWalletBackup).mnemonic).toBeDefined();

      // Yours Wallet with paths should have derivation paths
      expect('payDerivationPath' in decryptedYoursPaths).toBe(true);
      expect('ordDerivationPath' in decryptedYoursPaths).toBe(true);
    });

    it('should correctly identify format using type guards', () => {
      const oneSatFormat = {
        ordPk: 'L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        payPk: 'L2RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        identityPk: 'L3RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
      };

      const yoursFormatWithMnemonic = {
        mnemonic: 'test mnemonic',
        ordPk: 'L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        payPk: 'L2RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
      };

      const yoursFormatWithPaths = {
        ordPk: 'L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        payPk: 'L2RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi',
        payDerivationPath: "m/44'/236'/0'/1/0",
      };

      // OneSat format should not be identified as Yours
      expect(isYoursWalletBackup(oneSatFormat)).toBe(false);

      // Yours formats should be correctly identified
      expect(isYoursWalletBackup(yoursFormatWithMnemonic)).toBe(true);
      expect(isYoursWalletBackup(yoursFormatWithPaths)).toBe(true);
    });
  });
});