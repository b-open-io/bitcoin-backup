import { describe, expect, it } from 'bun:test';
import { encode as encodeMsgpack } from '@msgpack/msgpack';
import { strToU8, zipSync } from 'fflate';
import { decryptBackup, encryptBackup, parseYoursWalletZip } from '../src/index';
import type { OneSatBackup, YoursWalletBackup, YoursWalletZipBackup } from '../src/interfaces';
import { isYoursWalletBackup, isYoursWalletZipBackup } from '../src/yours-wallet';

describe('YoursWallet Backup', () => {
  const passphrase = 'testPassphrase123!';

  describe('YoursWalletBackup (JSON format)', () => {
    // Full format with mnemonic and derivation paths
    const fullYoursWalletBackup: YoursWalletBackup = {
      mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
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

      const decrypted = (await decryptBackup(encrypted, passphrase)) as YoursWalletBackup;
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

      const decrypted = (await decryptBackup(encrypted, passphrase)) as YoursWalletBackup;
      // The createdAt field is added automatically if not present
      expect(decrypted.createdAt).toBeDefined();
      const { createdAt, ...decryptedWithoutTimestamp } = decrypted;
      const { createdAt: originalCreatedAt, ...originalWithoutTimestamp } =
        minimalYoursWalletBackup;
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
      const decrypted = (await decryptBackup(encrypted, passphrase)) as YoursWalletBackup;
      // The createdAt field is added automatically if not present
      expect(decrypted.createdAt).toBeDefined();
      const { createdAt, ...decryptedWithoutTimestamp } = decrypted;
      expect(decryptedWithoutTimestamp).toEqual(backupWithoutIdentity);
    });
  });

  describe('YoursWalletZipBackup', () => {
    const identityAddress = '1FdKLZsksDDRukRtUSwv8b2TVXEngdDHya';
    const chromeStorage = {
      accounts: {
        [identityAddress]: {
          addresses: {
            bsvAddress: '1Cr5gSHf5tzFBvGuSa21VRoV9pRuRBmum9',
            identityAddress,
            ordAddress: '1EkeEuz1ZHqzD2Q8sueRjziBpf59KbNoMC',
          },
          encryptedKeys: 'encrypted_keys_here',
        },
      },
      selectedAccount: identityAddress,
      salt: 'abc123',
      version: 1,
    };
    // A msgpack-decodable sync chunk uses plain JSON-safe values so it also
    // survives a JSON encrypt/decrypt round-trip.
    const syncChunk = { provenTxs: [], transactions: [{ txid: 'deadbeef', height: 737660 }] };
    const storageSettings = { storageIdentityKey: '02abc', chain: 'main' };

    /** Build a real v2 Yours Wallet backup ZIP the same way the wallet does. */
    function buildV2Zip(): Uint8Array {
      const manifest = {
        version: 2,
        createdAt: new Date().toISOString(),
        chain: 'main',
        accounts: [{ identityKey: '02abc', identityAddress, name: 'Account 1', chunkCount: 1 }],
      };
      return zipSync({
        'manifest.json': strToU8(JSON.stringify(manifest)),
        'chromeStorage.json': strToU8(JSON.stringify(chromeStorage)),
        'settings.bin': encodeMsgpack(storageSettings),
        [`${identityAddress}/chunk-0000.bin`]: encodeMsgpack(syncChunk),
      });
    }

    it('parses a v2 (multi-account) backup ZIP', () => {
      const parsed = parseYoursWalletZip(buildV2Zip());
      expect(parsed.manifest?.version).toBe(2);
      expect(parsed.chromeStorage.selectedAccount).toBe(identityAddress);
      expect(parsed.settings).toEqual(storageSettings);
      expect(parsed.chunks?.[`${identityAddress}/chunk-0000.bin`]).toEqual(syncChunk);
    });

    it('parses a legacy (keys-only) backup with no manifest', () => {
      const zip = zipSync({ 'chromeStorage.json': strToU8(JSON.stringify(chromeStorage)) });
      const parsed = parseYoursWalletZip(zip);
      expect(parsed.manifest).toBeUndefined();
      expect(parsed.settings).toBeUndefined();
      expect(parsed.chunks).toBeUndefined();
      expect(parsed.chromeStorage.selectedAccount).toBe(identityAddress);
    });

    it('throws when chromeStorage.json is missing', () => {
      const zip = zipSync({ 'manifest.json': strToU8('{"version":2}') });
      expect(() => parseYoursWalletZip(zip)).toThrow('missing chromeStorage.json');
    });

    it('validates a parsed ZIP backup with the type guard', () => {
      const parsed = parseYoursWalletZip(buildV2Zip());
      expect(isYoursWalletZipBackup(parsed)).toBe(true);
    });

    it('rejects a non-object chromeStorage with the type guard', () => {
      expect(isYoursWalletZipBackup({ chromeStorage: 'not an object' } as never)).toBe(false);
    });

    it('encrypts and decrypts a parsed ZIP backup', async () => {
      const parsed = parseYoursWalletZip(buildV2Zip());
      parsed.label = 'Yours Wallet Full Backup';

      const encrypted = await encryptBackup(parsed, passphrase);
      expect(typeof encrypted).toBe('string');

      const decrypted = (await decryptBackup(encrypted, passphrase)) as YoursWalletZipBackup;
      expect(decrypted.createdAt).toBeDefined();
      const { createdAt, ...decryptedWithoutTimestamp } = decrypted;
      expect(decryptedWithoutTimestamp).toEqual(parsed);
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
        mnemonic:
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
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
