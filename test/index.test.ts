import { describe, it, expect, beforeAll } from 'bun:test';
import {
  encryptBackup,
  decryptBackup,
  // Import a payload type for testing invalid scenarios
  type BapMasterBackup,
  type OneSatBackup // Added OneSatBackup for testing
} from '../src/index'; // Test the public API

describe('Public API Functions (index.ts)', () => {
  const validPassphrase = 'aSecureP@ssw0rd';
  const masterPayload: BapMasterBackup = {
    ids: 'masterIds',
    xprv: 'masterXprv',
    mnemonic: 'master mnemonic phrase words a dozen or so here please and thank you'
  };
  const oneSatPayload: OneSatBackup = {
    ordPk: 'KyMZUNynwhjevQQ4eQURisggnmkoQvcWNrWG8MPwztQALEzDEtCu',
    payPk: 'L156TApxcSCDGQgXRNahKiivZ57ZavGHREy1df4p6PuaRvXE3a1D',
    identityPk: 'L4rprVahLjG4LWdULUeoxaVyq9chGQzg8kSVgSWfBrdeyAZs9VLo',
    label: 'Test 1Sat API'
  };
  // A payload that is an object but doesn't match any known structure
  const invalidStructurePayload = { some: 'data', not: 'aBackup' };
  let encryptedMasterString: string;
  let encryptedOneSatString: string;

  // Use beforeAll to ensure validEncryptedString is set before tests that need it
  beforeAll(async () => {
    encryptedMasterString = await encryptBackup(masterPayload, validPassphrase);
    encryptedOneSatString = await encryptBackup(oneSatPayload, validPassphrase);
  });

  describe('encryptBackup input validation', () => {
    it('should throw if payload is not a valid known structure', async () => {
      await expect(
        // @ts-expect-error Testing invalid payload type
        encryptBackup(invalidStructurePayload, validPassphrase)
      ).rejects.toThrow(
        'Invalid payload: Payload must be an object matching BapMasterBackup, BapMemberBackup, WifBackup, or OneSatBackup structure.'
      );
    });

    it('should throw if payload is null', async () => {
      await expect(
        // @ts-expect-error Testing invalid payload type
        encryptBackup(null, validPassphrase)
      ).rejects.toThrow(
        'Invalid payload: Payload must be an object matching BapMasterBackup, BapMemberBackup, WifBackup, or OneSatBackup structure.'
      );
    });

    it('should throw if payload is not an object', async () => {
      await expect(
        // @ts-expect-error Testing invalid payload type
        encryptBackup("not an object", validPassphrase)
      ).rejects.toThrow(
        'Invalid payload: Payload must be an object matching BapMasterBackup, BapMemberBackup, WifBackup, or OneSatBackup structure.'
      );
    });

    it('should accept a valid OneSatBackup payload', async () => {
      await expect(encryptBackup(oneSatPayload, validPassphrase)).resolves.toBeString();
    });

    it('should throw if passphrase is not a string', async () => {
      await expect(
        // @ts-expect-error Testing invalid passphrase type
        encryptBackup(masterPayload, 12345)
      ).rejects.toThrow('Invalid passphrase: Passphrase must be a non-empty string.');
    });

    it('should throw if passphrase is an empty string', async () => {
      await expect(
        encryptBackup(masterPayload, '')
      ).rejects.toThrow('Invalid passphrase: Passphrase must be a non-empty string.');
    });

    it('should throw if passphrase is too short (less than 8 characters)', async () => {
      await expect(encryptBackup(masterPayload, 'shortp')).rejects.toThrow(
        'Invalid passphrase: Passphrase must be at least 8 characters long.'
      );
    });

    it('should not throw for passphrase length if it meets minimum (8 characters)', async () => {
      try {
        await encryptBackup(masterPayload, 'eightchr'); // 8 characters
        // If it doesn't throw, the test passes for this specific validation
      } catch (e: unknown) {
        // We only care about the passphrase length error for this test
        if (e instanceof Error && e.message.includes('at least 8 characters')) {
          throw e; // Re-throw if it IS the error we are testing against (but shouldn't be)
        }
        // Ignore other errors that might occur after this validation (e.g., from encryptData itself if mocks fail)
      }
    });
  });

  describe('decryptBackup input validation', () => {
    it('should throw if encryptedString is not a string', async () => {
      await expect(
        // @ts-expect-error Testing invalid encryptedString type
        decryptBackup(12345, validPassphrase)
      ).rejects.toThrow('Invalid encryptedString: Must be a non-empty string.');
    });

    it('should throw if encryptedString is an empty string', async () => {
      await expect(
        decryptBackup('', validPassphrase)
      ).rejects.toThrow('Invalid encryptedString: Must be a non-empty string.');
    });

    it('should throw if passphrase is not a string for decrypt', async () => {
      await expect(
        // @ts-expect-error Testing invalid passphrase type
        decryptBackup(encryptedMasterString, 12345)
      ).rejects.toThrow('Invalid passphrase: Passphrase must be a non-empty string.');
    });

    it('should throw if passphrase is an empty string for decrypt', async () => {
      await expect(
        decryptBackup(encryptedMasterString, '')
      ).rejects.toThrow('Invalid passphrase: Passphrase must be a non-empty string.');
    });

    // Core decryption logic (correct passphrase, corrupted data, etc.) is tested in crypto.test.ts
    // This suite focuses on the input validation of the public API wrapper.
    it('should call decryptData for valid inputs (smoke test for BapMasterBackup)', async () => {
      const decrypted = await decryptBackup(encryptedMasterString, validPassphrase);
      expect(decrypted).toBeDefined();
      expect((decrypted as BapMasterBackup).ids).toBe(masterPayload.ids);
    });

    it('should call decryptData for valid inputs (smoke test for OneSatBackup)', async () => {
      const decrypted = await decryptBackup(encryptedOneSatString, validPassphrase);
      expect(decrypted).toBeDefined();
      expect((decrypted as OneSatBackup).ordPk).toBe(oneSatPayload.ordPk);
      expect((decrypted as OneSatBackup).payPk).toBe(oneSatPayload.payPk);
      expect((decrypted as OneSatBackup).identityPk).toBe(oneSatPayload.identityPk);
    });
  });
}); 