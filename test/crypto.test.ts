import { describe, it, expect, beforeAll } from 'bun:test';
import {
  encryptData,
  decryptData,
  DEFAULT_PBKDF2_ITERATIONS,
  LEGACY_PBKDF2_ITERATIONS,
  RECOMMENDED_PBKDF2_ITERATIONS
} from '../src/crypto';
import type {
  DecryptedBackup,
  BapMasterBackup,
  BapMemberBackup,
  WifBackup,
  OneSatBackup,
  EncryptedBackup
} from '../src/interfaces';

// Mock crypto for Node.js environment if bun:test doesn't provide it globally
// or if specific parts of Web Crypto API need consistent mocking.
// For Bun, globalThis.crypto should generally be available.

describe('Crypto Functions', () => {
  const passphrase = 'strongtes!passphr@se';
  const veryShortPassphrase = 'short';

  // Test Payloads
  const masterBackupPayload: BapMasterBackup = {
    ids: 'testBapIdsString',
    xprv: 'xprv9s21ZrQH143K3QjYCBAdHguS7U8sAdvA9xTRB2g9tJorR9zaDmyLgBpHXjQJzV7G3V1kH6E1iG5fMaU5uY9mN1fK1aQ1eTzL9fN1pW2sXyZ',
    mnemonic: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
    label: 'Test Master Wallet'
  };

  const memberBackupPayload: BapMemberBackup = {
    wif: 'L156TApxcSCDGQgXRNahKiivZ57ZavGHREy1df4p6PuaRvXE3a1D',
    id: 'testMemberId',
    label: 'Test Member Wallet'
  };

  const wifBackupPayload: WifBackup = {
    wif: 'L4rprVahLjG4LWdULUeoxaVyq9chGQzg8kSVgSWfBrdeyAZs9VLo',
    label: 'Test WIF Wallet'
  };

  const wifOnlyPayload: WifBackup = {
    wif: 'L4rprVahLjG4LWdULUeoxaVyq9chGQzg8kSVgSWfBrdeyAZs9VLo' // Using a real WIF here too
  };

  const oneSatBackupPayload: OneSatBackup = {
    ordPk: 'KyMZUNynwhjevQQ4eQURisggnmkoQvcWNrWG8MPwztQALEzDEtCu',
    payPk: 'L156TApxcSCDGQgXRNahKiivZ57ZavGHREy1df4p6PuaRvXE3a1D',
    identityPk: 'L4rprVahLjG4LWdULUeoxaVyq9chGQzg8kSVgSWfBrdeyAZs9VLo',
    label: 'Test 1Sat Wallet'
  };

  describe('encryptData', () => {
    it('should encrypt a BapMasterBackup payload successfully', async () => {
      const encrypted = await encryptData(masterBackupPayload, passphrase);
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(50); // Basic check for non-empty, encoded string
    });

    it('should encrypt a BapMemberBackup payload successfully', async () => {
      const encrypted = await encryptData(memberBackupPayload, passphrase);
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(50);
    });

    it('should encrypt a WifBackup payload successfully', async () => {
      const encrypted = await encryptData(wifBackupPayload, passphrase);
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(50);
    });

    it('should encrypt a OneSatBackup payload successfully', async () => {
      const encrypted = await encryptData(oneSatBackupPayload, passphrase);
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(50);
    });

    it('should include createdAt if not provided in original payload', async () => {
      const encrypted = await encryptData(wifOnlyPayload, passphrase);
      const decrypted = await decryptData(encrypted, passphrase) as WifBackup;
      expect(decrypted.createdAt).toBeDefined();
      expect(typeof decrypted.createdAt).toBe('string');
    });

    it('should use provided createdAt if present in original payload', async () => {
      const specificDate = new Date().toISOString();
      const payloadWithDate: WifBackup = { ...wifOnlyPayload, createdAt: specificDate };
      const encrypted = await encryptData(payloadWithDate, passphrase);
      const decrypted = await decryptData(encrypted, passphrase) as WifBackup;
      expect(decrypted.createdAt).toBe(specificDate);
    });

    it('should use RECOMMENDED_PBKDF2_ITERATIONS when iterations are not specified', async () => {
      const encrypted = await encryptData(masterBackupPayload, passphrase);
      
      // Decrypt with wrong (legacy) iterations - should fail
      await expect(decryptData(encrypted, passphrase, LEGACY_PBKDF2_ITERATIONS))
        .rejects.toThrow(/Decryption failed: Invalid passphrase or corrupted data/);
      
      // Decrypt with recommended iterations - should succeed
      const decrypted = await decryptData(encrypted, passphrase, RECOMMENDED_PBKDF2_ITERATIONS);
      expect((decrypted as BapMasterBackup).xprv).toBe(masterBackupPayload.xprv);
      
      const decryptedWithDefault = await decryptData(encrypted, passphrase, DEFAULT_PBKDF2_ITERATIONS);
      expect((decryptedWithDefault as BapMasterBackup).xprv).toBe(masterBackupPayload.xprv);

      const decryptedAuto = await decryptData(encrypted, passphrase);
      expect((decryptedAuto as BapMasterBackup).xprv).toBe(masterBackupPayload.xprv);
    });

    it('should use specified iterations during encryption (e.g., legacy)', async () => {
      const encrypted = await encryptData(masterBackupPayload, passphrase, LEGACY_PBKDF2_ITERATIONS);
      
      // Decrypt with wrong (recommended) iterations - should fail
      await expect(decryptData(encrypted, passphrase, RECOMMENDED_PBKDF2_ITERATIONS))
        .rejects.toThrow(/Decryption failed: Invalid passphrase or corrupted data/);
      
      // Decrypt with specified (legacy) iterations - should succeed
      const decrypted = await decryptData(encrypted, passphrase, LEGACY_PBKDF2_ITERATIONS);
      expect((decrypted as BapMasterBackup).xprv).toBe(masterBackupPayload.xprv);
    });
  });

  describe('decryptData', () => {
    it('should correctly decrypt an encrypted BapMasterBackup payload', async () => {
      const encrypted = await encryptData(masterBackupPayload, passphrase);
      const decrypted = await decryptData(encrypted, passphrase) as BapMasterBackup;
      expect(decrypted.ids).toBe(masterBackupPayload.ids);
      expect(decrypted.xprv).toBe(masterBackupPayload.xprv);
      expect(decrypted.mnemonic).toBe(masterBackupPayload.mnemonic);
      if (masterBackupPayload.label) {
        expect(decrypted.label).toBe(masterBackupPayload.label);
      }
      expect(decrypted.createdAt).toBeDefined();
    });

    it('should correctly decrypt an encrypted BapMemberBackup payload', async () => {
      const encrypted = await encryptData(memberBackupPayload, passphrase);
      const decrypted = await decryptData(encrypted, passphrase) as BapMemberBackup;
      expect(decrypted.wif).toBe(memberBackupPayload.wif);
      expect(decrypted.id).toBe(memberBackupPayload.id);
      if (memberBackupPayload.label) {
        expect(decrypted.label).toBe(memberBackupPayload.label);
      }
      expect(decrypted.createdAt).toBeDefined();
    });

    it('should correctly decrypt an encrypted WifBackup payload', async () => {
      const encrypted = await encryptData(wifBackupPayload, passphrase);
      const decrypted = await decryptData(encrypted, passphrase) as WifBackup;
      expect(decrypted.wif).toBe(wifBackupPayload.wif);
      if (wifBackupPayload.label) {
        expect(decrypted.label).toBe(wifBackupPayload.label);
      }
      expect(decrypted.createdAt).toBeDefined();
    });

    it('should correctly decrypt an encrypted OneSatBackup payload', async () => {
      const encrypted = await encryptData(oneSatBackupPayload, passphrase);
      const decrypted = await decryptData(encrypted, passphrase) as OneSatBackup;
      expect(decrypted.ordPk).toBe(oneSatBackupPayload.ordPk);
      expect(decrypted.payPk).toBe(oneSatBackupPayload.payPk);
      expect(decrypted.identityPk).toBe(oneSatBackupPayload.identityPk);
      if (oneSatBackupPayload.label) {
        expect(decrypted.label).toBe(oneSatBackupPayload.label);
      }
      expect(decrypted.createdAt).toBeDefined();
    });

    it('should throw an error for incorrect passphrase', async () => {
      const encrypted = await encryptData(wifBackupPayload, passphrase);
      await expect(decryptData(encrypted, 'wrongPassphrase123')).rejects.toThrow(
        /Decryption failed: Invalid passphrase or corrupted data/
      );
    });

    it('should throw an error for corrupted encrypted data (e.g., truncated)', async () => {
      let encrypted = await encryptData(wifBackupPayload, passphrase);
      encrypted = encrypted.substring(0, encrypted.length - 10); // Simulate corruption
      await expect(decryptData(encrypted, passphrase)).rejects.toThrow(); // Error message might vary
    });

    it('should throw an error for too short encrypted data', async () => {
      const shortData = 'shortdata';
      await expect(decryptData(shortData, passphrase)).rejects.toThrow(
        'Decryption failed: Encrypted data is too short.'
      );
    });
    
    it('should throw an error for malformed Base64 input', async () => {
      const malformedBase64 = 'NotValidBase64%%%***'; // This might be partially decoded by a lenient decoder
      // If the lenient decoder produces a short array, our length check will catch it.
      await expect(decryptData(malformedBase64, passphrase)).rejects.toThrow(
        'Decryption failed: Encrypted data is too short.' // Adjusted expectation
      );
    });

    // Test for legacy WIF decryption
    it('should correctly decrypt a legacy raw WIF string (manually encrypted for test with LEGACY_PBKDF2_ITERATIONS)', async () => {
      const rawWifToEncrypt = "L2rU9j3aVEdYdYgA9ZqA5tN6cZ7fJ2sK8gL9dYhW3xS7jN5pQdG2";
      const passphraseForLegacyTest = "legacyPass123";

      const salt = crypto.getRandomValues(new Uint8Array(16));
      const keyMaterialForLegacy = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(passphraseForLegacyTest),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      );
      const derivedKeyForLegacy = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: LEGACY_PBKDF2_ITERATIONS, hash: 'SHA-256' }, // Using LEGACY
        keyMaterialForLegacy,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );

      // 2. Encrypt the raw WIF bytes
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encodedWifBytes = new TextEncoder().encode(rawWifToEncrypt);
      const encryptedRawWifContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        derivedKeyForLegacy,
        encodedWifBytes
      );

      // 3. Concatenate salt, IV, ciphertext
      const combinedOutput = new Uint8Array(salt.length + iv.length + encryptedRawWifContent.byteLength);
      combinedOutput.set(salt, 0);
      combinedOutput.set(iv, salt.length);
      combinedOutput.set(new Uint8Array(encryptedRawWifContent), salt.length + iv.length);

      // 4. Base64 encode - using btoa for this direct binary to base64 for simplicity in test setup
      // This mirrors how old systems might have done it if not using a robust library.
      const legacyEncryptedWifForTest = btoa(String.fromCharCode.apply(null, Array.from(combinedOutput)));

      // 5. Decrypt using our library's decryptData
      const decrypted = await decryptData(legacyEncryptedWifForTest, passphraseForLegacyTest);

      expect(decrypted).toBeDefined();
      if ('wif' in decrypted && !('id' in decrypted) && !('mnemonic' in decrypted)) {
        const wifBackup = decrypted as WifBackup;
        expect(wifBackup.wif).toBe(rawWifToEncrypt);
        expect(wifBackup.label).toBeUndefined();
        expect(wifBackup.createdAt).toBeUndefined(); // Legacy raw WIFs won't have these fields
      } else {
        throw new Error('Decrypted data was not a simple WIF backup as expected for legacy test.');
      }
    });

    let encryptedWithDefaultIterations: EncryptedBackup;
    let encryptedWithLegacyIterations: EncryptedBackup;
    let encryptedOneSatBackup: EncryptedBackup;

    beforeAll(async () => {
      encryptedWithDefaultIterations = await encryptData(wifBackupPayload, passphrase, RECOMMENDED_PBKDF2_ITERATIONS);
      encryptedWithLegacyIterations = await encryptData(wifBackupPayload, passphrase, LEGACY_PBKDF2_ITERATIONS);
      encryptedOneSatBackup = await encryptData(oneSatBackupPayload, passphrase, RECOMMENDED_PBKDF2_ITERATIONS);
    });

    it('should decrypt with specified correct recommended iterations', async () => {
      const decrypted = await decryptData(encryptedWithDefaultIterations, passphrase, RECOMMENDED_PBKDF2_ITERATIONS);
      expect((decrypted as WifBackup).wif).toBe(wifBackupPayload.wif);
    });

    it('should decrypt with specified correct legacy iterations', async () => {
      const decrypted = await decryptData(encryptedWithLegacyIterations, passphrase, LEGACY_PBKDF2_ITERATIONS);
      expect((decrypted as WifBackup).wif).toBe(wifBackupPayload.wif);
    });

    it('should correctly decrypt OneSatBackup with specified correct iterations', async () => {
      const decrypted = await decryptData(encryptedOneSatBackup, passphrase, RECOMMENDED_PBKDF2_ITERATIONS);
      expect((decrypted as OneSatBackup).identityPk).toBe(oneSatBackupPayload.identityPk);
    });

    it('should fail decryption if specified iterations are wrong for recommended encryption', async () => {
      await expect(decryptData(encryptedWithDefaultIterations, passphrase, LEGACY_PBKDF2_ITERATIONS))
        .rejects.toThrow(/Decryption failed: Invalid passphrase or corrupted data/);
    });

    it('should auto-try recommended, then legacy iterations if none specified (recommended success)', async () => {
      const decrypted = await decryptData(encryptedWithDefaultIterations, passphrase);
      expect((decrypted as WifBackup).wif).toBe(wifBackupPayload.wif);
    });

    it('should auto-try recommended, then legacy iterations if none specified (legacy success)', async () => {
      const decrypted = await decryptData(encryptedWithLegacyIterations, passphrase);
      expect((decrypted as WifBackup).wif).toBe(wifBackupPayload.wif);
    });

    it('should auto-try and correctly decrypt OneSatBackup (recommended success)', async () => {
      const decrypted = await decryptData(encryptedOneSatBackup, passphrase);
      expect((decrypted as OneSatBackup).payPk).toBe(oneSatBackupPayload.payPk);
    });

    it('should decrypt with an array of iteration counts, succeeding on the correct one', async () => {
      const decryptedRecommend = await decryptData(encryptedWithDefaultIterations, passphrase, [LEGACY_PBKDF2_ITERATIONS, RECOMMENDED_PBKDF2_ITERATIONS]);
      expect((decryptedRecommend as WifBackup).wif).toBe(wifBackupPayload.wif);
      
      const decryptedLegacy = await decryptData(encryptedWithLegacyIterations, passphrase, [RECOMMENDED_PBKDF2_ITERATIONS, LEGACY_PBKDF2_ITERATIONS]);
      expect((decryptedLegacy as WifBackup).wif).toBe(wifBackupPayload.wif);

      const decryptedOneSat = await decryptData(encryptedOneSatBackup, passphrase, [LEGACY_PBKDF2_ITERATIONS, RECOMMENDED_PBKDF2_ITERATIONS]);
      expect((decryptedOneSat as OneSatBackup).identityPk).toBe(oneSatBackupPayload.identityPk);
    });

    it('should fail if all iteration counts in an array are incorrect', async () => {
      await expect(decryptData(encryptedWithDefaultIterations, passphrase, [1000, 2000]))
        .rejects.toThrow(); // General decryption failure message
    });
  });
}); 