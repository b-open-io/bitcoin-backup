import { describe, expect, it } from 'bun:test';
import { decryptBackup, encryptBackup } from '../src/index';
import type { VaultBackup } from '../src/interfaces';

describe('VaultBackup', () => {
  const passphrase = 'strongBackupPassphrase!123';

  // Simulate a vault that's already been encrypted by an application
  // The application handles its own encryption - we just backup the encrypted blob
  const mockEncryptedVault = 'application-encrypted-vault-data-base64-or-hex';

  const vaultBackupPayload: VaultBackup = {
    encryptedVault: mockEncryptedVault,
    scheme: 'vscode-bitcoin-v1',
    label: 'My Bitcoin Vault',
  };

  const minimalVaultBackup: VaultBackup = {
    encryptedVault: mockEncryptedVault,
  };

  describe('encryptBackup', () => {
    it('should encrypt a VaultBackup payload successfully', async () => {
      const encrypted = await encryptBackup(vaultBackupPayload, passphrase);
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(50);
    });

    it('should encrypt a minimal VaultBackup (only encryptedVault field)', async () => {
      const encrypted = await encryptBackup(minimalVaultBackup, passphrase);
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(50);
    });

    it('should add createdAt timestamp if not provided', async () => {
      const encrypted = await encryptBackup(minimalVaultBackup, passphrase);
      const decrypted = (await decryptBackup(encrypted, passphrase)) as VaultBackup;
      expect(decrypted.createdAt).toBeDefined();
      expect(typeof decrypted.createdAt).toBe('string');
    });

    it('should preserve createdAt if provided', async () => {
      const specificDate = new Date().toISOString();
      const payloadWithDate: VaultBackup = {
        ...minimalVaultBackup,
        createdAt: specificDate,
      };
      const encrypted = await encryptBackup(payloadWithDate, passphrase);
      const decrypted = (await decryptBackup(encrypted, passphrase)) as VaultBackup;
      expect(decrypted.createdAt).toBe(specificDate);
    });
  });

  describe('decryptBackup', () => {
    it('should correctly decrypt an encrypted VaultBackup payload', async () => {
      const encrypted = await encryptBackup(vaultBackupPayload, passphrase);
      const decrypted = (await decryptBackup(encrypted, passphrase)) as VaultBackup;

      expect(decrypted.encryptedVault).toBe(vaultBackupPayload.encryptedVault);
      expect(decrypted.scheme).toBe(vaultBackupPayload.scheme);
      expect(decrypted.label).toBe(vaultBackupPayload.label);
      expect(decrypted.createdAt).toBeDefined();
    });

    it('should correctly decrypt a minimal VaultBackup', async () => {
      const encrypted = await encryptBackup(minimalVaultBackup, passphrase);
      const decrypted = (await decryptBackup(encrypted, passphrase)) as VaultBackup;

      expect(decrypted.encryptedVault).toBe(minimalVaultBackup.encryptedVault);
      expect(decrypted.createdAt).toBeDefined();
    });

    it('should throw an error for incorrect passphrase', async () => {
      const encrypted = await encryptBackup(vaultBackupPayload, passphrase);
      await expect(decryptBackup(encrypted, 'wrongPassphrase123')).rejects.toThrow(
        /Decryption failed: Invalid passphrase or corrupted data/
      );
    });

    it('should preserve all optional fields during round-trip', async () => {
      const fullPayload: VaultBackup = {
        encryptedVault: mockEncryptedVault,
        scheme: 'custom-vault-v2',
        label: 'Test Vault',
        createdAt: '2024-01-01T00:00:00.000Z',
      };

      const encrypted = await encryptBackup(fullPayload, passphrase);
      const decrypted = (await decryptBackup(encrypted, passphrase)) as VaultBackup;

      expect(decrypted.encryptedVault).toBe(fullPayload.encryptedVault);
      expect(decrypted.scheme).toBe(fullPayload.scheme);
      expect(decrypted.label).toBe(fullPayload.label);
      expect(decrypted.createdAt).toBe(fullPayload.createdAt);
    });
  });

  describe('Type detection', () => {
    it('should correctly identify VaultBackup type', async () => {
      const encrypted = await encryptBackup(vaultBackupPayload, passphrase);
      const decrypted = await decryptBackup(encrypted, passphrase);

      // Type detection: VaultBackup has encryptedVault field
      expect('encryptedVault' in decrypted).toBe(true);

      // Should NOT have fields from other backup types
      expect('wif' in decrypted).toBe(false);
      expect('xprv' in decrypted).toBe(false);
      expect('ordPk' in decrypted).toBe(false);
    });
  });

  describe('Double encryption model', () => {
    it('should demonstrate independent passwords for vault and backup', async () => {
      // This test documents the double encryption workflow

      const _vaultPassword = 'vault-password-123';
      const backupPassword = 'backup-password-456';

      // Step 1: Application already encrypted vault with vaultPassword
      //         (simulated by mockEncryptedVault)
      // Step 2: bitcoin-backup encrypts the VaultBackup object with backupPassword
      const backupEncrypted = await encryptBackup(vaultBackupPayload, backupPassword);

      // Step 3: Decrypt backup with backupPassword
      const backupDecrypted = (await decryptBackup(backupEncrypted, backupPassword)) as VaultBackup;

      // Step 4: Application would then decrypt vault with vaultPassword
      //         (not tested here - that's application's responsibility)
      expect(backupDecrypted.encryptedVault).toBe(mockEncryptedVault);

      // The vault remains encrypted - only the backup layer has been decrypted
      expect(backupDecrypted.encryptedVault).not.toContain('plaintext');
    });

    it('should preserve vault encryption through backup encryption', async () => {
      const encrypted = await encryptBackup(vaultBackupPayload, passphrase);
      const decrypted = (await decryptBackup(encrypted, passphrase)) as VaultBackup;

      // Application's encrypted vault should be preserved exactly
      expect(decrypted.encryptedVault).toBe(vaultBackupPayload.encryptedVault);
    });
  });
});
