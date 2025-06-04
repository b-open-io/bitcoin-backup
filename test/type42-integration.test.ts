import { describe, expect, it } from 'bun:test';
import { PrivateKey } from '@bsv/sdk';
import { BAP } from '../../bap/src/index';
import { type BapMasterBackup, decryptBackup, encryptBackup } from '../src/index';

describe('Type 42 Integration with BAP', () => {
  const passphrase = 'super-secure-passphrase-42';

  it('should create, encrypt, and decrypt Type 42 backup from BAP', async () => {
    // 1. Generate a master key
    const rootPk = PrivateKey.fromRandom();
    const masterWif = rootPk.toWif();
    // 2. Create BAP instance with Type 42
    const bap = new BAP({
      rootPk: masterWif,
    });

    // 3. Create some identities
    const id1 = bap.newId();
    id1.setAttribute('name', 'Alice Test');
    id1.setAttribute('email', 'alice@test.com');

    const id2 = bap.newId();
    id2.setAttribute('name', 'Bob Test');

    // 4. Export as Type 42 backup (unified method)
    const backup = bap.exportForBackup('Integration Test Backup');

    // 5. Encrypt the backup
    const encrypted = await encryptBackup(backup, passphrase);

    // 6. Decrypt the backup
    const decrypted = (await decryptBackup(encrypted, passphrase)) as BapMasterBackup;

    // 7. Verify the backup structure
    expect(decrypted).toBeDefined();
    if ('rootPk' in decrypted) {
      expect(decrypted.rootPk).toBe(masterWif);
      expect(decrypted.label).toBe('Integration Test Backup');
      expect(decrypted.ids).toBeDefined();
      expect(typeof decrypted.ids).toBe('string');
    } else {
      throw new Error('Unexpected backup format');
    }

    // 8. Create new BAP instance from decrypted backup
    const bapRestored = new BAP({
      rootPk: decrypted.rootPk as string,
    });

    // 9. Import the encrypted IDs
    bapRestored.importIds(decrypted.ids, true);

    // 10. Verify we have the same identities
    const idKeys = bapRestored.listIds();
    expect(idKeys.length).toBe(2);

    // Check that we can retrieve the identities
    const restoredId1 = bapRestored.getId(idKeys[0]);
    expect(restoredId1).toBeDefined();
    if (restoredId1) {
      const attrs = restoredId1.getAttributes();
      // One of them should be Alice
      const hasAlice = Object.values(attrs).some((attr) => attr.value === 'Alice Test');
      expect(hasAlice).toBe(true);
    }
  });

  it('should handle mixed BIP32 and Type 42 backups', async () => {
    // Create a BIP32 backup
    const bip32Backup: BapMasterBackup = {
      ids: 'encrypted-bip32-ids',
      xprv: 'xprv9s21ZrQH143K4CwNNfZMtuZLSinrrbh6KUbJJgxLxPWpisKUWKYRrniPAjYRZbopxuzWNUMwuMj9VzWHfKw1yJ8Ktc4ZPPuFcrRqQ3EE3xW',
      mnemonic: 'test mnemonic phrase here',
    };

    // Create a Type 42 backup
    const type42Backup: BapMasterBackup = {
      ids: 'encrypted-type42-ids',
      rootPk: 'L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6',
      label: 'Test Type 42 Wallet',
    };

    // Both should encrypt successfully
    const encryptedBip32 = await encryptBackup(bip32Backup, passphrase);
    const encryptedType42 = await encryptBackup(type42Backup, passphrase);

    expect(encryptedBip32).toBeDefined();
    expect(encryptedType42).toBeDefined();
    expect(encryptedBip32).not.toBe(encryptedType42);

    // Both should decrypt to correct format
    const decryptedBip32 = (await decryptBackup(encryptedBip32, passphrase)) as BapMasterBackup;
    const decryptedType42 = (await decryptBackup(encryptedType42, passphrase)) as BapMasterBackup;

    // Check BIP32 format
    expect('xprv' in decryptedBip32).toBe(true);
    expect('mnemonic' in decryptedBip32).toBe(true);
    expect('rootPk' in decryptedBip32).toBe(false);

    // Check Type 42 format
    expect('rootPk' in decryptedType42).toBe(true);
    expect('label' in decryptedType42).toBe(true);
    expect('xprv' in decryptedType42).toBe(false);
  });

  it('should demonstrate migration scenario', async () => {
    // Start with BIP32 backup
    const oldBackup: BapMasterBackup = {
      ids: 'legacy-encrypted-ids',
      xprv: 'xprv9s21ZrQH143K4CwNNfZMtuZLSinrrbh6KUbJJgxLxPWpisKUWKYRrniPAjYRZbopxuzWNUMwuMj9VzWHfKw1yJ8Ktc4ZPPuFcrRqQ3EE3xW',
      mnemonic: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
      label: 'Legacy Wallet',
    };

    // User would need to:
    // 1. Restore from old backup
    // 2. Create new Type 42 identity
    // 3. Link old to new via ID transaction
    // 4. Create new Type 42 backup

    // This demonstrates the format difference
    const encryptedOld = await encryptBackup(oldBackup, passphrase);
    const decryptedOld = (await decryptBackup(encryptedOld, passphrase)) as BapMasterBackup;

    expect('xprv' in decryptedOld).toBe(true);
    expect('rootPk' in decryptedOld).toBe(false);

    // In real migration, user would extract the root key and create Type 42 backup
    // This is a one-way migration requiring explicit user action
  });
});
