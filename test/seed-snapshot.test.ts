import { expect, test } from 'bun:test';
import { decryptBackup, encryptBackup, type SigmaSeedBackup } from '../src/index';

test('encryption snapshots the seed inventory before asynchronous key derivation', async () => {
  const backup: SigmaSeedBackup = {
    format: 'sigma-seed',
    version: 1,
    mnemonic:
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    profiles: [{ index: 0, bapId: 'public-test-profile', metadata: { name: 'Original' } }],
    nextProfileIndex: 1,
    createdAt: 0,
  };
  const original = structuredClone(backup);
  const pending = encryptBackup(backup, 'public-test-password', 1);
  backup.profiles[0].metadata!.name = 'Changed';
  backup.profiles.length = 0;
  expect(await decryptBackup(await pending, 'public-test-password', 1)).toEqual(original);
});
