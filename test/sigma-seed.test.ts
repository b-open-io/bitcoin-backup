import { describe, expect, it } from 'bun:test';
import {
  type DecryptedBackup,
  decryptBackup,
  encryptBackup,
  getBackupType,
  isAccountBackup,
  isLegacyBackup,
  isMasterBackup,
  isSigmaSeedBackup,
  isType42Backup,
  isWifBackup,
  type SigmaSeedBackup,
} from '../src/index';
import { decryptData as legacyDecrypt } from './fixtures/legacy-reader';

// Public BIP39 all-zero entropy vector. Never use for real keys.
const seed: SigmaSeedBackup = {
  format: 'sigma-seed',
  version: 1,
  mnemonic:
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  profiles: [
    {
      index: 0,
      bapId: 'public-test-profile',
      metadata: { name: 'Example', nested: [null, true, 1] },
    },
  ],
  nextProfileIndex: 1,
  createdAt: 0,
};
const password = 'public-test-password';

// Encrypt unvalidated JSON to exercise the untrusted decrypted payload boundary.
async function rawEncrypted(payload: unknown): Promise<string> {
  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 1, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(payload))
  );
  return Buffer.concat([salt, iv, new Uint8Array(ciphertext)]).toString('base64');
}

describe('Sigma seed envelope', () => {
  it('preserves legacy payloads under both new and frozen old readers', async () => {
    const fixtures: Exclude<DecryptedBackup, SigmaSeedBackup>[] = [
      { rootPk: 'public-structural-fixture', ids: 'public-ids' },
      { xprv: 'public-structural-fixture', mnemonic: 'legacy mnemonic', ids: 'public-ids' },
      { wif: 'public-structural-fixture', id: 'public-id' },
      { wif: 'public-structural-fixture' },
      { ordPk: 'public-ord', payPk: 'public-pay', identityPk: 'public-identity' },
      { encryptedVault: 'public-vault' },
    ];
    for (const fixture of fixtures) {
      const payload = { ...fixture, createdAt: '2026-01-01T00:00:00.000Z' };
      const ciphertext = await encryptBackup(payload, password, 1);
      expect(await decryptBackup(ciphertext, password, 1)).toEqual(payload);
      expect(await legacyDecrypt(ciphertext, password, 1)).toEqual(payload);
    }
  });

  it('is rejected by the frozen pre-seed reader after successful decryption', async () => {
    const ciphertext = await encryptBackup(seed, password, 1);
    await expect(legacyDecrypt(ciphertext, password, 1)).rejects.toThrow(
      'Invalid backup structure after JSON parse.'
    );
  });

  it('round trips with default encryption and preserves numeric createdAt zero and JSON metadata', async () => {
    const restored = await decryptBackup(await encryptBackup(seed, password), password);
    expect(restored).toEqual(seed);
    expect(isSigmaSeedBackup(restored)).toBe(true);
    expect(isMasterBackup(restored)).toBe(false);
    expect(getBackupType(restored)).toBe('SigmaSeed');
  });

  it('supports all mnemonic word counts and hardened peer indices', () => {
    for (const wordCount of [12, 15, 18, 21, 24]) {
      expect(
        isSigmaSeedBackup({
          ...seed,
          mnemonic: Array(wordCount).fill('abandon').join(' '),
        })
      ).toBe(true);
    }
    expect(isSigmaSeedBackup({ ...seed, profiles: [], nextProfileIndex: 0 })).toBe(false);
    expect(isSigmaSeedBackup({ ...seed, createdAt: 0.5 })).toBe(false);
    expect(
      isSigmaSeedBackup({
        ...seed,
        profiles: [{ index: 2147483647, bapId: 'final-peer' }],
        nextProfileIndex: 2147483648,
      })
    ).toBe(true);
    expect(
      isSigmaSeedBackup({
        ...seed,
        profiles: [{ index: 2147483646, bapId: 'last-available' }],
        nextProfileIndex: 2147483647,
      })
    ).toBe(true);
  });

  const malformed: Record<string, unknown>[] = [
    { ...seed, version: 2 },
    { ...seed, format: 'future-seed' },
    { ...seed, scheme: 'unknown' },
    { ...seed, scheme: 'brc157-peer-profiles' },
    { ...seed, passphrasePolicy: 'empty' },
    { ...seed, entropyBytes: 16 },
    { ...seed, passphrasePolicy: 'optional' },
    { ...seed, rootPk: 'legacy-root', ids: 'legacy-ids' },
    { ...seed, xprv: 'legacy-root', ids: 'legacy-ids' },
    { ...seed, wif: 'legacy-key' },
    { ...seed, encryptedVault: 'legacy-vault' },
    { ...seed, unexpected: true },
    { ...seed, entropyBytes: 17 },
    { ...seed, mnemonic: 'abandon' },
    { ...seed, createdAt: '2026-01-01' },
    { ...seed, createdAt: -1 },
    { ...seed, nextProfileIndex: 0 },
    { ...seed, nextProfileIndex: 2147483649 },
    { ...seed, profiles: [{ index: 0.5, bapId: 'test' }] },
    { ...seed, profiles: [{ index: -1, bapId: 'test' }] },
    { ...seed, profiles: [{ index: 2147483648, bapId: 'test' }] },
    { ...seed, profiles: [{ index: 0, bapId: '' }] },
    { ...seed, profiles: [{ index: 0, bapId: 'test', metadata: [] }] },
    { ...seed, profiles: [{ index: 0, bapId: 'test', path: "m/0'/0'" }] },
    {
      ...seed,
      profiles: [
        { index: 0, bapId: 'one' },
        { index: 0, bapId: 'two' },
      ],
    },
    {
      ...seed,
      profiles: [
        { index: 0, bapId: 'one' },
        { index: 1, bapId: 'one' },
      ],
      nextProfileIndex: 2,
    },
  ];
  for (const [i, payload] of malformed.entries()) {
    it(`rejects malformed envelope ${i} at encryption and decryption boundaries`, async () => {
      expect(isSigmaSeedBackup(payload)).toBe(false);
      await expect(
        encryptBackup(payload as unknown as DecryptedBackup, password, 1)
      ).rejects.toThrow();
      await expect(decryptBackup(await rawEncrypted(payload), password, 1)).rejects.toThrow();
    });
  }

  const incompleteMarkers = [
    { format: 'unknown-seed-format' },
    { scheme: 'unknown-seed-scheme' },
    { profiles: [] },
    { nextProfileIndex: 0 },
    { entropyBytes: 16 },
    { passphrasePolicy: 'unknown' },
    { format: null },
    { scheme: null },
  ];
  const legacySources: DecryptedBackup[] = [
    { rootPk: 'public-root-fixture', ids: 'public-ids' },
    { xprv: 'public-xprv-fixture', mnemonic: 'legacy words', ids: 'public-ids' },
    { wif: 'public-member-fixture', id: 'public-member-id' },
    { wif: 'public-wif-fixture' },
  ];
  for (const [sourceIndex, source] of legacySources.entries()) {
    for (const marker of incompleteMarkers) {
      it(`rejects incomplete ${Object.keys(marker)[0]} marker mixed with legacy source ${sourceIndex}`, async () => {
        const mixed = { ...source, ...marker };
        expect(isSigmaSeedBackup(mixed)).toBe(false);
        for (const guard of [
          isLegacyBackup,
          isType42Backup,
          isMasterBackup,
          isAccountBackup,
          isWifBackup,
        ]) {
          expect(guard(mixed as unknown as DecryptedBackup)).toBe(false);
        }
        expect(getBackupType(mixed as unknown as DecryptedBackup)).toBe('Unknown');
        await expect(
          encryptBackup(mixed as unknown as DecryptedBackup, password, 1)
        ).rejects.toThrow();
        await expect(decryptBackup(await rawEncrypted(mixed), password, 1)).rejects.toThrow();
      });
    }
  }

  it('rejects non-JSON metadata before encryption', async () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    for (const metadata of [{ number: Number.NaN }, { missing: undefined }, cycle, new Date()]) {
      expect(
        isSigmaSeedBackup({ ...seed, profiles: [{ index: 0, bapId: 'test', metadata }] })
      ).toBe(false);
    }
  });
});

describe('partial seed inventory', () => {
  it('round-trips the explicit incomplete inventory marker', async () => {
    const partial: SigmaSeedBackup = { ...seed, inventoryComplete: false };
    expect(isSigmaSeedBackup(partial)).toBe(true);
    expect(
      await decryptBackup(await encryptBackup(partial, 'test-password'), 'test-password')
    ).toEqual(partial);
  });
  it.each([
    true,
    'false',
    null,
    0,
  ])('rejects invalid inventoryComplete %p', async (inventoryComplete) => {
    const invalid = { ...seed, inventoryComplete };
    expect(isSigmaSeedBackup(invalid)).toBe(false);
    await expect(
      encryptBackup(invalid as unknown as SigmaSeedBackup, 'test-password')
    ).rejects.toThrow();
  });
  it('reserves the marker on legacy payloads', async () => {
    await expect(
      encryptBackup(
        { rootPk: 'fixture', ids: '', inventoryComplete: false } as unknown as SigmaSeedBackup,
        'test-password'
      )
    ).rejects.toThrow();
  });
});
