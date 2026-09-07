import { afterAll, beforeAll, expect, test } from 'bun:test';
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { version } from '../package.json';
import { type DecryptedBackup, decryptBackup, getBackupType } from '../src/index';

const password = 'public-cli-test-password';
const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const seed = {
  format: 'sigma-seed',
  version: 1,
  mnemonic,
  profiles: [
    { index: 7, bapId: 'public-profile', metadata: { name: 'Public', nested: [true, null, 3] } },
  ],
  nextProfileIndex: 8,
  createdAt: 0,
  label: 'Public fixture',
};
let directory: string;
const cli = resolve('dist/cli/bbackup.js');
async function run(...args: string[]) {
  const child = Bun.spawn([process.execPath, cli, ...args], { stdout: 'pipe', stderr: 'pipe' });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { code, stdout, stderr };
}
beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'bitcoin-backup-cli-'));
  const build = Bun.spawn([process.execPath, 'run', 'build'], { stdout: 'pipe', stderr: 'pipe' });
  const [code, stdout, stderr] = await Promise.all([
    build.exited,
    new Response(build.stdout).text(),
    new Response(build.stderr).text(),
  ]);
  if (code) throw new Error(`CLI build failed: ${stdout}${stderr}`);
}, 30000);
afterAll(async () => {
  if (directory) await rm(directory, { recursive: true, force: true });
});

test('built CLI reports package version and all command help', async () => {
  expect((await run('--version')).stdout.trim()).toBe(version);
  for (const command of ['enc', 'dec', 'upg', 'forget'])
    expect((await run(command, '--help')).code).toBe(0);
});

for (const partial of [false, true]) {
  test(`built seed CLI roundtrip/upgrade preserves ${partial ? 'partial' : 'complete'} inventory`, async () => {
    const payload = { ...seed, ...(partial ? { inventoryComplete: false } : {}) };
    const input = join(directory, `seed-${partial}.json`);
    const encrypted = join(directory, `seed-${partial}.bep`);
    const output = join(directory, `seed-${partial}-output.json`);
    const upgraded = join(directory, `seed-${partial}-upgraded.bep`);
    await writeFile(input, JSON.stringify(payload));
    const enc = await run('enc', input, '-p', password, '-t', '2', '-o', encrypted);
    expect(enc.code).toBe(0);
    expect(enc.stdout + enc.stderr).not.toContain(mnemonic);
    expect(enc.stdout + enc.stderr).not.toContain(password);
    await writeFile(output, 'old output');
    await chmod(output, 0o644);
    const dec = await run('dec', encrypted, '-p', password, '-t', '2', '-o', output);
    expect(dec.code).toBe(0);
    expect(dec.stdout + dec.stderr).not.toContain(mnemonic);
    expect(JSON.parse(await readFile(output, 'utf8'))).toEqual(payload);
    expect((await stat(output)).mode & 0o777).toBe(0o600);
    expect(getBackupType(JSON.parse(await readFile(output, 'utf8')))).toBe('SigmaSeed');
    expect((await run('upg', encrypted, '-p', password, '-t', '2', '-o', upgraded)).code).toBe(0);
    expect(await decryptBackup(await readFile(upgraded, 'utf8'), password)).toEqual(payload);
    const printed = await run('dec', upgraded, '-p', password);
    expect(printed.code).toBe(0);
    expect(printed.stdout).toContain(mnemonic);
  }, 15000);
}

test('built CLI rejects malformed seeds, removed fields and secret-bearing malformed JSON without outputs', async () => {
  const input = join(directory, 'invalid.json');
  const output = join(directory, 'must-not-write.bep');
  for (const payload of [
    { ...seed, version: 2 },
    { ...seed, scheme: 'brc157-peer-profiles' },
    { ...seed, entropyBytes: 16 },
    { ...seed, passphrasePolicy: 'empty' },
    { ...seed, rootPk: 'public-key', ids: '' },
    { ...seed, profiles: [] },
  ]) {
    await writeFile(input, JSON.stringify(payload));
    expect((await run('enc', input, '-p', password, '-t', '1', '-o', output)).code).not.toBe(0);
    expect(await Bun.file(output).exists()).toBe(false);
  }
  await writeFile(input, `{"mnemonic":"${mnemonic}" BROKEN`);
  const invalid = await run('enc', input, '-p', password, '-o', output);
  expect(invalid.code).not.toBe(0);
  expect(invalid.stdout + invalid.stderr).not.toContain(mnemonic);
});

test('built CLI fails wrong passwords and invalid iterations without touching existing output', async () => {
  const encrypted = join(directory, 'wrong-password.bep');
  const input = join(directory, 'wrong-password.json');
  await writeFile(input, JSON.stringify(seed));
  expect((await run('enc', input, '-p', password, '-t', '2', '-o', encrypted)).code).toBe(0);
  const output = join(directory, 'keep.json');
  await writeFile(output, 'keep existing');
  expect(
    (await run('dec', encrypted, '-p', 'wrong-public-password', '-t', '2', '-o', output)).code
  ).not.toBe(0);
  expect(await readFile(output, 'utf8')).toBe('keep existing');
  for (const value of ['0', '-1', '1.5', '2junk', '4294967296']) {
    expect((await run('dec', encrypted, '-p', password, '-t', value, '-o', output)).code).not.toBe(
      0
    );
  }
  expect(await readFile(output, 'utf8')).toBe('keep existing');
  expect((await run('dec', encrypted)).code).not.toBe(0);
});

test('built CLI preserves every legacy envelope family and default paths', async () => {
  const fixtures: DecryptedBackup[] = [
    { rootPk: 'public-root', ids: 'public-ids' },
    { xprv: 'public-xprv', mnemonic: '', ids: 'public-ids' },
    { wif: 'public-member', id: 'public-id' },
    { wif: 'public-wif' },
    { ordPk: 'public-ord', payPk: 'public-pay', identityPk: 'public-identity' },
    { encryptedVault: 'public-vault', scheme: 'custom-vault-v2' },
    { payPk: 'public-pay', ordPk: 'public-ord', mnemonic: 'public-legacy-words' },
    { chromeStorage: { public: true } },
  ];
  for (const [index, fixture] of fixtures.entries()) {
    const payload = { ...fixture, createdAt: '2026-01-01T00:00:00.000Z' };
    const input = join(directory, `legacy-${index}.json`);
    const encrypted = join(directory, `legacy-${index}_encrypted.bep`);
    const upgraded = join(directory, `legacy-${index}_encrypted_upgraded.bep`);
    await writeFile(input, JSON.stringify(payload));
    expect((await run('enc', input, '-p', password, '-t', '100000')).code).toBe(0);
    expect((await run('upg', encrypted, '-p', password)).code).toBe(0);
    expect(await decryptBackup(await readFile(upgraded, 'utf8'), password)).toEqual(payload);
  }
}, 30000);

test('built CLI default KDF roundtrip and unknown ciphertext structure rejection', async () => {
  const input = join(directory, 'default.json');
  const encrypted = join(directory, 'default.bep');
  const output = join(directory, 'default-output.json');
  await writeFile(input, JSON.stringify(seed));
  expect((await run('enc', input, '-p', password, '-o', encrypted)).code).toBe(0);
  expect((await run('dec', encrypted, '-p', password, '-o', output)).code).toBe(0);
  expect(JSON.parse(await readFile(output, 'utf8'))).toEqual(seed);
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
  for (const payload of [
    { ...seed, version: 2 },
    { rootPk: 'public-root', ids: '', format: 'unknown-format' },
  ]) {
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(JSON.stringify(payload))
    );
    await writeFile(
      encrypted,
      Buffer.concat([salt, iv, new Uint8Array(ciphertext)]).toString('base64')
    );
    await writeFile(output, 'preserve existing');
    for (const command of ['dec', 'upg']) {
      const result = await run(command, encrypted, '-p', password, '-t', '1', '-o', output);
      expect(result.code).not.toBe(0);
      expect(result.stdout + result.stderr).not.toContain(mnemonic);
      expect(await readFile(output, 'utf8')).toBe('preserve existing');
    }
  }
}, 15000);

test('built CLI seals v2 with a device slot, manages slots, and still decrypts', async () => {
  const input = join(directory, 'v2.json');
  const encrypted = join(directory, 'v2.bep');
  const output = join(directory, 'v2-output.json');
  await writeFile(input, JSON.stringify(seed));
  const pair = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const pubkey = Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join('');
  expect(
    (await run('enc', input, '-p', password, '-o', encrypted, '--device-pubkey', pubkey)).code
  ).toBe(0);
  const slots = JSON.parse((await run('slots', encrypted)).stdout) as {
    version: number;
    slots: { id: string }[];
  };
  expect(slots.version).toBe(2);
  expect(slots.slots.map((s) => s.id)).toEqual(['passphrase', 'device-1']);
  expect(
    (await run('slot', 'add', encrypted, '-p', password, '--new-password', 'second-passphrase-1'))
      .code
  ).toBe(0);
  expect((await run('slot', 'remove', encrypted, 'device-1', '-p', password)).code).toBe(0);
  const after = JSON.parse((await run('slots', encrypted)).stdout) as { slots: { id: string }[] };
  expect(after.slots.map((s) => s.id)).toEqual(['passphrase', 'passphrase-3']);
  expect((await run('dec', encrypted, '-p', 'second-passphrase-1', '-o', output)).code).toBe(0);
  expect(JSON.parse(await readFile(output, 'utf8'))).toEqual(seed);
  expect((await run('slot', 'remove', encrypted, 'passphrase', '-p', password)).code).toBe(0);
  expect(
    (await run('slot', 'remove', encrypted, 'passphrase-3', '-p', 'second-passphrase-1')).code
  ).toBe(1);
}, 30000);
