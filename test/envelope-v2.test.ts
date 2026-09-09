import { describe, expect, it } from 'bun:test';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Utils } from '@bsv/sdk';
import { decodeBase64Envelope, hasV2Magic, parseEnvelope } from '../src/envelope';
import {
  addSlot,
  ARGON2ID_FAST,
  decryptBackup,
  eciesDecrypt,
  encryptBackup,
  inspectEnvelope,
  isDerivationDescriptor,
  isEnvelopeV2,
  isWifBackup,
  openBackup,
  removeSlot,
  rewrapBackup,
  sealBackup,
  updateBackupPayload,
  type WifBackup,
} from '../src/index';

const passphraseA = 'strongPassphraseA123!';
const passphraseB = 'otherPassphraseB456!';

const wifPayload: WifBackup = {
  wif: 'L4rprVahLjG4LWdULUeoxaVyq9chGQzg8kSVgSWfBrdeyAZs9VLo',
};

async function deviceKeypair() {
  const kp = (await globalThis.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  )) as CryptoKeyPair;
  const raw = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', kp.publicKey));
  const hex = Utils.toHex(Array.from(raw));
  return { kp, hex };
}

describe('envelope v2 seal/open', () => {
  it('round trips with one pbkdf2 slot', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'main', passphrase: passphraseA },
    ]);
    expect(isEnvelopeV2(enc)).toBe(true);
    expect(inspectEnvelope(enc)).toMatchObject({ version: 2 });
    const dec = (await openBackup(enc, { passphrase: passphraseA })) as WifBackup;
    expect(dec.wif).toBe(wifPayload.wif);
    expect(dec.createdAt).toBeDefined();
  });

  it('round trips with two pbkdf2 slots', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'a', passphrase: passphraseA },
      { type: 'pbkdf2', id: 'b', passphrase: passphraseB },
    ]);
    const decA = (await openBackup(enc, { slotId: 'a', passphrase: passphraseA })) as WifBackup;
    const decB = (await openBackup(enc, { slotId: 'b', passphrase: passphraseB })) as WifBackup;
    expect(decA.wif).toBe(wifPayload.wif);
    expect(decB.wif).toBe(wifPayload.wif);
    const decAny = (await openBackup(enc, { passphrase: passphraseB })) as WifBackup;
    expect(decAny.wif).toBe(wifPayload.wif);
  });

  it('round trips with one argon2id slot', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'argon2id', id: 'main', passphrase: passphraseA, ...ARGON2ID_FAST },
    ]);
    expect(inspectEnvelope(enc)).toMatchObject({
      version: 2,
      slots: [{ type: 'argon2id', id: 'main', memoryKiB: ARGON2ID_FAST.memoryKiB }],
    });
    const dec = (await openBackup(enc, { passphrase: passphraseA })) as WifBackup;
    expect(dec.wif).toBe(wifPayload.wif);
    await expect(openBackup(enc, { passphrase: passphraseB })).rejects.toThrow(/Invalid passphrase/);
  });

  it('round trips with one device-p256 slot', async () => {
    const { kp, hex } = await deviceKeypair();
    const enc = await sealBackup(wifPayload, [{ type: 'device-p256', id: 'dev1', publicKey: hex }]);
    const info = inspectEnvelope(enc);
    expect(info.version).toBe(2);
    expect(info.slots[0].type).toBe('device-p256');
    expect(info.slots[0].publicKey).toBe(hex.toLowerCase());
    const dec = (await openBackup(enc, {
      slotId: 'dev1',
      unwrap: (wrapped) => eciesDecrypt(kp.privateKey, wrapped),
    })) as WifBackup;
    expect(dec.wif).toBe(wifPayload.wif);
  });

  it('round trips mixed pbkdf2 + device-p256', async () => {
    const { kp, hex } = await deviceKeypair();
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'pw', passphrase: passphraseA },
      { type: 'device-p256', id: 'dev', publicKey: hex },
    ]);
    expect(inspectEnvelope(enc).slots.length).toBe(2);
    const viaPw = (await openBackup(enc, { passphrase: passphraseA })) as WifBackup;
    expect(viaPw.wif).toBe(wifPayload.wif);
    const viaDev = (await openBackup(enc, {
      slotId: 'dev',
      unwrap: (w) => eciesDecrypt(kp.privateKey, w),
    })) as WifBackup;
    expect(viaDev.wif).toBe(wifPayload.wif);
  });

  it('decryptBackup opens v2 with pbkdf2 slot; wrong passphrase throws', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'main', passphrase: passphraseA },
    ]);
    const dec = (await decryptBackup(enc, passphraseA)) as WifBackup;
    expect(dec.wif).toBe(wifPayload.wif);
    await expect(decryptBackup(enc, 'wrongPassphrase123')).rejects.toThrow(
      /Decryption failed: Invalid passphrase/
    );
  });

  it('preserves createdAt rule like v1', async () => {
    const dated = { ...wifPayload, createdAt: '2023-01-03T00:00:00.000Z' };
    const enc = await sealBackup(dated, [{ type: 'pbkdf2', id: 'a', passphrase: passphraseA }]);
    const dec = (await openBackup(enc, { passphrase: passphraseA })) as WifBackup;
    expect(dec.createdAt).toBe(dated.createdAt);
  });
});

describe('envelope v2 slot management', () => {
  it('addSlot then open with the new slot', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'a', passphrase: passphraseA },
    ]);
    const enc2 = await addSlot(
      enc,
      { passphrase: passphraseA },
      {
        type: 'pbkdf2',
        id: 'b',
        passphrase: passphraseB,
      }
    );
    const dec = (await openBackup(enc2, { slotId: 'b', passphrase: passphraseB })) as WifBackup;
    expect(dec.wif).toBe(wifPayload.wif);
    expect(inspectEnvelope(enc2).slots.length).toBe(2);
  });

  it('removeSlot refuses the last slot', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'only', passphrase: passphraseA },
    ]);
    await expect(removeSlot(enc, { passphrase: passphraseA }, 'only')).rejects.toThrow(/last slot/);
    const enc2 = await addSlot(
      enc,
      { passphrase: passphraseA },
      {
        type: 'pbkdf2',
        id: 'second',
        passphrase: passphraseB,
      }
    );
    const enc3 = await removeSlot(enc2, { passphrase: passphraseA }, 'second');
    expect(inspectEnvelope(enc3).slots.length).toBe(1);
    const dec = (await openBackup(enc3, { passphrase: passphraseA })) as WifBackup;
    expect(dec.wif).toBe(wifPayload.wif);
  });

  it('rewrapBackup changes the content key (ciphertext differs, payload identical)', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'a', passphrase: passphraseA },
    ]);
    const payloadBefore = await openBackup(enc, { passphrase: passphraseA });
    const enc2 = await rewrapBackup(enc, { passphrase: passphraseA }, [
      { type: 'pbkdf2', id: 'fresh', passphrase: passphraseB },
    ]);
    expect(enc2).not.toBe(enc);
    const payloadAfter = await openBackup(enc2, { passphrase: passphraseB });
    expect(payloadAfter).toEqual(payloadBefore);
    const rawBefore = decodeBase64Envelope(enc);
    const rawAfter = decodeBase64Envelope(enc2);
    const parsedBefore = parseEnvelope(rawBefore);
    const parsedAfter = parseEnvelope(rawAfter);
    // Ciphertext (payload encryption) must differ because contentKey is new.
    expect(Utils.toHex(Array.from(parsedAfter.ciphertext))).not.toBe(
      Utils.toHex(Array.from(parsedBefore.ciphertext))
    );
  });
});

describe('envelope v2 byte layout fixture', () => {
  it('parses fixed device-p256 vector offsets and decrypts with private JWK', async () => {
    const fixturePath = join(import.meta.dir, 'fixtures', 'envelope-v2', 'device-vector.json');
    const fixture = JSON.parse(await readFile(fixturePath, 'utf8')) as {
      recipientPrivateJwk: JsonWebKey;
      recipientPublicKeyHex: string;
      contentKeyHex: string;
      wrappedBase64: string;
      ephemeralPubHex: string;
      nonceHex: string;
      ciphertextHex: string;
    };
    const wrapped = Uint8Array.from(Utils.toArray(fixture.wrappedBase64, 'base64'));
    expect(wrapped.length).toBeGreaterThanOrEqual(65 + 12 + 16);
    const ephemeral = wrapped.slice(0, 65);
    const nonce = wrapped.slice(65, 77);
    const ciphertext = wrapped.slice(77);
    expect(Utils.toHex(Array.from(ephemeral)).toLowerCase()).toBe(
      fixture.ephemeralPubHex.toLowerCase()
    );
    expect(Utils.toHex(Array.from(nonce)).toLowerCase()).toBe(fixture.nonceHex.toLowerCase());
    expect(Utils.toHex(Array.from(ciphertext)).toLowerCase()).toBe(
      fixture.ciphertextHex.toLowerCase()
    );
    const privateKey = await globalThis.crypto.subtle.importKey(
      'jwk',
      fixture.recipientPrivateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    const plaintext = await eciesDecrypt(privateKey, wrapped);
    expect(Utils.toHex(Array.from(plaintext)).toLowerCase()).toBe(
      fixture.contentKeyHex.toLowerCase()
    );
  });

  it('v2 envelope byte layout has magic, version, header length, iv and ciphertext', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'layout', passphrase: passphraseA },
    ]);
    const raw = decodeBase64Envelope(enc);
    expect(raw[0]).toBe(0x42);
    expect(raw[1]).toBe(0x45);
    expect(raw[2]).toBe(0x50);
    expect(raw[3]).toBe(0x32);
    expect(raw[4]).toBe(0x02);
    const hdrLen = (raw[5] << 8) | raw[6];
    expect(hasV2Magic(raw)).toBe(true);
    const { header, iv, ciphertext } = parseEnvelope(raw);
    expect(header.v).toBe(2);
    expect(header.slots.length).toBe(1);
    expect(iv.length).toBe(12);
    expect(ciphertext.length).toBeGreaterThan(16);
    expect(7 + hdrLen + 12 + ciphertext.length).toBe(raw.length);
  });
});

describe('envelope v2 malformed inputs throw before subtle.decrypt', () => {
  async function expectBeforeDecrypt(fn: () => Promise<unknown>, pattern: RegExp) {
    const original = globalThis.crypto.subtle.decrypt;
    let called = false;
    // @ts-expect-error spy
    globalThis.crypto.subtle.decrypt = async (...args: unknown[]) => {
      called = true;
      // @ts-expect-error delegate
      return original.apply(globalThis.crypto.subtle, args);
    };
    try {
      await expect(fn()).rejects.toThrow(pattern);
      expect(called).toBe(false);
    } finally {
      globalThis.crypto.subtle.decrypt = original;
    }
  }

  it('malformed header throws', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'a', passphrase: passphraseA },
    ]);
    const raw = decodeBase64Envelope(enc);
    const hdrLen = (raw[5] << 8) | raw[6];
    // Corrupt header JSON (flip a byte inside header).
    const corrupted = new Uint8Array(raw);
    corrupted[10] = corrupted[10] ^ 0xff;
    const corruptedB64 = Utils.toBase64(Array.from(corrupted));
    // Header JSON corruption may either fail parse or fail slot validation; both must throw before decrypt.
    // Use a definitely-invalid JSON header instead for determinism.
    const badHeader = new TextEncoder().encode('{not-json');
    const out = new Uint8Array(4 + 1 + 2 + badHeader.length + 12 + 32);
    out.set([0x42, 0x45, 0x50, 0x32, 0x02], 0);
    out[5] = (badHeader.length >> 8) & 0xff;
    out[6] = badHeader.length & 0xff;
    out.set(badHeader, 7);
    const badB64 = Utils.toBase64(Array.from(out));
    await expectBeforeDecrypt(
      () => openBackup(badB64, { passphrase: passphraseA }),
      /Malformed envelope header/
    );
    void corruptedB64;
    void hdrLen;
  });

  it('unknown slot type throws', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'a', passphrase: passphraseA },
    ]);
    const raw = decodeBase64Envelope(enc);
    const hdrLen = (raw[5] << 8) | raw[6];
    const headerJson = JSON.parse(new TextDecoder().decode(raw.slice(7, 7 + hdrLen)));
    headerJson.slots[0].type = 'future-slot';
    const newHeaderBytes = new TextEncoder().encode(JSON.stringify(headerJson));
    const out = new Uint8Array(4 + 1 + 2 + newHeaderBytes.length + (raw.length - 7 - hdrLen));
    out.set([0x42, 0x45, 0x50, 0x32, 0x02], 0);
    out[5] = (newHeaderBytes.length >> 8) & 0xff;
    out[6] = newHeaderBytes.length & 0xff;
    out.set(newHeaderBytes, 7);
    out.set(raw.slice(7 + hdrLen), 7 + newHeaderBytes.length);
    const badB64 = Utils.toBase64(Array.from(out));
    expect(enc).toBeDefined();
    await expectBeforeDecrypt(
      () => openBackup(badB64, { passphrase: passphraseA }),
      /Unknown slot type/
    );
  });

  it('unknown version throws', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'a', passphrase: passphraseA },
    ]);
    const raw = decodeBase64Envelope(enc);
    const tampered = new Uint8Array(raw);
    tampered[4] = 0x03;
    const badB64 = Utils.toBase64(Array.from(tampered));
    await expectBeforeDecrypt(
      () => openBackup(badB64, { passphrase: passphraseA }),
      /Unknown envelope version/
    );
  });

  it('truncated bytes throw', async () => {
    const enc = await sealBackup(wifPayload, [
      { type: 'pbkdf2', id: 'a', passphrase: passphraseA },
    ]);
    const raw = decodeBase64Envelope(enc);
    const hdrLen = (raw[5] << 8) | raw[6];
    // Truncate inside the header.
    const cutHeader = raw.slice(0, 7 + hdrLen - 5);
    await expectBeforeDecrypt(
      () => openBackup(Utils.toBase64(Array.from(cutHeader)), { passphrase: passphraseA }),
      /truncated|claims/
    );
    // Truncate inside the IV (header intact, body too short).
    const cutIv = raw.slice(0, 7 + hdrLen + 5);
    await expectBeforeDecrypt(
      () => openBackup(Utils.toBase64(Array.from(cutIv)), { passphrase: passphraseA }),
      /truncated/
    );
    // Header claiming more bytes than exist.
    const inflated = new Uint8Array(raw);
    inflated[5] = 0xff;
    inflated[6] = 0xff;
    const inflatedB64 = Utils.toBase64(Array.from(inflated));
    await expectBeforeDecrypt(() => openBackup(inflatedB64, { passphrase: passphraseA }), /claims/);
  });
});

describe('derivation descriptor', () => {
  it('WifBackup with derivation still detects as Wif', async () => {
    const payload: WifBackup = {
      wif: 'L4rprVahLjG4LWdULUeoxaVyq9chGQzg8kSVgSWfBrdeyAZs9VLo',
      derivation: { scheme: 'bip32', path: "m/0'/1'" },
    };
    expect(isWifBackup(payload)).toBe(true);
    const enc = await sealBackup(payload, [{ type: 'pbkdf2', id: 'a', passphrase: passphraseA }]);
    const info = inspectEnvelope(enc);
    expect(info.descriptor).toEqual({ scheme: 'bip32', path: "m/0'/1'" });
    const dec = (await openBackup(enc, { passphrase: passphraseA })) as WifBackup;
    expect(isWifBackup(dec)).toBe(true);
    expect(dec.derivation).toEqual({ scheme: 'bip32', path: "m/0'/1'" });
  });

  it('isDerivationDescriptor accepts valid, rejects unknown scheme', () => {
    expect(isDerivationDescriptor({ scheme: 'brc157' })).toBe(true);
    expect(isDerivationDescriptor({ scheme: 'bip32', path: "m/0'/1'" })).toBe(true);
    expect(isDerivationDescriptor({ scheme: 'type42' })).toBe(true);
    expect(isDerivationDescriptor({ scheme: 'brc42' })).toBe(true);
    expect(isDerivationDescriptor({ scheme: 'legacy-bip32-unhardened', cohort: 'old' })).toBe(true);
    expect(isDerivationDescriptor({ scheme: 'unknown' })).toBe(false);
    expect(isDerivationDescriptor({})).toBe(false);
    expect(isDerivationDescriptor(null)).toBe(false);
  });
});

describe('v1 fixtures still treated as v1', () => {
  it('every file under test/fixtures/encrypted/ is not v2 and inspects as v1', async () => {
    const dir = join(import.meta.dir, 'fixtures', 'encrypted');
    const files = await readdir(dir);
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const content = (await readFile(join(dir, file), 'utf8')).trim();
      expect(isEnvelopeV2(content)).toBe(false);
      expect(inspectEnvelope(content)).toMatchObject({ version: 1, slots: [] });
    }
  });

  it('v1 encrypt/decrypt round trip still works alongside v2', async () => {
    const payload: WifBackup = { wif: 'L4rprVahLjG4LWdULUeoxaVyq9chGQzg8kSVgSWfBrdeyAZs9VLo' };
    const v1 = await encryptBackup(payload, passphraseA);
    expect(isEnvelopeV2(v1)).toBe(false);
    const dec = (await decryptBackup(v1, passphraseA)) as WifBackup;
    expect(dec.wif).toBe(payload.wif);
  });
});

describe('updateBackupPayload', () => {
  it('replaces the payload and keeps every slot', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    const publicKey = Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join('');
    const sealed = await sealBackup({ wif: 'first' }, [
      { type: 'pbkdf2', id: 'pw', passphrase: 'correct horse battery' },
      { type: 'device-p256', id: 'dev', publicKey },
    ]);
    const updated = await updateBackupPayload(
      sealed,
      { passphrase: 'correct horse battery' },
      {
        wif: 'second',
      }
    );
    expect(inspectEnvelope(updated).slots.map((s) => s.id)).toEqual(['pw', 'dev']);
    expect(await openBackup(updated, { passphrase: 'correct horse battery' })).toMatchObject({
      wif: 'second',
    });
    const viaDevice = await openBackup(updated, {
      slotId: 'dev',
      unwrap: (wrapped) => eciesDecrypt(pair.privateKey, wrapped),
    });
    expect(viaDevice).toMatchObject({ wif: 'second' });
  });
});
