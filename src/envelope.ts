import { Utils } from '@bsv/sdk';
import {
  deriveArgon2idKey,
  resolveArgon2idParams,
  type Argon2idParams,
} from './argon2';
import {
  deriveKey,
  isValidPayload,
  parseDecryptedPayload,
  RECOMMENDED_PBKDF2_ITERATIONS,
} from './crypto';
import { assertP256PublicKeyHex, eciesEncrypt } from './ecies';
import { isDerivationDescriptor } from './guards';
import type { DecryptedBackup, DerivationDescriptor, EncryptedBackup } from './interfaces';
import { assertLegacyPassphrase, assertPassphrase } from './passphrase';
import { isSigmaSeedBackup } from './seed';

const { toArray, toBase64 } = Utils;

export const ENVELOPE_MAGIC = 'BEP2';
export const ENVELOPE_VERSION = 0x02;
const MAGIC_BYTES = [0x42, 0x45, 0x50, 0x32];
const SALT_LENGTH_BYTES = 16;
const IV_LENGTH_BYTES = 12;
const CONTENT_KEY_LENGTH_BYTES = 32;
const EPHEMERAL_PUB_LENGTH = 65;
const NONCE_LENGTH = 12;
const GCM_TAG_LENGTH = 16;

const SLOT_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/u;

export type Pbkdf2Slot = {
  type: 'pbkdf2';
  id: string;
  salt: string;
  iterations: number;
  wrapped: string;
};

export type DeviceP256Slot = {
  type: 'device-p256';
  id: string;
  publicKey: string;
  wrapped: string;
};

export type Argon2idSlot = {
  type: 'argon2id';
  id: string;
  salt: string;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  wrapped: string;
};

export type Slot = Pbkdf2Slot | DeviceP256Slot | Argon2idSlot;

export interface EnvelopeHeader {
  v: 2;
  slots: Slot[];
  descriptor?: DerivationDescriptor;
}

export type SlotSpec =
  | { type: 'pbkdf2'; id: string; passphrase: string; iterations?: number }
  | ({ type: 'argon2id'; id: string; passphrase: string } & Partial<Argon2idParams>)
  | { type: 'device-p256'; id: string; publicKey: string };

export type Unlock =
  | { passphrase: string }
  | { slotId: string; passphrase: string }
  | { slotId: string; unwrap: (wrapped: Uint8Array) => Promise<Uint8Array> };

export interface InspectResult {
  version: 1 | 2;
  slots: Array<{
    type: string;
    id: string;
    publicKey?: string;
    iterations?: number;
    memoryKiB?: number;
    parallelism?: number;
  }>;
  descriptor?: DerivationDescriptor;
}

function b64encode(bytes: Uint8Array): string {
  return toBase64(Array.from(bytes));
}

function b64decode(b64: string, label: string): Uint8Array {
  let numbers: number[];
  try {
    numbers = toArray(b64, 'base64');
  } catch {
    throw new Error(`${label}: invalid Base64.`);
  }
  return Uint8Array.from(numbers);
}

export function validateSlotId(id: unknown): void {
  if (typeof id !== 'string' || id.length < 1 || id.length > 63 || !SLOT_ID_RE.test(id)) {
    throw new Error('Invalid slot id: must be 1-63 chars matching ^[a-zA-Z0-9][a-zA-Z0-9._-]*$.');
  }
}

function validateIterations(iterations: unknown): void {
  if (
    typeof iterations !== 'number' ||
    !Number.isSafeInteger(iterations) ||
    iterations < 1 ||
    iterations > 4294967295
  ) {
    throw new Error('Invalid iterations: must be a positive 32-bit integer.');
  }
}

function buildPayloadJson(payload: DecryptedBackup): string {
  const payloadToEncrypt = {
    ...payload,
    createdAt: isSigmaSeedBackup(payload)
      ? payload.createdAt
      : (payload as { createdAt?: unknown }).createdAt || new Date().toISOString(),
  };
  return JSON.stringify(payloadToEncrypt);
}

function getDescriptorFromPayload(payload: DecryptedBackup): DerivationDescriptor | undefined {
  const maybe = (payload as { derivation?: unknown }).derivation;
  if (maybe === undefined) return undefined;
  if (!isDerivationDescriptor(maybe)) {
    throw new Error('Invalid derivation descriptor on payload.');
  }
  return maybe;
}

function validateSlotSpecShape(slot: SlotSpec, seen: Set<string>): void {
  if (!slot || typeof slot !== 'object') throw new Error('Invalid slot: must be an object.');
  if (slot.type !== 'pbkdf2' && slot.type !== 'argon2id' && slot.type !== 'device-p256') {
    throw new Error(`Unknown slot type '${(slot as { type: unknown }).type}'.`);
  }
  validateSlotId(slot.id);
  if (seen.has(slot.id)) throw new Error(`Duplicate slot id '${slot.id}'.`);
  seen.add(slot.id);
  if (slot.type === 'pbkdf2') {
    assertLegacyPassphrase(slot.passphrase);
    if (slot.iterations !== undefined) validateIterations(slot.iterations);
  } else if (slot.type === 'argon2id') {
    assertPassphrase(slot.passphrase);
    resolveArgon2idParams(slot);
  } else {
    assertP256PublicKeyHex(slot.publicKey, 'Invalid device publicKey');
  }
}

async function wrapAesGcm(kek: CryptoKey, contentKey: Uint8Array): Promise<string> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const ct = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      kek,
      contentKey as BufferSource
    )
  );
  const wrapped = new Uint8Array(iv.length + ct.length);
  wrapped.set(iv, 0);
  wrapped.set(ct, iv.length);
  return b64encode(wrapped);
}

async function wrapContentKey(slot: SlotSpec, contentKey: Uint8Array): Promise<Slot> {
  if (slot.type === 'pbkdf2') {
    const iterations = slot.iterations ?? RECOMMENDED_PBKDF2_ITERATIONS;
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
    const kek = await deriveKey(slot.passphrase, salt as Uint8Array<ArrayBuffer>, iterations);
    return {
      type: 'pbkdf2',
      id: slot.id,
      salt: b64encode(salt),
      iterations,
      wrapped: await wrapAesGcm(kek, contentKey),
    };
  }
  if (slot.type === 'argon2id') {
    const params = resolveArgon2idParams(slot);
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
    const kek = await deriveArgon2idKey(slot.passphrase, salt, params);
    return {
      type: 'argon2id',
      id: slot.id,
      salt: b64encode(salt),
      memoryKiB: params.memoryKiB,
      iterations: params.iterations,
      parallelism: params.parallelism,
      wrapped: await wrapAesGcm(kek, contentKey),
    };
  }
  const wrappedBytes = await eciesEncrypt(slot.publicKey, contentKey);
  return {
    type: 'device-p256',
    id: slot.id,
    publicKey: slot.publicKey.toLowerCase(),
    wrapped: b64encode(wrappedBytes),
  };
}

async function unwrapAesGcm(
  kek: CryptoKey,
  wrapped: Uint8Array,
  label: string,
): Promise<Uint8Array> {
  if (wrapped.length < IV_LENGTH_BYTES + GCM_TAG_LENGTH) {
    throw new Error(`Malformed envelope header: ${label} wrapped bytes are truncated.`);
  }
  const iv = wrapped.slice(0, IV_LENGTH_BYTES);
  const ct = wrapped.slice(IV_LENGTH_BYTES);
  const pt = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    kek,
    ct as BufferSource
  );
  return new Uint8Array(pt);
}

async function unwrapPbkdf2Slot(slot: Pbkdf2Slot, passphrase: string): Promise<Uint8Array> {
  const salt = b64decode(slot.salt, 'pbkdf2 slot salt');
  if (salt.length !== SALT_LENGTH_BYTES) {
    throw new Error('Malformed envelope header: pbkdf2 salt must decode to 16 bytes.');
  }
  const wrapped = b64decode(slot.wrapped, 'pbkdf2 slot wrapped');
  const kek = await deriveKey(passphrase, salt as Uint8Array<ArrayBuffer>, slot.iterations);
  return unwrapAesGcm(kek, wrapped, 'pbkdf2');
}

async function unwrapArgon2idSlot(slot: Argon2idSlot, passphrase: string): Promise<Uint8Array> {
  const salt = b64decode(slot.salt, 'argon2id slot salt');
  if (salt.length !== SALT_LENGTH_BYTES) {
    throw new Error('Malformed envelope header: argon2id salt must decode to 16 bytes.');
  }
  const wrapped = b64decode(slot.wrapped, 'argon2id slot wrapped');
  const kek = await deriveArgon2idKey(passphrase, salt, {
    memoryKiB: slot.memoryKiB,
    iterations: slot.iterations,
    parallelism: slot.parallelism,
  });
  return unwrapAesGcm(kek, wrapped, 'argon2id');
}

function isPassphraseSlot(slot: Slot): slot is Pbkdf2Slot | Argon2idSlot {
  return slot.type === 'pbkdf2' || slot.type === 'argon2id';
}

async function unwrapPassphraseSlot(
  slot: Pbkdf2Slot | Argon2idSlot,
  passphrase: string,
): Promise<Uint8Array> {
  return slot.type === 'argon2id'
    ? unwrapArgon2idSlot(slot, passphrase)
    : unwrapPbkdf2Slot(slot, passphrase);
}

export function decodeBase64Envelope(encrypted: EncryptedBackup): Uint8Array {
  let numbers: number[];
  try {
    numbers = toArray(encrypted, 'base64');
  } catch {
    throw new Error('Decryption failed: Invalid Base64 input.');
  }
  if (encrypted.length > 0 && numbers.length === 0) {
    throw new Error('Decryption failed: Invalid Base64 input (decoded to empty).');
  }
  return Uint8Array.from(numbers);
}

export function hasV2Magic(decoded: Uint8Array): boolean {
  return (
    decoded.length >= 5 &&
    decoded[0] === MAGIC_BYTES[0] &&
    decoded[1] === MAGIC_BYTES[1] &&
    decoded[2] === MAGIC_BYTES[2] &&
    decoded[3] === MAGIC_BYTES[3]
  );
}

export function parseEnvelope(decoded: Uint8Array): {
  header: EnvelopeHeader;
  iv: Uint8Array;
  ciphertext: Uint8Array;
} {
  if (decoded.length < 7) {
    throw new Error('Malformed envelope header: bytes are truncated.');
  }
  if (
    decoded[0] !== MAGIC_BYTES[0] ||
    decoded[1] !== MAGIC_BYTES[1] ||
    decoded[2] !== MAGIC_BYTES[2] ||
    decoded[3] !== MAGIC_BYTES[3]
  ) {
    throw new Error('Malformed envelope header: missing BEP2 magic.');
  }
  const version = decoded[4];
  if (version !== ENVELOPE_VERSION) {
    throw new Error(`Unknown envelope version ${version}.`);
  }
  const hdrLen = (decoded[5] << 8) | decoded[6];
  if (7 + hdrLen > decoded.length) {
    throw new Error(
      `Malformed envelope header: header claims ${hdrLen} bytes but only ${decoded.length - 7} remain.`
    );
  }
  const headerBytes = decoded.slice(7, 7 + hdrLen);
  let headerJson: unknown;
  try {
    headerJson = JSON.parse(new TextDecoder().decode(headerBytes));
  } catch {
    throw new Error('Malformed envelope header: invalid JSON.');
  }
  if (headerJson === null || typeof headerJson !== 'object' || Array.isArray(headerJson)) {
    throw new Error('Malformed envelope header: header must be an object.');
  }
  const h = headerJson as Record<string, unknown>;
  if (h.v !== 2) {
    throw new Error(`Unknown envelope version ${String(h.v)}.`);
  }
  if (!Array.isArray(h.slots) || h.slots.length === 0) {
    throw new Error('Malformed envelope header: slots must be a non-empty array.');
  }
  if ('descriptor' in h && h.descriptor !== undefined && !isDerivationDescriptor(h.descriptor)) {
    throw new Error('Malformed envelope header: invalid descriptor.');
  }
  const seen = new Set<string>();
  const slots: Slot[] = [];
  for (const raw of h.slots) {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error('Malformed envelope header: slot must be an object.');
    }
    const s = raw as Record<string, unknown>;
    if (s.type !== 'pbkdf2' && s.type !== 'argon2id' && s.type !== 'device-p256') {
      throw new Error(`Unknown slot type '${String(s.type)}'.`);
    }
    if (typeof s.id !== 'string' || s.id.length < 1 || s.id.length > 63 || !SLOT_ID_RE.test(s.id)) {
      throw new Error('Malformed envelope header: invalid slot id.');
    }
    if (seen.has(s.id)) {
      throw new Error(`Malformed envelope header: duplicate slot id '${s.id}'.`);
    }
    seen.add(s.id);
    if (s.type === 'pbkdf2' || s.type === 'argon2id') {
      const label = s.type;
      if (typeof s.salt !== 'string' || typeof s.wrapped !== 'string') {
        throw new Error(`Malformed envelope header: ${label} slot missing salt/wrapped.`);
      }
      if (
        typeof s.iterations !== 'number' ||
        !Number.isSafeInteger(s.iterations) ||
        s.iterations < 1 ||
        s.iterations > 4294967295
      ) {
        throw new Error(`Malformed envelope header: invalid ${label} iterations.`);
      }
      if (s.type === 'argon2id') {
        try {
          resolveArgon2idParams({
            memoryKiB: s.memoryKiB as number,
            iterations: s.iterations,
            parallelism: s.parallelism as number,
          });
        } catch {
          throw new Error('Malformed envelope header: invalid argon2id parameters.');
        }
      }
      let saltBytes: Uint8Array;
      let wrappedBytes: Uint8Array;
      try {
        saltBytes = b64decode(s.salt, `${label} slot salt`);
      } catch {
        throw new Error(`Malformed envelope header: ${label} salt is not valid Base64.`);
      }
      if (saltBytes.length !== SALT_LENGTH_BYTES) {
        throw new Error(`Malformed envelope header: ${label} salt must decode to 16 bytes.`);
      }
      try {
        wrappedBytes = b64decode(s.wrapped, `${label} slot wrapped`);
      } catch {
        throw new Error(`Malformed envelope header: ${label} wrapped is not valid Base64.`);
      }
      if (wrappedBytes.length < IV_LENGTH_BYTES + GCM_TAG_LENGTH) {
        throw new Error(`Malformed envelope header: ${label} wrapped bytes are truncated.`);
      }
      if (s.type === 'argon2id') {
        slots.push({
          type: 'argon2id',
          id: s.id,
          salt: s.salt,
          memoryKiB: s.memoryKiB as number,
          iterations: s.iterations,
          parallelism: s.parallelism as number,
          wrapped: s.wrapped,
        });
      } else {
        slots.push({
          type: 'pbkdf2',
          id: s.id,
          salt: s.salt,
          iterations: s.iterations,
          wrapped: s.wrapped,
        });
      }
    } else {
      if (typeof s.publicKey !== 'string' || typeof s.wrapped !== 'string') {
        throw new Error('Malformed envelope header: device-p256 slot missing publicKey/wrapped.');
      }
      try {
        assertP256PublicKeyHex(s.publicKey, 'Invalid device publicKey');
      } catch (error) {
        throw new Error(`Malformed envelope header: ${(error as Error).message}`);
      }
      let wrappedBytes: Uint8Array;
      try {
        wrappedBytes = b64decode(s.wrapped, 'device-p256 slot wrapped');
      } catch {
        throw new Error('Malformed envelope header: device-p256 wrapped is not valid Base64.');
      }
      if (wrappedBytes.length < EPHEMERAL_PUB_LENGTH + NONCE_LENGTH + GCM_TAG_LENGTH) {
        throw new Error('Malformed envelope header: device-p256 wrapped bytes are truncated.');
      }
      if (wrappedBytes[0] !== 0x04) {
        throw new Error(
          'Malformed envelope header: device-p256 ephemeral key must be 0x04-prefixed.'
        );
      }
      slots.push({ type: 'device-p256', id: s.id, publicKey: s.publicKey, wrapped: s.wrapped });
    }
  }
  const rest = decoded.slice(7 + hdrLen);
  if (rest.length < IV_LENGTH_BYTES + GCM_TAG_LENGTH) {
    throw new Error('Malformed envelope: bytes are truncated.');
  }
  const iv = rest.slice(0, IV_LENGTH_BYTES);
  const ciphertext = rest.slice(IV_LENGTH_BYTES);
  const header: EnvelopeHeader = {
    v: 2,
    slots,
    ...(h.descriptor !== undefined ? { descriptor: h.descriptor as DerivationDescriptor } : {}),
  };
  return { header, iv, ciphertext };
}

function encodeEnvelope(
  header: EnvelopeHeader,
  iv: Uint8Array,
  ciphertext: Uint8Array
): EncryptedBackup {
  const headerJson = JSON.stringify(header);
  const headerBytes = new TextEncoder().encode(headerJson);
  if (headerBytes.length > 65535) {
    throw new Error('Envelope header too large.');
  }
  const out = new Uint8Array(4 + 1 + 2 + headerBytes.length + iv.length + ciphertext.length);
  out[0] = MAGIC_BYTES[0];
  out[1] = MAGIC_BYTES[1];
  out[2] = MAGIC_BYTES[2];
  out[3] = MAGIC_BYTES[3];
  out[4] = ENVELOPE_VERSION;
  out[5] = (headerBytes.length >> 8) & 0xff;
  out[6] = headerBytes.length & 0xff;
  out.set(headerBytes, 7);
  out.set(iv, 7 + headerBytes.length);
  out.set(ciphertext, 7 + headerBytes.length + iv.length);
  return b64encode(out);
}

async function importContentKey(contentKey: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (contentKey.length !== CONTENT_KEY_LENGTH_BYTES) {
    throw new Error('Invalid content key length.');
  }
  return globalThis.crypto.subtle.importKey(
    'raw',
    contentKey as BufferSource,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}

async function resolveContentKey(header: EnvelopeHeader, unlock: Unlock): Promise<Uint8Array> {
  if ('unwrap' in unlock && 'slotId' in unlock) {
    const slot = header.slots.find((s) => s.id === unlock.slotId);
    if (!slot) throw new Error(`Slot '${unlock.slotId}' not found.`);
    const wrapped = b64decode(slot.wrapped, 'slot wrapped');
    const contentKey = await unlock.unwrap(wrapped);
    if (!(contentKey instanceof Uint8Array) || contentKey.length !== CONTENT_KEY_LENGTH_BYTES) {
      throw new Error('Invalid unwrap result: must return 32-byte content key.');
    }
    return contentKey;
  }
  if ('slotId' in unlock && 'passphrase' in unlock) {
    const slot = header.slots.find((s) => s.id === unlock.slotId);
    if (!slot) throw new Error(`Slot '${unlock.slotId}' not found.`);
    if (!isPassphraseSlot(slot)) {
      throw new Error(`Slot '${unlock.slotId}' is not a passphrase slot.`);
    }
    try {
      const contentKey = await unwrapPassphraseSlot(slot, unlock.passphrase);
      if (contentKey.length !== CONTENT_KEY_LENGTH_BYTES) {
        throw new Error('Decryption failed: Invalid content key.');
      }
      return contentKey;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'OperationError') {
        throw new Error('Decryption failed: Invalid passphrase or corrupted data.');
      }
      throw error;
    }
  }
  if ('passphrase' in unlock && !('slotId' in unlock)) {
    const passphraseSlots = header.slots.filter(isPassphraseSlot);
    if (passphraseSlots.length === 0) {
      throw new Error('Decryption failed: No passphrase slot available.');
    }
    for (const slot of passphraseSlots) {
      try {
        const contentKey = await unwrapPassphraseSlot(slot, unlock.passphrase);
        if (contentKey.length === CONTENT_KEY_LENGTH_BYTES) return contentKey;
      } catch (error) {
        if (error instanceof DOMException && error.name === 'OperationError') continue;
        throw error;
      }
    }
    throw new Error('Decryption failed: Invalid passphrase or corrupted data.');
  }
  throw new Error('Invalid unlock: must provide passphrase or slotId+unwrap.');
}

async function decryptPayload(
  contentKey: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Promise<DecryptedBackup> {
  const key = await importContentKey(contentKey, ['decrypt']);
  let pt: ArrayBuffer;
  try {
    pt = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      ciphertext as BufferSource
    );
  } catch (error) {
    if (error instanceof DOMException && error.name === 'OperationError') {
      throw new Error('Decryption failed: Invalid passphrase or corrupted data.');
    }
    throw error;
  }
  return parseDecryptedPayload(new TextDecoder().decode(pt));
}

export async function sealBackup(
  payload: DecryptedBackup,
  slots: SlotSpec[]
): Promise<EncryptedBackup> {
  if (!isValidPayload(payload)) {
    throw new Error(
      'Invalid payload: Payload must be an object matching SigmaSeedBackup, BapMasterBackup, BapAccountBackup, WifBackup, OneSatBackup, VaultBackup, YoursWalletBackup, or YoursWalletZipBackup structure.'
    );
  }
  if (!Array.isArray(slots) || slots.length === 0) {
    throw new Error('Invalid slots: at least one slot is required.');
  }
  const seen = new Set<string>();
  for (const s of slots) validateSlotSpecShape(s, seen);
  const descriptor = getDescriptorFromPayload(payload);
  const payloadJson = buildPayloadJson(payload);
  const payloadBytes = new TextEncoder().encode(payloadJson);
  const contentKey = globalThis.crypto.getRandomValues(new Uint8Array(CONTENT_KEY_LENGTH_BYTES));
  const wrappedSlots: Slot[] = [];
  for (const s of slots) {
    wrappedSlots.push(await wrapContentKey(s, contentKey));
  }
  const header: EnvelopeHeader = {
    v: 2,
    slots: wrappedSlots,
    ...(descriptor !== undefined ? { descriptor } : {}),
  };
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const key = await importContentKey(contentKey, ['encrypt']);
  const ct = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      payloadBytes as BufferSource
    )
  );
  return encodeEnvelope(header, iv, ct);
}

export async function openBackup(
  encrypted: EncryptedBackup,
  unlock: Unlock
): Promise<DecryptedBackup> {
  if (typeof encrypted !== 'string' || encrypted.length === 0) {
    throw new Error('Invalid encryptedString: Must be a non-empty string.');
  }
  const decoded = decodeBase64Envelope(encrypted);
  if (!hasV2Magic(decoded)) {
    throw new Error('Invalid envelope: not a v2 envelope.');
  }
  const { header, iv, ciphertext } = parseEnvelope(decoded);
  const contentKey = await resolveContentKey(header, unlock);
  return decryptPayload(contentKey, iv, ciphertext);
}

export async function openV2WithPassphrase(
  encrypted: EncryptedBackup,
  passphrase: string,
  attemptIterations?: number | number[]
): Promise<DecryptedBackup> {
  const decoded = decodeBase64Envelope(encrypted);
  const { header, iv, ciphertext } = parseEnvelope(decoded);
  let allowed: number[] | undefined;
  if (typeof attemptIterations === 'number') allowed = [attemptIterations];
  else if (Array.isArray(attemptIterations)) allowed = attemptIterations;
  const passphraseSlots = header.slots.filter(isPassphraseSlot);
  const filtered =
    allowed === undefined
      ? passphraseSlots
      : passphraseSlots.filter(
          (s) => s.type === 'argon2id' || allowed.includes(s.iterations),
        );
  if (filtered.length === 0) {
    if (allowed !== undefined && passphraseSlots.length > 0) {
      throw new Error('Decryption failed: No v2 slot matches the attempted iterations.');
    }
    throw new Error('Decryption failed: Invalid passphrase or corrupted data.');
  }
  for (const slot of filtered) {
    try {
      const contentKey = await unwrapPassphraseSlot(slot, passphrase);
      if (contentKey.length !== CONTENT_KEY_LENGTH_BYTES) continue;
      return await decryptPayload(contentKey, iv, ciphertext);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'OperationError') continue;
      if (
        error instanceof Error &&
        error.message === 'Decryption failed: Invalid passphrase or corrupted data.'
      ) {
        continue;
      }
      throw error;
    }
  }
  throw new Error('Decryption failed: Invalid passphrase or corrupted data.');
}

export function inspectEnvelope(encrypted: EncryptedBackup): InspectResult {
  if (typeof encrypted !== 'string' || encrypted.length === 0) {
    throw new Error('Invalid encryptedString: Must be a non-empty string.');
  }
  const decoded = decodeBase64Envelope(encrypted);
  if (!hasV2Magic(decoded)) {
    return { version: 1, slots: [] };
  }
  const { header } = parseEnvelope(decoded);
  return {
    version: 2,
    slots: header.slots.map((s) =>
      s.type === 'pbkdf2'
        ? { type: s.type, id: s.id, iterations: s.iterations }
        : s.type === 'argon2id'
          ? {
              type: s.type,
              id: s.id,
              iterations: s.iterations,
              memoryKiB: s.memoryKiB,
              parallelism: s.parallelism,
            }
          : { type: s.type, id: s.id, publicKey: s.publicKey }
    ),
    ...(header.descriptor !== undefined ? { descriptor: header.descriptor } : {}),
  };
}

export function isEnvelopeV2(encrypted: EncryptedBackup): boolean {
  try {
    if (typeof encrypted !== 'string' || encrypted.length === 0) return false;
    const decoded = decodeBase64Envelope(encrypted);
    if (!hasV2Magic(decoded)) return false;
    parseEnvelope(decoded);
    return true;
  } catch {
    return false;
  }
}

export async function addSlot(
  encrypted: EncryptedBackup,
  unlock: Unlock,
  slot: SlotSpec
): Promise<EncryptedBackup> {
  const decoded = decodeBase64Envelope(encrypted);
  if (!hasV2Magic(decoded)) throw new Error('Invalid envelope: not a v2 envelope.');
  const { header, iv, ciphertext } = parseEnvelope(decoded);
  validateSlotSpecShape(slot, new Set(header.slots.map((s) => s.id)));
  const contentKey = await resolveContentKey(header, unlock);
  const wrapped = await wrapContentKey(slot, contentKey);
  const newHeader: EnvelopeHeader = {
    v: 2,
    slots: [...header.slots, wrapped],
    ...(header.descriptor !== undefined ? { descriptor: header.descriptor } : {}),
  };
  return encodeEnvelope(newHeader, iv, ciphertext);
}

export async function removeSlot(
  encrypted: EncryptedBackup,
  unlock: Unlock,
  slotId: string
): Promise<EncryptedBackup> {
  const decoded = decodeBase64Envelope(encrypted);
  if (!hasV2Magic(decoded)) throw new Error('Invalid envelope: not a v2 envelope.');
  const { header, iv, ciphertext } = parseEnvelope(decoded);
  if (!header.slots.some((s) => s.id === slotId)) {
    throw new Error(`Slot '${slotId}' not found.`);
  }
  if (header.slots.length <= 1) {
    throw new Error('Cannot remove the last slot.');
  }
  await resolveContentKey(header, unlock);
  const newHeader: EnvelopeHeader = {
    v: 2,
    slots: header.slots.filter((s) => s.id !== slotId),
    ...(header.descriptor !== undefined ? { descriptor: header.descriptor } : {}),
  };
  return encodeEnvelope(newHeader, iv, ciphertext);
}

export async function rewrapBackup(
  encrypted: EncryptedBackup,
  unlock: Unlock,
  slots: SlotSpec[]
): Promise<EncryptedBackup> {
  if (!Array.isArray(slots) || slots.length === 0) {
    throw new Error('Invalid slots: at least one slot is required.');
  }
  const seen = new Set<string>();
  for (const s of slots) validateSlotSpecShape(s, seen);
  const decoded = decodeBase64Envelope(encrypted);
  if (!hasV2Magic(decoded)) throw new Error('Invalid envelope: not a v2 envelope.');
  const { header, iv: oldIv, ciphertext: oldCiphertext } = parseEnvelope(decoded);
  const oldContentKey = await resolveContentKey(header, unlock);
  const payload = await decryptPayload(oldContentKey, oldIv, oldCiphertext);
  const payloadJson = JSON.stringify(payload);
  const payloadBytes = new TextEncoder().encode(payloadJson);
  const newContentKey = globalThis.crypto.getRandomValues(new Uint8Array(CONTENT_KEY_LENGTH_BYTES));
  const wrappedSlots: Slot[] = [];
  for (const s of slots) {
    wrappedSlots.push(await wrapContentKey(s, newContentKey));
  }
  const descriptor = getDescriptorFromPayload(payload);
  const newHeader: EnvelopeHeader = {
    v: 2,
    slots: wrappedSlots,
    ...(descriptor !== undefined ? { descriptor } : {}),
  };
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const key = await importContentKey(newContentKey, ['encrypt']);
  const ct = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      payloadBytes as BufferSource
    )
  );
  return encodeEnvelope(newHeader, iv, ct);
}

/**
 * Re-encrypts a new payload under the envelope's existing content key, keeping every slot.
 * Use this to update a document without needing the credentials of every other slot.
 */
export async function updateBackupPayload(
  encrypted: EncryptedBackup,
  unlock: Unlock,
  payload: DecryptedBackup
): Promise<EncryptedBackup> {
  if (!isValidPayload(payload)) {
    throw new Error('Invalid payload: Payload must match a supported backup structure.');
  }
  const decoded = decodeBase64Envelope(encrypted);
  if (!hasV2Magic(decoded)) throw new Error('Invalid envelope: not a v2 envelope.');
  const { header } = parseEnvelope(decoded);
  const contentKey = await resolveContentKey(header, unlock);
  const descriptor = getDescriptorFromPayload(payload);
  const newHeader: EnvelopeHeader = {
    v: 2,
    slots: header.slots,
    ...(descriptor !== undefined ? { descriptor } : {}),
  };
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const key = await importContentKey(contentKey, ['encrypt']);
  const ct = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      new TextEncoder().encode(buildPayloadJson(payload)) as BufferSource
    )
  );
  return encodeEnvelope(newHeader, iv, ct);
}
