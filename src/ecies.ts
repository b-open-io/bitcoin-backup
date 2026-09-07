import { Utils } from '@bsv/sdk';

const { toArray, toBase64 } = Utils;

const INFO = 'se-vault-v1';

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(toArray(hex, 'hex'));
}

function bytesToHex(bytes: Uint8Array): string {
  return Utils.toHex(Array.from(bytes));
}

function bytesToBase64Url(bytes: Uint8Array): string {
  const b64 = toBase64(Array.from(bytes));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

export function assertP256PublicKeyHex(publicKeyHex: string, label: string): Uint8Array {
  return validateUncompressedHex(publicKeyHex, label).bytes;
}

function validateUncompressedHex(
  publicKeyHex: string,
  label: string
): { x: Uint8Array; y: Uint8Array; bytes: Uint8Array } {
  if (typeof publicKeyHex !== 'string' || !/^[0-9a-fA-F]+$/u.test(publicKeyHex)) {
    throw new Error(`${label}: public key must be hex.`);
  }
  if (publicKeyHex.length !== 130) {
    throw new Error(`${label}: public key must be 65-byte X9.63 uncompressed hex (130 hex chars).`);
  }
  const bytes = hexToBytes(publicKeyHex);
  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new Error(`${label}: public key must be 65-byte X9.63 uncompressed (0x04 || X || Y).`);
  }
  return { x: bytes.slice(1, 33), y: bytes.slice(33, 65), bytes };
}

async function importEcdhPublicKey(publicKeyHex: string, label: string): Promise<CryptoKey> {
  const { x, y } = validateUncompressedHex(publicKeyHex, label);
  const jwk: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    x: bytesToBase64Url(x),
    y: bytesToBase64Url(y),
    ext: true,
  };
  try {
    return await globalThis.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
  } catch (error) {
    throw new Error(`${label}: invalid P-256 public key (${(error as Error).message}).`);
  }
}

async function deriveKek(sharedSecret: ArrayBuffer): Promise<CryptoKey> {
  const hkdfKey = await globalThis.crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );
  const kekBytes = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(INFO),
    },
    hkdfKey,
    256
  );
  return globalThis.crypto.subtle.importKey(
    'raw',
    kekBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts plaintext for a P-256 ECDH recipient.
 * Layout: ephemeralPub(65, X9.63) || nonce(12) || AES-GCM(KEK, contentKey) + tag(16).
 * KEK = HKDF-SHA256(sharedSecret, salt=empty, info="se-vault-v1", 32).
 */
export async function eciesEncrypt(
  recipientPublicKeyHex: string,
  plaintextBytes: Uint8Array
): Promise<Uint8Array> {
  const recipientPublicKey = await importEcdhPublicKey(recipientPublicKeyHex, 'eciesEncrypt');
  const ephemeral = (await globalThis.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  )) as CryptoKeyPair;
  const ephemeralRaw = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('raw', ephemeral.publicKey)
  );
  if (ephemeralRaw.length !== 65 || ephemeralRaw[0] !== 0x04) {
    throw new Error('eciesEncrypt: failed to export ephemeral P-256 public key.');
  }
  const sharedSecret = await globalThis.crypto.subtle.deriveBits(
    { name: 'ECDH', public: recipientPublicKey },
    ephemeral.privateKey,
    256
  );
  const kek = await deriveKek(sharedSecret);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource },
      kek,
      plaintextBytes as BufferSource
    )
  );
  const wrapped = new Uint8Array(ephemeralRaw.length + nonce.length + ciphertext.length);
  wrapped.set(ephemeralRaw, 0);
  wrapped.set(nonce, ephemeralRaw.length);
  wrapped.set(ciphertext, ephemeralRaw.length + nonce.length);
  return wrapped;
}

/**
 * Decrypts an ECIES wrap produced by `eciesEncrypt`.
 */
export async function eciesDecrypt(
  privateKey: CryptoKey,
  wrapped: Uint8Array
): Promise<Uint8Array> {
  if (!(wrapped instanceof Uint8Array)) {
    throw new Error('eciesDecrypt: wrapped must be a Uint8Array.');
  }
  if (wrapped.length < 65 + 12 + 16) {
    throw new Error('eciesDecrypt: wrapped bytes are truncated.');
  }
  const ephemeralBytes = wrapped.slice(0, 65);
  const nonce = wrapped.slice(65, 65 + 12);
  const ciphertext = wrapped.slice(65 + 12);
  if (ephemeralBytes[0] !== 0x04) {
    throw new Error('eciesDecrypt: ephemeral public key must be X9.63 uncompressed.');
  }
  const ephemeralHex = bytesToHex(ephemeralBytes);
  const ephemeralPublicKey = await importEcdhPublicKey(ephemeralHex, 'eciesDecrypt');
  let sharedSecret: ArrayBuffer;
  try {
    sharedSecret = await globalThis.crypto.subtle.deriveBits(
      { name: 'ECDH', public: ephemeralPublicKey },
      privateKey,
      256
    );
  } catch (error) {
    throw new Error(`eciesDecrypt: ECDH failed (${(error as Error).message}).`);
  }
  const kek = await deriveKek(sharedSecret);
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource },
    kek,
    ciphertext as BufferSource
  );
  return new Uint8Array(plaintext);
}
