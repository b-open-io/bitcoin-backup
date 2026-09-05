import type { SigmaSeedBackup } from './interfaces';

const MAX_INDEX = 2147483647;
const fields = new Set([
  'format',
  'version',
  'scheme',
  'mnemonic',
  'entropyBytes',
  'passphrasePolicy',
  'profiles',
  'nextProfileIndex',
  'inventoryComplete',
  'createdAt',
  'label',
]);
const profileFields = new Set(['index', 'bapId', 'metadata']);

function object(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

function index(value: unknown): value is number {
  return (
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_INDEX
  );
}

function json(value: unknown, ancestors = new Set<object>()): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (!Array.isArray(value) && !object(value)) return false;
  if (ancestors.has(value)) return false;
  ancestors.add(value);
  const valid = Object.values(value).every((item) => json(item, ancestors));
  ancestors.delete(value);
  return valid;
}

/** Reserve seed markers before legacy duck typing so mixed payloads fail closed. */
export function hasSigmaSeedMarker(value: object): boolean {
  if (
    [
      'format',
      'entropyBytes',
      'passphrasePolicy',
      'profiles',
      'nextProfileIndex',
      'inventoryComplete',
    ].some((key) => key in value)
  )
    return true;
  // VaultBackup already owns an optional scheme field. Preserve that existing contract.
  return (
    'scheme' in value &&
    (!('encryptedVault' in value) ||
      value.scheme === 'brc157-peer-profiles' ||
      ['rootPk', 'xprv', 'wif'].some((key) => key in value))
  );
}

/** Structural validation only; mnemonic checksum and BAP/key binding belong to the Sigma seed module. */
export function isSigmaSeedBackup(value: unknown): value is SigmaSeedBackup {
  if (!object(value) || Object.keys(value).some((key) => !fields.has(key))) return false;
  if (
    value.format !== 'sigma-seed' ||
    value.version !== 1 ||
    value.scheme !== 'brc157-peer-profiles' ||
    value.passphrasePolicy !== 'empty'
  )
    return false;
  if (typeof value.entropyBytes !== 'number' || ![16, 20, 24, 28, 32].includes(value.entropyBytes))
    return false;
  if (
    typeof value.mnemonic !== 'string' ||
    value.mnemonic.trim() !== value.mnemonic ||
    value.mnemonic.split(/\s+/u).length !== (value.entropyBytes * 3) / 4
  )
    return false;
  if (
    typeof value.nextProfileIndex !== 'number' ||
    !Number.isSafeInteger(value.nextProfileIndex) ||
    value.nextProfileIndex < 0 ||
    value.nextProfileIndex > MAX_INDEX + 1 ||
    typeof value.createdAt !== 'number' ||
    !Number.isSafeInteger(value.createdAt) ||
    value.createdAt < 0
  )
    return false;
  if ('inventoryComplete' in value && value.inventoryComplete !== false) return false;
  if ('label' in value && typeof value.label !== 'string') return false;
  if (!Array.isArray(value.profiles) || value.profiles.length === 0) return false;
  const indices = new Set<number>();
  const ids = new Set<string>();
  for (const profile of value.profiles) {
    if (!object(profile) || Object.keys(profile).some((key) => !profileFields.has(key)))
      return false;
    if (
      !index(profile.index) ||
      profile.index >= value.nextProfileIndex ||
      indices.has(profile.index)
    )
      return false;
    if (typeof profile.bapId !== 'string' || !profile.bapId.trim() || ids.has(profile.bapId))
      return false;
    if ('metadata' in profile && (!object(profile.metadata) || !json(profile.metadata)))
      return false;
    indices.add(profile.index);
    ids.add(profile.bapId);
  }
  return true;
}
