import { argon2id } from "@noble/hashes/argon2.js";

export interface Argon2idParams {
	memoryKiB: number;
	iterations: number;
	parallelism: number;
}

/** RFC 9106 “much less memory available” recommendation for interactive unlock. */
export const ARGON2ID_DEFAULTS: Argon2idParams = {
	memoryKiB: 65536,
	iterations: 3,
	parallelism: 1,
};

/** Fast parameters for automated tests only. Never a production default. */
export const ARGON2ID_FAST: Argon2idParams = {
	memoryKiB: 32,
	iterations: 1,
	parallelism: 1,
};

const MIN_MEMORY_KIB = 8;
const MAX_MEMORY_KIB = 2 * 1024 * 1024;
const MAX_ITERATIONS = 1024;
const MAX_PARALLELISM = 16;
const DK_LEN = 32;

export function validateArgon2idParams(params: Argon2idParams): Argon2idParams {
	const { memoryKiB, iterations, parallelism } = params;
	if (
		!Number.isSafeInteger(memoryKiB) ||
		memoryKiB < MIN_MEMORY_KIB ||
		memoryKiB > MAX_MEMORY_KIB
	) {
		throw new Error("Invalid argon2id memory: must be an integer KiB between 8 and 2097152.");
	}
	if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS) {
		throw new Error("Invalid argon2id iterations: must be an integer between 1 and 1024.");
	}
	if (
		!Number.isSafeInteger(parallelism) ||
		parallelism < 1 ||
		parallelism > MAX_PARALLELISM
	) {
		throw new Error("Invalid argon2id parallelism: must be an integer between 1 and 16.");
	}
	return { memoryKiB, iterations, parallelism };
}

export function resolveArgon2idParams(partial?: Partial<Argon2idParams>): Argon2idParams {
	return validateArgon2idParams({
		memoryKiB: partial?.memoryKiB ?? ARGON2ID_DEFAULTS.memoryKiB,
		iterations: partial?.iterations ?? ARGON2ID_DEFAULTS.iterations,
		parallelism: partial?.parallelism ?? ARGON2ID_DEFAULTS.parallelism,
	});
}

export function deriveArgon2idRaw(
	passphrase: string,
	salt: Uint8Array,
	params: Argon2idParams,
): Uint8Array {
	const checked = validateArgon2idParams(params);
	if (salt.length < 16) throw new Error("argon2id salt must be at least 16 bytes.");
	return argon2id(passphrase, salt, {
		t: checked.iterations,
		m: checked.memoryKiB,
		p: checked.parallelism,
		dkLen: DK_LEN,
		maxmem: Math.max(checked.memoryKiB * 1024 * 2, 32 * 1024 * 1024),
	});
}

export async function deriveArgon2idKey(
	passphrase: string,
	salt: Uint8Array,
	params: Argon2idParams,
): Promise<CryptoKey> {
	const raw = deriveArgon2idRaw(passphrase, salt, params);
	return globalThis.crypto.subtle.importKey(
		"raw",
		raw as BufferSource,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}
