/** Wallet-grade passphrase rules. Do not trim; spaces are significant. */

export const MIN_PASSPHRASE_LENGTH = 12;
export const LONG_PASSPHRASE_LENGTH = 16;
export const MAX_PASSPHRASE_LENGTH = 1024;

const COMMON_PASSPHRASES = new Set([
	"password",
	"password123",
	"password1234",
	"123456789012",
	"1234567890123456",
	"qwertyuiopas",
	"letmein12345",
	"bitcoin12345",
	"passphrase123",
	"correcthorsebatterystaple",
]);

export function assertLegacyPassphrase(passphrase: unknown): asserts passphrase is string {
	if (typeof passphrase !== "string" || passphrase.length === 0) {
		throw new Error("Invalid passphrase: Passphrase must be a non-empty string.");
	}
	if (passphrase.length < 8) {
		throw new Error("Invalid passphrase: Passphrase must be at least 8 characters long.");
	}
}

export function assertPassphrase(passphrase: unknown): asserts passphrase is string {
	if (typeof passphrase !== "string" || passphrase.length === 0) {
		throw new Error("Invalid passphrase: Passphrase must be a non-empty string.");
	}
	if (passphrase.length > MAX_PASSPHRASE_LENGTH) {
		throw new Error("Invalid passphrase: Passphrase is too long.");
	}
	if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
		throw new Error(
			`Invalid passphrase: Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters long.`,
		);
	}
	if (/^\s+$/u.test(passphrase)) {
		throw new Error("Invalid passphrase: Passphrase cannot be only whitespace.");
	}
	if (COMMON_PASSPHRASES.has(passphrase.toLowerCase())) {
		throw new Error("Invalid passphrase: Choose a less common passphrase.");
	}
	const classes = [
		/[a-z]/u.test(passphrase),
		/[A-Z]/u.test(passphrase),
		/[0-9]/u.test(passphrase),
		/[^A-Za-z0-9]/u.test(passphrase),
	].filter(Boolean).length;
	if (passphrase.length < LONG_PASSPHRASE_LENGTH && classes < 3) {
		throw new Error(
			`Invalid passphrase: Use at least ${LONG_PASSPHRASE_LENGTH} characters, or mix upper, lower, and digits.`,
		);
	}
}
