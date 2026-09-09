import { describe, expect, it } from "bun:test";
import { assertLegacyPassphrase, assertPassphrase } from "../src/passphrase";

describe("assertLegacyPassphrase", () => {
	it("accepts eight characters", () => {
		expect(() => assertLegacyPassphrase("eightchr")).not.toThrow();
	});
	it("rejects shorter strings", () => {
		expect(() => assertLegacyPassphrase("shortp")).toThrow(/at least 8/);
	});
});

describe("assertPassphrase", () => {
	it("accepts a long lowercase passphrase", () => {
		expect(() => assertPassphrase("correct horse battery staple")).not.toThrow();
	});
	it("accepts a mixed 12-character password", () => {
		expect(() => assertPassphrase("Abcd1234!xyz")).not.toThrow();
	});
	it("does not trim surrounding spaces", () => {
		expect(() => assertPassphrase("  mixed Pass 12")).not.toThrow();
	});
	it("rejects short secrets", () => {
		expect(() => assertPassphrase("shortp")).toThrow(/at least 12/);
	});
	it("rejects whitespace-only secrets", () => {
		expect(() => assertPassphrase("            ")).toThrow(/whitespace/);
	});
	it("rejects a common password", () => {
		expect(() => assertPassphrase("password1234")).toThrow(/less common/);
	});
	it("rejects a short password without mixed classes", () => {
		expect(() => assertPassphrase("abcdefghijkl")).toThrow(/16 characters/);
	});
});
