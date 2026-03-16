# Touch ID Password Cache for bbackup

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Secure Enclave-backed password caching to `bbackup` so users type their password once and use Touch ID for all subsequent encrypt/decrypt operations.

**Architecture:** A new `src/touchid.ts` module wraps `@1sat/vault` to cache passphrases keyed by a SHA-256 hash of the `.bep` file path. The CLI gains `--touchid` flag and a `forget` command. The library API is unchanged -- Touch ID is CLI-only convenience. The `.bep` file format is unmodified; portability is preserved. `@1sat/vault` is an **optional peer dependency** -- the library works without it on all platforms.

**Tech Stack:** TypeScript, `@1sat/vault` (Secure Enclave, optional peer dep), Bun (runtime + `CryptoHasher`), Commander.js

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/touchid.ts` | Create | SE password cache: save, retrieve, forget, isAvailable |
| `cli/bbackup.ts` | Modify | Add `--touchid` to enc/dec/upg, add `forget` command |
| `build.ts` | Modify | Add `@1sat/vault` to external arrays |
| `test/touchid.test.ts` | Create | Unit tests for password cache module |
| `package.json` | Modify | Add `@1sat/vault` as optional peer dep, bump version |

---

### Task 1: Add `@1sat/vault` dependency and update build config

**Files:**
- Modify: `package.json`
- Modify: `build.ts`

`@1sat/vault` must be an **optional peer dependency**, not a regular dependency. This way:
- Consumers on non-macOS platforms don't get the Swift postinstall
- The library works everywhere; Touch ID is opt-in
- The bundler treats it as external (not inlined)

- [ ] **Step 1: Install @1sat/vault as optional peer dep**

```bash
cd ~/code/bitcoin-backup && bun add @1sat/vault@0.0.3 --optional
```

Then manually move it from `dependencies`/`optionalDependencies` to `peerDependencies` + `peerDependenciesMeta` in `package.json`:

```json
"peerDependencies": {
  "@bsv/sdk": "^1.5.2 || ^2.0.0",
  "@1sat/vault": ">=0.0.3"
},
"peerDependenciesMeta": {
  "@1sat/vault": { "optional": true }
}
```

- [ ] **Step 2: Add @1sat/vault to build.ts externals**

In `build.ts`, update both the library and CLI external arrays:

```typescript
const defaultLibraryConfig: BuildConfig = {
  entrypoints: ['./src/index.ts'],
  outdir: './dist',
  external: ['@bsv/sdk', '@1sat/vault'],
  target: 'node'
}

const cliConfig: BuildConfig = {
  entrypoints: ['./cli/bbackup.ts'],
  outdir: './dist/cli',
  external: ['@bsv/sdk', 'commander', '@1sat/vault'],
  format: 'esm',
  target: 'node',
  naming: "[name].js"
}
```

- [ ] **Step 3: Verify import resolves**

```bash
cd ~/code/bitcoin-backup && bun -e 'import { isSupported } from "@1sat/vault"; console.log("SE supported:", isSupported())'
```

Expected: `SE supported: true` (on arm64 Mac)

- [ ] **Step 4: Run existing tests to verify no breakage**

```bash
cd ~/code/bitcoin-backup && bun test
```

Expected: 68 pass, 1 fail (pre-existing type42 integration test)

- [ ] **Step 5: Commit**

```bash
cd ~/code/bitcoin-backup
git add package.json bun.lock build.ts
git commit -m "Add @1sat/vault as optional peer dep, update build externals"
```

---

### Task 2: Create `src/touchid.ts` -- password cache module

**Files:**
- Create: `src/touchid.ts`
- Test: `test/touchid.test.ts`

The module caches passphrases in the Secure Enclave, keyed by a deterministic label derived from the absolute path of the `.bep` file. Each backup file gets its own cached password.

Label format: `bbackup-<hex>` where `<hex>` is the first 16 chars of SHA-256 of the absolute file path. This keeps labels short, deterministic, and within the 63-char label limit.

Uses `Bun.CryptoHasher` for hashing -- this project runs on Bun everywhere.

- [ ] **Step 1: Write the failing tests**

Create `test/touchid.test.ts`:

```typescript
import { describe, expect, it } from "bun:test";

describe("touchid password cache", () => {
  it("should export cachePassword, getCachedPassword, forgetPassword, isTouchIDAvailable", async () => {
    const mod = await import("../src/touchid");
    expect(typeof mod.cachePassword).toBe("function");
    expect(typeof mod.getCachedPassword).toBe("function");
    expect(typeof mod.forgetPassword).toBe("function");
    expect(typeof mod.isTouchIDAvailable).toBe("function");
  });

  it("getLabelForFile should produce deterministic labels", async () => {
    const { getLabelForFile } = await import("../src/touchid");
    const label1 = getLabelForFile("/tmp/test.bep");
    const label2 = getLabelForFile("/tmp/test.bep");
    expect(label1).toBe(label2);
    expect(label1).toMatch(/^bbackup-[a-f0-9]{16}$/);
  });

  it("getLabelForFile should produce different labels for different paths", async () => {
    const { getLabelForFile } = await import("../src/touchid");
    const label1 = getLabelForFile("/tmp/a.bep");
    const label2 = getLabelForFile("/tmp/b.bep");
    expect(label1).not.toBe(label2);
  });

  it("getLabelForFile resolves relative paths to absolute", async () => {
    const { getLabelForFile } = await import("../src/touchid");
    const label1 = getLabelForFile("./test.bep");
    const label2 = getLabelForFile("test.bep");
    // Both resolve to same absolute path from cwd
    expect(label1).toBe(label2);
  });

  it("isTouchIDAvailable returns a boolean", async () => {
    const { isTouchIDAvailable } = await import("../src/touchid");
    expect(typeof isTouchIDAvailable()).toBe("boolean");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/code/bitcoin-backup && bun test test/touchid.test.ts
```

Expected: FAIL -- module not found

- [ ] **Step 3: Write the implementation**

Create `src/touchid.ts`:

```typescript
/**
 * Touch ID password cache for bbackup.
 *
 * Caches passphrases in the macOS Secure Enclave via @1sat/vault.
 * Each .bep file gets its own vault entry, keyed by a hash of its absolute path.
 * The passphrase is encrypted with a P-256 key that never leaves the SE chip.
 * Decryption (retrieval) triggers Touch ID.
 *
 * This module is a convenience layer -- the .bep file format is unchanged.
 * Backups remain portable; only the cached password is hardware-bound.
 */

import { resolve } from "node:path";

/**
 * Derive a deterministic vault label from a file path.
 * Uses first 16 hex chars of SHA-256(absolutePath).
 */
export function getLabelForFile(filePath: string): string {
  const absolutePath = resolve(filePath);
  const hash = new Bun.CryptoHasher("sha256").update(absolutePath).digest("hex");
  return `bbackup-${hash.slice(0, 16)}`;
}

/** Check if Touch ID password caching is available on this platform. */
export function isTouchIDAvailable(): boolean {
  try {
    const { isSupported } = require("@1sat/vault");
    return isSupported();
  } catch {
    return false;
  }
}

/**
 * Lazily load @1sat/vault. Throws if not installed.
 */
async function loadVault() {
  try {
    return await import("@1sat/vault");
  } catch {
    throw new Error(
      "@1sat/vault is not installed. Install it with: bun add @1sat/vault"
    );
  }
}

/**
 * Cache a passphrase for a .bep file in the Secure Enclave.
 * No Touch ID required (encryption uses public key only).
 */
export async function cachePassword(
  filePath: string,
  passphrase: string,
): Promise<void> {
  const vault = await loadVault();
  const label = getLabelForFile(filePath);
  await vault.protectSecret(label, passphrase, {
    file: resolve(filePath),
  });
}

/**
 * Retrieve a cached passphrase for a .bep file.
 * Triggers Touch ID -- the ECDH happens inside the Secure Enclave.
 * Returns null if no cached password exists.
 */
export async function getCachedPassword(
  filePath: string,
): Promise<string | null> {
  const vault = await loadVault();
  const label = getLabelForFile(filePath);
  try {
    const { plaintext } = await vault.unlockSecret(label);
    return plaintext;
  } catch {
    return null;
  }
}

/**
 * Remove a cached passphrase for a .bep file.
 */
export async function forgetPassword(filePath: string): Promise<void> {
  const vault = await loadVault();
  const label = getLabelForFile(filePath);
  try {
    await vault.removeSecret(label);
  } catch {
    // No cached password to remove
  }
}
```

Key design decisions:
- `getLabelForFile` is synchronous (uses `node:crypto`, not async)
- `isTouchIDAvailable` uses `require()` with try/catch so it returns false if vault isn't installed
- `loadVault()` is lazy -- `@1sat/vault` only loads when Touch ID is actually used
- No static import of `@1sat/vault` at module level -- the module can be imported on any platform

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/code/bitcoin-backup && bun test test/touchid.test.ts
```

Expected: 5 pass

- [ ] **Step 5: Run all tests to verify no regression**

```bash
cd ~/code/bitcoin-backup && bun test
```

Expected: 73 pass, 1 fail (pre-existing)

- [ ] **Step 6: Lint**

```bash
cd ~/code/bitcoin-backup && bun run lint:fix
```

- [ ] **Step 7: Commit**

```bash
cd ~/code/bitcoin-backup
git add src/touchid.ts test/touchid.test.ts
git commit -m "Add Touch ID password cache module (src/touchid.ts)"
```

---

### Task 3: Add `--touchid` to all CLI commands + `forget` command

**Files:**
- Modify: `cli/bbackup.ts`

All three commands (enc, dec, upg) get the same pattern:
1. `-p` becomes optional (was `requiredOption`, now `option`)
2. `--touchid` flag: without `-p` retrieves cached password; with `-p` caches it
3. New `forget` command for explicit cache removal

All caching and lookup uses the **`.bep` file path** as the key. For `dec` and `upg`, that's the input file. For `enc`, that's the output file.

- [ ] **Step 1: Rewrite `cli/bbackup.ts` with Touch ID support**

Replace the entire contents of `cli/bbackup.ts`:

```typescript
#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { Command } from 'commander';
import {
  type DecryptedBackup,
  decryptBackup,
  encryptBackup,
  RECOMMENDED_PBKDF2_ITERATIONS,
} from '../src/index';

const program = new Command();

program
  .name('bbackup')
  .description('CLI tool for managing and securing Bitcoin-related identity backups.')
  .version('0.0.9');

/**
 * Resolve a password from explicit flag, Touch ID cache, or error.
 * @param bepFilePath The .bep file path used as the Touch ID cache key.
 */
async function resolvePassword(opts: {
  password?: string;
  touchid?: boolean;
  bepFilePath: string;
  cacheOnSuccess?: boolean;
}): Promise<string> {
  const { password, touchid, bepFilePath } = opts;

  if (password) return password;

  if (touchid) {
    const { isTouchIDAvailable, getCachedPassword } = await import('../src/touchid');
    if (!isTouchIDAvailable()) {
      console.error('Touch ID is not available on this platform (requires macOS arm64).');
      process.exit(1);
    }
    console.log('Retrieving password via Touch ID...');
    const cached = await getCachedPassword(bepFilePath);
    if (cached) return cached;
    console.error('No cached password found for this file.');
    console.error('Run with -p <password> --touchid first to cache it.');
    process.exit(1);
  }

  console.error('Password required. Use -p <password> or --touchid.');
  process.exit(1);
}

/** Cache password after successful operation if --touchid + -p were both provided. */
async function maybeCachePassword(opts: {
  password?: string;
  touchid?: boolean;
  bepFilePath: string;
}): Promise<void> {
  if (!opts.touchid || !opts.password) return;
  const { isTouchIDAvailable, cachePassword } = await import('../src/touchid');
  if (!isTouchIDAvailable()) return;
  await cachePassword(opts.bepFilePath, opts.password);
  console.log('Password cached with Touch ID for future use.');
}

// --- enc ---

program
  .command('enc <inputFile>')
  .description('Encrypt a JSON backup file.')
  .option('-p, --password <password>', 'Passphrase for encryption')
  .option('--touchid', 'Use Touch ID to retrieve or cache password')
  .option('-o, --output <outputFile>', 'Path to save the encrypted backup')
  .option(
    '-t, --iterations <count>',
    'Number of PBKDF2 iterations',
    (val) => Number.parseInt(val, 10),
    RECOMMENDED_PBKDF2_ITERATIONS,
  )
  .action(
    async (
      inputFile: string,
      options: { password?: string; output?: string; iterations: number; touchid?: boolean },
    ) => {
      let outputFile = options.output;
      if (!outputFile) {
        const inputPath = path.parse(inputFile);
        outputFile = path.join(inputPath.dir, `${inputPath.name}_encrypted.bep`);
        console.log(`Output file not specified, defaulting to: ${outputFile}`);
      }

      // For enc, the cache key is the OUTPUT .bep file
      const password = await resolvePassword({
        password: options.password,
        touchid: options.touchid,
        bepFilePath: outputFile,
      });

      console.log(
        `Encrypting ${inputFile} to ${outputFile} using ${options.iterations} iterations...`,
      );

      try {
        const absoluteInputPath = path.resolve(inputFile);
        const decryptedJsonString = await fs.readFile(absoluteInputPath, 'utf-8');
        const decryptedPayload = JSON.parse(decryptedJsonString) as DecryptedBackup;

        if (!decryptedPayload || typeof decryptedPayload !== 'object') {
          throw new Error(
            'Invalid input file content: Must be a valid JSON object representing a backup.',
          );
        }

        const encryptedBackupString = await encryptBackup(
          decryptedPayload,
          password,
          options.iterations,
        );

        const absoluteOutputPath = path.resolve(outputFile);
        const outputDir = path.dirname(absoluteOutputPath);
        await fs.mkdir(outputDir, { recursive: true });

        await fs.writeFile(absoluteOutputPath, encryptedBackupString, 'utf-8');
        console.log(`File encrypted successfully and saved to ${absoluteOutputPath}`);

        await maybeCachePassword({
          password: options.password,
          touchid: options.touchid,
          bepFilePath: outputFile,
        });
      } catch (error) {
        if (error instanceof Error) {
          console.error('Encryption failed:', error.message);
        } else {
          console.error('An unknown error occurred during encryption:', error);
        }
        process.exit(1);
      }
    },
  );

// --- dec ---

program
  .command('dec <inputFile>')
  .description('Decrypt an encrypted backup file.')
  .option('-p, --password <password>', 'Passphrase for decryption')
  .option('--touchid', 'Use Touch ID to retrieve or cache password')
  .option(
    '-o, --output <outputFile>',
    'Path to save the decrypted JSON. If omitted, prints to console.',
  )
  .action(async (inputFile: string, options: { password?: string; output?: string; touchid?: boolean }) => {
    // For dec, the cache key is the INPUT .bep file
    const password = await resolvePassword({
      password: options.password,
      touchid: options.touchid,
      bepFilePath: inputFile,
    });

    console.log(`Attempting to decrypt file: ${inputFile}`);
    try {
      const absoluteInputPath = path.resolve(inputFile);
      const encryptedString = await fs.readFile(absoluteInputPath, 'utf-8');

      if (!encryptedString.trim()) {
        console.error('Error: Encrypted file is empty or contains only whitespace.');
        process.exit(1);
      }

      console.log('File content read, attempting decryption...');
      const decryptedPayload = await decryptBackup(encryptedString.trim(), password);

      await maybeCachePassword({
        password: options.password,
        touchid: options.touchid,
        bepFilePath: inputFile,
      });

      if (options.output) {
        const absoluteOutputPath = path.resolve(options.output);
        const outputDir = path.dirname(absoluteOutputPath);
        await fs.mkdir(outputDir, { recursive: true });
        await fs.writeFile(absoluteOutputPath, JSON.stringify(decryptedPayload, null, 2), 'utf8');
        console.log(`\nDecryption successful! Decrypted payload saved to: ${absoluteOutputPath}`);
      } else {
        console.log('\nDecryption successful!\n');
        console.log('Decrypted Payload:');
        console.log(JSON.stringify(decryptedPayload, null, 2));
      }
    } catch (error) {
      console.error('\nDecryption failed:');
      if (error instanceof Error) {
        console.error('Error:', error.message);
      } else {
        console.error('An unknown error occurred during decryption:', error);
      }
      process.exit(1);
    }
  });

// --- upg ---

program
  .command('upg <inputFile>')
  .description('Upgrade an encrypted backup file to the recommended PBKDF2 iterations.')
  .option('-p, --password <password>', 'Passphrase for decryption and re-encryption')
  .option('--touchid', 'Use Touch ID to retrieve or cache password')
  .option('-o, --output <outputFile>', 'Path to save the upgraded encrypted file')
  .action(async (inputFile: string, options: { password?: string; output?: string; touchid?: boolean }) => {
    const password = await resolvePassword({
      password: options.password,
      touchid: options.touchid,
      bepFilePath: inputFile,
    });

    let outputFile = options.output;
    console.log(`Attempting to upgrade file: ${inputFile}`);

    try {
      const absoluteInputPath = path.resolve(inputFile);
      const encryptedBackup = await fs.readFile(absoluteInputPath, 'utf-8');

      console.log('Decrypting file...');
      const decryptedPayload = await decryptBackup(encryptedBackup, password);
      console.log('File decrypted successfully.');

      console.log(`Re-encrypting with ${RECOMMENDED_PBKDF2_ITERATIONS} iterations...`);
      const upgradedEncryptedBackup = await encryptBackup(
        decryptedPayload,
        password,
        RECOMMENDED_PBKDF2_ITERATIONS,
      );
      console.log('File re-encrypted successfully.');

      if (!outputFile) {
        const dirname = path.dirname(absoluteInputPath);
        const ext = path.extname(absoluteInputPath);
        const basename = path.basename(absoluteInputPath, ext);
        outputFile = path.join(dirname, `${basename}_upgraded${ext}`);
        console.log(`Output file not specified, defaulting to: ${outputFile}`);
      }

      const absoluteOutputPath = path.resolve(outputFile);
      const outputDir = path.dirname(absoluteOutputPath);
      await fs.mkdir(outputDir, { recursive: true });

      console.log(`Writing upgraded file to: ${absoluteOutputPath}`);
      await fs.writeFile(absoluteOutputPath, upgradedEncryptedBackup, 'utf-8');
      console.log(
        `File ${inputFile} upgraded and saved as ${absoluteOutputPath} with ${RECOMMENDED_PBKDF2_ITERATIONS} PBKDF2 iterations.`,
      );

      await maybeCachePassword({
        password: options.password,
        touchid: options.touchid,
        bepFilePath: outputFile ?? inputFile,
      });
    } catch (error: unknown) {
      console.error('Error during file upgrade:');
      if (error instanceof Error) {
        console.error('Error:', error.message);
      } else {
        console.error('An unknown error occurred during upgrade:', error);
      }
      process.exit(1);
    }
  });

// --- forget ---

program
  .command('forget <file>')
  .description('Remove cached Touch ID password for a backup file.')
  .action(async (file: string) => {
    const { isTouchIDAvailable, forgetPassword } = await import('../src/touchid');

    if (!isTouchIDAvailable()) {
      console.error('Touch ID is not available on this platform.');
      process.exit(1);
    }

    await forgetPassword(file);
    console.log(`Cached password removed for ${path.resolve(file)}`);
  });

program.parse(process.argv);
```

Key design decisions vs. the original:
- Password resolution extracted into `resolvePassword()` helper (DRY)
- Cache-on-success extracted into `maybeCachePassword()` helper (DRY)
- `enc` caches and looks up by **output** `.bep` path (consistent with `dec` looking up by input `.bep` path -- both use the `.bep` file as key)
- No `--forget` flag on `dec` -- the standalone `forget` command is cleaner
- `-p` changed from `requiredOption` to `option` on all commands
- Version bumped to `0.0.9` in `.version()` call
- Dynamic `import('../src/touchid')` only when Touch ID is actually used

- [ ] **Step 2: Verify the CLI still works without --touchid**

```bash
echo '{"wif":"L4rprVahLjG4LWdULUeoxaVyq9chGQzg8kSVgSWfBrdeyAZs9VLo","label":"test"}' > /tmp/test-backup.json
bun cli/bbackup.ts enc /tmp/test-backup.json -p "testpass123!" -o /tmp/test.bep
bun cli/bbackup.ts dec /tmp/test.bep -p "testpass123!"
```

Expected: encrypts and decrypts as before

- [ ] **Step 3: Lint**

```bash
cd ~/code/bitcoin-backup && bun run lint:fix
```

- [ ] **Step 4: Build**

```bash
cd ~/code/bitcoin-backup && bun run build
```

- [ ] **Step 5: Run all tests**

```bash
cd ~/code/bitcoin-backup && bun test
```

Expected: 73+ pass, 1 fail (pre-existing)

- [ ] **Step 6: Commit**

```bash
cd ~/code/bitcoin-backup
git add cli/bbackup.ts
git commit -m "Add --touchid to enc/dec/upg commands, add forget command"
```

---

### Task 4: Update README, CHANGELOG, bump version

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `package.json` (version bump to 0.0.9)

- [ ] **Step 1: Read existing README.md and CHANGELOG.md**

Read both files to understand existing format.

- [ ] **Step 2: Add Touch ID section to README**

Add after the existing CLI usage section:

```markdown
### Touch ID Password Cache (macOS Apple Silicon)

On supported hardware, `bbackup` can cache your passphrase in the Secure Enclave so you don't have to type it every time.

**First decrypt -- password required, gets cached:**

    bbackup dec wallet.bep -p "my-password" --touchid

**Every time after -- just Touch ID:**

    bbackup dec wallet.bep --touchid

**Works with all commands:**

    bbackup enc backup.json -p "my-password" --touchid -o wallet.bep
    bbackup dec wallet.bep --touchid
    bbackup upg old.bep --touchid
    bbackup forget wallet.bep

**Important:**

- Cached passwords are hardware-bound to your Mac's Secure Enclave
- The `.bep` file format is unchanged -- backups remain portable
- Touch ID is a convenience layer, not a replacement for your passphrase
- Without `--touchid`, all commands work exactly as before
- Requires `@1sat/vault` package: `bun add @1sat/vault`
- Requires macOS on Apple Silicon (arm64)
```

- [ ] **Step 3: Add CHANGELOG entry**

Add at top of CHANGELOG.md:

```markdown
## 0.0.9

### Added
- Touch ID password cache via `--touchid` flag on enc, dec, and upg commands
- `bbackup forget <file>` command to remove cached passwords
- `src/touchid.ts` module for programmatic SE password caching
- `@1sat/vault` as optional peer dependency for Secure Enclave support
```

- [ ] **Step 4: Bump version to 0.0.9 in package.json**

- [ ] **Step 5: Build and test**

```bash
cd ~/code/bitcoin-backup && bun run build && bun test
```

- [ ] **Step 6: Commit**

```bash
cd ~/code/bitcoin-backup
git add README.md CHANGELOG.md package.json cli/bbackup.ts
git commit -m "Document Touch ID password cache, bump to v0.0.9"
```

---

## Usage Summary

After implementation, the user experience is:

```bash
# Traditional flow (unchanged)
bbackup enc wallet.json -p "hunter2" -o wallet.bep
bbackup dec wallet.bep -p "hunter2"

# Touch ID flow -- type password once
bbackup dec wallet.bep -p "hunter2" --touchid    # decrypts + caches password
bbackup dec wallet.bep --touchid                   # Touch ID, no password needed
bbackup enc wallet.json --touchid -o wallet.bep    # uses cached password from wallet.bep

# Manage cached passwords
bbackup forget wallet.bep                          # remove cached password
```

The `.bep` file is identical in both flows. You can decrypt a Touch ID-cached backup on any machine with the original password. The cache is purely local convenience.
