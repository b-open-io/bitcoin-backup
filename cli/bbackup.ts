#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { Command } from 'commander';
import {
  type DecryptedBackup,
  RECOMMENDED_PBKDF2_ITERATIONS,
  decryptBackup,
  encryptBackup,
} from '../src/index';

const program = new Command();

program
  .name('bbackup')
  .description('CLI tool for managing and securing Bitcoin-related identity backups.')
  .version('0.1.0'); // We can fetch this from package.json later

program
  .command('enc <inputFile>')
  .description('Encrypt a JSON backup file.')
  .requiredOption('-p, --password <password>', 'Passphrase for encryption')
  .option('-o, --output <outputFile>', 'Path to save the encrypted backup')
  .option(
    '-t, --iterations <count>',
    'Number of PBKDF2 iterations',
    (val) => Number.parseInt(val, 10),
    RECOMMENDED_PBKDF2_ITERATIONS
  )
  .action(
    async (
      inputFile: string,
      options: { password: string; output?: string; iterations: number }
    ) => {
      let outputFile = options.output;
      if (!outputFile) {
        const inputPath = path.parse(inputFile);
        outputFile = path.join(inputPath.dir, `${inputPath.name}_encrypted.bep`);
        console.log(`Output file not specified, defaulting to: ${outputFile}`);
      }

      console.log(
        `Encrypting ${inputFile} to ${outputFile} using ${options.iterations} iterations...`
      );

      try {
        const absoluteInputPath = path.resolve(inputFile);
        const decryptedJsonString = await fs.readFile(absoluteInputPath, 'utf-8');
        const decryptedPayload = JSON.parse(decryptedJsonString) as DecryptedBackup;

        if (!decryptedPayload || typeof decryptedPayload !== 'object') {
          throw new Error(
            'Invalid input file content: Must be a valid JSON object representing a backup.'
          );
        }

        const encryptedBackupString = await encryptBackup(
          decryptedPayload,
          options.password,
          options.iterations
        );

        const absoluteOutputPath = path.resolve(outputFile);
        const outputDir = path.dirname(absoluteOutputPath);
        await fs.mkdir(outputDir, { recursive: true });

        await fs.writeFile(absoluteOutputPath, encryptedBackupString, 'utf-8');
        console.log(`File encrypted successfully and saved to ${absoluteOutputPath}`);
      } catch (error) {
        if (error instanceof Error) {
          console.error('Encryption failed:', error.message);
        } else {
          console.error('An unknown error occurred during encryption:', error);
        }
        process.exit(1);
      }
    }
  );

program
  .command('dec <inputFile>')
  .description('Decrypt an encrypted backup file.')
  .requiredOption('-p, --password <password>', 'Passphrase for decryption')
  .option(
    '-o, --output <outputFile>',
    'Path to save the decrypted JSON. If omitted, prints to console.'
  )
  .action(async (inputFile: string, options: { password: string; output?: string }) => {
    console.log(`Attempting to decrypt file: ${inputFile}`);
    try {
      const absoluteInputPath = path.resolve(inputFile);
      const encryptedString = await fs.readFile(absoluteInputPath, 'utf-8');

      if (!encryptedString.trim()) {
        console.error('Error: Encrypted file is empty or contains only whitespace.');
        process.exit(1);
      }

      console.log('File content read, attempting decryption...');
      const decryptedPayload = await decryptBackup(encryptedString.trim(), options.password);

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

program
  .command('upg <inputFile>')
  .description('Upgrade an encrypted backup file to the recommended PBKDF2 iterations.')
  .requiredOption('-p, --password <password>', 'Passphrase for decryption and re-encryption')
  .option('-o, --output <outputFile>', 'Path to save the upgraded encrypted file')
  .action(async (inputFile: string, options: { password: string; output?: string }) => {
    let outputFile = options.output;

    console.log(`Attempting to upgrade file: ${inputFile}`);

    try {
      const absoluteInputPath = path.resolve(inputFile);
      const encryptedBackup = await fs.readFile(absoluteInputPath, 'utf-8');

      console.log('Decrypting file...');
      const decryptedPayload = await decryptBackup(encryptedBackup, options.password);
      console.log('File decrypted successfully.');

      console.log(`Re-encrypting with ${RECOMMENDED_PBKDF2_ITERATIONS} iterations...`);
      const upgradedEncryptedBackup = await encryptBackup(
        decryptedPayload,
        options.password,
        RECOMMENDED_PBKDF2_ITERATIONS
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
        `File ${inputFile} upgraded and saved as ${absoluteOutputPath} with ${RECOMMENDED_PBKDF2_ITERATIONS} PBKDF2 iterations.`
      );
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

program.parse(process.argv);
