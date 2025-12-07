/**
 * VaultBackup Demo
 *
 * Demonstrates backing up an encrypted key vault. The application handles its own
 * vault encryption, and bitcoin-backup provides universal strong backup encryption -
 * just like all other backup formats.
 */

import { decryptBackup, encryptBackup, type VaultBackup } from '../src/index';

async function demoVaultBackup() {
  console.log('=== VaultBackup Demo ===\n');

  // Step 1: Application exports its encrypted vault
  // The vault is already encrypted by the application with its own encryption
  const appEncryptedVault = simulateAppVaultEncryption();

  console.log('1. Application encrypted vault');
  console.log('   Vault encrypted with: application password');
  console.log('   Contains: 5 keys\n');

  // Step 2: Create VaultBackup object
  const vaultBackup: VaultBackup = {
    encryptedVault: appEncryptedVault,
    scheme: 'vscode-bitcoin-v1', // Identifies the vault encryption scheme
    label: 'My Bitcoin Vault',
  };

  console.log('2. Created VaultBackup');
  console.log('   Scheme:', vaultBackup.scheme);
  console.log('   Fields:', Object.keys(vaultBackup));
  console.log();

  // Step 3: bitcoin-backup encrypts the VaultBackup (universal strong encryption)
  const backupPassword = 'my-backup-password';

  console.log('3. Encrypting backup with bitcoin-backup');
  console.log('   PBKDF2 iterations: 600,000');
  console.log('   Algorithm: AES-256-GCM');
  const encrypted = await encryptBackup(vaultBackup, backupPassword);

  console.log('   ✓ Backup encrypted');
  console.log(`   Length: ${encrypted.length} characters\n`);

  // Step 4: Save to file
  console.log('4. Save to: vault.bep\n');

  // Step 5: Later, restore from backup
  console.log('5. Restoring from backup');
  const decrypted = (await decryptBackup(encrypted, backupPassword)) as VaultBackup;

  console.log('   ✓ Backup decrypted');
  console.log('   Scheme:', decrypted.scheme);
  console.log('   Label:', decrypted.label);
  console.log('   Vault:', '[still encrypted by application]');
  console.log();

  // Step 6: Application decrypts vault
  console.log('6. Application decrypts vault');
  console.log('   User provides application password');
  console.log('   ✓ Keys recovered\n');

  // Security benefits
  console.log('=== Security ===\n');
  console.log('✓ Double encryption:');
  console.log('  - Vault encrypted by application');
  console.log('  - Backup encrypted by bitcoin-backup (600k iterations)');
  console.log();
  console.log('✓ Universal strong backup:');
  console.log('  - Same encryption for all backup types');
  console.log('  - No fragmented security parameters');
  console.log('  - Works with any application vault format');
  console.log();
  console.log('✓ Interoperability with scheme field:');
  console.log('  - Default scheme: "vscode-bitcoin-v1"');
  console.log('  - Custom schemes: extend for your own vault format');
  console.log("  - Applications can understand each other's vaults");
  console.log();
}

/**
 * Simulates an application's encrypted vault
 */
function simulateAppVaultEncryption(): string {
  // The application encrypts its vault however it wants
  // We just need the encrypted blob to back up
  const mockVaultData = {
    keys: [
      { type: 'wif', label: 'Funding', value: 'L...' },
      { type: 'wif', label: 'Ordinals', value: 'L...' },
      { type: 'wif', label: 'Identity', value: 'L...' },
      { type: 'hdprivate', label: 'HD Master', value: 'xprv...' },
      { type: 'mnemonic', label: 'Recovery', value: 'legal winner...' },
    ],
  };

  // Application's encrypted output (any format)
  return Buffer.from(JSON.stringify(mockVaultData)).toString('base64');
}

// Run demo
demoVaultBackup().catch(console.error);
