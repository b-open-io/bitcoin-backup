import { PrivateKey } from '@bsv/sdk';
import { type BapMasterBackup, decryptBackup, encryptBackup } from '../src/index';

/**
 * Demonstration of Type 42 key derivation and backup functionality
 */
async function demonstrateType42() {
  console.log('🔑 Type 42 Key Derivation & Backup Demo\n');

  // 1. Generate a master key for Alice
  const aliceMaster = PrivateKey.fromRandom();
  const alicePub = aliceMaster.toPublicKey();

  console.log("1. Alice's Master Key Generated:");
  console.log(`   WIF: ${aliceMaster.toWif()}`);
  console.log(`   Public Key: ${alicePub.toString()}\n`);

  // 2. Create a Type 42 backup for Alice's master key
  const aliceBackup: BapMasterBackup = {
    ids: 'encrypted-bap-identity-data-alice',
    rootPk: aliceMaster.toWif(),
    label: 'Alice Primary Wallet',
    createdAt: new Date().toISOString(),
  };

  console.log("2. Alice's Type 42 Backup Created:");
  console.log(JSON.stringify(aliceBackup, null, 2));
  console.log();

  // 3. Encrypt the backup
  const passphrase = 'super-secure-passphrase-2024';
  const encryptedBackup = await encryptBackup(aliceBackup, passphrase);

  console.log('3. Backup Encrypted:');
  console.log(`   Encrypted length: ${encryptedBackup.length} characters`);
  console.log(`   Sample: ${encryptedBackup.substring(0, 50)}...\n`);

  // 4. Decrypt and verify
  const decryptedBackup = (await decryptBackup(encryptedBackup, passphrase)) as BapMasterBackup;

  console.log('4. Backup Decrypted Successfully:');
  if ('rootPk' in decryptedBackup) {
    console.log(`   Master Key Match: ${decryptedBackup.rootPk === aliceBackup.rootPk}`);
    console.log(`   Label: ${decryptedBackup.label}`);
  }
  console.log();

  // 5. Demonstrate Type 42 key derivation
  console.log('5. Type 42 Key Derivation Demo:');

  // Bob generates his key pair
  const bob = PrivateKey.fromRandom();
  const bobPub = bob.toPublicKey();

  console.log(`   Bob's Public Key: ${bobPub.toString()}`);

  // Alice and Bob agree on invoice numbers for different purposes
  const invoices = ['payment-invoice-001', 'messaging-key-2024-01', 'file-encryption-session-xyz'];

  for (const invoiceNumber of invoices) {
    // Alice derives a child private key for this specific purpose with Bob
    const aliceChildKey = aliceMaster.deriveChild(bobPub, invoiceNumber);

    // Alice can derive Bob's corresponding public key
    const bobDerivedPubKey = bobPub.deriveChild(aliceMaster, invoiceNumber);

    // Bob can derive his corresponding private key
    const bobChildKey = bob.deriveChild(alicePub, invoiceNumber);

    // Verify the keys match
    const keysMatch = bobChildKey.toPublicKey().toString() === bobDerivedPubKey.toString();

    console.log(`\n   Invoice: ${invoiceNumber}`);
    console.log(`   Alice derived key: ${aliceChildKey.toWif()}`);
    console.log(`   Bob derived key: ${bobChildKey.toWif()}`);
    console.log(`   Keys compatible: ${keysMatch}`);
  }

  console.log('\n6. Format Detection:');
  console.log('   Type 42 format detected by presence of "rootPk" field');
  console.log('   Legacy format detected by presence of "xprv" and "mnemonic" fields');
  console.log('   ✅ Automatic format detection enables seamless migration\n');

  console.log('🎉 Type 42 Demo Complete!');
  console.log('\nKey Benefits of Type 42:');
  console.log('- Enhanced privacy through private key derivation');
  console.log('- Unlimited invoice numbering space');
  console.log('- Shared key universes between parties');
  console.log('- No need for mnemonic phrases');
  console.log('- Automatic format detection for easy migration');
}

// Run the demo
demonstrateType42().catch(console.error);
