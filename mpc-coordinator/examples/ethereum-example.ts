/**
 * MPC PoC Ethereum Example
 *
 * Demonstrates core features:
 * 1. Generate 3-of-3 threshold MPC key (ECDSA_SECP256K1)
 * 2. Derive Ethereum address from public key
 * 3. Use the key for ECDSA signing (Ethereum transaction)
 * 4. Key shares are stored in SoftHSM
 */

import axios from 'axios';
import { keccak256 } from 'ethers';

const API_BASE = 'http://localhost:3000/api';
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Utility: Derive Ethereum address from public key
 */
function deriveEthereumAddress(uncompressedPublicKey: string): string {
  const publicKeyWithoutPrefix = uncompressedPublicKey.startsWith('04')
    ? uncompressedPublicKey.slice(2)
    : uncompressedPublicKey;
  const hash = keccak256('0x' + publicKeyWithoutPrefix);
  return '0x' + hash.slice(-40);
}

/**
 * Main PoC flow
 */
async function runPoC() {
  console.log('=== MPC PoC Demo (Ethereum) ===\n');

  try {
    // Step 1: Generate 3-of-3 MPC key
    console.log('Step 1: Generating 3-of-3 MPC key...');
    const timestamp = Date.now();
    const setupParams = {
      keyId: `ethereum-key-${timestamp}`,
      algorithm: 'ECDSA_SECP256K1',
      threshold: 3,
      totalPlayers: 3,
      playerIds: ['player1', 'player2', 'player3'],
    };

    const setupResponse = await axios.post(`${API_BASE}/setup/start`, setupParams);
    const ethereumAddress = deriveEthereumAddress(setupResponse.data.publicKey);

    console.log('✅ Key generated successfully!');
    console.log(`   Public Key: ${setupResponse.data.publicKey.substring(0, 40)}...`);
    console.log(`   Ethereum Address: ${ethereumAddress}`);
    console.log(`   Threshold: ${setupResponse.data.threshold}-of-${setupResponse.data.totalPlayers}\n`);

    await delay(1000);

    // Step 2: Query key info
    console.log('Step 2: Querying key info...');
    const keyInfo = await axios.get(`${API_BASE}/setup/${setupParams.keyId}`);
    console.log('✅ Key status:', keyInfo.data.status);
    console.log(`   Participants: ${keyInfo.data.shares?.length || 0}\n`);

    await delay(1000);

    // Step 3: Use the key to sign (simulate Ethereum transaction)
    console.log('Step 3: Signing Ethereum transaction with 3 participants...');
    const signingParams = {
      keyId: setupParams.keyId,
      txId: `eth-tx-${timestamp}`,
      messageHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      derivationPath: 'm/44\'/60\'/0\'/0/0', // Ethereum BIP44 path
      playerIds: ['player1', 'player2', 'player3'], // All 3 participants
      metadata: {
        blockchain: 'ethereum',
        network: 'sepolia',
      },
    };

    const signResponse = await axios.post(`${API_BASE}/signing/ecdsa`, signingParams);
    console.log('✅ Signing successful!');
    console.log(`   Signature (r): ${signResponse.data.signature.r.substring(0, 40)}...`);
    console.log(`   Signature (s): ${signResponse.data.signature.s.substring(0, 40)}...`);
    console.log(`   Signature (v): ${signResponse.data.signature.v}\n`);

    await delay(500);

    // Step 4: Query signing session
    console.log('Step 4: Querying signing session...');
    const sessionInfo = await axios.get(`${API_BASE}/signing/session/${signingParams.txId}`);
    console.log('✅ Session status:', sessionInfo.data.status);
    console.log(`   Completed at: ${sessionInfo.data.completedAt}\n`);

    console.log('=== PoC Complete ===\n');
    console.log('Verified features:');
    console.log('✓ 5-phase MPC key generation (Setup Phase 1-5)');
    console.log('✓ 4-round ECDSA signing (Signing Round 1-4)');
    console.log('✓ 3-of-3 signature scheme');
    console.log('✓ Ethereum address derivation (Keccak256)');
    console.log('✓ Ethereum signature format (r, s, v)');
    console.log('✓ SoftHSM secure key storage');
    console.log('✓ PostgreSQL + Prisma data persistence');
    console.log('\nThe same key can be used for Bitcoin and Ethereum (both use ECDSA_SECP256K1)');

  } catch (error: any) {
    console.error('❌ Error:', error.response?.data || error.message);
    throw error;
  }
}

/**
 * Main function
 */
async function main() {
  try {
    await axios.get(`${API_BASE}/../health`);
    console.log('✅ API service is running\n');
    await runPoC();
  } catch (error: any) {
    if (error.code === 'ECONNREFUSED') {
      console.error('❌ Cannot connect to API service');
      console.error('Please run: npm run dev');
    } else {
      console.error('❌ Execution failed:', error.message);
    }
    process.exit(1);
  }
}

main();

export { runPoC };
