/**
 * MPC REST Service Integration Test
 *
 * This example demonstrates how to use the new mpc-rest-service (C++ wrapper)
 * to perform MPC key generation and signing.
 *
 * Prerequisites:
 * 1. Start mpc-rest-service instances:
 *    Terminal 1: cd mpc-rest-service/build && ./mpc_rest_service 8001 1
 *    Terminal 2: cd mpc-rest-service/build && ./mpc_rest_service 8002 2
 *
 * 2. Run this test:
 *    cd mpc-coordinator && npm run test:rest
 */

import { createMPCRestClients, MPCRestClient } from '../src/services/mpc-rest-client';

const ALGORITHM = 'ECDSA_SECP256K1';
const PLAYER_IDS = [1, 2];
const THRESHOLD = 2; // n-of-n (CMP only supports n-of-n, not t-of-n)

/**
 * Test 1: Health Check
 */
async function testHealthCheck(clients: Map<number, MPCRestClient>) {
  console.log('\n=== Test 1: Health Check ===');

  for (const [playerId, client] of clients) {
    try {
      const health = await client.healthCheck();
      console.log(`✅ Player ${playerId}: ${JSON.stringify(health)}`);
    } catch (error: any) {
      console.error(`❌ Player ${playerId} health check failed:`, error.message);
      throw error;
    }
  }
}

/**
 * Test 2: Setup Phase - Generate MPC Key
 */
async function testSetupPhase(clients: Map<number, MPCRestClient>) {
  console.log('\n=== Test 2: Setup Phase (5 rounds) ===');

  const keyId = `test-key-${Date.now()}`;
  const tenantId = 'test-tenant';

  console.log(`Key ID: ${keyId}`);
  console.log(`Algorithm: ${ALGORITHM}`);
  console.log(`Players: ${PLAYER_IDS.join(', ')}`);
  console.log(`Threshold: ${THRESHOLD}-of-${PLAYER_IDS.length}\n`);

  // Phase 1: Generate commitments
  console.log('Phase 1: Generating commitments...');
  const commitments: Array<{ playerId: number; commitment: string }> = [];

  for (const [playerId, client] of clients) {
    const result = await client.generateSetupCommitments({
      keyId,
      tenantId,
      algorithm: ALGORITHM,
      playerIds: PLAYER_IDS,
      threshold: THRESHOLD,
    });
    commitments.push({
      playerId,
      commitment: result.commitment,
    });
    console.log(`  Player ${playerId}: ${result.commitment.substring(0, 20)}...`);
  }

  // Phase 2: Store commitments and get decommitments
  console.log('\nPhase 2: Storing commitments...');
  const decommitments: Array<any> = [];

  for (const [playerId, client] of clients) {
    const result = await client.storeSetupCommitments({
      keyId,
      commitments,
    });
    decommitments.push({
      playerId,
      ack: result.ack,
      seed: result.seed,
      share: result.share,
      paillierPublicKey: result.paillierPublicKey,
      ringPedersenPublicKey: result.ringPedersenPublicKey,
    });
    console.log(`  Player ${playerId}: ACK ${result.ack.substring(0, 20)}...`);
  }

  // Phase 3: Generate proofs
  console.log('\nPhase 3: Generating ZK proofs...');
  const proofs: Array<any> = [];

  for (const [playerId, client] of clients) {
    const result = await client.generateSetupProofs({
      keyId,
      decommitments,
    });
    proofs.push({
      playerId,
      schnorr_s: result.schnorr_s,
      paillierBlumZkp: result.paillierBlumZkp,
      ringPedersenParamZkp: result.ringPedersenParamZkp,
    });
    console.log(`  Player ${playerId}: Proof generated`);
  }

  // Phase 4: Verify proofs
  console.log('\nPhase 4: Verifying ZK proofs...');
  const largeFactorProofs: Array<any> = [];

  for (const [playerId, client] of clients) {
    const result = await client.verifySetupProofs({
      keyId,
      proofs,
    });
    largeFactorProofs.push({
      fromPlayerId: playerId,
      proofs: result.paillierLargeFactorProofs,
    });
    console.log(`  Player ${playerId}: Proofs verified`);
  }

  // Phase 5: Create secret (finalize key generation)
  console.log('\nPhase 5: Creating secret...');
  let publicKey = '';

  for (const [playerId, client] of clients) {
    const result = await client.createSecret({
      keyId,
      paillierLargeFactorProofs: largeFactorProofs,
    });
    publicKey = result.publicKey;
    console.log(`  Player ${playerId}: Secret created`);
  }

  console.log(`\n✅ Setup Complete! Public Key: ${publicKey.substring(0, 40)}...\n`);

  return { keyId, publicKey };
}

/**
 * Test 3: Signing Phase - Sign a Message
 */
async function testSigningPhase(
  clients: Map<number, MPCRestClient>,
  keyId: string
) {
  console.log('\n=== Test 3: Signing Phase (4 rounds) ===');

  const txid = `test-tx-${Date.now()}`;
  const messageHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; // SHA256 of empty string
  const messageHashBytes = Buffer.from(messageHash, 'hex').toString('hex');

  console.log(`TX ID: ${txid}`);
  console.log(`Message Hash: ${messageHash}\n`);

  // Round 1: Start signing
  console.log('Round 1: Starting signing...');
  const mtaRequestsMap: Map<number, any> = new Map();

  for (const [playerId, client] of clients) {
    const result = await client.startSigning({
      keyId,
      txid,
      algorithm: ALGORITHM,
      blocks: [
        {
          data: messageHashBytes,
          path: [],
        },
      ],
      metadata: '{}',
      players: PLAYER_IDS.map(String),
      playerIds: PLAYER_IDS,
    });
    mtaRequestsMap.set(playerId, result.mtaRequests);
    console.log(`  Player ${playerId}: MTA requests generated (${result.mtaRequests.length} items)`);
  }

  // Round 2: MTA response
  console.log('\nRound 2: MTA response...');
  const mtaResponsesMap: Map<number, any> = new Map();

  for (const [playerId, client] of clients) {
    // Collect requests from ALL players (including self)
    const requests: Array<any> = [];
    for (const [otherPlayerId, mtaReqs] of mtaRequestsMap) {
      requests.push({
        playerId: otherPlayerId,
        mtaRequests: mtaReqs,
      });
    }

    const result = await client.mtaResponse({
      txid,
      requests,
    });
    mtaResponsesMap.set(playerId, result);
    console.log(`  Player ${playerId}: MTA response generated`);
  }

  // Round 3: MTA verify
  console.log('\nRound 3: MTA verify...');
  const deltasMap: Map<number, any> = new Map();

  for (const [playerId, client] of clients) {
    // Collect responses from ALL players (including self)
    const mtaResponses: Array<any> = [];
    for (const [otherPlayerId, resp] of mtaResponsesMap) {
      mtaResponses.push({
        playerId: otherPlayerId,
        flags: resp.flags,
        ack: resp.ack,
        responses: resp.responses,
      });
    }

    const result = await client.mtaVerify({
      txid,
      mtaResponses,
    });
    deltasMap.set(playerId, result.deltas);
    console.log(`  Player ${playerId}: MTA verified`);
  }

  // Round 4a: Get si
  console.log('\nRound 4a: Calculating signature shares (si)...');
  const sisMap: Map<number, any> = new Map();

  for (const [playerId, client] of clients) {
    // Collect deltas from ALL players (including self)
    const deltas: Array<any> = [];
    for (const [otherPlayerId, deltaList] of deltasMap) {
      deltas.push({
        playerId: otherPlayerId,
        deltas: deltaList,
      });
    }

    const result = await client.getSi({
      txid,
      deltas,
    });
    sisMap.set(playerId, result.sis);
    console.log(`  Player ${playerId}: si calculated`);
  }

  // Round 4b: Combine signature
  console.log('\nRound 4b: Combining signature shares...');
  let finalSignature: any = null;

  // Only one player needs to combine (choose player 1)
  const combinerClient = clients.get(PLAYER_IDS[0])!;
  const sValues: Array<any> = [];

  for (const [playerId, sis] of sisMap) {
    sValues.push({
      playerId,
      sis,
    });
  }

  const result = await combinerClient.getSignature({
    txid,
    s: sValues,
  });

  finalSignature = result.signatures[0];
  console.log(`  ✅ Final signature:`);
  console.log(`     r: ${finalSignature.r.substring(0, 40)}...`);
  console.log(`     s: ${finalSignature.s.substring(0, 40)}...`);
  console.log(`     v: ${finalSignature.v}`);

  return finalSignature;
}

/**
 * Main test runner
 */
async function main() {
  console.log('=== MPC REST Service Integration Test ===');
  console.log('Testing connection to mpc-rest-service...\n');

  try {
    // Create clients for all players
    const clients = createMPCRestClients(PLAYER_IDS);

    // Test 1: Health check
    await testHealthCheck(clients);

    // Test 2: Setup phase (key generation)
    const { keyId, publicKey } = await testSetupPhase(clients);

    // Test 3: Signing phase
    const signature = await testSigningPhase(clients, keyId);

    console.log('\n=== All Tests Passed! ===\n');
    console.log('Summary:');
    console.log(`✓ Key generated: ${keyId}`);
    console.log(`✓ Public key: ${publicKey.substring(0, 60)}...`);
    console.log(`✓ Signature r: ${signature.r.substring(0, 60)}...`);
    console.log(`✓ Signature s: ${signature.s.substring(0, 60)}...`);
    console.log(`✓ Recovery ID: ${signature.v}`);
    console.log('\nIntegration test completed successfully! 🎉\n');

  } catch (error: any) {
    console.error('\n❌ Test failed:', error.message);
    if (error.code === 'ECONNREFUSED') {
      console.error('\nMake sure mpc-rest-service is running:');
      console.error('  Terminal 1: cd mpc-rest-service/build && ./mpc_rest_service 8001 1');
      console.error('  Terminal 2: cd mpc-rest-service/build && ./mpc_rest_service 8002 2\n');
    }
    process.exit(1);
  }
}

// Run the test
if (require.main === module) {
  main();
}

export { testHealthCheck, testSetupPhase, testSigningPhase };
