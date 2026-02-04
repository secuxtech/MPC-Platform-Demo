import { PrismaClient, KeyStatus } from '@prisma/client';
import { createLogger } from '../utils/logger';
import { MPCRestClient } from './mpc-rest-client';
import { getHSM } from '../hsm/softhsm';

const logger = createLogger('SetupService');
const prisma = new PrismaClient();

function createMPCRestClients(playerIds: number[]): Map<number, MPCRestClient> {
  const clients = new Map<number, MPCRestClient>();
  playerIds.forEach((playerId, index) => {
    const baseUrl = `http://localhost:${8000 + playerId}`;
    clients.set(playerId, new MPCRestClient({ baseUrl, playerId }));
  });
  return clients;
}

export interface SetupParams {
  keyId: string;
  algorithm: string;
  threshold: number;
  totalPlayers: number;
  playerIds: string[];
  tenantId?: string;
  derivationSeed?: string;
}

export interface SetupResult {
  publicKey: string;
  chainCode?: string;
  shares: Array<{
    playerId: string;
    hsmHandle: string;
  }>;
}

export class SetupService {
  /**
   * Execute full 5-phase MPC key generation setup using MPCRestClient
   */
  async executeFullSetup(params: SetupParams): Promise<SetupResult> {
    const tenantId = params.tenantId || process.env.DEFAULT_TENANT_ID || 'test-tenant';

    logger.info(`Starting full setup for key ${params.keyId}`);
    logger.info(`Algorithm: ${params.algorithm}, Threshold: ${params.threshold}-of-${params.totalPlayers}`);

    try {
      // 1. Create MPC key record in database
      await prisma.mpcKey.create({
        data: {
          keyId: params.keyId,
          algorithm: params.algorithm,
          publicKey: '', // Will be updated after phase 5
          threshold: params.threshold,
          totalPlayers: params.totalPlayers,
          tenantId,
          status: KeyStatus.GENERATING,
        },
      });

      // 2. Create player records if they don't exist
      for (const playerId of params.playerIds) {
        await prisma.player.upsert({
          where: { playerId },
          update: { isActive: true },
          create: {
            playerId,
            name: playerId,
            isActive: true,
          },
        });
      }

      // 3. Convert string playerIds to numeric IDs (player1 -> 1, player2 -> 2, etc.)
      const numericPlayerIds = params.playerIds.map((id, index) => index + 1);
      const clients = createMPCRestClients(numericPlayerIds);

      // Phase 1: Generate commitments
      logger.info('Phase 1: Generating commitments');
      const commitments: Array<{ playerId: number; commitment: string }> = [];

      for (const [playerId, client] of clients) {
        const result = await client.generateSetupCommitments({
          keyId: params.keyId,
          tenantId,
          algorithm: params.algorithm,
          playerIds: numericPlayerIds,
          threshold: params.threshold,
        });
        commitments.push({ playerId, commitment: result.commitment });
      }

      // Phase 2: Store commitments and get decommitments
      logger.info('Phase 2: Storing commitments');
      const decommitments: Array<any> = [];

      for (const [playerId, client] of clients) {
        const result = await client.storeSetupCommitments({
          keyId: params.keyId,
          tenantId,
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
      }

      // Phase 3: Generate proofs
      logger.info('Phase 3: Generating ZK proofs');
      const proofs: Array<any> = [];

      for (const [playerId, client] of clients) {
        const result = await client.generateSetupProofs({
          keyId: params.keyId,
          decommitments,
        });
        proofs.push({
          playerId,
          schnorr_s: result.schnorr_s,
          paillierBlumZkp: result.paillierBlumZkp,
          ringPedersenParamZkp: result.ringPedersenParamZkp,
        });
      }

      // Phase 4: Verify proofs
      logger.info('Phase 4: Verifying ZK proofs');
      const largeFactorProofs: Array<any> = [];

      for (const [playerId, client] of clients) {
        const result = await client.verifySetupProofs({
          keyId: params.keyId,
          proofs,
        });
        largeFactorProofs.push({
          fromPlayerId: playerId,
          proofs: result.paillierLargeFactorProofs,
        });
      }

      // Phase 5: Create secret (finalize key generation)
      logger.info('Phase 5: Creating secret');
      let publicKey = '';

      for (const [playerId, client] of clients) {
        const result = await client.createSecret({
          keyId: params.keyId,
          paillierLargeFactorProofs: largeFactorProofs,
        });
        publicKey = result.publicKey;
      }

      // 6. Store key shares in HSM
      logger.info('Storing key shares in SoftHSM');
      const hsm = getHSM();
      const shares = [];

      for (let i = 0; i < params.playerIds.length; i++) {
        const playerId = params.playerIds[i];
        const numericId = i + 1;

        // Generate random key data for HSM (in real impl, this would be the actual key share)
        const keyData = await hsm.generateRandom(32);
        const hsmHandle = await hsm.storeKey(`${params.keyId}-${playerId}`, keyData, 'secret');

        shares.push({ playerId, hsmHandle });

        // Store key share metadata in database
        await prisma.keyShare.create({
          data: {
            keyId: params.keyId,
            playerId,
            shareData: keyData,
            hsmKeyHandle: hsmHandle,
            auxiliaryKeys: {
              paillierPublicKey: decommitments[i].paillierPublicKey,
              ringPedersenPublicKey: decommitments[i].ringPedersenPublicKey,
            },
          },
        });
      }

      // 7. Update MPC key with public key and status
      await prisma.mpcKey.update({
        where: { keyId: params.keyId },
        data: {
          publicKey,
          status: KeyStatus.ACTIVE,
        },
      });

      logger.info(`Setup completed successfully for key ${params.keyId}`);
      logger.info(`Public Key: ${publicKey.substring(0, 40)}...`);

      return { publicKey, shares };
    } catch (error: any) {
      logger.error(`Setup failed for key ${params.keyId}:`, error);

      // Mark key as failed
      try {
        await prisma.mpcKey.update({
          where: { keyId: params.keyId },
          data: { status: KeyStatus.REVOKED },
        });
      } catch (e) {
        // Ignore if key doesn't exist
      }

      // Extract clean error message
      const errorMessage = error.response?.data?.error || error.message || 'Unknown error';
      throw new Error(errorMessage);
    }
  }


  /**
   * Get key information by keyId
   */
  async getKeyInfo(keyId: string): Promise<any> {
    const key = await prisma.mpcKey.findUnique({
      where: { keyId },
      include: {
        shares: {
          select: {
            playerId: true,
            hsmKeyHandle: true,
            createdAt: true,
          },
        },
      },
    });

    return key;
  }

  /**
   * List keys with optional filters
   */
  async listKeys(filters: { tenantId?: string; algorithm?: string; status?: string }): Promise<any[]> {
    const where: any = {};

    if (filters.tenantId) where.tenantId = filters.tenantId;
    if (filters.algorithm) where.algorithm = filters.algorithm;
    if (filters.status) where.status = filters.status;

    const keys = await prisma.mpcKey.findMany({
      where,
      include: {
        shares: {
          select: {
            playerId: true,
            hsmKeyHandle: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return keys;
  }
}
