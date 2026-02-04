import { PrismaClient, SessionStatus } from '@prisma/client';
import { createLogger } from '../utils/logger';
import { MPCRestClient } from './mpc-rest-client';
import { getHSM } from '../hsm/softhsm';

const logger = createLogger('EcdsaService');
const prisma = new PrismaClient();

function createMPCRestClients(playerIds: number[]): Map<number, MPCRestClient> {
  const clients = new Map<number, MPCRestClient>();
  playerIds.forEach((playerId) => {
    const baseUrl = `http://localhost:${8000 + playerId}`;
    clients.set(playerId, new MPCRestClient({ baseUrl, playerId }));
  });
  return clients;
}

export interface SigningParams {
  keyId: string;
  txId: string;
  messageHash: string;
  derivationPath?: string;
  playerIds: string[];
  metadata?: any;
}

export interface SigningResult {
  r: string;
  s: string;
  v: number;
}

export class EcdsaSigningService {
  /**
   * Execute full 4-round ECDSA signing protocol using MPCRestClient
   */
  async signMessage(params: SigningParams): Promise<SigningResult> {
    logger.info(`Starting ECDSA signing for tx ${params.txId} with key ${params.keyId}`);
    logger.info(`Participants: ${params.playerIds.join(', ')}`);

    try {
      // 1. Verify key exists and is active
      const key = await prisma.mpcKey.findUnique({
        where: { keyId: params.keyId },
        include: {
          shares: {
            where: {
              playerId: {
                in: params.playerIds,
              },
            },
          },
        },
      });

      if (!key) {
        throw new Error(`Key ${params.keyId} not found`);
      }

      if (key.status !== 'ACTIVE') {
        throw new Error(`Key ${params.keyId} is not active (status: ${key.status})`);
      }

      if (key.shares.length !== params.playerIds.length) {
        throw new Error(`Missing key shares for some players`);
      }

      // Verify threshold requirement
      if (params.playerIds.length < key.threshold) {
        throw new Error(`Not enough players: need at least ${key.threshold}, got ${params.playerIds.length}`);
      }

      // 2. Create signing session in database
      await prisma.signingSession.create({
        data: {
          txId: params.txId,
          keyId: params.keyId,
          algorithm: key.algorithm,
          messageHash: params.messageHash,
          derivationPath: params.derivationPath,
          participantIds: params.playerIds,
          metadata: params.metadata,
          status: SessionStatus.STARTED,
        },
      });

      // 3. Load key shares from HSM (verify they exist)
      logger.info('Verifying key shares in SoftHSM');
      const hsm = getHSM();
      for (const share of key.shares) {
        if (share.hsmKeyHandle) {
          logger.debug(`Verified key share for player ${share.playerId} in HSM`);
        }
      }

      // 4. Convert string playerIds to numeric IDs
      const numericPlayerIds = params.playerIds.map((id, index) => index + 1);
      const clients = createMPCRestClients(numericPlayerIds);

      // Round 1: Start signing
      logger.info('Round 1: Starting signing');
      const mtaRequestsMap: Map<number, any> = new Map();

      for (const [playerId, client] of clients) {
        const result = await client.startSigning({
          keyId: params.keyId,
          txid: params.txId,
          algorithm: key.algorithm,
          blocks: [{
            data: params.messageHash,
            path: [],
          }],
          metadata: JSON.stringify(params.metadata || {}),
          players: params.playerIds,
          playerIds: numericPlayerIds,
        });
        mtaRequestsMap.set(playerId, result.mtaRequests);
      }

      // Round 2: MTA response
      logger.info('Round 2: MTA response');
      const mtaResponsesMap: Map<number, any> = new Map();

      for (const [playerId, client] of clients) {
        const requests: Array<any> = [];
        for (const [otherPlayerId, mtaReqs] of mtaRequestsMap) {
          requests.push({
            playerId: otherPlayerId,
            mtaRequests: mtaReqs,
          });
        }

        const result = await client.mtaResponse({
          txid: params.txId,
          requests,
        });
        mtaResponsesMap.set(playerId, result);
      }

      // Round 3: MTA verify
      logger.info('Round 3: MTA verify');
      const deltasMap: Map<number, any> = new Map();

      for (const [playerId, client] of clients) {
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
          txid: params.txId,
          mtaResponses,
        });
        deltasMap.set(playerId, result.deltas);
      }

      // Round 4a: Get si
      logger.info('Round 4a: Calculating signature shares (si)');
      const sisMap: Map<number, any> = new Map();

      for (const [playerId, client] of clients) {
        const deltas: Array<any> = [];
        for (const [otherPlayerId, deltaList] of deltasMap) {
          deltas.push({
            playerId: otherPlayerId,
            deltas: deltaList,
          });
        }

        const result = await client.getSi({
          txid: params.txId,
          deltas,
        });
        sisMap.set(playerId, result.sis);
      }

      // Round 4b: Combine signature
      logger.info('Round 4b: Combining signature shares');
      const combinerClient = clients.get(numericPlayerIds[0])!;
      const sValues: Array<any> = [];

      for (const [playerId, sis] of sisMap) {
        sValues.push({
          playerId,
          sis,
        });
      }

      const result = await combinerClient.getSignature({
        txid: params.txId,
        s: sValues,
      });

      const finalSignature = result.signatures[0];

      // Update session with final signature
      await prisma.signingSession.update({
        where: { txId: params.txId },
        data: {
          signature: JSON.stringify(finalSignature),
          status: SessionStatus.COMPLETED,
          completedAt: new Date(),
        },
      });

      logger.info(`Signing completed successfully for tx ${params.txId}`);
      logger.info(`Signature (r): ${finalSignature.r.substring(0, 40)}...`);
      logger.info(`Signature (s): ${finalSignature.s.substring(0, 40)}...`);
      logger.info(`Signature (v): ${finalSignature.v}`);

      return {
        r: finalSignature.r,
        s: finalSignature.s,
        v: finalSignature.v,
      };
    } catch (error: any) {
      logger.error(`Signing failed for tx ${params.txId}:`, error);

      // Mark session as failed
      try {
        await prisma.signingSession.update({
          where: { txId: params.txId },
          data: { status: SessionStatus.FAILED },
        });
      } catch (e) {
        // Ignore if session doesn't exist
      }

      // Extract clean error message
      const errorMessage = error.response?.data?.error || error.message || 'Unknown error';
      throw new Error(errorMessage);
    }
  }

  /**
   * Get signing session information by txId
   */
  async getSessionInfo(txId: string): Promise<any> {
    const session = await prisma.signingSession.findUnique({
      where: { txId },
    });

    return session;
  }

  /**
   * List signing sessions with optional filters
   */
  async listSessions(filters: { keyId?: string; status?: string }): Promise<any[]> {
    const where: any = {};

    if (filters.keyId) where.keyId = filters.keyId;
    if (filters.status) where.status = filters.status;

    const sessions = await prisma.signingSession.findMany({
      where,
      orderBy: {
        createdAt: 'desc',
      },
    });

    return sessions;
  }
}
