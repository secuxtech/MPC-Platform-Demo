/**
 * MPC REST Service Client
 *
 * This client connects to the new mpc-rest-service (C++ wrapper)
 * which provides direct access to mpc-lib functions.
 *
 * API endpoints (as defined in mpc-rest-service):
 * - Setup: /generate_setup_commitments, /store_setup_commitments,
 *          /generate_setup_proofs, /verify_setup_proofs, /create_secret
 * - Signing: /start_signing, /mta_response, /mta_verify, /get_si, /get_signature
 */

import axios, { AxiosInstance } from 'axios';
import { createLogger } from '../utils/logger';

const logger = createLogger('MPCRestClient');

export interface MPCRestClientConfig {
  baseUrl: string;
  playerId: number;
  timeout?: number;
}

/**
 * MPC REST Service Client
 * Connects to the C++ mpc-rest-service for direct mpc-lib access
 */
export class MPCRestClient {
  private client: AxiosInstance;
  private playerId: number;

  constructor(private config: MPCRestClientConfig) {
    this.playerId = config.playerId;
    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout || 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    logger.info(`MPC REST Client initialized for player ${config.playerId}`);
  }

  // ==================== SETUP APIs ====================

  /**
   * Setup API 1: Generate setup commitments
   */
  async generateSetupCommitments(params: {
    keyId: string;
    tenantId: string;
    algorithm: string;
    playerIds: number[];
    threshold: number;
  }) {
    try {
      const response = await this.client.post('/generate_setup_commitments', params);
      logger.debug(`Player ${this.playerId} generated setup commitment`);
      return response.data;
    } catch (error: any) {
      logger.error(`Generate setup commitments failed:`, error.response?.data || error.message);
      const errMsg = error.response?.data?.error || error.message || "Unknown error"; throw new Error(errMsg);
    }
  }

  /**
   * Setup API 2: Store setup commitments
   */
  async storeSetupCommitments(params: {
    keyId: string;
    tenantId: string;
    commitments: Array<{
      playerId: number;
      commitment: string;
    }>;
  }) {
    try {
      logger.debug(`Player ${this.playerId} calling store_setup_commitments with:`, JSON.stringify(params).substring(0, 200));
      const response = await this.client.post('/store_setup_commitments', params);
      logger.debug(`Player ${this.playerId} stored setup commitments`);
      return response.data;
    } catch (error: any) {
      logger.error(`Store setup commitments failed for player ${this.playerId}`);
      logger.error(`  Request params: ${JSON.stringify(params).substring(0, 200)}`);
      logger.error(`  Status: ${error.response?.status}`);
      logger.error(`  Data: ${JSON.stringify(error.response?.data)}`);
      logger.error(`  Message: ${error.message}`);
      logger.error(`  Code: ${error.code}`);
      const errMsg = error.response?.data?.error || error.message || "Unknown error";
      throw new Error(errMsg);
    }
  }

  /**
   * Setup API 3: Generate setup proofs
   */
  async generateSetupProofs(params: {
    keyId: string;
    decommitments: Array<{
      playerId: number;
      ack: string;
      seed: string;
      share: {
        X: string;
        schnorr_R: string;
      };
      paillierPublicKey: string;
      ringPedersenPublicKey: string;
    }>;
  }) {
    try {
      const response = await this.client.post('/generate_setup_proofs', params);
      logger.debug(`Player ${this.playerId} generated setup proofs`);
      return response.data;
    } catch (error: any) {
      logger.error(`Generate setup proofs failed:`, error.response?.data || error.message);
      const errMsg = error.response?.data?.error || error.message || "Unknown error"; throw new Error(errMsg);
    }
  }

  /**
   * Setup API 4: Verify setup proofs
   */
  async verifySetupProofs(params: {
    keyId: string;
    proofs: Array<{
      playerId: number;
      schnorr_s: string;
      paillierBlumZkp: string;
      ringPedersenParamZkp: string;
    }>;
  }) {
    try {
      const response = await this.client.post('/verify_setup_proofs', params);
      logger.debug(`Player ${this.playerId} verified setup proofs`);
      return response.data;
    } catch (error: any) {
      logger.error(`Verify setup proofs failed:`, error.response?.data || error.message);
      const errMsg = error.response?.data?.error || error.message || "Unknown error"; throw new Error(errMsg);
    }
  }

  /**
   * Setup API 5: Create secret (finalize key generation)
   */
  async createSecret(params: {
    keyId: string;
    paillierLargeFactorProofs: Array<{
      fromPlayerId: number;
      proofs: Array<{
        playerId: number;
        proof: string;
      }>;
    }>;
  }) {
    try {
      const response = await this.client.post('/create_secret', params);
      logger.debug(`Player ${this.playerId} created secret`);
      return response.data;
    } catch (error: any) {
      logger.error(`Create secret failed:`, error.response?.data || error.message);
      const errMsg = error.response?.data?.error || error.message || "Unknown error"; throw new Error(errMsg);
    }
  }

  // ==================== SIGNING APIs ====================

  /**
   * Signing API 1: Start signing
   */
  async startSigning(params: {
    keyId: string;
    txid: string;
    algorithm: string;
    chaincode?: string;
    blocks: Array<{
      data: string;
      path?: number[];
    }>;
    metadata?: string;
    players: string[];
    playerIds: number[];
  }) {
    try {
      const response = await this.client.post('/start_signing', params);
      logger.debug(`Player ${this.playerId} started signing`);
      return response.data;
    } catch (error: any) {
      logger.error(`Start signing failed:`, error.response?.data || error.message);
      const errMsg = error.response?.data?.error || error.message || "Unknown error"; throw new Error(errMsg);
    }
  }

  /**
   * Signing API 2: MTA response
   */
  async mtaResponse(params: {
    txid: string;
    version?: number;
    requests: Array<{
      playerId: number;
      mtaRequests: Array<{
        K: string;
        G: string;
        c_key: string;
        c_k_gamma: string;
        zkp_sch_k: string;
        zkp_sch_gamma: string;
        zkp_oper_k: string;
        zkp_oper_gamma: string;
      }>;
    }>;
  }) {
    try {
      const response = await this.client.post('/mta_response', params);
      logger.debug(`Player ${this.playerId} generated MTA response`);
      return response.data;
    } catch (error: any) {
      logger.error(`MTA response failed:`, error.response?.data || error.message);
      const errMsg = error.response?.data?.error || error.message || "Unknown error"; throw new Error(errMsg);
    }
  }

  /**
   * Signing API 3: MTA verify
   */
  async mtaVerify(params: {
    txid: string;
    mtaResponses: Array<{
      playerId: number;
      flags?: number;
      responses: Array<{
        c_gamma_k_v_my_b: string;
        beta_zkp: string;
        c_w_my_b: string;
        beta_tag_zkp: string;
      }>;
    }>;
  }) {
    try {
      const response = await this.client.post('/mta_verify', params);
      logger.debug(`Player ${this.playerId} verified MTA`);
      return response.data;
    } catch (error: any) {
      logger.error(`MTA verify failed:`, error.response?.data || error.message);
      const errMsg = error.response?.data?.error || error.message || "Unknown error"; throw new Error(errMsg);
    }
  }

  /**
   * Signing API 4: Get si (signature share)
   */
  async getSi(params: {
    txid: string;
    deltas: Array<{
      playerId: number;
      deltas: Array<{
        R: string;
        deltas: string[];
      }>;
    }>;
  }) {
    try {
      const response = await this.client.post('/get_si', params);
      logger.debug(`Player ${this.playerId} calculated si`);
      return response.data;
    } catch (error: any) {
      logger.error(`Get si failed:`, error.response?.data || error.message);
      const errMsg = error.response?.data?.error || error.message || "Unknown error"; throw new Error(errMsg);
    }
  }

  /**
   * Signing API 5: Get signature (combine shares)
   */
  async getSignature(params: {
    txid: string;
    s: Array<{
      playerId: number;
      sis: string[];
    }>;
  }) {
    try {
      const response = await this.client.post('/get_signature', params);
      logger.debug(`Player ${this.playerId} got final signature`);
      return response.data;
    } catch (error: any) {
      logger.error(`Get signature failed:`, error.response?.data || error.message);
      const errMsg = error.response?.data?.error || error.message || "Unknown error"; throw new Error(errMsg);
    }
  }

  // ==================== UTILITY ====================

  /**
   * Health check
   */
  async healthCheck() {
    try {
      const response = await this.client.get('/health');
      return response.data;
    } catch (error: any) {
      logger.error(`Health check failed:`, error.message);
      const errMsg = error.response?.data?.error || error.message || "Unknown error"; throw new Error(errMsg);
    }
  }
}

/**
 * Factory function to create MPC REST clients for all players
 */
export function createMPCRestClients(
  playerIds: number[],
  baseUrls?: Map<number, string>
): Map<number, MPCRestClient> {
  const clients = new Map<number, MPCRestClient>();

  playerIds.forEach((playerId, index) => {
    const baseUrl = baseUrls?.get(playerId) || `http://localhost:${8000 + playerId}`;
    clients.set(playerId, new MPCRestClient({ baseUrl, playerId }));
  });

  logger.info(`Created ${clients.size} MPC REST clients`);
  return clients;
}
