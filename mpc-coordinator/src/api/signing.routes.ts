import { Router, Request, Response } from 'express';
import { createLogger } from '../utils/logger';
import { EcdsaSigningService } from '../services/ecdsa.service';

const logger = createLogger('SigningRoutes');
const router = Router();
const ecdsaService = new EcdsaSigningService();

/**
 * POST /api/signing/ecdsa
 * Perform ECDSA signing (for Bitcoin & Ethereum)
 * Simplified PoC version - basic validation only
 */
router.post('/ecdsa', async (req: Request, res: Response) => {
  try {
    const params = req.body;

    // Basic validation
    if (!params.keyId || !params.txId || !params.messageHash || !params.playerIds) {
      return res.status(400).json({
        error: 'Missing required parameters',
        required: ['keyId', 'txId', 'messageHash', 'playerIds'],
      });
    }

    // Validate messageHash format (should be 64 hex characters)
    const messageHash = params.messageHash.replace(/^0x/, '');
    if (!/^[0-9a-fA-F]{64}$/.test(messageHash)) {
      return res.status(400).json({
        error: 'Invalid messageHash format',
        message: 'messageHash must be 64 hex characters (with or without 0x prefix)',
      });
    }

    // Validate playerIds is array with at least 2 players
    if (!Array.isArray(params.playerIds) || params.playerIds.length < 2) {
      return res.status(400).json({
        error: 'Invalid playerIds',
        message: 'playerIds must be an array with at least 2 players',
      });
    }

    logger.info(`Starting ECDSA signing for tx ${params.txId} with key ${params.keyId}`);

    // Execute full 4-round ECDSA signing
    const result = await ecdsaService.signMessage({
      ...params,
      messageHash,
    });

    return res.json({
      success: true,
      txId: params.txId,
      signature: {
        r: result.r,
        s: result.s,
        v: result.v,
      },
      algorithm: 'ECDSA_SECP256K1',
      signedAt: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('ECDSA signing failed:', error);

    return res.status(500).json({
      error: 'Signing failed',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/signing/session/:txId
 * Query signing session status (Simplified - basic info only)
 */
router.get('/session/:txId', async (req: Request, res: Response) => {
  try {
    const { txId } = req.params;

    const sessionInfo = await ecdsaService.getSessionInfo(txId);

    if (!sessionInfo) {
      return res.status(404).json({
        error: 'Session not found',
        txId,
      });
    }

    return res.json(sessionInfo);
  } catch (error) {
    logger.error('Failed to get session info:', error);
    return res.status(500).json({
      error: 'Failed to get session info',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

export default router;
