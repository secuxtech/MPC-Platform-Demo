import { Router, Request, Response } from 'express';
import { createLogger } from '../utils/logger';
import { SetupService } from '../services/setup.service';

const logger = createLogger('SetupRoutes');
const router = Router();
const setupService = new SetupService();

/**
 * POST /api/setup/start
 * Start key generation process (Setup Phase 1-5)
 * Simplified PoC version - basic validation only
 */
router.post('/start', async (req: Request, res: Response) => {
  try {
    const params = req.body;

    // Basic validation
    if (!params.keyId || !params.algorithm || !params.threshold || !params.totalPlayers || !params.playerIds) {
      return res.status(400).json({
        error: 'Missing required parameters',
        required: ['keyId', 'algorithm', 'threshold', 'totalPlayers', 'playerIds'],
      });
    }

    // Validate threshold and totalPlayers
    // Note: CMP protocol only supports n-of-n (threshold must equal totalPlayers)
    if (params.threshold !== params.totalPlayers) {
      return res.status(400).json({
        error: 'Invalid threshold',
        message: 'CMP protocol only supports n-of-n signatures (threshold must equal total players)',
      });
    }

    if (params.playerIds.length !== params.totalPlayers) {
      return res.status(400).json({
        error: 'Invalid player count',
        message: `Expected ${params.totalPlayers} player IDs, got ${params.playerIds.length}`,
      });
    }

    logger.info(`Starting setup for key ${params.keyId} with ${params.threshold}-of-${params.totalPlayers}`);

    // Execute full 5-phase setup
    const result = await setupService.executeFullSetup(params);

    return res.json({
      success: true,
      keyId: params.keyId,
      publicKey: result.publicKey,
      algorithm: params.algorithm,
      threshold: params.threshold,
      totalPlayers: params.totalPlayers,
      createdAt: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Setup failed:', error);

    return res.status(500).json({
      error: 'Setup failed',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/setup/:keyId
 * Query key status (Simplified - basic info only)
 */
router.get('/:keyId', async (req: Request, res: Response) => {
  try {
    const { keyId } = req.params;

    const keyInfo = await setupService.getKeyInfo(keyId);

    if (!keyInfo) {
      return res.status(404).json({
        error: 'Key not found',
        keyId,
      });
    }

    return res.json(keyInfo);
  } catch (error) {
    logger.error('Failed to get key info:', error);
    return res.status(500).json({
      error: 'Failed to get key info',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

export default router;
