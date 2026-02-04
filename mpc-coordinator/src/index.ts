import express, { Express, Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import { createLogger } from './utils/logger';
import { initializeHSM, closeHSM } from './hsm/softhsm';
import { PrismaClient } from '@prisma/client';

// Load environment variables
dotenv.config();

const logger = createLogger('Main');
const prisma = new PrismaClient();

// Import routes
import setupRoutes from './api/setup.routes';
import signingRoutes from './api/signing.routes';
import healthRoutes from './api/health.routes';

const app: Express = express();
const port = process.env.PORT || 3000;

// Middleware (Simplified for PoC)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  logger.info(`${req.method} ${req.path}`);
  next();
});

// Health check
app.use('/health', healthRoutes);

// API routes
app.use('/api/setup', setupRoutes);
app.use('/api/signing', signingRoutes);

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined,
  });
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found' });
});

// Graceful shutdown (Simplified for PoC)
async function shutdown() {
  logger.info('Shutting down...');
  await closeHSM();
  await prisma.$disconnect();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Start server
app.listen(port, async () => {
  logger.info(`MPC Node.js Integration Server`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`Listening on port ${port}`);

  try {
    // Initialize HSM
    logger.info('Initializing SoftHSM...');
    await initializeHSM();
    logger.info('SoftHSM initialized successfully');

    // Test database connection
    logger.info('Testing database connection...');
    await prisma.$queryRaw`SELECT 1`;
    logger.info('Database connected successfully');

    logger.info('Server is ready to accept requests');

  } catch (error) {
    logger.error('Failed to initialize server:', error);
    process.exit(1);
  }
});

export default app;
