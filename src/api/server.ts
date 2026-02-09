import express from 'express';
import cors from 'cors';
import { RelayerService } from '../services/RelayerService';
import { ChallengeManager } from '../services/ChallengeManager';
import { Transaction } from '@multiversx/sdk-core';
import { logger } from '../utils/logger';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

export const createApp = (
  relayerService: RelayerService,
  challengeManager: ChallengeManager,
) => {
  const app = express();

  app.use(helmet());
  app.use(rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
  }));
  app.use(cors());
  app.use(express.json());

  app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  /**
   * Get the correct relayer address for a specific user (shard matching).
   */
  app.get('/relayer/address/:userAddress', (req, res) => {
    const { userAddress } = req.params;
    if (!userAddress) {
      res.status(400).json({ error: 'User address is required' });
      return;
    }

    try {
      const relayerAddress =
        relayerService.getRelayerAddressForUser(userAddress);
      res.status(200).json({ relayerAddress });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      res.status(404).json({ error: message });
    }
  });

  /**
   * Legacy config endpoint (optional, but keep for backward compat if single shard env)
   * For multi-shard, this might be misleading if it just returns one address.
   * We'll keep it but maybe warn or just return a default one (e.g. shard 0).
   */
  app.get('/config', (req, res) => {
    // Return shard 0 or first available as default
    try {
      // Mocking a default user address to get *some* relayer
      // In a real scenario, this endpoint should be deprecated
      // For now, let's just return nothing or a comprehensive list?
      // Let's return empty if we can't decide, or just not implement it if not used by new clients.
      // Existing clients use /config?
      // "createRelayedV3.test.ts" usage implies direct config access might be happening?
      // "multiversx-openclaw-skills" used /config. We are changing that.
      // We can return a generic response or deprecate it.
      res.status(200).json({
        message: 'Use /relayer/address/:userAddress to get correct relayer',
      });
    } catch {
      res.status(500).json({ error: 'Internal error' });
    }
  });

  /**
   * Request a PoW challenge for a specific address.
   * Required for agents who are not yet registered.
   */
  app.post('/challenge', (req, res) => {
    const { address } = req.body;
    if (!address) {
      res.status(400).json({ error: 'Address is required' });
      return;
    }

    const challenge = challengeManager.getChallenge(address);
    res.status(200).json(challenge);
  });

  app.post('/relay', async (req, res) => {
    try {
      const { transaction, challengeNonce } = req.body;

      if (!transaction) {
        res.status(400).json({ error: 'Transaction is required' });
        return;
      }

      let tx: Transaction;
      try {
        tx = Transaction.newFromPlainObject(transaction);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Invalid format';
        res
          .status(400)
          .json({ error: 'Invalid transaction format', details: message });
        return;
      }

      const txHash = await relayerService.signAndRelay(tx, challengeNonce);
      res.status(200).json({ txHash });
    } catch (error: unknown) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error({ error: err.message }, 'Relay error');
      const message = err.message || 'Internal Server Error';

      if (message.includes('Quota exceeded')) {
        res.status(429).json({ error: message });
      } else if (
        message.includes('verification failed') ||
        message.includes('Unauthorized')
      ) {
        res.status(403).json({ error: message });
      } else if (message.includes('Invalid inner transaction')) {
        res.status(400).json({ error: message });
      } else {
        res.status(500).json({ error: message });
      }
    }
  });

  return app;
};
