import { DevnetEntrypoint } from '@multiversx/sdk-core';
import { RelayerAddressManager } from './services/RelayerAddressManager';
import { createApp } from './api/server';
import { config } from './config';
import { QuotaManager } from './services/QuotaManager';
import { ChallengeManager } from './services/ChallengeManager';
import { RelayerService } from './services/RelayerService';
import { logger } from './utils/logger';

const main = async () => {
  logger.info('Starting MultiversX OpenClaw Relayer...');
  logger.info(
    { config: { ...config, relayerPemPath: '***' } },
    'Loaded configuration',
  );

  const url = config.networkProvider;
  const kind = url.includes('api') ? 'api' : 'proxy';
  const entrypoint = new DevnetEntrypoint({ url, kind });
  const provider = entrypoint.createNetworkProvider();

  // Initialize Address Manager
  const relayerAddressManager = new RelayerAddressManager(
    config.relayerWalletsDir,
  );

  const quotaManager = new QuotaManager(config.dbPath, config.quotaLimit);
  const challengeManager = new ChallengeManager(
    config.challengeTimeout,
    config.challengeDifficulty,
  );
  const relayerService = new RelayerService(
    provider,
    relayerAddressManager,
    quotaManager,
    challengeManager,
    [
      config.identityRegistryAddress,
      config.reputationRegistryAddress,
      config.validationRegistryAddress,
    ].filter(a => !!a),
  );

  const app = createApp(relayerService, challengeManager);

  app.listen(config.port, () => {
    logger.info({ port: config.port }, 'Server listening');
  });
};

if (require.main === module) {
  main().catch(err => {
    logger.fatal({ error: err }, 'Fatal error');
    process.exit(1);
  });
}
