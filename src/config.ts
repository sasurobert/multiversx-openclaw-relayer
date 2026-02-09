import dotenv from 'dotenv';

// Load .env file
dotenv.config();

export interface AppConfig {
  networkProvider: string;
  identityRegistryAddress: string;
  reputationRegistryAddress: string;
  validationRegistryAddress: string;
  quotaLimit: number;
  dbPath: string;
  relayerWalletsDir: string;
  port: number;
  challengeTimeout: number;
  challengeDifficulty: number;
  quotaResetIntervalMs: number;
  challengeTtlSeconds: number;
  logLevel: string;
}

export const config: AppConfig = {
  networkProvider:
    process.env.NETWORK_PROVIDER || 'https://devnet-gateway.multiversx.com',
  identityRegistryAddress: process.env.IDENTITY_REGISTRY_ADDRESS || '',
  reputationRegistryAddress: process.env.REPUTATION_REGISTRY_ADDRESS || '',
  validationRegistryAddress: process.env.VALIDATION_REGISTRY_ADDRESS || '',
  quotaLimit: parseInt(process.env.QUOTA_LIMIT || '10', 10),
  dbPath: process.env.DB_PATH || ':memory:',
  relayerWalletsDir: process.env.RELAYER_WALLETS_DIR || 'wallets',
  port: parseInt(process.env.PORT || '3000', 10),
  challengeTimeout: parseInt(process.env.CHALLENGE_TIMEOUT || '10', 10),
  challengeDifficulty: parseInt(process.env.CHALLENGE_DIFFICULTY || '18', 10),
  quotaResetIntervalMs: 24 * 60 * 60 * 1000, // 24 hours
  challengeTtlSeconds: 60, // 1 minute
  logLevel: process.env.LOG_LEVEL || 'info',
};
