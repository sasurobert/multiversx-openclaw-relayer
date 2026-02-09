import { createHash, randomBytes } from 'crypto';
import { config } from '../config.js';
import { logger } from '../utils/logger';

export interface Challenge {
  address: string;
  target: string;
  salt: string;
  difficulty: number;
  expiresAt: number;
}

export class ChallengeManager {
  private challenges: Map<string, Challenge> = new Map();
  private readonly ttlMs: number;
  private readonly difficultyBits: number;

  constructor(
    ttlSeconds: number = config.challengeTtlSeconds,
    difficultyBits: number = config.challengeDifficulty,
  ) {
    this.ttlMs = ttlSeconds * 1000;
    this.difficultyBits = difficultyBits;
  }

  getChallenge(address: string): Challenge {
    const salt = randomBytes(16).toString('hex');
    const expiresAt = Date.now() + this.ttlMs;

    const challenge: Challenge = {
      address,
      target: address,
      salt,
      difficulty: this.difficultyBits,
      expiresAt,
    };

    this.challenges.set(address, challenge);
    return challenge;
  }

  verifySolution(address: string, nonce: string): boolean {
    const challenge = this.challenges.get(address);
    if (!challenge) return false;

    if (Date.now() > challenge.expiresAt) {
      this.challenges.delete(address);
      return false;
    }

    const data = `${challenge.address}${challenge.salt}${nonce}`;
    const hash = createHash('sha256').update(data).digest(); // Get Buffer for bit checking

    if (!this.checkDifficulty(hash, challenge.difficulty)) {
      logger.warn(
        { address, hash: hash.toString('hex') },
        'Challenge: Invalid solution',
      );
      return false;
    }

    logger.info({ address }, 'Challenge: Valid solution');
    this.challenges.delete(address); // One-time use
    return true;
  }

  /**
   * Check if the hash starts with N zero bits
   */
  private checkDifficulty(hash: Buffer, difficulty: number): boolean {
    const fullBytes = Math.floor(difficulty / 8);
    const remainingBits = difficulty % 8;

    // Check full bytes
    for (let i = 0; i < fullBytes; i++) {
      if (hash[i] !== 0) return false;
    }

    // Check remaining bits in the next byte
    if (remainingBits > 0) {
      const lastByte = hash[fullBytes];
      // Shift right to remove non-zero bits we care about
      // E.g. if remainingBits is 2, byte must be < 2^(8-2) = 64 (00xxxxxx)
      if (lastByte >= 1 << (8 - remainingBits)) return false;
    }

    return true;
  }
}
