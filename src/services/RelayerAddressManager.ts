import { UserSigner } from '@multiversx/sdk-wallet';
import { Address } from '@multiversx/sdk-core';
import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger';

export class RelayerAddressManager {
  private signers: Map<number, UserSigner> = new Map();
  private addresses: Map<number, string> = new Map();

  constructor(walletsDir: string) {
    this.loadWallets(walletsDir);
  }

  private loadWallets(walletsDir: string) {
    if (!fs.existsSync(walletsDir)) {
      logger.warn({ walletsDir }, 'Wallets directory does not exist');
      return;
    }

    const files = fs.readdirSync(walletsDir);
    for (const file of files) {
      if (file.endsWith('.pem')) {
        try {
          const pemContent = fs.readFileSync(
            path.join(walletsDir, file),
            'utf8',
          );
          const signer = UserSigner.fromPem(pemContent);
          const userAddress = signer.getAddress();
          // Convert UserAddress to Address from sdk-core if needed, or just use it.
          // UserAddress has .toString() which returns bech32.
          // Address.newFromBech32 is safe.
          const address = Address.newFromBech32(userAddress.toString());
          const shard = this.getShard(address);

          this.signers.set(shard, signer);
          this.addresses.set(shard, address.toBech32());
          logger.info(
            { shard, address: address.toBech32() },
            'Loaded relayer wallet',
          );
        } catch (e) {
          logger.error({ file, error: e }, 'Failed to load wallet');
        }
      }
    }
  }

  private getShard(address: Address): number {
    // Shard calculation logic based on MultiversX specs
    // The last bits of the pubkey determine the shard.
    // Assuming SDK has a method, but strictly implementing here if needed.
    // Actually, Address object from SDK has a logic, but let's use the one that matches standard behavior.
    // Standard is: last byte of pubkey is mapped to shard.
    // However, let's trust the SDK Address implementation if used generally,
    // but for now I will rely on the property of the Loaded Address to create the map.
    // When checking for a user, I will use their address to find THEIR shard.

    // We need to know which shard a given address belongs to.
    // In this method, 'address' is the RELAYER'S address.
    // But we also need 'getRelayerForUser(userAddress)'.

    // For MultiversX:
    // mask = numShards - 1 (if power of 2) or more complex.
    // Default devnet often has 3 shards (0, 1, 2).
    // Let's rely on a simplified assumption or standard logic if not critical to implement fully from scratch.
    // Actually, easiest is to let the network provider tell us, OR implement standard logic.
    // Implementation:
    // const pubKey = address.getPublicKey();
    // const lastByte = pubKey[31];
    // // Shard logic depends on network config (metachain, num shards).
    // // Assuming 3 shards for now as typical for mainnet/devnet.
    // return address.getShard(); // SDK Address should have this if constructed with network config?

    // Wait, Address class in sdk-core usually doesn't know about network config (num shards).
    // It serves utility.
    // We might need to inject 'numberOfShards'.

    // For this specific issue: The Relayer MUST be in the same shard as the sender.
    // So we need to match Shard(Relayer) == Shard(Sender).

    // How do we compute Shard(Sender)?
    // We can accept it as a param or compute it.
    // Let's compute it assuming standard 3 shards configuration if no config provided.
    // OR better: The Manager holds ALL available relayers. When asked for a relayer for UserA,
    // it computes UserA's shard, and returns the Relayer for that shard.

    // To be safe, let's implementation standard shard computation.
    // number_of_shards = 3 (default for now)

    // Actually, `Address` from sdk-core does NOT expose getShard() directly without config context usually?
    // Let's check `Address` or implement getShard manually.
    // Reference: https://docs.multiversx.com/developers/developer-reference/sc-annotations/#address-structure

    // Basic impl:

    // Sharding on Devnet/Mainnet: 3 shards.
    // Shard 0: 0, 3, 6...
    // Shard 1: 1, 4, 7...
    // Shard 2: 2, 5, 8...
    // BUT Metachain is different.

    // Simplification: We will just try to match based on available wallets.
    // If we have a wallet that "claims" to be shard X, we use it for user in shard X.
    // Ideally we'd use a robust utility.

    // Let's just create a dummy helper here that does module 3 for now,
    // but cleaner is to rely on what the Relayer Service *knows* about its wallets.
    // We can just iterate through our loaded relayers and check `getShardOf(relayer) == getShardOf(user)`.

    // Wait, SDK `Address` object doesn't expose `getShard()`.

    return getShardFromAddress(address);
  }

  public getSignerForShard(shard: number): UserSigner | undefined {
    return this.signers.get(shard);
  }

  public getAddressForShard(shard: number): string | undefined {
    return this.addresses.get(shard);
  }

  public getRelayerAddressForUser(userAddressStr: string): string {
    const userAddress = Address.newFromBech32(userAddressStr);
    const shard = getShardFromAddress(userAddress);
    const relayerAddress = this.addresses.get(shard);

    if (!relayerAddress) {
      throw new Error(`No relayer configured for shard ${shard}`);
    }
    return relayerAddress;
  }

  public getSignerForUser(userAddressStr: string): UserSigner {
    const userAddress = Address.newFromBech32(userAddressStr);
    const shard = getShardFromAddress(userAddress);
    const signer = this.signers.get(shard);

    if (!signer) {
      throw new Error(`No relayer configured for shard ${shard}`);
    }
    return signer;
  }
}

// Helper: 3 Shards Default (Devnet/Mainnet/Testnet compatible for standard addresses)
function getShardFromAddress(address: Address): number {
  const pubKey = address.getPublicKey();
  // Logic from MultiversX Go:
  // https://github.com/multiversx/mx-chain-go/blob/master/sharding/sharding.go
  // Simplified: last byte % 3 (if no metachain)
  // Actually, it's more complex with bitmasking.
  // However, for purposes of "same shard", simply matching the computation is enough.
  // Let's implement the standard logic assuming 3 shards.

  const lastByte = pubKey[31];
  // const mask = 0x03; // for 3 shards (next power of 2 is 4, so 2 bits)
  // Actually mask depends on numShards.
  // Mainnet/Devnet: 3 shards.

  // For 3 shards, the logic is usually roughly:
  // shard = lastByte & mask
  // if shard > 2 { shard = lastByte & (mask >> 1) }
  // Wait, let's simplify:

  // We can iterate available relayers and check `Address.areInSameShard(addr1, addr2)`.
  // Wait, is that available? No.

  // Let's implement a robust enough lookup assuming the standard 3 shards configuration.
  // Using a very simple heuristic for now which is acceptable for this Starter Kit / Demo context
  // unless user provided specific network config.
  // We will assume 3 Shards.

  const numShards = 3;
  const maskHigh = 3; // 11 binary (for 4)
  const maskLow = 1; // 01 binary (for 2)

  let shard = lastByte & maskHigh;
  if (shard > numShards - 1) {
    shard = lastByte & maskLow;
  }
  return shard;
}
