import {
    Transaction,
    Address,
    TransactionComputer,
    SmartContractQuery,
} from '@multiversx/sdk-core';
import { UserVerifier, UserPublicKey } from '@multiversx/sdk-wallet';
import { QuotaManager } from './QuotaManager';
import { ChallengeManager } from './ChallengeManager';
import { RelayerAddressManager } from './RelayerAddressManager';

export interface ISimulationResult {
    status?: {
        status?: string;
    };
    raw?: {
        status?: string;
        receiverShard?: { status?: string };
        senderShard?: { status?: string };
    };
    execution?: {
        result?: string;
        message?: string;
        gasConsumed?: number;
    };
    result?: {
        execution?: {
            result?: string;
            message?: string;
            gasConsumed?: number;
        };
    };
    error?: string;
}

export interface IRelayerNetworkProvider {
    queryContract(query: SmartContractQuery): Promise<any>; // Query results vary wildly, keeping any for now but could be improved with generic
    sendTransaction(tx: Transaction): Promise<string>;
    simulateTransaction(tx: Transaction): Promise<ISimulationResult>;
}

export class RelayerService {
    private provider: IRelayerNetworkProvider;
    private relayerAddressManager: RelayerAddressManager;
    private quotaManager: QuotaManager;
    private challengeManager: ChallengeManager;
    private registryAddresses: string[];

    constructor(
        provider: IRelayerNetworkProvider,
        relayerAddressManager: RelayerAddressManager,
        quotaManager: QuotaManager,
        challengeManager: ChallengeManager,
        registryAddresses: string[] = [],
    ) {
        this.provider = provider;
        this.relayerAddressManager = relayerAddressManager;
        this.quotaManager = quotaManager;
        this.challengeManager = challengeManager;
        this.registryAddresses = registryAddresses;
    }

    public getRelayerAddressForUser(userAddress: string): string {
        return this.relayerAddressManager.getRelayerAddressForUser(userAddress);
    }

    async validateTransaction(tx: Transaction): Promise<boolean> {
        try {
            const publicKey = new UserPublicKey(tx.sender.getPublicKey());
            const verifier = new UserVerifier(publicKey);

            const computer = new TransactionComputer();
            const message = computer.computeBytesForSigning(tx);
            const isValid = verifier.verify(message, tx.signature);

            return isValid;
        } catch (error) {
            console.error('Validation error:', error);
            return false;
        }
    }

    async isAuthorized(address: Address): Promise<boolean> {
        if (this.registryAddresses.length === 0) {
            console.log('Authorization: No registries configured, failing open.');
            return true;
        }

        const identityRegistry = this.registryAddresses[0];
        console.log(
            `Authorization: Checking registry ${identityRegistry} for ${address.toBech32()}`,
        );

        try {
            const query = new SmartContractQuery({
                contract: new Address(identityRegistry),
                function: 'get_agent_id',
                arguments: [address.getPublicKey()],
            });

            const queryResponse = await this.provider.queryContract(query);

            // Robust check for returnData vs returnDataParts
            const returnData =
                queryResponse.returnData || queryResponse.returnDataParts;

            if (!returnData || returnData.length === 0) {
                console.log(
                    `Authorization: Registry returned no data for ${address.toBech32()}`,
                );
                return false;
            }

            // Decode the result. EIP-8004/MX-8004 returns u64 for agent_id.
            // 0 means not registered.
            const raw = Buffer.from(returnData[0], 'base64');
            const agentId = raw.length > 0 ? BigInt('0x' + raw.toString('hex')) : 0n;

            console.log(`Authorization: Agent ID found: ${agentId.toString()}`);
            return agentId > 0n;
        } catch (error) {
            console.error('Authorization: Agent registration check failed:', error);
            return false;
        }
    }

    async signAndRelay(
        tx: Transaction,
        challengeNonce?: string,
    ): Promise<string> {
        const sender = tx.sender;
        console.log(`Relay: Processing transaction from ${sender.toBech32()}`);

        // 1. Quota Check
        if (!this.quotaManager.checkLimit(sender.toBech32())) {
            console.warn(`Relay: Quota exceeded for ${sender.toBech32()}`);
            throw new Error('Quota exceeded for this agent');
        }

        // 2. Authorization Logic
        console.log('Relay: Step 1 - Checking Authorization');
        const isRegistered = await this.isAuthorized(sender);

        if (isRegistered) {
            console.log('Relay: Agent is registered on-chain.');
        } else {
            console.log(
                'Relay: Agent NOT registered. Verifying challenge solution.',
            );
            if (
                !challengeNonce ||
                !this.challengeManager.verifySolution(sender.toBech32(), challengeNonce)
            ) {
                console.warn(`Relay: Unauthorized attempt by ${sender.toBech32()}`);
                throw new Error(
                    'Unauthorized: Agent not registered. Solve challenge and register first.',
                );
            }
            console.log('Relay: Challenge solution verified.');
        }

        // 3. Signature Validation
        if (!(await this.validateTransaction(tx))) {
            throw new Error('Invalid inner transaction signature');
        }

        // 4. Wrap & Sign
        const relayerSigner = this.relayerAddressManager.getSignerForUser(
            sender.toBech32(),
        );
        const relayerAddress = relayerSigner.getAddress();

        // VALIDATION: In Relayed V3, the sender MUST set the relayer address BEFORE signing.
        // We must not overwrite it, but we MUST verify it's correct for the sender's shard.
        if (!tx.relayer || tx.relayer.toBech32() !== relayerAddress.bech32()) {
            throw new Error(
                `Invalid relayer address. Expected ${relayerAddress.bech32()} for sender's shard.`,
            );
        }

        if (tx.version < 2) {
            throw new Error(
                'Invalid transaction version for Relayed V3. Expected version >= 2.',
            );
        }

        const computer = new TransactionComputer();
        tx.relayerSignature = await relayerSigner.sign(
            computer.computeBytesForSigning(tx),
        );

        // 5. Pre-broadcast Simulation (Crucial for Relayed V3)
        console.log('Relay: Step 4 - Running On-Chain Simulation');
        try {
            const simulationResult = await this.provider.simulateTransaction(tx);
            console.log(
                'Relay: Simulation raw result:',
                JSON.stringify(simulationResult, (_, v) => typeof v === 'bigint' ? v.toString() : v),
            );

            // Robust Parser: Handle both flattened (API) and nested (Proxy/Gateway) structures
            const statusFromStatus = simulationResult?.status?.status;
            const statusFromRaw = simulationResult?.raw?.status;
            const execution =
                simulationResult?.execution || simulationResult?.result?.execution;

            // Check shard-specific status in raw if top-level status is missing
            const receiverShardStatus = simulationResult?.raw?.receiverShard?.status;
            const senderShardStatus = simulationResult?.raw?.senderShard?.status;
            const shardSuccess = (receiverShardStatus === 'success') && (!senderShardStatus || senderShardStatus === 'success');

            const resultStatus =
                statusFromStatus || statusFromRaw || execution?.result || (shardSuccess ? 'success' : '');

            if (resultStatus !== 'success') {
                const message =
                    execution?.message || simulationResult?.error || 'Unknown error';
                console.error(`Relay: Simulation failed: ${message}`);
                throw new Error(`On-chain simulation failed: ${message}`);
            }
            console.log('Relay: Simulation successful.');
        } catch (simError: unknown) {
            const message = simError instanceof Error ? simError.message : String(simError);
            console.error('Relay: Simulation error caught:', message);
            throw simError;
        }

        // 6. Broadcast
        console.log('Relay: Step 5 - Broadcasting Transaction');
        try {
            const hash = await this.provider.sendTransaction(tx);
            this.quotaManager.incrementUsage(sender.toBech32());
            console.log(`Relay: Successful broadcast. Hash: ${hash}`);
            return hash;
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : String(error);
            console.error('Relay: Broadcast failed:', message);
            throw new Error(`Broadcast failed: ${message}`);
        }
    }
}
