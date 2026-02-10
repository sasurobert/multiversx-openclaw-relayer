import {
    Transaction,
    Address,
    TransactionComputer,
    Abi,
    DevnetEntrypoint,
    SmartContractQuery,
    SmartContractQueryResponse,
} from '@multiversx/sdk-core';
import { UserVerifier, UserPublicKey } from '@multiversx/sdk-wallet';
import { QuotaManager } from './QuotaManager';
import { ChallengeManager } from './ChallengeManager';
import { parseSimulationResult } from '../utils/simulationParser';
import { RelayerAddressManager } from './RelayerAddressManager';
import { logger } from '../utils/logger';
import fs from 'fs';
import path from 'path';

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
    queryContract(query: SmartContractQuery): Promise<SmartContractQueryResponse>;
    sendTransaction(tx: Transaction): Promise<string>;
    simulateTransaction(tx: Transaction): Promise<ISimulationResult>;
}

export class RelayerService {
    private relayerAddressManager: RelayerAddressManager;
    private quotaManager: QuotaManager;
    private challengeManager: ChallengeManager;
    private registryAddresses: string[];
    private identityAbi?: Abi;
    private entrypoint: DevnetEntrypoint;
    private provider: IRelayerNetworkProvider;

    constructor(
        provider: IRelayerNetworkProvider,
        relayerAddressManager: RelayerAddressManager,
        quotaManager: QuotaManager,
        challengeManager: ChallengeManager,
        registryAddresses: string[] = [],
        entrypoint?: DevnetEntrypoint
    ) {
        this.provider = provider;
        this.relayerAddressManager = relayerAddressManager;
        this.quotaManager = quotaManager;
        this.challengeManager = challengeManager;
        this.registryAddresses = registryAddresses;
        this.entrypoint = entrypoint || new DevnetEntrypoint({ url: (provider as IRelayerNetworkProvider & { url?: string }).url || 'http://localhost:7950' });

        this.initializeAbis();
    }

    private initializeAbis() {
        try {
            const abiPath = path.join(__dirname, '../abis/identity-registry.abi.json');
            if (fs.existsSync(abiPath)) {
                // Patch ABI types that sdk-core TypeMapper doesn't recognize
                const raw = fs.readFileSync(abiPath, 'utf8');
                const patched = raw
                    .replace(/"TokenId"/g, '"TokenIdentifier"')
                    .replace(/"NonZeroBigUint"/g, '"BigUint"');
                this.identityAbi = Abi.create(JSON.parse(patched));
            }
        } catch (error) {
            logger.error({ error }, 'Failed to initialize ABIs in RelayerService');
        }
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
            logger.error({ error }, 'Validation error');
            return false;
        }
    }

    async isAuthorized(address: Address): Promise<boolean> {
        if (this.registryAddresses.length === 0 || !this.identityAbi) {
            logger.info('Authorization: No registries or ABI configured, failing open.');
            return true;
        }

        const identityRegistry = this.registryAddresses[0];
        logger.info({ registry: identityRegistry, address: address.toBech32() }, 'Authorization: Checking registry');

        try {
            const controller = this.entrypoint.createSmartContractController(this.identityAbi);

            const results = await controller.query({
                contract: Address.newFromBech32(identityRegistry),
                function: 'get_agent_id',
                arguments: [address],
            });

            const agentId = results[0] as bigint;
            logger.info({ agentId: agentId.toString() }, 'Authorization: Agent ID found (ABI-typed)');
            return agentId > 0n;
        } catch (error) {
            logger.error({ error }, 'Authorization: Agent registration check failed');
            return false;
        }
    }

    async signAndRelay(
        tx: Transaction,
        challengeNonce?: string,
    ): Promise<string> {
        const sender = tx.sender;
        logger.info({ sender: sender.toBech32() }, 'Relay: Processing transaction');

        // 1. Quota Check
        if (!this.quotaManager.checkLimit(sender.toBech32())) {
            logger.warn({ sender: sender.toBech32() }, 'Relay: Quota exceeded');
            throw new Error('Quota exceeded for this agent');
        }

        // 2. Authorization Logic
        logger.info('Relay: Step 1 - Checking Authorization');
        const isRegistered = await this.isAuthorized(sender);

        if (isRegistered) {
            logger.info('Relay: Agent is registered on-chain.');
        } else {
            logger.info('Relay: Agent NOT registered. Verifying challenge solution.');
            if (
                !challengeNonce ||
                !this.challengeManager.verifySolution(sender.toBech32(), challengeNonce)
            ) {
                logger.warn({ sender: sender.toBech32() }, 'Relay: Unauthorized attempt');
                throw new Error(
                    'Unauthorized: Agent not registered. Solve challenge and register first.',
                );
            }
            logger.info('Relay: Challenge solution verified.');
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
        logger.info('Relay: Step 4 - Running On-Chain Simulation');
        if (process.env.SKIP_SIMULATION === 'true') {
            logger.info('Relay: Simulation SKIPPED by config.');
        } else {
            try {
                const simulationResult = await this.provider.simulateTransaction(tx);
                logger.debug(
                    { result: JSON.parse(JSON.stringify(simulationResult, (_, v) => typeof v === 'bigint' ? v.toString() : v)) },
                    'Relay: Simulation raw result',
                );

                const { success, errorMessage } = parseSimulationResult(simulationResult);

                if (!success) {
                    logger.error({ error: errorMessage }, 'Relay: Simulation failed');
                    throw new Error(`On-chain simulation failed: ${errorMessage}`);
                }
                logger.info('Relay: Simulation successful.');
            } catch (simError: unknown) {
                const message = simError instanceof Error ? simError.message : String(simError);
                logger.error({ error: message }, 'Relay: Simulation error caught');
                throw simError;
            }
        }

        // 6. Broadcast
        logger.info('Relay: Step 5 - Broadcasting Transaction');
        try {
            const hash = await this.provider.sendTransaction(tx);
            this.quotaManager.incrementUsage(sender.toBech32());
            logger.info({ txHash: hash }, 'Relay: Successful broadcast');
            return hash;
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : String(error);
            logger.error({ error: message }, 'Relay: Broadcast failed');
            throw new Error(`Broadcast failed: ${message}`);
        }
    }
}
