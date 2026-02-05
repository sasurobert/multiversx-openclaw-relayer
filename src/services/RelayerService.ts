import { Transaction, Address, TransactionComputer, SmartContractQuery, ContractFunction, AddressValue } from "@multiversx/sdk-core";
import { UserVerifier, UserSigner, UserPublicKey } from "@multiversx/sdk-wallet";
import { QuotaManager } from "./QuotaManager";
import { ChallengeManager } from "./ChallengeManager";
import { RelayerAddressManager } from "./RelayerAddressManager";

export interface IRelayerNetworkProvider {
    queryContract(query: SmartContractQuery): Promise<any>;
    sendTransaction(tx: Transaction): Promise<string>;
    simulateTransaction(tx: Transaction): Promise<any>;
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
        registryAddresses: string[] = []
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
            console.error("Validation error:", error);
            return false;
        }
    }

    async isAuthorized(address: Address): Promise<boolean> {
        if (this.registryAddresses.length === 0) return true; // Fail open if misconfigured

        // 1. Check On-Chain Registry
        const identityRegistry = this.registryAddresses[0];
        try {
            const query = new SmartContractQuery({
                contract: new Address(identityRegistry),
                function: "get_agent_id",
                arguments: [new Address(address.toBech32()).getPublicKey()]
            });

            const queryResponse = await this.provider.queryContract(query);
            const returnData = queryResponse.returnData;
            const isRegistered = returnData && returnData.length > 0;

            if (isRegistered) return true;
        } catch (error) {
            console.error("Agent registration check failed:", error);
        }

        // 2. Fallback: Check if challenge was solved (for registration flow)
        // This is handled by the caller checking the challengeNonce usually, 
        // but if we want "isAuthorized" to mean "can relay", we need to know the context.
        return false;
    }

    async signAndRelay(tx: Transaction, challengeNonce?: string): Promise<string> {
        const sender = tx.sender;
        const receiver = tx.receiver.toBech32();
        const data = tx.data.toString();

        // 1. Quota Check
        if (!this.quotaManager.checkLimit(sender.toBech32())) {
            throw new Error("Quota exceeded for this agent");
        }

        // 2. Authorization Logic
        // Case A: Agent is already registered on-chain -> Always Authorized
        const isRegistered = await this.isAuthorized(sender);

        if (isRegistered) {
            // Authorized. Proceed.
        }
        // Case B: New Agent solving challenge -> Authorized ONLY for registration
        else {
            // If not registered, they MUST solve a challenge AND must be trying to register.
            if (!challengeNonce || !this.challengeManager.verifySolution(sender.toBech32(), challengeNonce)) {
                throw new Error("Unauthorized: Agent not registered. Solve challenge and register first.");
            }
        }

        // 3. Signature Validation
        if (!(await this.validateTransaction(tx))) {
            throw new Error("Invalid inner transaction signature");
        }

        // 4. Wrap & Sign
        const relayerSigner = this.relayerAddressManager.getSignerForUser(sender.toBech32());
        const relayerAddress = relayerSigner.getAddress();

        // VALIDATION: In Relayed V3, the sender MUST set the relayer address BEFORE signing.
        // We must not overwrite it, but we MUST verify it's correct for the sender's shard.
        if (!tx.relayer || tx.relayer.toBech32() !== relayerAddress.bech32()) {
            throw new Error(`Invalid relayer address. Expected ${relayerAddress.bech32()} for sender's shard.`);
        }

        if (tx.version < 2) {
            throw new Error("Invalid transaction version for Relayed V3. Expected version >= 2.");
        }

        const computer = new TransactionComputer();
        tx.relayerSignature = await relayerSigner.sign(computer.computeBytesForSigning(tx));

        // 5. Pre-broadcast Simulation (Crucial for Relayed V3)
        try {
            const simulationResult: any = await this.provider.simulateTransaction(tx);

            // Robust Parser: Handle both flattened (API) and nested (Proxy/Gateway) structures
            const statusFromStatus = simulationResult?.status?.status;
            const statusFromRaw = simulationResult?.raw?.status;
            const execution = simulationResult?.execution || simulationResult?.result?.execution;
            const resultStatus = statusFromStatus || statusFromRaw || execution?.result;

            if (resultStatus !== 'success') {
                const message = execution?.message || simulationResult?.error || 'Unknown error';
                throw new Error(`On-chain simulation failed: ${message}`);
            }
        } catch (simError: any) {
            console.error("Simulation failed:", simError);
            throw new Error(`Simulation error: ${simError.message}`);
        }

        // 6. Broadcast
        try {
            const hash = await this.provider.sendTransaction(tx);
            this.quotaManager.incrementUsage(sender.toBech32());
            return hash;
        } catch (error: any) {
            console.error("Broadcast failed:", error);
            throw new Error(`Broadcast failed: ${error.message}`);
        }
    }
}
