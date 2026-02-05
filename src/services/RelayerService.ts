import { Transaction, Address, TransactionComputer } from "@multiversx/sdk-core";
import { UserVerifier, UserSigner, UserPublicKey } from "@multiversx/sdk-wallet";
import { ProxyNetworkProvider } from "@multiversx/sdk-network-providers";
import { QuotaManager } from "./QuotaManager";
import { ChallengeManager } from "./ChallengeManager";
import { RelayerAddressManager } from "./RelayerAddressManager";

export class RelayerService {
    private provider: ProxyNetworkProvider;
    private relayerAddressManager: RelayerAddressManager;
    private quotaManager: QuotaManager;
    private challengeManager: ChallengeManager;
    private registryAddresses: string[];

    constructor(
        provider: ProxyNetworkProvider,
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

    async isRegisteredAgent(address: Address): Promise<boolean> {
        if (this.registryAddresses.length === 0) return true; // Fail open if misconfigured

        const identityRegistry = this.registryAddresses[0]; // Assume first is Identity
        try {
            // Use the doPostGeneric pattern for VM queries
            const vmQueryUrl = "/vm-values/query";
            const queryPayload = {
                scAddress: identityRegistry,
                funcName: "get_agent_id",
                args: [Buffer.from(address.getPublicKey()).toString("hex")]
            };

            const queryResponse = await (this.provider as any).doPostGeneric(vmQueryUrl, queryPayload);
            return queryResponse?.data?.data?.returnData && queryResponse.data.data.returnData.length > 0;
        } catch (error) {
            console.error("Agent registration check failed:", error);
            return false;
        }
    }

    async signAndRelay(tx: Transaction, challengeNonce?: string): Promise<string> {
        const sender = tx.sender;
        const receiver = tx.receiver.toBech32();
        const data = tx.data.toString();

        // 1. Quota Check
        if (!this.quotaManager.checkLimit(sender.toBech32())) {
            throw new Error("Quota exceeded for this agent");
        }

        // 2. Security Whitelist & Logic
        const isTargetingRegistry = this.registryAddresses.includes(receiver);
        const isRegistration = data.startsWith("register_agent");

        if (isRegistration) {
            // New bot: must solve challenge
            if (!challengeNonce || !this.challengeManager.verifySolution(sender.toBech32(), challengeNonce)) {
                throw new Error("Bot verification failed: Invalid challenge solution");
            }
        } else {
            // Existing bot: must be in Identity Registry
            if (isTargetingRegistry && !(await this.isRegisteredAgent(sender))) {
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
            const simulationResult = await this.provider.simulateTransaction(tx);
            if (simulationResult?.execution?.result !== 'success') {
                const msg = simulationResult?.execution?.message || 'Simulation failed';
                throw new Error(`On-chain simulation failed: ${msg}`);
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
