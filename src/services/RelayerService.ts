import { Transaction, Address, TransactionComputer } from "@multiversx/sdk-core";
import { UserVerifier, UserSigner, UserPublicKey } from "@multiversx/sdk-wallet";
import { ProxyNetworkProvider } from "@multiversx/sdk-network-providers";
import { QuotaManager } from "./QuotaManager";
import { ChallengeManager } from "./ChallengeManager";

export class RelayerService {
    private provider: ProxyNetworkProvider;
    private relayerSigner: UserSigner;
    private quotaManager: QuotaManager;
    private challengeManager: ChallengeManager;
    private registryAddresses: string[];

    constructor(
        provider: ProxyNetworkProvider,
        relayerSigner: UserSigner,
        quotaManager: QuotaManager,
        challengeManager: ChallengeManager,
        registryAddresses: string[] = []
    ) {
        this.provider = provider;
        this.relayerSigner = relayerSigner;
        this.quotaManager = quotaManager;
        this.challengeManager = challengeManager;
        this.registryAddresses = registryAddresses;
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
        const relayerAddress = this.relayerSigner.getAddress();
        tx.relayer = Address.newFromBech32(relayerAddress.bech32());
        tx.version = 2; // Relayed V2

        const computer = new TransactionComputer();
        tx.relayerSignature = await this.relayerSigner.sign(computer.computeBytesForSigning(tx));

        // 5. Broadcast
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
