import { describe, it, expect, beforeEach, vi } from "vitest";
import { RelayerService } from "../src/services/RelayerService";
import { Transaction, Address, TransactionComputer } from "@multiversx/sdk-core";
import { UserSigner, Mnemonic, UserVerifier, UserPublicKey } from "@multiversx/sdk-wallet";
import { ProxyNetworkProvider } from "@multiversx/sdk-network-providers";
import { QuotaManager } from "../src/services/QuotaManager";
import { ChallengeManager } from "../src/services/ChallengeManager";

describe("RelayerService", () => {
    let relayer: RelayerService;
    let quotaManager: QuotaManager;
    let challengeManager: ChallengeManager;
    let mockProvider: ProxyNetworkProvider;
    let relayerSigner: UserSigner;
    const REGISTRY_ADDR = "erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu";

    beforeEach(() => {
        mockProvider = {
            sendTransaction: async (tx: any) => "mock-tx-hash",
            queryContract: vi.fn().mockResolvedValue({ returnData: ["base64EncodedData"] }),
            doPostGeneric: vi.fn().mockResolvedValue({ data: { data: { returnData: ["base64EncodedData"] } } })
        } as unknown as ProxyNetworkProvider;

        const mnemonic = Mnemonic.generate();
        relayerSigner = new UserSigner(mnemonic.deriveKey(0));
        quotaManager = new QuotaManager(":memory:", 10);
        challengeManager = new ChallengeManager(60, 4); // Low difficulty for tests (4 bits)

        relayer = new RelayerService(mockProvider, relayerSigner, quotaManager, challengeManager, [REGISTRY_ADDR]);
    });

    it("should validate a correct transaction", async () => {
        const mnemonic = Mnemonic.generate();
        const signer = new UserSigner(mnemonic.deriveKey(0));
        const sender = Address.newFromBech32(signer.getAddress().bech32());

        const tx = new Transaction({
            nonce: 1n,
            value: 0n,
            receiver: sender,
            sender: sender,
            gasLimit: 50000n,
            chainID: "D",
            version: 1,
        });

        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = signature;

        await expect(relayer.validateTransaction(tx)).resolves.toBe(true);
    });

    it("should check registration status correctly", async () => {
        const sender = Address.newFromBech32("erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu");
        await expect(relayer.isRegisteredAgent(sender)).resolves.toBe(true);
    });

    it("should sign and relay a transaction for registered agent", async () => {
        const mnemonic = Mnemonic.generate();
        const signer = new UserSigner(mnemonic.deriveKey(0));
        const sender = Address.newFromBech32(signer.getAddress().bech32());

        const tx = new Transaction({
            nonce: 1n,
            value: 0n,
            receiver: sender,
            sender: sender,
            gasLimit: 50000n,
            chainID: "D",
            version: 1,
        });
        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = signature;

        // Mock being registered
        vi.spyOn(relayer, 'isRegisteredAgent').mockResolvedValue(true);

        await expect(relayer.signAndRelay(tx)).resolves.toBe("mock-tx-hash");
    });

    it("should permit registration with a valid challenge solution", async () => {
        const mnemonic = Mnemonic.generate();
        const signer = new UserSigner(mnemonic.deriveKey(0));
        const sender = Address.newFromBech32(signer.getAddress().bech32());

        const challenge = challengeManager.getChallenge(sender.toBech32());

        // Brute force solve low difficulty (4 bits) challenge for test
        let nonce = 0;
        let solvedNonce = "";
        while (nonce < 1000) {
            if (challengeManager.verifySolution(sender.toBech32(), nonce.toString())) {
                solvedNonce = nonce.toString();
                // Re-add to challenge manager because verifySolution deletes it
                challengeManager.getChallenge(sender.toBech32());
                // Set the specific salt and difficulty from the original for the relayer's internal manager
                // Actually easier to just mock verifySolution or use the real manager if we can find a nonce.
                break;
            }
            nonce++;
        }

        const tx = new Transaction({
            nonce: 1n,
            value: 0n,
            receiver: Address.newFromBech32(REGISTRY_ADDR),
            sender: sender,
            gasLimit: 50000n,
            chainID: "D",
            version: 1,
            data: Buffer.from("register_agent@6e616d65@68747470733a2f2f6578616d706c652e636f6d@7075626b6579") // name@uri@pk
        });
        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = signature;

        // Re-inject a valid challenge for verification
        // Since we are using the real ChallengeManager, we need a real solution.
        // Let's just mock verification to avoid timing issues in tests.
        vi.spyOn(challengeManager, 'verifySolution').mockReturnValue(true);

        await expect(relayer.signAndRelay(tx, "valid-nonce")).resolves.toBe("mock-tx-hash");
    });

    it("should reject transaction when quota exceeded", async () => {
        const mnemonic = Mnemonic.generate();
        const signer = new UserSigner(mnemonic.deriveKey(0));
        const sender = Address.newFromBech32(signer.getAddress().bech32());
        const senderBech32 = sender.toBech32();

        for (let i = 0; i < 10; i++) {
            quotaManager.incrementUsage(senderBech32);
        }

        const tx = new Transaction({
            nonce: 1n,
            value: 0n,
            receiver: sender,
            sender: sender,
            gasLimit: 50000n,
            chainID: "D",
            version: 1,
        });
        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = signature;

        await expect(relayer.signAndRelay(tx)).rejects.toThrow("Quota exceeded for this agent");
    });
});
