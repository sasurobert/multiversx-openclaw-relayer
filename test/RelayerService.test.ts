import { describe, it, expect, beforeEach, vi } from "vitest";
import { RelayerService } from "../src/services/RelayerService";
import { Transaction, Address, TransactionComputer } from "@multiversx/sdk-core";
import { UserSigner, Mnemonic } from "@multiversx/sdk-wallet";
import { ProxyNetworkProvider } from "@multiversx/sdk-network-providers";
import { QuotaManager } from "../src/services/QuotaManager";
import { ChallengeManager } from "../src/services/ChallengeManager";
import { RelayerAddressManager } from "../src/services/RelayerAddressManager";

describe("RelayerService", () => {
    let relayer: RelayerService;
    let quotaManager: QuotaManager;
    let challengeManager: ChallengeManager;
    let mockProvider: ProxyNetworkProvider;
    let mockRelayerAddressManager: RelayerAddressManager; // Mock
    let relayerSigner: UserSigner;
    const REGISTRY_ADDR = "erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu";

    beforeEach(() => {
        mockProvider = {
            sendTransaction: async (tx: any) => "mock-tx-hash",
            simulateTransaction: vi.fn().mockResolvedValue({ execution: { result: "success" } }),
            queryContract: vi.fn().mockResolvedValue({ returnData: ["base64EncodedData"] }),
            doPostGeneric: vi.fn().mockResolvedValue({ data: { data: { returnData: ["base64EncodedData"] } } })
        } as unknown as ProxyNetworkProvider;

        const mnemonic = Mnemonic.generate();
        relayerSigner = new UserSigner(mnemonic.deriveKey(0));

        // Mock RelayerAddressManager to return the single signer we created
        mockRelayerAddressManager = {
            getRelayerAddressForUser: vi.fn().mockReturnValue(relayerSigner.getAddress().bech32()),
            getSignerForUser: vi.fn().mockReturnValue(relayerSigner),
            loadWallets: vi.fn(),
            getShard: vi.fn().mockReturnValue(1)
        } as unknown as RelayerAddressManager;

        quotaManager = new QuotaManager(":memory:", 10);
        challengeManager = new ChallengeManager(60, 4); // Low difficulty for tests (4 bits)

        relayer = new RelayerService(mockProvider, mockRelayerAddressManager, quotaManager, challengeManager, [REGISTRY_ADDR]);
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
        tx.signature = Uint8Array.from(signature);

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
            relayer: Address.newFromBech32(relayerSigner.getAddress().bech32()),
            version: 2,
        });
        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = Uint8Array.from(signature);

        // Mock being registered
        vi.spyOn(relayer, 'isRegisteredAgent').mockResolvedValue(true);

        await expect(relayer.signAndRelay(tx)).resolves.toBe("mock-tx-hash");
        expect(mockRelayerAddressManager.getSignerForUser).toHaveBeenCalledWith(sender.toBech32());
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
            relayer: Address.newFromBech32(relayerSigner.getAddress().bech32()),
            version: 2,
            data: Uint8Array.from(Buffer.from("register_agent@6e616d65@68747470733a2f2f6578616d706c652e636f6d@7075626b6579")) // name@uri@pk
        });
        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = Uint8Array.from(signature);

        // Re-inject a valid challenge for verification
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
            relayer: Address.newFromBech32(relayerSigner.getAddress().bech32()),
            version: 2,
        });
        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = Uint8Array.from(signature);

        await expect(relayer.signAndRelay(tx)).rejects.toThrow("Quota exceeded for this agent");
    });
});
