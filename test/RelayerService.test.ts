import { vi, describe, it, expect, beforeEach } from 'vitest';

const { mockController } = vi.hoisted(() => ({
    mockController: {
        query: vi.fn(),
    }
}));

vi.mock('@multiversx/sdk-core', async importOriginal => {
    const mod = await importOriginal<typeof import('@multiversx/sdk-core')>();
    return {
        ...mod,
        Abi: {
            create: vi.fn().mockReturnValue({}),
        },
        DevnetEntrypoint: vi.fn().mockImplementation(() => ({
            createSmartContractController: vi.fn().mockReturnValue(mockController),
        })),
        SmartContractController: vi.fn().mockReturnValue(mockController),
    };
});

import {
    RelayerService,
    IRelayerNetworkProvider,
} from '../src/services/RelayerService';
import {
    Transaction,
    Address,
    TransactionComputer,
    DevnetEntrypoint,
} from '@multiversx/sdk-core';
import { UserSigner, Mnemonic } from '@multiversx/sdk-wallet';
import { QuotaManager } from '../src/services/QuotaManager';
import { ChallengeManager } from '../src/services/ChallengeManager';
import { RelayerAddressManager } from '../src/services/RelayerAddressManager';

describe('RelayerService', () => {
    let relayer: RelayerService;
    let quotaManager: QuotaManager;
    let challengeManager: ChallengeManager;
    let mockProvider: IRelayerNetworkProvider;
    let mockRelayerAddressManager: RelayerAddressManager; // Mock
    let relayerSigner: UserSigner;
    const REGISTRY_ADDR =
        'erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu';

    beforeEach(() => {
        mockProvider = {
            sendTransaction: async (_tx: any) => 'mock-tx-hash',
            simulateTransaction: vi
                .fn()
                .mockResolvedValue({
                    execution: {
                        result: 'success',
                        gasConsumed: 50000n // realism: SDK returns BigInt for gas
                    }
                }),
            queryContract: vi
                .fn()
                .mockResolvedValue({
                    returnData: [Buffer.from('0000000000000001', 'hex').toString('base64')],
                    returnDataParts: [Buffer.from('0000000000000001', 'hex')]
                }),
        };

        const mnemonic = Mnemonic.generate();
        relayerSigner = new UserSigner(mnemonic.deriveKey(0));

        // Mock RelayerAddressManager to return the single signer we created
        mockRelayerAddressManager = {
            getRelayerAddressForUser: vi
                .fn()
                .mockReturnValue(relayerSigner.getAddress().bech32()),
            getSignerForUser: vi.fn().mockReturnValue(relayerSigner),
            loadWallets: vi.fn(),
            getShard: vi.fn().mockReturnValue(1),
        } as unknown as RelayerAddressManager;

        quotaManager = new QuotaManager(':memory:', 10);
        challengeManager = new ChallengeManager(60, 4); // Low difficulty for tests (4 bits)

        const mockEntrypoint = {
            createSmartContractController: vi.fn().mockReturnValue(mockController),
            simulateTransaction: mockProvider.simulateTransaction,
            sendTransaction: mockProvider.sendTransaction,
        } as unknown as DevnetEntrypoint;

        relayer = new RelayerService(
            mockProvider,
            mockRelayerAddressManager,
            quotaManager,
            challengeManager,
            [REGISTRY_ADDR],
            mockEntrypoint
        );
    });

    it('should validate a correct transaction', async () => {
        const mnemonic = Mnemonic.generate();
        const signer = new UserSigner(mnemonic.deriveKey(0));
        const sender = Address.newFromBech32(signer.getAddress().bech32());

        const tx = new Transaction({
            nonce: 1n,
            value: 0n,
            receiver: sender,
            sender: sender,
            gasLimit: 50000n,
            chainID: 'D',
            version: 1,
        });

        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = Uint8Array.from(signature);

        await expect(relayer.validateTransaction(tx)).resolves.toBe(true);
    });

    it('should check registration status correctly', async () => {
        const sender = Address.newFromBech32(
            'erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu',
        );
        mockController.query.mockResolvedValue([1n]);
        await expect(relayer.isAuthorized(sender)).resolves.toBe(true);
    });

    it('should reject when agent ID is 0', async () => {
        const sender = Address.newFromBech32(
            'erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu',
        );
        // Mock returning 0
        mockController.query.mockResolvedValue([0n]);
        await expect(relayer.isAuthorized(sender)).resolves.toBe(false);
    });

    it('should sign and relay a transaction for registered agent', async () => {
        const mnemonic = Mnemonic.generate();
        const signer = new UserSigner(mnemonic.deriveKey(0));
        const sender = Address.newFromBech32(signer.getAddress().bech32());

        const tx = new Transaction({
            nonce: 1n,
            value: 0n,
            receiver: sender,
            sender: sender,
            gasLimit: 50000n,
            chainID: 'D',
            relayer: Address.newFromBech32(relayerSigner.getAddress().bech32()),
            version: 2,
        });
        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = Uint8Array.from(signature);

        // Mock being registered
        vi.spyOn(relayer, 'isAuthorized').mockResolvedValue(true);

        await expect(relayer.signAndRelay(tx)).resolves.toBe('mock-tx-hash');
        expect(mockRelayerAddressManager.getSignerForUser).toHaveBeenCalledWith(
            sender.toBech32(),
        );
    });

    it('should permit registration with a valid challenge solution', async () => {
        const mnemonic = Mnemonic.generate();
        const signer = new UserSigner(mnemonic.deriveKey(0));
        const sender = Address.newFromBech32(signer.getAddress().bech32());

        challengeManager.getChallenge(sender.toBech32());
        // Brute force solve low difficulty (4 bits) challenge for test
        let nonce = 0;
        while (nonce < 1000) {
            if (
                challengeManager.verifySolution(sender.toBech32(), nonce.toString())
            ) {
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
            chainID: 'D',
            relayer: Address.newFromBech32(relayerSigner.getAddress().bech32()),
            version: 2,
            data: Uint8Array.from(
                Buffer.from(
                    'register_agent@6e616d65@68747470733a2f2f6578616d706c652e636f6d@7075626b6579',
                ),
            ), // name@uri@pk
        });
        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = Uint8Array.from(signature);

        // Re-inject a valid challenge for verification
        vi.spyOn(challengeManager, 'verifySolution').mockReturnValue(true);

        await expect(relayer.signAndRelay(tx, 'valid-nonce')).resolves.toBe(
            'mock-tx-hash',
        );
    });

    it('should reject transaction when simulation fails', async () => {
        const mnemonic = Mnemonic.generate();
        const signer = new UserSigner(mnemonic.deriveKey(0));
        const sender = Address.newFromBech32(signer.getAddress().bech32());

        const tx = new Transaction({
            nonce: 1n,
            value: 0n,
            receiver: sender,
            sender: sender,
            gasLimit: 50000n,
            chainID: 'D',
            relayer: Address.newFromBech32(relayerSigner.getAddress().bech32()),
            version: 2,
        });
        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = Uint8Array.from(signature);

        // Mock being registered
        vi.spyOn(relayer, 'isAuthorized').mockResolvedValue(true);
        // Mock simulation failure - DO NOT RE-ASSIGN mockProvider.simulateTransaction
        (mockProvider.simulateTransaction as any).mockResolvedValue({
            execution: {
                result: 'fail',
                message: 'insufficient funds',
                gasConsumed: 100n
            }
        });

        await expect(relayer.signAndRelay(tx)).rejects.toThrow(
            'On-chain simulation failed: insufficient funds',
        );
    });

    it('should reject transaction when quota exceeded', async () => {
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
            chainID: 'D',
            relayer: Address.newFromBech32(relayerSigner.getAddress().bech32()),
            version: 2,
        });
        const computer = new TransactionComputer();
        const signature = await signer.sign(computer.computeBytesForSigning(tx));
        tx.signature = Uint8Array.from(signature);

        await expect(relayer.signAndRelay(tx)).rejects.toThrow(
            'Quota exceeded for this agent',
        );
    });
});
