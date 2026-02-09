# MultiversX OpenClaw Relayer Service

A secure, high-performance general relayer service for OpenClaw agents on MultiversX. This service enables agents to submit transactions without holding EGLD for gas, using the Relayed V3 protocol.

## Features

- **🚀 Relayed V3 Support**: Automatically wraps and signs transactions for gasless execution.
- **🔒 Production Ready**: Built with Express, secure configuration management, and comprehensive testing.
- **🛡️ Security First**:
    - **Identity Verification**: Enforces MX-8004 Registry checks to ensure only authorized agents can relay.
    - **Quota Management**: Rate limiting per agent to prevent gas draining.
    - **Signature Validation**: Strict verification of inner transaction signatures.

## Quick Start

```bash
git clone https://github.com/sasurobert/multiversx-openclaw-relayer.git
cd multiversx-openclaw-relayer
chmod +x setup.sh && ./setup.sh
```

The setup script installs dependencies, creates a default `.env`, builds, and runs tests.

### Prerequisites

| Tool | Version | Required |
|------|---------|----------|
| Node.js | v18+ | Yes |
| npm | v9+ | Yes |
| `relayer.pem` | — | Yes (wallet with EGLD for gas) |

### Configuration

Create a `.env` file in the root directory:

```env
# Network Configuration
NETWORK_PROVIDER=https://devnet-gateway.multiversx.com
IDENTITY_REGISTRY_ADDRESS=erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu

# Relayer Wallet (Multi-Shard Support)
# To support multiple shards, provide a directory containing "shardX.pem" files.
RELAYER_WALLETS_DIR=./wallets/

# Legacy (Single Shard)
# RELAYER_PEM_PATH=./relayer.pem

# Security & Limits
QUOTA_LIMIT=10  # Max transactions per agent per 24h
DB_PATH=./relayer.db # For persistent quota tracking
PORT=3000
```

### Running the Service

**Development:**
```bash
npm run start
```

**Production:**
```bash
npm run build
node dist/index.js
```

## API Reference

### `POST /relay`
Submits a transaction to be relayed.

**Request Body:**
```json
{
  "nonce": 10,
  "value": "0",
  "receiver": "erd1...",
  "sender": "erd1...",
  "gasPrice": 1000000000,
  "gasLimit": 50000,
  "data": "base64...",
  "chainID": "D",
  "version": 1,
  "signature": "hex..."
}
```

**Response (200 OK):**
```json
{
  "txHash": "wt1..."
}
```

**Errors:**
- `400 Bad Request`: Invalid signature or payload.
- `429 Too Many Requests`: Agent quota exceeded.

### `GET /health`
Health check endpoint.

**Response:**
```json
{ "status": "ok" }
```

## Architecture

The service is composed of three layers:
1. **API Layer** (`src/api`): specific Express handlers.
2. **Service Layer** (`src/services`): `RelayerService` for logic and `QuotaManager` for limits.
3. **Core Layer** (`sdk-core`): MultiversX interactions.

## Security

This service implements **MX-8004** compliance checks. It verifies that the sender is a registered agent in the On-Chain Identity Registry before relaying any transaction.

## Testing

Run the full test suite (Unit + Integration):

```bash
npm test
```
