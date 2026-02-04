# MPC Platform Demo

A demonstration platform for Multi-Party Computation (MPC) with distributed key generation and threshold signatures, built on top of [Fireblocks MPC Library](https://github.com/fireblocks/mpc-lib).

## 🎯 Overview

This platform implements secure threshold cryptography using the CMP (Crypto Multi-Party) protocol, enabling distributed key generation and signing operations without any single party having access to the complete private key.

**Key Features:**
- ✅ 5-phase distributed key generation (Setup Phase)
- ✅ 4-round ECDSA threshold signing (Signing Phase)
- ✅ Support for n-of-n signatures (2-of-2, 3-of-3, 4-of-4, etc.)
- ✅ ECDSA support for SECP256K1 (Bitcoin, Ethereum)
- ✅ Secure key storage with SoftHSM (PKCS#11)
- ✅ PostgreSQL persistence for metadata
- ✅ RESTful API architecture
- ✅ TypeScript coordinator service
- ✅ Thin C++ wrapper around mpc-lib

## 📁 Project Structure

```
mpc-platform/
├── mpc-coordinator/          # TypeScript orchestration service
│   ├── src/
│   │   ├── api/              # REST API routes
│   │   │   ├── health.routes.ts
│   │   │   ├── setup.routes.ts
│   │   │   └── signing.routes.ts
│   │   ├── services/         # Business logic
│   │   │   ├── setup.service.ts       # 5-phase key generation
│   │   │   ├── ecdsa.service.ts       # 4-round signing
│   │   │   └── mpc-rest-client.ts     # Client for C++ service
│   │   ├── hsm/              # SoftHSM integration
│   │   │   └── softhsm.ts
│   │   ├── utils/            # Utilities
│   │   │   └── logger.ts
│   │   └── prisma/           # Database schema
│   │       └── schema.prisma
│   ├── examples/             # Usage examples
│   │   ├── bitcoin-example.ts
│   │   ├── ethereum-example.ts
│   │   └── rest-service-integration-test.ts
│   └── scripts/
│       └── init-softhsm.js
│
├── mpc-rest-service/         # C++ wrapper service
│   ├── main.cpp              # HTTP server
│   ├── mpc_wrapper.cpp       # Thin wrapper around mpc-lib
│   ├── platform_service.cpp  # Platform abstraction
│   ├── persistency.cpp       # In-memory storage
│   └── json_utils.cpp        # JSON serialization
│
├── mpc-lib/                  # Fireblocks MPC library (submodule)
│
├── docs/                     # Documentation
│   ├── MPC_PROTOCOL.md
│   ├── MPC_LIBRARY_MIGRATION_GUIDE.md
│   ├── NOTES.md
│   └── archives/             # Archived documentation
│
└── start-*.sh                # Shell scripts
```

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ and npm
- **C++ Compiler** (g++ 11+)
- **CMake** 3.20+
- **PostgreSQL** 13+
- **SoftHSM** 2.x

### 2. Build C++ Service

```bash
cd mpc-rest-service
mkdir build && cd build
cmake ..
make -j4
```

### 3. Setup Coordinator

```bash
cd mpc-coordinator
npm install

# Configure database
cp .env.example .env
# Edit .env with your database credentials

# Run migrations
npx prisma db push
```

### 4. Start Services
```bash
# Start all MPC players
sh start-all-players.sh

# Start MPC coordinator
sh start-coordinator.sh

# Run example scripts
sh start-examples.sh
```

### API Reference
- **Setup API** - `/api/setup/*` - Key generation endpoints
- **Signing API** - `/api/signing/*` - Signature generation endpoints
- **Health Check** - `/health` - Service status

## 🏗️ Architecture

### System Design

```mermaid
graph LR
    subgraph Coordinator["mpc-coordinator<br/>(Port 3000)"]
        subgraph API["REST API Layer"]
            SetupRoutes[Setup Routes<br/>/api/setup/*]
            SigningRoutes[Signing Routes<br/>/api/signing/*]
            Health[Health<br/>/health]
        end
        
        SetupService[Setup Service<br/>• 5-phase Setup<br/>• Key Generate]
        ECDSAService[ECDSA Service<br/>• 4-round Sign<br/>• Coordinator]
        
        MPCRestClient[MPCRestClient<br/>• HTTP Client<br/>• Player Manager]
        
        SoftHSM[SoftHSM<br/>PKCS#11<br/>• Key Store<br/>• Encrypt<br/>• Decrypt]
        PrismaORM[Prisma ORM<br/>Client<br/>• MpcKey<br/>• Session<br/>• Player]
        PostgreSQL[PostgreSQL<br/>DB<br/>• Keys<br/>• Sessions<br/>• Players]
        Logger[Logger<br/>Winston<br/>• Debug<br/>• Info<br/>• Error]
        
        SetupRoutes --> SetupService
        SigningRoutes --> ECDSAService
        SetupService --> MPCRestClient
        ECDSAService --> MPCRestClient
        
        MPCRestClient --> SoftHSM
        MPCRestClient --> PrismaORM
        PrismaORM --> PostgreSQL
        MPCRestClient --> Logger
    end
    
    subgraph Player1["Player 1 (Port 8001)"]
        Wrapper1[mpc_rest_serrvice]
        Lib1[mpc-lib]
        Wrapper1 --> Lib1
    end
    
    subgraph Player2["Player 2 (Port 8002)"]
        Wrapper2[mpc_rest_serrvice]
        Lib2[mpc-lib]
        Wrapper2 --> Lib2
    end
    
    subgraph Player3["Player 3 (Port 8003)"]
        Wrapper3[mpc_rest_serrvice]
        Lib3[mpc-lib]
        Wrapper3 --> Lib3
    end
    
    MPCRestClient -.->|HTTP| Wrapper1
    MPCRestClient -.->|HTTP| Wrapper2
    MPCRestClient -.->|HTTP| Wrapper3
    
    style Coordinator fill:#e1f5ff
    style API fill:#fff4e1
    style Player1 fill:#ffe1f5
    style Player2 fill:#ffe1f5
    style Player3 fill:#ffe1f5
```

### Key Components

1. **mpc-coordinator (TypeScript/Node.js)**
   - Orchestrates multi-party protocol
   - Manages database and HSM
   - Exposes RESTful API
   - Handles error recovery

2. **mpc-rest-service (C++)**
   - Thin wrapper around mpc-lib
   - One instance per player
   - Stateless HTTP endpoints
   - In-memory persistence

3. **mpc-lib (C++)**
   - Fireblocks cryptographic library
   - CMP protocol implementation
   - ECDSA and EdDSA support

### Protocol Flow

#### Setup Phase (5 rounds)
```
Round 1: generate_setup_commitments()  → commitment
Round 2: store_setup_commitments()     → decommitment
Round 3: generate_setup_proofs()       → zkp_proof
Round 4: verify_setup_proofs()         → verification_result
Round 5: create_secret()               → public_key + secret_share
```

#### Signing Phase (4 rounds)
```
Round 1: start_signing()     → mta_requests
Round 2: mta_response()      → mta_responses
Round 3: mta_verify()        → verification_result
Round 4: get_si()            → signature_share
Combine: get_signature()     → final_signature (r, s, v)
```

## 🔐 Security Features

### Key Storage
- **SoftHSM**: PKCS#11 HSM for secure key storage
- **Encryption**: All key shares encrypted at rest
- **Isolation**: Each player has separate HSM slot

### Network Security
- **localhost only**: Services communicate only on localhost
- **No key transmission**: Private keys never leave their respective services
- **Authentication**: Tenant-based access control

### Protocol Security
- **Zero-knowledge proofs**: Commitment scheme prevents cheating
- **Threshold security**: No single point of failure
- **MTA (Multiplicative-to-Additive)**: Secure multiplication protocol

## 🔧 Configuration

### Environment Variables

Create `mpc-coordinator/.env`:

```env
# Database
DATABASE_URL="postgresql://user:password@localhost:5432/mpc_db"

# Tenant
DEFAULT_TENANT_ID="secux-tenant-001"

# SoftHSM
SOFTHSM2_CONF="/path/to/softhsm2.conf"
PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
HSM_TOKEN_LABEL=MPC-Token
HSM_USER_PIN=1234
HSM_SO_PIN=5678

# API
PORT=3000
LOG_LEVEL="info"
```

### SoftHSM Configuration

See `scripts/init-softhsm.js` for automated setup.


## 📝 Examples

### Bitcoin Transaction Signing

```typescript
// Generate 3-of-3 key
const setupResponse = await axios.post('http://localhost:3000/api/setup/start', {
  keyId: 'btc-key-001',
  algorithm: 'ECDSA_SECP256K1',
  threshold: 3,
  totalPlayers: 3,
  playerIds: ['player1', 'player2', 'player3'],
});

// Sign Bitcoin transaction
const signResponse = await axios.post('http://localhost:3000/api/signing/ecdsa', {
  keyId: 'btc-key-001',
  txId: 'btc-tx-001',
  messageHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  derivationPath: "m/44'/0'/0'/0/0",
  playerIds: ['player1', 'player2', 'player3'],
  metadata: { blockchain: 'bitcoin', network: 'testnet' },
});

console.log('Signature:', signResponse.data.signature);
// { r: '0x...', s: '0x...', v: 27 }
```

### Ethereum Transaction Signing

```typescript
// Generate 3-of-3 key
const setupResponse = await axios.post('http://localhost:3000/api/setup/start', {
  keyId: 'eth-key-001',
  algorithm: 'ECDSA_SECP256K1',
  threshold: 3,
  totalPlayers: 3,
  playerIds: ['player1', 'player2', 'player3'],
});

// Derive Ethereum address
const publicKey = setupResponse.data.publicKey;
const address = deriveEthereumAddress(publicKey);

// Sign Ethereum transaction
const signResponse = await axios.post('http://localhost:3000/api/signing/ecdsa', {
  keyId: 'eth-key-001',
  txId: 'eth-tx-001',
  messageHash: '0x...',  // Keccak256 hash of transaction
  derivationPath: "m/44'/60'/0'/0/0",
  playerIds: ['player1', 'player2', 'player3'],
  metadata: { blockchain: 'ethereum', network: 'sepolia' },
});

console.log('Signature:', signResponse.data.signature);
```

## More Documentation
- [Fireblocks mpc-lib](mpc-lib/README.md)
- [MPC REST Service](mpc-rest-service/README.md)
