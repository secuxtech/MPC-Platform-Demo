# MPC REST Service

A minimal C++ REST wrapper for the Fireblocks MPC library (mpc-lib). This service provides simple HTTP endpoints that map directly to mpc-lib functions.

## Architecture

```
mpc-coordinator (TypeScript) ──► mpc-rest-service (C++) ──► mpc-lib (C++)
   [All logic here]              [Simple JSON wrapper]      [Crypto primitives]
```

## Build

### Prerequisites

- CMake 3.15+
- C++17 compiler
- OpenSSL
- nlohmann/json library
- mpc-lib (already built)

### Build Steps

```bash
# 1. Install prerequisites
sudo apt-get update
sudo apt-get install -y cmake g++ libssl-dev git

# 2. Ensure mpc-lib is built
cd ../mpc-lib/build
make
cd ../../mpc-rest-service

# 3. Build mpc-rest-service
mkdir build && cd build
cmake ..
make
```

## Usage

### Start Service

```bash
# Player 1 on port 8001
./mpc_rest_service 8001 1

# Player 2 on port 8002
./mpc_rest_service 8002 2
```

### Test Health Check

```bash
curl http://localhost:8001/health
```

## API Endpoints

### Setup APIs (5 endpoints)

1. **POST /generate_setup_commitments**
   - Generate initial setup commitments
   - Input: `{keyId, tenantId, algorithm, playerIds, threshold}`
   - Output: `{commitment}`

2. **POST /store_setup_commitments**
   - Store commitments from all players
   - Input: `{keyId, commitments: [{playerId, commitment}]}`
   - Output: `{ack, seed, share, paillierPublicKey, ringPedersenPublicKey}`

3. **POST /generate_setup_proofs**
   - Generate zero-knowledge proofs
   - Input: `{keyId, decommitments: [{playerId, ...}]}`
   - Output: `{schnorr_s, paillierBlumZkp, ringPedersenParamZkp}`

4. **POST /verify_setup_proofs**
   - Verify proofs from all players
   - Input: `{keyId, proofs: [{playerId, ...}]}`
   - Output: `{paillierLargeFactorProofs: [{playerId, proof}]}`

5. **POST /create_secret**
   - Finalize key generation
   - Input: `{keyId, paillierLargeFactorProofs: [{fromPlayerId, proofs: [{playerId, proof}]}]}`
   - Output: `{publicKey, algorithm}`

### Signing APIs (5 endpoints)

6. **POST /start_signing**
   - Start signing process
   - Input: `{keyId, txid, algorithm, chaincode, blocks, metadata, players, playerIds}`
   - Output: `{mtaRequests: [...]}`

7. **POST /mta_response**
   - Respond to MTA requests
   - Input: `{txid, requests: [{playerId, mtaRequests: [...]}]}`
   - Output: `{flags, responses: [...]}`

8. **POST /mta_verify**
   - Verify MTA responses
   - Input: `{txid, mtaResponses: [{playerId, responses: [...]}]}`
   - Output: `{flags, deltas: [...]}`

9. **POST /get_si**
   - Calculate signature share (si)
   - Input: `{txid, deltas: [{playerId, deltas: [...]}]}`
   - Output: `{flags, sis: [...]}`

10. **POST /get_signature**
    - Combine shares into final signature
    - Input: `{txid, s: [{playerId, sis: [...]}]}`
    - Output: `{flags, signatures: [{r, s, v}]}`

## File Structure

```
mpc-rest-service/
├── main.cpp                   # HTTP server (150 lines)
├── mpc_wrapper.h              # Wrapper declarations
├── mpc_wrapper.cpp            # Wrapper implementations (200 lines)
├── json_utils.h               # JSON utilities
├── json_utils.cpp             # JSON utilities (50 lines)
├── platform_service.h         # Platform service interface
├── platform_service.cpp       # Platform service impl (50 lines)
├── persistency.h              # Persistency interface
├── persistency.cpp            # Persistency impl (50 lines)
├── CMakeLists.txt             # Build configuration
└── README.md                  # This file
```

## Example Usage with curl

### Setup Phase

```bash
# Step 1: Generate commitments (on both players)
curl -X POST http://localhost:8001/generate_setup_commitments \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "test-key",
    "tenantId": "tenant-1",
    "algorithm": "ECDSA_SECP256K1",
    "playerIds": [1, 2],
    "threshold": 2
  }'

# Step 2-5: Continue with other setup endpoints...
# (See mpc-coordinator for full orchestration)
```

## Integration with mpc-coordinator

The mpc-coordinator (TypeScript) handles all orchestration:

```typescript
// Example: Coordinate setup across players
const player1 = axios.create({ baseURL: 'http://localhost:8001' });
const player2 = axios.create({ baseURL: 'http://localhost:8002' });

// Phase 1: Generate commitments from both players
const [comm1, comm2] = await Promise.all([
  player1.post('/generate_setup_commitments', params),
  player2.post('/generate_setup_commitments', params)
]);

// Phase 2: Store commitments on both players
await Promise.all([
  player1.post('/store_setup_commitments', { keyId, commitments: [comm1, comm2] }),
  player2.post('/store_setup_commitments', { keyId, commitments: [comm1, comm2] })
]);

// Continue with phases 3-5...
```

## Important Limitations

### CMP Protocol: n-of-n Only

The CMP protocol **only supports n-of-n**, not threshold (t-of-n):

- ✅ 2-of-2: Supported
- ✅ 3-of-3: Supported
- ❌ 2-of-3: NOT supported
- ❌ 3-of-5: NOT supported


## Troubleshooting

### Build Issues

If you encounter build issues:

1. Ensure mpc-lib is built: `cd mpc-lib/build && make`
2. Check OpenSSL is installed: `openssl version`
3. Install nlohmann/json: `sudo apt-get install nlohmann-json3-dev`
