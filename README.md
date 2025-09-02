<h1 align="center"> Openfort EIP-7702 Smart Accounts </h1>

<p align="center">
  <img src="./docs/Logo_black_primary_no_bg.png" alt="Openfort" style="width: 300px;" />
</p>

> 🚧 **Work In Progress**
> 
> This repository is under active development.  
> Contracts are **unaudited**, and the codebase may have **breaking changes** without notice.

**All-in-one EIP-7702 powered smart accounts with session key support**
<br></br>

<p align="center">
  <a href="https://github.com/openfort/openfort-7702-account/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"></a>
  <img src="https://img.shields.io/badge/solidity-0.8.29-blue" alt="Solidity 0.8.29">
  <a href="https://eips.ethereum.org/EIPS/eip-7702"><img src="https://img.shields.io/badge/tech-EIP7702-red" alt="EIP 7702">
  <img src="https://img.shields.io/badge/status-unaudited-orange" alt="Unaudited">
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#docs--deep-dives">Docs</a> •
  <a href="#getting-started">Quickstart</a> •
  <a href="#standards--compatibility">Standards</a> •
  <a href="#security--audits">Security</a>
</p>

---

## Overview

Smart wallets have made great strides in improving user experience, but still face challenges with key management, account recovery, and cross-application session management. Openfort's EIP-7702 implementations aim to solve these problems with a comprehensive smart account solution that puts users in control.

We believe smart accounts should provide an excellent experience throughout a user's journey:

- **Effortless Onboarding**: Use WebAuthn and Passkeys with no deployment transaction required  
- **Flexible Authentication**: Multiple authentication methods including EOA and WebAuthn/Passkeys  
- **Fine-grained Access Control**: Keys with customizable permissions and spending limits  
- **Secure Transactions**: Built-in security features including whitelisting, function filtering, and time-based controls  
- **Seamless Experience**: Full compatibility with ERC-4337 account abstraction standard  
- **Gas Sponsorship**: Allow applications to pay for user transactions through session keys  
- **No Vendor Lock-in**: Built on EIP-7702 and ERC-4337 standards for maximum interoperability  
- **🟢 Live Demo**: [https://7702.openfort.xyz](https://7702.openfort.xyz)

---

## Features

- [x] **Zero Deployment Cost**: Create accounts without any deployment transaction via EIP-7702  
- [x] **WebAuthn Support**: Use hardware security keys and passkeys for authentication  
- [x] **P-256 / P-256 NoExtractable Support**: Validate WebCrypto non-extractable P-256 keys with prehashed digest flow  
- [x] **Session Keys**: Temporary keys with custom permissions and expiration  
- [x] **Contract Whitelisting**: Restrict which contracts session keys can access  
- [x] **Function Filtering**: Define which function selectors can be called  
- [x] **Time-Based Controls**: Define activation and expiration for keys  
- [x] **Spending Limits**: ETH and token spend caps per session key  
- [x] **Transaction Counting**: Restrict number of uses per session key  
- [x] **Batch Transactions**: Execute multiple calls in one operation  
- [x] **ERC-4337 Support**: Works with bundlers and EntryPoint  
- [x] **Gas Sponsorship**: Dapps or relayers can pay for user ops  
- [x] **Enhanced Recovery Options**: Social recovery relies on guardians (EOA/WebAuthn)
- [x] **ERC-7821: Minimal Batch Executor Interface**: A minimal batch executor interface for delegations
- [x] **Gas Policy** — per-session gas/cost/tx budgets
- [ ] **Multi-chain Support**: Coming soon  

---

## Contract Architecture

### Core Contracts

- **`BaseOPF7702.sol`**  
  Abstract base account logic supporting validation, replay protection, and signature scheme resolution (EOA, WebAuthn, P-256). Implements ERC-4337’s `IAccount` interface and handles EIP-7702 storage layout.

- **`Execution.sol`**  
  Stateless transaction executor contract with single and batch transaction support. Exposes `execute()` and `executeBatch()` with event emission and limit checks.

- **`KeysManager.sol`**  
  Handles key registration, expiration, permissions, function whitelisting, and spending enforcement. Implements all session key logic and supports various key types via `KeyType`.

- **`OPF7702.sol`**  
  Main smart account contract that combines execution and key management. Fully implements the Openfort EIP-7702 smart account and ERC-4337 compatibility.
  
- **`OPF7702Recoverable.sol`**
Extension of the main smart account that adds advanced social recovery capabilities. Enables guardian-based recovery flows, lock/unlock mechanisms and guardian proposal/revocation lifecycle management with full event traceability.

---

## Supported Key Types

| Type | Typical Source | Notes |
|------|----------------|-------|
| `EOA` | Wallets (secp256k1) | 64/65-byte ECDSA |
| `WEBAUTHN` | Passkeys/YubiKey (P-256) | WebAuthn assertion payload |
| `P256` | P-256 extractable | Standard ECDSA over P-256 |
| `P256NONKEY` | Non-extractable WebCrypto | Pre-SHA-256 digest path |

---

## Standards & Compatibility

| Standard | What we implement | Where |
|---------|--------------------|-------|
| **EIP-7702** | Delegation / authority & upgrade hooks | `OPFMain`, `BaseOPF7702` |
| **ERC-4337** | `IAccount` validate flow | `BaseOPF7702`, `OPF7702` |
| **EIP-712** | Typed data for init/recovery | `OPF7702Recoverable` |
| **ERC-1271** | On-chain signature validation | `OPF7702` |
| **ERC-7821** | Minimal batch executor modes | `Execution` |
| **ERC-7201** | Namespaced storage layout | `ERC7201` util |

---

## Getting Started

### Installation

```bash
# Clone the repo
git clone https://github.com/openfort/openfort-7702-account.git
cd openfort-7702-account

# Install dependencies
forge install

# Run default tests
forge test

### Quick Start

#### Initialize an Account


// Create a new account with an owner
function initialize(
    Key calldata _key,
    KeyReg calldata _keyData,
    Key calldata _sessionKey,
    KeyReg calldata _sessionKeyData,
    bytes memory _signature,
    bytes32 _initialGuardian
);
```

#### Register a Key

```solidity
// Create a WebAuthn key structure
PubKey memory pubKey = PubKey({
    x: 0x..., // X coordinate from credential
    y: 0x...  // Y coordinate from credential
});

Key memory _key = Key({
    pubKey: pubKey,
    eoaAddress: address(0),
    keyType: KeyType.WEBAUTHN
});

ISpendLimit.SpendTokenInfo memory spendInfo =
    ISpendLimit.SpendTokenInfo({token: TOKEN, limit: 0});

KeyReg memory keyData = KeyReg({
        validUntil: validUntil,
        validAfter: 0,
        limit: limit,
        whitelisting: true,
        contractAddress: ETH_RECIVE,
        spendTokenInfo: spendInfo,
        allowedSelectors: _allowedSelectors(),
        ethLimit: ETH_LIMIT
    });

// Register the session key
account.registerKey(Key calldata _key, KeyReg calldata _keyData);
```

#### Execute Transactions

```solidity
// Single transaction
// Batch transactions
account.execute(mode, executionData);
```

## Technical Details

### Storage Layout

The contracts use a fixed storage layout starting at a specific slot:

```solidity
keccak256(abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)) & ~bytes32(uint256(0xff)) == 0xeddd36aac8c71936fe1d5edb073ff947aa7c1b6174e87c15677c96ab9ad95400 == 107588995614188179791452663824698570634674667931787294340862201729294267929600
```

This enables deterministic storage access across different addresses, essential for EIP-7702.

### Key Implementation

A *key* is a short-lived externally-owned account or WebAuthn credential authorized to execute a restricted subset of calls without holding any ETH. Keys enable powerful use cases like:

- Game developers sponsoring player transactions
- Temporary account access for services
- Hardware security key authentication
- Scheduled and recurring transactions

### ERC-4337 Integration

The contract implements the `IAccount` interface and can receive and validate UserOperations from ERC-4337 bundlers. The validation logic supports both owner signatures and session key signatures.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For security inquiries, please contact: security@openfort.xyz