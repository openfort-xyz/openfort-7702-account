<h1 align="center"> Openfort EIP-7702 Smart Accounts </h1>

<p align="center">
  <img src="docs/Logo_black_primary_no_bg.png" alt="Openfort" style="width: 300px;" />
</p>

> 🚧 **Work In Progress**
> 
> This repository is under active development.  
> Contracts are **unaudited**, and the codebase may have **breaking changes** without notice.

**All-in-one EIP-7702 powered smart accounts with session key support**

---

## Overview

Smart wallets have made great strides in improving user experience, but still face challenges with key management, account recovery, and cross-application session management. Openfort's EIP-7702 implementations aim to solve these problems with a comprehensive smart account solution that puts users in control.

We believe smart accounts should provide an excellent experience throughout a user's journey:

- **Effortless Onboarding**: Use WebAuthn and Passkeys with no deployment transaction required  
- **Flexible Authentication**: Multiple authentication methods including EOA and WebAuthn/Passkeys  
- **Fine-grained Access Control**: Session keys with customizable permissions and spending limits  
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
- [ ] **Multi-chain Support**: Coming soon  
- [ ] **Enhanced Recovery Options**: Coming soon

---

## Contract Architecture

### Core Contracts

- **`BaseOPF7702.sol`**  
  Abstract base account logic supporting validation, replay protection, and signature scheme resolution (EOA, WebAuthn, P-256). Implements ERC-4337’s `IAccount` interface and handles EIP-7702 storage layout.

- **`Execution.sol`**  
  Stateless transaction executor contract with single and batch transaction support. Exposes `execute()` and `executeBatch()` with event emission and limit checks.

- **`KeysManager.sol`**  
  Handles session key registration, expiration, permissions, function whitelisting, and spending enforcement. Implements all session key logic and supports various key types via `KeyType`.

- **`OPF7702.sol`**  
  Main smart account contract that combines execution and key management. Fully implements the Openfort EIP-7702 smart account and ERC-4337 compatibility.

### Supporting Interfaces

- **`ISessionKey.sol`** – Session key storage/logic interface  
- **`IWebAuthnVerifier.sol`** – Interface for WebAuthn verification  
- **`IValidation.sol`** – Shared structs and validation types

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

```solidity
// Create a new account with an owner
function initialize(
    Key calldata _key,
    SpendTokenInfo calldata _spendTokenInfo,
    bytes4[] calldata _allowedSelectors,
    bytes32 _hash,
    bytes memory _signature,
    uint256 _validUntil,
    uint256 _nonce
);
```

#### Register a Session Key

```solidity
// Create a WebAuthn key structure
PubKey memory pubKey = PubKey({
    x: 0x..., // X coordinate from credential
    y: 0x...  // Y coordinate from credential
});

Key memory key = Key({
    pubKey: pubKey,
    eoaAddress: address(0),
    keyType: KeyType.WEBAUTHN
});

// Register the session key
account.registerSessionKey(
    key,
    uint48(block.timestamp + 1 days),  // Valid until tomorrow
    uint48(block.timestamp),           // Valid from now
    10,                                // Allow 10 transactions
    true,                              // Enable whitelisting
    address(0x5678...),                // Allow this contract
    tokenInfo,                         // Token spending limits
    selectors,                         // Allowed functions
    1 ether                            // ETH spending limit
);
```

#### Execute Transactions

```solidity
// Single transaction
account.execute(targetAddress, value, calldata);

// Batch transactions
account.execute(transactions);
```

## Technical Details

### Storage Layout

The contracts use a fixed storage layout starting at a specific slot:

```solidity
keccak256("openfort.baseAccount.7702.v1") = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368 == 57943590311362240630886240343495690972153947532773266946162183175043753177960
```

This enables deterministic storage access across different addresses, essential for EIP-7702.

### Session Key Implementation

A *session key* is a short-lived externally-owned account or WebAuthn credential authorized to execute a restricted subset of calls without holding any ETH. Session keys enable powerful use cases like:

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