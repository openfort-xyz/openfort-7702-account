# <h1 align="center"> Openfort EIP-7702 Smart Accounts </h1>

<p style="background-color: black; display: inline-block; padding: 5px;">
  <img src="contracts/Logo_black_primary_no_bg.png" alt="Openfort" style="width: 300px;" />
</p>

> 🚧 **Work In Progress**
> 
> This repository is under active development.
> Contracts are **unaudited**, and the codebase may have **breaking changes** without notice.

**All-in-one EIP-7702 powered smart accounts with session key support**

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

## Features

* [x] **Zero Deployment Cost**: Create accounts without any deployment transaction via EIP-7702
* [x] **WebAuthn Support**: Use hardware security keys and passkeys for authentication
* [x] **Session Keys**: Create temporary keys with custom permissions and spending limits
* [x] **Contract Whitelisting**: Restrict which contracts a session key can interact with
* [x] **Function Filtering**: Limit which functions a session key can call
* [x] **Time-Based Controls**: Set expiration and activation times for session keys
* [x] **Spending Limits**: Set token and ETH spending caps for individual keys
* [x] **Transaction Counting**: Limit how many transactions a session key can execute
* [x] **Batch Transactions**: Execute multiple transactions in a single call
* [x] **ERC-4337 Support**: Full compatibility with account abstraction standard
* [x] **Gas Sponsorship**: Allow anyone to pay for transaction fees on behalf of users
* [ ] **Multi-chain Support**: Manage accounts across multiple blockchains (coming soon)
* [ ] **Enhanced Recovery Options**: Advanced account recovery mechanisms (coming soon)

## Contract Architecture

### Core Contracts

- `OpenfortBaseAccount7702V1.sol`: Main implementation using EIP-191 signatures with session key support
- `OpenfortBaseAccount7702V1_712.sol`: Enhanced implementation using EIP-712 typed data signatures
- `TokenCallbackHandler.sol`: Handles callbacks for various token standards

### Supporting Interfaces

- `ISessionKey.sol`: Defines structures and functions for session key management
- `IWebAuthnVerifier.sol`: Interface for WebAuthn signature verification
- `IValidation.sol`: Defines structures for signature validation

## Getting Started

### Installation

```bash
# Clone the repository
git clone https://github.com/openfort/openfort-7702-account.git
cd openfort-7702-account

# Install dependencies
forge install
forge test
```

### Quick Start

#### Initialize an Account

```solidity
// Create a new account with an owner
account.initialize(
    ownerAddress,
    block.timestamp + 1 hour, // Valid until
    userOpHash,
    signature,
    0 // Initial nonce
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
keccak256("openfort.baseAccount.7702.v1") = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
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