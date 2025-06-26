# Openfort EIP-7702 Smart Contract Accounts

<p align="center">
  <img src="../contracts/Logo_black_primary_no_bg.png" alt="Openfort" style="width: 300px;" />
</p>

> 💡 Live Demo: [https://7702.openfort.xyz](https://7702.openfort.xyz)

This documentation covers the implementation of EIP-7702 compatible smart contract accounts by Openfort. These accounts enable account abstraction while leveraging the new capabilities introduced by EIP-7702 (Pectra Upgrade).

---

## Table of Contents

* [Overview](#overview)
* [Key Features](#key-features)
  * [EIP-7702 Implementation](#eip-7702-implementation)
  * [Session Keys](#session-keys)
  * [WebAuthn & P-256 Support](#webauthn--p-256-support)
  * [Spending Controls](#spending-controls)
  * [Security Features](#security-features)
* [Architecture](#architecture)
  * [Core Components](#core-components)
  * [Storage](#storage)
  * [Key Types](#key-types)
  * [Session Key Structure](#session-key-structure)
  * [EIP-4337 / EIP-7702 Interplay](#eip-4337--eip-7702-interplay)
  * [Guardian Lifecycle](#guardian-lifecycle)
  * [Social Recovery](#social-recovery)
* [Usage Guide](#usage-guide)
  * [Account Initialization](#account-initialization)
  * [Session Key Management](#session-key-management)
  * [Transaction Execution](#transaction-execution)
* [Security Considerations](#security-considerations)
* [Implementation Details](#implementation-details)
  * [Signature Verification](#signature-verification)
  * [Storage Clearing](#storage-clearing)
* [Examples](#examples)
  * [Registering a WebAuthn or P-256 Session Key](#registering-a-webauthn-or-p-256-session-key)
  * [Using EOA Session Keys](#using-eoa-session-keys)
* [Testing](#testing)
* [License](#license)
* [Disclaimer](#disclaimer)
* [Contact](#contact)

---

## Overview

Openfort's implementation of EIP-7702 (Account Implementation Contract Standard) allows smart contracts to be executed at any address without a deployment transaction. Our architecture includes:

- **OPF7702**: A modular, production-ready smart account supporting ERC-4337 + session keys
- **Session Keys**: Temporary keys (WebAuthn, EOA, P-256) with scoped permissions
- **EIP-1271 + EIP-712**: Secure signature validation for typed and raw data

---

## Key Features

### EIP-7702 Implementation

- No deployment transaction required
- Deterministic storage layout via fixed slots
- Compatible with ERC-4337 bundlers and EntryPoint

### Session Keys

- Temporary session keys with limited scope
- EOA, WebAuthn, and P-256 support
- Whitelisting, time limits, and transaction limits

### WebAuthn & P-256 Support

- Hardware-backed keys via WebAuthn (biometrics, YubiKeys)
- **P256**: Supports extractable (standard ECDSA) and non-extractable keys via SHA-256 digests
- Fully verified on-chain with Openfort libraries

### Spending Controls

- Set max ETH and ERC-20 token usage per session key
- Limit function selectors and allowed contracts

### Security Features

- Reentrancy guard
- Key expiration and usage tracking
- Contract/function selector filters

---

## Architecture

### Core Components

- **`BaseOPF7702.sol`** – Abstract base with account validation, signature handling, and nonce tracking. Implements `IAccount`.
- **`Execution.sol`** – Stateless transaction execution. Handles `execute` and `executeBatch`.
- **`KeysManager.sol`** – Manages session key registration, validation, and revocation.
- **`OPF7702.sol`** – Full production implementation combining `Execution` and `KeysManager`.
- **`OPF7702Recoverable.sol`**  - Extension of the main smart account that adds advanced social recovery capabilities. Enables guardian-based recovery flows, lock/unlock mechanisms and guardian proposal/revocation lifecycle management with full event traceability.

### Storage

```solidity
keccak256("openfort.baseAccount.7702.v1") = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
```

### Key Types

```solidity
enum KeyType {
    EOA,
    WEBAUTHN,
    P256,
    P256NONKEY
}
```

### Session Key Structure

```solidity
struct SessionKey {
    PubKey pubKey;
    bool isActive;
    uint48 validUntil;
    uint48 validAfter;
    uint48 limit;
    bool masterSessionKey;
    bool whitelisting;
    mapping(address => bool) whitelist;
    bytes4[] allowedSelectors;
    uint256 ethLimit;
    SpendTokenInfo spendTokenInfo;
}
```

## EIP-4337 / EIP-7702 Interplay

The contract supports both:
	•	Owner validation via EIP-712 / ECDSA
	•	Session key validation via on-chain rules + signature

## Social Recovery
The OPF7702Recoverable contract extends the base smart account with advanced social recovery features that allow users to recover access through trusted guardians. These guardians can be EOAs or WebAuthn public keys.

## Usage Guide

### Account Initialization

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

### Session Key Management

```solidity
// Register the session key
  function registerSessionKey(
      Key calldata _key,
      uint48 _validUntil,
      uint48 _validAfter,
      uint48 _limit,
      bool _whitelisting,
      address _contractAddress,
      SpendTokenInfo calldata _spendTokenInfo,
      bytes4[] calldata _allowedSelectors,
      uint256 _ethLimit
    );
```

### Transaction Execution

```solidity
    function execute(Call[] calldata _transactions) external payable virtual nonReentrant {
        _requireForExecute();

        uint256 txCount = _transactions.length;
        if (txCount == 0 || txCount > MAX_TX) {
            revert OpenfortBaseAccount7702V1__InvalidTransactionLength();
        }

        for (uint256 i = 0; i < txCount;) {
            Call calldata callItem = _transactions[i];
            _executeCall(callItem.target, callItem.value, callItem.data);
            unchecked {
                ++i;
            }
        }
    }

    function executeBatch(
        address[] calldata _target,
        uint256[] calldata _value,
        bytes[] calldata _data
    ) public payable virtual nonReentrant {
        _requireForExecute();

        uint256 batchLength = _target.length;
        if (
            batchLength == 0 || batchLength > MAX_TX || batchLength != _value.length
                || batchLength != _data.length
        ) {
            revert OpenfortBaseAccount7702V1__InvalidTransactionLength();
        }

        for (uint256 i = 0; i < batchLength;) {
            _executeCall(_target[i], _value[i], _data[i]);
            unchecked {
                ++i;
            }
        }
    }

    function _executeCall(address _target, uint256 _value, bytes calldata _data) internal virtual {
        if (_target == address(this)) {
            revert OpenfortBaseAccount7702V1__InvalidTransactionTarget();
        }

        emit TransactionExecuted(_target, _value, _data);
        (bool success, bytes memory returnData) = _target.call{value: _value}(_data);
        if (!success) {
            revert OpenfortBaseAccount7702V1__TransactionFailed(returnData);
        }
    }
```

### Guardian Lifecycle
Guardians are managed via a lifecycle with scheduled delays and explicit confirmations to prevent malicious takeovers:
	•	Propose Guardian:
A new guardian is proposed with a delay before activation.
```solidity
function proposeGuardian(Key memory _guardian)
```
Emits: GuardianProposed

	•	Confirm Guardian Proposal:
After the delay, the guardian can be activated.
```solidity
function confirmGuardianProposal(Key memory _guardian)
```
Emits: GuardianAdded

	•	Cancel Guardian Proposal:
An unconfirmed proposal can be revoked.
```solidity
function cancelGuardianProposal(Key memory _guardian)
```

## Security Considerations
	•	Use whitelisting for limited session keys
	•	Expire session keys promptly
	•	Use P256NONKEY for hardware-only key protection
	•	Validate token/ETH limits on registration

## Storage Clearing

```solidity
function _clearStorage() internal {
    bytes32 baseSlot = keccak256("openfort.baseAccount.7702.v1");
    for (uint256 i = 2; i < 6; i++) {
        bytes32 slot = bytes32(uint256(baseSlot) + i);
        assembly { sstore(slot, 0) }
    }
}
```

## License

MIT License. See LICENSE.

## Disclaimer

This repository is under active development and not audited. Use at your own risk.

## Contact

Security: security@openfort.xyz
Docs: https://docs.openfort.xyz