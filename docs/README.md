# Openfort EIP-7702 Smart Contract Accounts

<p align="center">
  <img src="Logo_black_primary_no_bg.png" alt="Openfort" style="width: 300px;" />
</p>

> 💡 Live Demo: [https://7702.openfort.xyz](https://7702.openfort.xyz)

This documentation covers the implementation of EIP-7702 compatible smart contract accounts by Openfort. These accounts enable account abstraction while leveraging the new capabilities introduced by EIP-7702 (Pectra Upgrade).

---

## Table of Contents

- [Overview](#overview)
- [Docs & Deep Dives](#docs--deep-dives)
- [Key Features](#key-features)
  - [EIP-7702 Implementation](#eip-7702-implementation)
  - [Keys](#keys)
  - [WebAuthn & P-256 Support](#webauthn--p-256-support)
  - [Spending Controls](#spending-controls)
  - [Security Features](#security-features)
- [Architecture](#architecture)
  - [Core Components](#core-components)
  - [Storage](#storage)
  - [Key Types](#key-types)
  - [Key Structure](#key-structure)
  - [EIP-4337 / EIP-7702 Interplay](#eip-4337--eip-7702-interplay)
  - [Guardian Lifecycle](#guardian-lifecycle)
  - [Social Recovery](#social-recovery)
- [Usage Guide](#usage-guide)
  - [Account Initialization](#account-initialization)
  - [Key Management](#key-management)
  - [Transaction Execution](#transaction-execution)
- [Security Considerations](#security-considerations)
- [Implementation Details](#implementation-details)
  - [Signature Verification](#signature-verification)
  - [Storage Clearing](#storage-clearing)
- [Examples](#examples)
  - [Registering a WebAuthn or P-256 Session Key](#registering-a-webauthn-or-p-256-session-key)
  - [Using EOA Session Keys](#using-eoa-session-keys)
- [Testing](#testing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Contact](#contact)

---

## Docs & Deep Dives

- **Architecture** — high-level design, modules, call flow, and data shapes: [docs/Architecture.md](Architecture.md)
- **Keys** — registration, permissions, signature envelopes, and policy limits: [docs/SessionKeys.md](SessionKeys.md)
- **Recovery** — guardians, timelines, EIP-712 digests, and invariants: [docs/Recovery.md](Recovery.md)
- **Gas Policy** — per-session gas/cost/tx budgets, validation flow, defaults, and examples: [docs/GasPolicy.md](GasPolicy.md)
- **AA Primer** — how this integrates with ERC-4337 and EIP-7702: [docs/AA.md](AA.md)

---

## Overview

Openfort's implementation of EIP-7702 (Account Implementation Contract Standard) allows smart contracts to be executed at any address without a deployment transaction. Our architecture includes:

- **OPF7702**: A modular, production-ready smart account supporting ERC-4337 + session keys
- **Keys**: Temporary keys (WebAuthn, EOA, P-256) with scoped permissions
- **EIP-1271 + EIP-712**: Secure signature validation for typed and raw data

---

## Key Features

### EIP-7702 Implementation

- No deployment transaction required
- Deterministic storage layout via fixed slots
- Compatible with ERC-4337 bundlers and EntryPoint

### Keys

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
keccak256(abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)) & ~bytes32(uint256(0xff)) = 0xeddd36aac8c71936fe1d5edb073ff947aa7c1b6174e87c15677c96ab9ad95400
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

### Key Structure

```solidity
    struct KeyData {
        PubKey pubKey;
        bool isActive;
        uint48 validUntil;
        uint48 validAfter;
        uint48 limit;
        bool masterKey;
        bool whitelisting;
        mapping(address contractAddress => bool allowed) whitelist;
        ISpendLimit.SpendTokenInfo spendTokenInfo;
        bytes4[] allowedSelectors;
        uint256 ethLimit;
    }
```

## EIP-4337 / EIP-7702 Interplay

The contract supports both:
	•	Owner validation via EIP-712 / ECDSA
	•	Key validation via on-chain rules + signature

## Social Recovery
The OPF7702Recoverable contract extends the base smart account with advanced social recovery features that allow users to recover access through trusted guardians. These guardians can be EOAs or WebAuthn public keys.

## Usage Guide

### Account Initialization

```solidity
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

### Key Management

```solidity
// Register the key
function registerKey(Key calldata _key, KeyReg calldata _keyData) 
```

### Transaction Execution

```solidity
    function execute(bytes32 mode, bytes memory executionData)
        public
        payable
        virtual
        nonReentrant
    {
        // Authenticate *once* for the whole recursive run.
        _requireForExecute();

        // Run the worker; revert if overall call‑count > MAX_TX.
        _run(mode, executionData, 0);
    }

        function _run(bytes32 mode, bytes memory data, uint256 counter) internal returns (uint256) {
        uint256 id = _executionModeId(mode);

        /* -------- mode 3 : batch‑of‑batches ----------------------- */
        if (id == 3) {
            // Clear the top‑level mode‑3 flag so inner batches can be
            // parsed as mode 1 or 2.
            mode ^= bytes32(uint256(3 << (22 * 8)));

            bytes[] memory batches = abi.decode(data, (bytes[]));
            _checkLength(batches.length); // per‑batch structural cap

            for (uint256 i; i < batches.length; ++i) {
                counter = _run(mode, batches[i], counter);
            }
            return counter;
        }

        /* -------- flat batch (mode 1 or 2) ------------------------ */
        if (id == 0) revert IExecution.OpenfortBaseAccount7702V1__UnsupportedExecutionMode();

        bool withOpData;
        /// @solidity memory-safe-assembly
        assembly {
            let len := mload(data)
            let flag := gt(mload(add(data, 0x20)), 0x3f)
            withOpData := and(eq(id, 2), and(gt(len, 0x3f), flag))
        }

        Call[] memory calls;
        bytes memory opData;
        if (withOpData) {
            (calls, opData) = abi.decode(data, (Call[], bytes));
        } else {
            calls = abi.decode(data, (Call[]));
        }

        _checkLength(calls.length); // per‑batch structural cap
        if (opData.length != 0) revert IExecution.OpenfortBaseAccount7702V1__UnsupportedOpData();

        for (uint256 i; i < calls.length; ++i) {
            Call memory c = calls[i];
            address to = c.target == address(0) ? address(this) : c.target;
            _execute(to, c.value, c.data);

            // ---- global counter enforcement -------------------- //
            if (++counter > MAX_TX) {
                revert IExecution.OpenfortBaseAccount7702V1__TooManyCalls(counter, MAX_TX);
            }
        }
        return counter;
    }

        function _execute(address to, uint256 value, bytes memory data) internal virtual {
        (bool success, bytes memory result) = to.call{value: value}(data);
        if (success) return;
        /// @solidity memory-safe-assembly
        assembly {
            revert(add(result, 0x20), mload(result))
        }
    }
```

### Guardian Lifecycle
Guardians are managed via a lifecycle with scheduled delays and explicit confirmations to prevent malicious takeovers:
	•	Propose Guardian:
A new guardian is proposed with a delay before activation.
```solidity
function proposeGuardian(bytes32 _guardian)
```
Emits: GuardianProposed

	•	Confirm Guardian Proposal:
After the delay, the guardian can be activated.
```solidity
function confirmGuardianProposal(bytes32 _guardian)
```
Emits: GuardianAdded

	•	Cancel Guardian Proposal:
An unconfirmed proposal can be revoked.
```solidity
function cancelGuardianProposal(bytes32 _guardian)
```

## Security Considerations
	•	Use whitelisting for limited session keys
	•	Expire session keys promptly
	•	Use P256NONKEY for hardware-only key protection
	•	Validate token/ETH limits on registration

## Storage Clearing

```solidity
    function _clearStorage() internal {
        bytes32 baseSlot = keccak256(
            abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)
        ) & ~bytes32(uint256(0xff));

        // clear slot 0, _EP_SLOT & _VERIFIER_SLOT
        bytes32 epSlot = UpgradeAddress._EP_SLOT;
        bytes32 verifierSlot = UpgradeAddress._VERIFIER_SLOT;
        assembly {
            sstore(baseSlot, 0)
            sstore(epSlot, 0)
            sstore(verifierSlot, 0)
        }

        // ---- Clear composite structs:
        // recoveryData: starts at base+7, size 4 slots  -> [7,8,9,10]
        // guardiansData: starts at base+11, size 3 slots -> [11,12,13]
        unchecked {
            for (uint256 i = 7; i <= 13; ++i) {
                bytes32 slot = bytes32(uint256(baseSlot) + i);
                assembly {
                    sstore(slot, 0)
                }
            }
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