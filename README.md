<h1 align="center">Openfort EIP-7702 Smart Accounts</h1>

<p align="center">
  <img src="./docs/Logo_black_primary_no_bg.png" alt="Openfort" width="300" />
</p>

> 🚧 **Work in Progress**  
> Contracts are unaudited and may change without notice.

<p align="center">
  <a href="https://github.com/openfort/openfort-7702-account/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"></a>
  <img src="https://img.shields.io/badge/solidity-0.8.29-blue" alt="Solidity 0.8.29">
  <a href="https://eips.ethereum.org/EIPS/eip-7702"><img src="https://img.shields.io/badge/tech-EIP7702-red" alt="EIP 7702"></a>
  <img src="https://img.shields.io/badge/status-unaudited-orange" alt="Unaudited">
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#feature-checklist">Feature Checklist</a> •
  <a href="#core-components">Core Contracts</a> •
  <a href="#key-concepts">Key Concepts</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#technical-details">Technical Details</a> •
  <a href="#security">Security</a>
</p>

**All-in-one EIP-7702 powered smart accounts with session key support**

---

## Overview

Openfort 7702 Accounts combine EIP‑7702 delegation with ERC‑4337 account abstraction to deliver a standards-first smart account that supports:

- Passkey/WebAuthn, P‑256 and classic EOA ownership in a single wallet
- Exhaustive session key controls (targets, selectors, spend caps, gas budgets, expiry)
- Social recovery with guardian timelocks and wallet-wide locking
- Zero-deployment onboarding by reusing delegation storage (EIP‑7702)

Use the contracts as a drop-in wallet implementation, extend the recovery layer, or plug the session-key policy engine into your own flows. A live demo is available at [https://passkey-wallet.com](https://passkey-wallet.com/).

---

## Features

- **Multi-scheme signatures** – ECDSA (secp256k1), WebAuthn assertions, raw P‑256 / “non-extractable” P‑256 (pre-hashed) supported natively.  
- **Session keys by design** – Each key carries quotas, target/function permissions, token/ETH spend policies, and optional custodial gas policy hooks.  
- **Deterministic storage** – Layout anchored via ERC‑7201 so delegation slots remain stable across upgrades.  
- **Guardian recovery** – Independent manager contract orchestrates guardian proposals, revocations, recovery locks and EIP‑712 signing.  
- **Gas policy accounting** – Optional per-session envelope limits over PVG/VGL/CGL/PM legs guard against griefing.  
- **Batch execution** – ERC‑7821 inspired executor supports flat and recursive batch modes with call-count limits and revert bubbling.  
- **No vendor lock-in** – Pure Solidity + widely adopted standards; contracts expose granular interfaces for composability.

### Additional Capabilities

- Zero deployment onboarding through EIP‑7702 delegation.
- ERC‑777 token reception hook for seamless airdrops and funding flows.
- Guardian lifecycle events for off-chain monitoring.
- Extensive NatSpec interfaces for tooling and integration hints.

---

## Feature Checklist
- [x] **Zero Deployment Cost** – Create accounts without any deployment transaction via EIP-7702.  
- [x] **WebAuthn Support** – Use hardware security keys and passkeys for authentication.  
- [x] **P-256 / P-256 Non-Extractable Support** – Validate WebCrypto non-extractable P-256 keys with a pre-hashed digest flow.  
- [x] **Session Keys** – Temporary keys with custom permissions and expiration.  
- [x] **Contract Whitelisting** – Restrict which contracts session keys can access.  
- [x] **Function Filtering** – Define which function selectors can be called.  
- [x] **Time-Based Controls** – Define activation and expiration for keys.  
- [x] **Spending Limits** – ETH and token spend per period (day, week, month, etc.).  
- [x] **Subscription Limits** – Token spend limited by amount and rolling period.  
- [x] **Transaction Counting** – Restrict number of uses per session key.  
- [x] **Batch Transactions** – Execute multiple calls in one operation.  
- [x] **ERC-4337 Support** – Works with bundlers and EntryPoint.  
- [x] **Gas Sponsorship** – Dapps or relayers can pay for user operations.  
- [x] **Enhanced Recovery Options** – Guardian-based social recovery for EOAs and WebAuthn keys.  
- [x] **ERC-7821 Support** – Minimal batch executor interface for delegated execution.  
- [x] **Gas Policy Module** – Per-session gas/cost/transaction budgets.  
- [x] **Social Recovery Manager** – External module orchestrating guardian proposals and recovery.  
- [ ] **Multi-chain Support** – Coming soon.  

---

## Core Components

| Contract | Role | Key Responsibilities |
|----------|------|----------------------|
| `BaseOPF7702` | foundational account | ERC‑4337 `IAccount` hook, signature dispatch, 7702 storage access, ERC‑1271 / ERC‑777 / receiver support |
| `Execution` | execution engine | ERC‑7821 execute modes, batch recursion, MAX_TX enforcement, revert bubbling helper |
| `KeysManager` | key registry | Key registration, quota tracking, selector/target whitelists, token spend accounting, admin pause/unpause |
| `OPF7702` | primary account | Wires execution + key management, implements `_validateSignature`, exposes helper getters |
| `OPF7702Recoverable` | recovery wrapper | Adds initializer, guardian-based recovery, wallet locks, emits recovery lifecycle events |
| `GasPolicy` | optional policy | Per-config envelope accounting, auto/manual config, IERC165 discovery |
| `SocialRecoveryManager` | guardian orchestrator | Guardian proposal/revoke flows, recovery digests, ordered signature validation |
| `ERC7201` | storage util | Public namespace & slot constant for tooling/integration |

---

## Key Concepts

### Keys & Permissions
- **Key types** (`IKey.KeyType`): `EOA`, `WEBAUTHN`, `P256`, `P256NONKEY`.  
- **Quotas**: `limits` enforce call counts; `SpendStorage` enforces token/ETH spend per `SpendPeriod` (minute → forever).  
- **Permissions**: `setCanCall` grants selectors/targets with wildcard support; empty calldata sentinel enables native transfers.  
- **Custodial mode**: Keys flagged as custodial automatically initialize gas-policy envelopes through `GasPolicy`.

### Execution Modes
- Mode `0x0100…0000`: flat batch (`Call[]`)  
- Mode `0x0100…78210002`: batch of batches (recursive)  
- Call count capped by `MAX_TX` (default 9) across recursion depth.

### Recovery Workflow
1. Guardians proposed with timelock + confirmation window.  
2. `startRecovery` locks the wallet, records quorum (ceil half of guardians) and expiry window.  
3. Guardians sign EIP‑712 digest (`getDigestToSign`); `completeRecovery` validates sorted signatures and installs the new master key.  
4. Lock is cleared or persists until `lockPeriod` lapses.

---

## Standards & Compatibility

| Standard | Implementation Detail |
|----------|----------------------|
| **EIP‑7702** | Delegation authority + deterministic layout |
| **ERC‑4337** | `IAccount` validation (`_validateSignature`, `_requireFromEntryPoint`) |
| **ERC‑1271** | On-chain signature validation for master keys |
| **ERC‑777** | `tokensReceived` hook to accept token mints/transfers |
| **ERC‑7821** | Execution mode detection and batch semantics |
| **ERC‑7201** | Public namespace + storage root exposure |
| **EIP‑712** | Init and recovery digests for guardian flows |

All public/external entry points are surfaced via interfaces in `src/interfaces/` for downstream tooling.

---

## Quick Start

```bash
git clone https://github.com/openfort/openfort-7702-account.git
cd openfort-7702-account

# install deps (uses Foundry)
forge install

# run tests
forge test
```

### Initialize an Account

```solidity
function initialize(
    Key calldata _key,
    KeyReg calldata _keyData,
    Key calldata _sessionKey,
    KeyReg calldata _sessionKeyData,
    bytes memory _signature,
    bytes32 _initialGuardian
);
```

### Register a Key

```solidity
// Create a WebAuthn key structure
PubKey memory pubKey = PubKey({
    x: 0x..., // X coordinate from credential
    y: 0x...  // Y coordinate from credential
});

KeyData memory key = KeyData({
        /// @notice Cryptographic key type (e.g., EOA / P256 / WEBAUTHN).
        keyType: KeyType.WEBAUTHN,
        /// @notice Whether the key is currently active (paused/revoked sets this to false).
        isActive: true,
        /// @notice True if this is the master/admin key.
        masterKey: true,
        /// @notice True if control is delegated (see {KeyControl.Custodial}).
        isDelegatedControl: false,
        /// @notice Inclusive expiry timestamp (key invalid after this time).
        validUntil: type(uint48).max,
        /// @notice Not-before timestamp (key invalid before this time).
        validAfter: 0,
        /// @notice Remaining transactions quota for this key (decremented on use).
        limits: 0,
        /// @notice Encoded key
        key: abi.encode(x, y) // x: bytes32, y: bytes32
    });

KeyDataReg memory keyData = KeyDataReg({
        /// @notice Cryptographic key type (e.g., EOA / P256 / WEBAUTHN).
        keyType: KeyType.WEBAUTHN,
        /// @notice Inclusive expiry timestamp for the new key.
        validUntil: type(uint48).max,
        /// @notice Not-before timestamp for the new key.
        validAfter: 0,
        /// @notice Initial transactions quota (must be zero for master keys).
        limits: 0,
        /// @notice Encoded key
        key: abi.encode(x, y), // x: bytes32, y: bytes32
        /// @notice Control mode for this key (self vs custodial).
        keyControl: KeyControl.Self
    });

// Register the key
account.registerKey(keyData);
```

### Execute Transactions

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

### Implementation Notes

- Deploy `OPFMain` (inherits `OPF7702Recoverable`) with EntryPoint, WebAuthn verifier, GasPolicy and SocialRecoveryManager addresses.  
- Call `initialize` with master key data, optional session key, contract-signed authorization, and initial guardian hash.  
- Register additional keys via `registerKey`, then tailor permissions with `setCanCall` and `setTokenSpend`.  
- Execute calls through `execute(mode, executionData)` – the executor enforces quotas and calls `_validateSignature` automatically.

Refer to the NatSpec in `src/core` and `src/interfaces` for parameter-level details, or explore the demo dapp for end-to-end flows.

---

## Security

The contracts are **not audited**. Use at your own risk.  
Responsible disclosure: security@openfort.xyz

---

## License

MIT © Openfort
