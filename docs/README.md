# Openfort EIP-7702 Smart Contract Accounts

<p align="center">
  <img src="Logo_black_primary_no_bg.png" alt="Openfort" style="width: 300px;" />
</p>

> 💡 Live Demo: [https://7702.openfort.xyz](https://7702.openfort.xyz)

Openfort’s smart account stack combines **EIP-7702** authorities with **ERC-4337** user operations. The contracts in `src/` provide a modular wallet that supports multi-format keys, granular permissions, custodial gas policies, and guardian-driven recovery – all without a deployment transaction.

---

## Table of Contents
- [Overview](#overview)
- [Repository Layout](#repository-layout)
- [Docs & Deep Dives](#docs--deep-dives)
- [Key Features](#key-features)
  - [Account Abstraction Stack](#account-abstraction-stack)
  - [Key Management](#key-management)
  - [Permission & Budget Controls](#permission--budget-controls)
  - [Social Recovery](#social-recovery)
  - [Developer Ergonomics](#developer-ergonomics)
- [Architecture](#architecture)
  - [Core Components](#core-components)
  - [Storage & Immutables](#storage--immutables)
  - [Key Model](#key-model)
  - [Execution Modes](#execution-modes)
- [Session Gas Policy](#session-gas-policy)
- [Social Recovery Summary](#social-recovery-summary)
- [Usage Guide](#usage-guide)
  - [Account Initialization](#account-initialization)
  - [Registering Keys](#registering-keys)
  - [Configuring Permissions](#configuring-permissions)
  - [Executing Transactions](#executing-transactions)
- [Security Considerations](#security-considerations)
- [Implementation Notes](#implementation-notes)
  - [Signature Verification](#signature-verification)
  - [Storage Clearing](#storage-clearing)
- [Testing](#testing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Contact](#contact)

---

## Overview

- **7702-native smart accounts** that can be enabled through a delegation without deploying new bytecode.
- **4337-compatible validation pipeline** that plugs into the canonical EntryPoint and bundler tooling.
- **Fine-grained key permissions** (targets, selectors, token spend, gas budgets) with first-class WebAuthn / P-256 support.
- **Guardian-based recovery** orchestrated by an external manager so storage upgrades stay lightweight.

---

## Repository Layout

```text
src/
  core/          # Account stack: Base -> KeysManager -> Execution -> OPF7702 -> OPF7702Recoverable -> OPFMain
  interfaces/    # Public contract interfaces (accounts, policies, recovery)
  libs/          # Shared helpers (key validation, signature utils, upgrade slots, initializable)
  utils/         # Auxiliary modules (SocialRecoveryManager, GasPolicy, ERC7201 view helpers)
docs/            # In-depth documentation and component guides
test/            # Foundry tests
```

---

## Docs & Deep Dives

- **Architecture** — modules, call flow, storage diagrams: [docs/Architecture.md](Architecture.md)
- **Session Keys** — registration, permissions, signature envelopes: [docs/SessionKeys.md](SessionKeys.md)
- **Recovery** — guardian flows, EIP-712 digests, invariants: [docs/Recovery.md](Recovery.md)
- **Gas Policy** — per-session budgets, validation flow, defaults: [docs/GasPolicy.md](GasPolicy.md)
- **AA Primer** — how the stack interops with ERC-4337 & EIP-7702: [docs/AA.md](AA.md)

---

## Key Features

### Account Abstraction Stack
- `BaseOPF7702` implements ERC-4337’s `IAccount`, ERC-1271 signing, and token receiver interfaces (ERC-721, ERC-1155, ERC-777).
- `OPF7702` layers execution, multi-key validation, and replay protection for user operations.
- `OPFMain` anchors storage at a fixed ERC-7201 slot and exposes an `upgradeProxyDelegation` helper for 7702 authorities.

### Key Management
- Keys are identified by deterministic hashes and stored alongside validity windows, quotas, and control modes.
- Supports `KeyType`: `EOA`, `WEBAUTHN`, `P256`, `P256NONKEY`.
- Custodial keys (`KeyControl.Custodial`) auto-initialize gas budgets through the `GasPolicy`.

### Permission & Budget Controls
- `setCanCall` guards `(target, selector)` tuples with wildcard sentinels (`ANY_TARGET`, `ANY_FN_SEL`, `EMPTY_CALLDATA_FN_SEL`).
- `setTokenSpend` / `updateTokenSpend` enforce token or native currency budgets per configurable period (minute → forever).
- ERC-7821 style execution batches are capped at `MAX_TX = 9` low-level calls across recursion depth.

### Social Recovery
- `SocialRecoveryManager` keeps all guardian storage outside the account implementation.
- Guardians are hashed (`computeHash(address)`) and must sign ordered EIP-712 digests to finalize recovery.
- Locking semantics ensure guardian churn and recovery cannot race.

### Developer Ergonomics
- EntryPoint, WebAuthn verifier, gas policy, and recovery manager are immutables with guarded upgrade hooks (`setEntryPoint`, `setWebAuthnVerifier`, `setGasPolicy`).
- Extensive events (`KeyRegistered`, `CanCallSet`, `TokenSpendSet`, `GasPolicyAccounted`, `WalletLocked`, …) provide off-chain traceability.
- Modular libs (`UpgradeAddress`, `KeysManagerLib`, `SigLengthLib`) isolate reusable logic.

---

## Architecture

### Core Components

| Contract / Lib | Path | Responsibility | Highlights |
|----------------|------|----------------|------------|
| `BaseOPF7702` | `src/core/BaseOPF7702.sol` | ERC-4337 `IAccount` shim, immutables, ERC-165/1271 receivers | Guards privileged calls, emits deposit events, maintains upgrade slots |
| `KeysManager` | `src/core/KeysManager.sol` | Key lifecycle, permissions, spend accounting | Auto-inits custodial gas policy, wildcard selector support, enumerable permissions |
| `Execution` | `src/core/Execution.sol` | ERC-7821 executor with recursion guard | Modes 1 & 3, `MAX_TX` enforcement, reentrancy guard |
| `OPF7702` | `src/core/OPF7702.sol` | Signature routing & call validation | Supports EOA/WebAuthn/P256/P256NONKEY, invokes `GasPolicy` for delegated keys |
| `OPF7702Recoverable` | `src/core/OPF7702Recoverable.sol` | Recovery plumbing & initialization | Seeds guardians, integrates `SocialRecoveryManager`, rotates master key on recovery |
| `OPFMain` | `src/core/OPFMain.sol` | Production account with fixed layout | `layout at` ERC-7201 slot, exposes `upgradeProxyDelegation` helper |
| `SocialRecoveryManager` | `src/utils/SocialRecover.sol` | Guardian registry & recovery orchestrator | Timelocked proposals, strict signature ordering, lock tracking |
| `GasPolicy` | `src/utils/GasPolicy.sol` | Session gas budget enforcement | Per `(configId, account)` envelope, manual/auto init, optimistic accounting |
| `UpgradeAddress` | `src/libs/UpgradeAddress.sol` | Upgrade slot helpers | Normalises upgrade calls and emits address change events |

### Storage & Immutables
- Storage root: `keccak256(abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)) & ~bytes32(uint256(0xff)) = 0xeddd...95400`
- `BaseOPF7702` keeps immutable pointers to `ENTRY_POINT`, `WEBAUTHN_VERIFIER`, `GAS_POLICY`, `RECOVERY_MANAGER`.
- Upgrade hooks (`setEntryPoint`, `setWebAuthnVerifier`, `setGasPolicy`) require `msg.sender` to be the account itself or the current EntryPoint (`_requireForExecute`).
- `_clearStorage()` zeroes the ERC-7201 namespace root, upgrade slots, and `ReentrancyGuard` status to enable deterministic re-initialisation flows.

### Key Model

```solidity
enum KeyType { EOA, WEBAUTHN, P256, P256NONKEY }

enum KeyControl { Self, Custodial }

struct KeyData {
    KeyType keyType;
    bool isActive;
    bool masterKey;
    bool isDelegatedControl;
    uint48 validUntil;
    uint48 validAfter;
    uint48 limits;    // 0 for master keys, >0 for session keys
    bytes key;        // abi.encode(address) or abi.encode(pubKey.x, pubKey.y)
}

struct KeyDataReg {
    KeyType keyType;
    uint48 validUntil;
    uint48 validAfter;
    uint48 limits;
    bytes key;
    KeyControl keyControl;
}
```

Execution permissions (`ExecutePermissions`) and spend rules (`SpendStorage`) live in separate mappings per key. `idKeys` provides sequential indexing for iterating and maintaining master key invariants (`idKeys[0]` is always the master key).

### Execution Modes
- `mode_1`: flat batch of `(target, value, data)` calls.
- `mode_3`: batch-of-batches, recursively processed as mode 1.
- Unsupported modes revert with `OpenfortBaseAccount7702V1__UnsupportedExecutionMode`.
- Global call depth capped at `MAX_TX = 9` across nested batches.

---

## Session Gas Policy

`GasPolicy.sol` enforces cumulative “envelope units” per `(configId, account)`:

- **Manual init**: `initializeGasPolicy(account, configId, bytes16 gasLimitBE)` stores an explicit 128-bit cap.
- **Auto init**: `initializeGasPolicy(account, configId, uint256 limit)` multiplies default legs (PVG/VGL/CGL/PMV/PO), adds `SAFETY_BPS = 12_000` (+20%), and enforces a `uint128` bound.
- **Validation**: `checkUserOpPolicy(id, userOp)` sums gas legs (including paymaster values if supplied), checks for overflow and budget exhaustion, updates `gasUsed`, and emits `GasPolicyAccounted`.
- Only the account (`msg.sender == userOp.sender`) may mutate budgets, preventing griefing.

Custodial session keys automatically call `initializeGasPolicy(address(this), keyId, limits)` during registration.

---

## Social Recovery Summary

- Guardians are stored as `bytes32` hashes of guardian EOAs (`computeHash`). Direct addresses never touch storage.
- `SocialRecoveryManager` enforces `securityPeriod`/`securityWindow` timelocks for adds/removals, and `recoveryPeriod`/`lockPeriod` for recovery execution.
- `startRecovery` checks guardian status, key eligibility (non-zero, not active, not a guardian, not P256/P256NONKEY), snapshots quorum (`ceil(guardianCount / 2)`), and locks the wallet.
- `completeRecovery` validates strictly ordered guardian signatures over `getDigestToSign(account)` and returns the approved `KeyDataReg`. `OPF7702Recoverable` then rotates the master key.
- `WalletLocked` events broadcast transitions; the lock clears automatically on completion/cancellation or when `lockPeriod` expires.

See [docs/Recovery.md](Recovery.md) for timelines and message formats.

---

## Usage Guide

### Account Initialization

```solidity
function initialize(
    IKey.KeyDataReg calldata _keyData,
    IKey.KeyDataReg calldata _sessionKeyData,
    bytes memory _signature,
    bytes32 _initialGuardian
) external initializer;
```

Steps performed:
1. `_clearStorage()` resets the ERC-7201 namespace.
2. Validates `_keyData` (must be master: `limits == 0`, non-P256/P256NONKEY, `KeyControl.Self`).
3. Registers the master key and optional session key (if `_sessionKeyData.key` is non-empty).
4. Seeds the guardian set via `SocialRecoveryManager.initializeGuardians(address(this), _initialGuardian)`.
5. Emits `IOPF7702.Initialized(_keyData)`.

The call must originate from the EntryPoint or a self-call (`_requireForExecute`).

### Registering Keys

```solidity
function registerKey(IKey.KeyDataReg calldata _keyData) external;
```

- Session keys require `limits > 0`.
- Custodial keys (`KeyControl.Custodial`) automatically set `isDelegatedControl = true` and call `GasPolicy.initializeGasPolicy`.
- Emits `KeyRegistered` with hashed `keyId`.

Master keys are registered only during initialization or recovery; `_addMasterKey` enforces `idKeys[0]`.

### Configuring Permissions

- **Execution permissions**  
  `setCanCall(bytes32 keyId, address target, bytes4 selector, bool can)` grants or revokes `(target, selector)` tuples. `ANY_TARGET`, `ANY_FN_SEL`, and `EMPTY_CALLDATA_FN_SEL` are available wildcards.
  
- **Spend limits**  
  - `setTokenSpend(keyId, token, limit, period)` creates per-token limits. Use `NATIVE_ADDRESS` for ETH.
  - `updateTokenSpend(...)` mutates existing limits and resets counters.
  - `removeTokenSpend(...)` clears individual tokens; `clearTokenSpend(keyId)` wipes all spend rules.

- **Lifecycle**  
  `pauseKey`, `unpauseKey`, and `revokeKey` manage key state while preserving stored permissions for later reactivation if needed.

All management functions require `_requireForExecute()` (self-call or EntryPoint).

### Executing Transactions

```solidity
function execute(bytes32 mode, bytes memory executionData)
    public
    payable
    virtual
    nonReentrant;
```

- `mode = Execution.mode_1` → flat `Call[]` batch.
- `mode = Execution.mode_3` → batch-of-batches (`bytes[]`).
- `MAX_TX` (9) bounds total low-level calls per outer execution.
- Nested batches reuse the initial authentication (`_requireForExecute`) and propagate revert data.

Helper: `Execution._executionModeId` decodes the 10-byte execution flag derived from ERC-7821.

---

## Security Considerations

- Guardian management and recovery calls are always gated by `msg.sender == _account`; external EOAs must route through the account (e.g., via EntryPoint).
- Recovery proposals reject zero hashes, the account’s own hash, the current master key hash, and active guardian hashes.
- `GasPolicy` performs all accounting with explicit overflow checks and never issues external calls.
- ERC-777, ERC-721, and ERC-1155 receiver interfaces are implemented in `BaseOPF7702`, ensuring safe token transfers.
- Reentrancy is guarded at the execution entry point; inner calls must handle their own invariants.

---

## Implementation Notes

### Signature Verification

- **EOA**: `ECDSA.recover` against `userOpHash`; master key short-circuits to success.
- **WebAuthn**: Delegated to `IWebAuthnVerifier.verifySignature`; rejects reused challenges and enforces signature length via `SigLengthLib`.
- **P256 / P256NONKEY**: Verified via `IWebAuthnVerifier.verifyP256Signature` (NONKEY pre-hashes the digest).
- Delegated (custodial) keys call `GasPolicy.checkUserOpPolicy` before allowing the execution to proceed.
- `isValidSignature(bytes32,bytes)` (ERC-1271) wraps the same validators for off-chain signing flows.

### Storage Clearing

```solidity
function _clearStorage() internal {
    bytes32 baseSlot = keccak256(
        abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)
    ) & ~bytes32(uint256(0xff));

    bytes32 epSlot = UpgradeAddress._EP_SLOT;
    bytes32 verifierSlot = UpgradeAddress._VERIFIER_SLOT;
    bytes32 gasPolicySlot = UpgradeAddress._GAS_POLICY_SLOT;
    assembly {
        sstore(baseSlot, 0)
        sstore(epSlot, 0)
        sstore(verifierSlot, 0)
        sstore(gasPolicySlot, 0)
    }

    assembly {
        sstore(add(baseSlot, 5), 0) // reset ReentrancyGuard status
    }
}
```

---

## Testing

This repository uses **Foundry**.

```bash
forge install
forge test
```

Tests cover key registration flows, social recovery, gas policy accounting, and execution guardrails.

---

## License

MIT License. See [LICENSE](../LICENSE).

---

## Disclaimer

The contracts are under active development and have not undergone a formal audit. Use in production at your own risk.

---

## Contact

- Security inquiries: [security@openfort.xyz](mailto:security@openfort.xyz)
- Documentation: [https://docs.openfort.xyz](https://docs.openfort.xyz)
