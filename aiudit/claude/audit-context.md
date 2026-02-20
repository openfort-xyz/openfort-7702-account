# Audit Context: Openfort 7702 Account

**Date**: 2026-02-19
**Scope**: `/src` — Full codebase
**Methodology**: Trail of Bits Deep Context Builder (Ultra-Granular Pure Context Mode)
**Phase**: Context Building Only (No vulnerability findings, no fix recommendations)

---

## Phase 1 — Initial Orientation (Bottom-Up Scan)

### 1.1 Major Modules / Contracts

| Contract | File | Type | Role |
|----------|------|------|------|
| BaseOPF7702 | src/core/BaseOPF7702.sol | Abstract | ERC-4337 base account, token receivers, upgradeable addresses |
| KeysManager | src/core/KeysManager.sol | Abstract | Multi-format key registration, permissions, spend limits |
| Execution | src/core/Execution.sol | Abstract | ERC-7821 batch executor with recursion + call-count limits |
| OPF7702 | src/core/OPF7702.sol | Concrete | Signature validation (EOA/WebAuthn/P256), ERC-1271, spend enforcement |
| OPF7702Recoverable | src/core/OPF7702Recoverable.sol | Concrete | Initialization + recovery integration via EIP-712 |
| OPFMain | src/core/OPFMain.sol | Concrete (deploy) | Final deployment target with EIP-7702 proxy upgrade |
| SocialRecoveryManager | src/utils/SocialRecover.sol | Standalone | Guardian management, recovery orchestration with timelocks |
| GasPolicy | src/utils/GasPolicy.sol | Standalone | Per-session gas budget enforcement for custodial keys |
| WebAuthnVerifier | src/utils/WebAuthnVerifier.sol | Standalone | WebAuthn + P256 signature verification (Solady-based) |
| WebAuthnVerifierV2 | src/utils/WebAuthnVerifierV2.sol | Standalone | Alternative WebAuthn verifier (uint256 coords) |

**Inheritance chain (OPFMain):**
```
OPFMain → OPF7702Recoverable → OPF7702 → Execution → KeysManager → BaseOPF7702
                                    ↳ Initializable        ↳ ReentrancyGuard
                              ↳ EIP712, ERC7201
```

### 1.2 Actors

| Actor | Trust Level | Entry Points |
|-------|-------------|--------------|
| EOA Owner (address(this) in 7702) | Highest | All via EntryPoint or direct self-call |
| EntryPoint (ERC-4337) | Trusted (immutable) | validateUserOp, execute |
| Session Key (non-master) | Restricted | execute (validated per-key permissions) |
| Guardian | Semi-trusted | startRecovery on SocialRecoveryManager |
| Anyone | Untrusted | receive, fallback, completeRecovery |
| RECOVERY_MANAGER | Trusted (immutable) | Called by wallet during init/recovery |
| GAS_POLICY | Trusted (immutable) | Called during custodial key validation |

### 1.3 Critical Storage Variables

| Variable | Location | Purpose |
|----------|----------|---------|
| `id` | KeysManager | Monotonic key counter (id=0 reserved for master key) |
| `idKeys[uint256 → bytes32]` | KeysManager | Maps registration index to keyId hash |
| `keys[bytes32 → KeyData]` | KeysManager | Key metadata (type, validity, limits, active) |
| `permissions[bytes32 → ExecutePermissions]` | KeysManager | Per-key (target, selector) whitelist |
| `spendStore[bytes32 → SpendStorage]` | KeysManager | Per-key token spend limits & accounting |
| `_initialized / _initializing` | Initializable | One-time init guard |
| `_EP_SLOT / _VERIFIER_SLOT / _GAS_POLICY_SLOT` | UpgradeAddress | Upgradeable contract references |
| `recoveryData[address]` | SocialRecoveryManager | Pending recovery proposals |
| `guardiansData[address]` | SocialRecoveryManager | Guardian set + lock state |
| `gasLimitConfigs[bytes32][address]` | GasPolicy | Per-session gas budgets |

**ERC-7201 Storage Root:** `0xeddd36aac8c71936fe1d5edb073ff947aa7c1b6174e87c15677c96ab9ad95400`

### 1.4 Key Data Structures

**KeyData struct** (IKey.sol:L48-65):
- `keyType`: KeyType (EOA/WEBAUTHN/P256/P256NONKEY)
- `isActive`: bool
- `masterKey`: bool
- `isDelegatedControl`: bool
- `validUntil`: uint48 (inclusive expiry)
- `validAfter`: uint48 (not-before)
- `limits`: uint48 (remaining TX quota, decremented on use)
- `key`: bytes (abi.encode(address) for EOA, abi.encode(x,y) for P256/WebAuthn)

### 1.5 Critical Library Functions (KeysManagerLib)

| Function | What it does | Key observation |
|----------|-------------|-----------------|
| `computeKeyId(keyType, key)` | `keccak256(uint8(keyType), keccak256(key))` | Key type is part of ID — same pubkey with different types = different keyId |
| `computeHash(address)` | `keccak256(abi.encodePacked(address))` | Used for guardian IDs — different from computeKeyId |
| `validateKeyBefore(sKey)` | Requires `isActive` AND rejects `masterKey` | Master key cannot be target of setCanCall/setTokenSpend |
| `validateTimestamps(...)` | validUntil > block.timestamp, != max(uint48), must extend on update | Session keys CANNOT have type(uint48).max expiry |
| `checkTargetAddress(addr)` | Rejects address(0) and address(this) | Self-call targets blocked at permission-setting time |
| `packCanExecute(target, fnSel)` | `target << 96 \| fnSel >> 224` | Packs target+selector into a single bytes32 |

### 1.6 Key Validation Library (KeyDataValidationLib)

| Function | Logic | Observation |
|----------|-------|-------------|
| `isRegistered(sKey)` | `validUntil != 0` | Different from isActive! Revoked keys have validUntil = 0 |
| `hasQuota(sKey)` | `masterKey \|\| limits > 0` | Master keys always have quota |
| `consumeQuota(sKey)` | `if (!masterKey && limits > 0) limits -= 1` | Unchecked, but guarded by limits > 0 check |

### 1.7 Signature Length Validation (SigLengthLib)

`assertWebAuthnOuterLen`: Computes expected outer signature length from `authenticatorData.length` and `clientDataJSON.length`, accounting for ABI padding. Reverts if mismatch. Inner head is exactly 9 words (288 bytes), outer overhead is 96 bytes (3 * 32).

---

## Phase 2 — Ultra-Granular Function Analysis

### Module A: BaseOPF7702 + Execution

#### BaseOPF7702.sol

**FUNCTION: `_requireForExecute()`** (Lines 193-198)
- **Purpose**: Central authorization gate for all state-changing operations on the account. Only allows `msg.sender == address(this)` (self-calls from batch execution) or `msg.sender == address(entryPoint())` (ERC-4337 EntryPoint dispatching validated UserOperations).
- **Invariants**:
  1. Only two callers are ever authorized: `address(this)` and `entryPoint()`.
  2. The EntryPoint address is resolved through `UpgradeAddress.entryPoint(ENTRY_POINT)` which checks override slots.
  3. If `_EP_SLOT` is overridden, the override address is used instead of the immutable.

**FUNCTION: `fallback()`** (Lines 108-133)
- **Purpose**: Catches unmatched function calls. Implements ERC-165 `supportsInterface` and standard token receiver callbacks (`onERC721Received`, `onERC1155Received`, `onERC1155BatchReceived`). Returns `bytes4(msg.sig)` for token callbacks, `true` for `supportsInterface` with matching IDs.
- **Key observation**: No state changes. Falls through to empty return for unrecognized selectors.

**FUNCTION: `receive()`** (Lines 135-137)
- **Purpose**: Accepts plain ETH transfers. Empty body, no state changes.

**FUNCTION: `setEntryPoint(address)`** (Lines 163-166)
- **Purpose**: Overwrites the EntryPoint address in `_EP_SLOT`. Gated by `_requireForExecute()`.
- **Key observation**: Circular dependency — changing the EntryPoint requires authorization from the current EntryPoint.

**FUNCTION: `setWebAuthnVerifier(address)`** (Lines 168-171)
- **Purpose**: Overwrites the WebAuthn verifier in `_VERIFIER_SLOT`. Gated by `_requireForExecute()`.

**FUNCTION: `setGasPolicy(address)`** (Lines 173-176)
- **Purpose**: Overwrites the GasPolicy in `_GAS_POLICY_SLOT`. Gated by `_requireForExecute()`.

**FUNCTION: `_clearStorage()`** (Lines 140-160)
- **Purpose**: Assembly-based storage wipe. Zeroes: `baseSlot` (id), `_EP_SLOT`, `_VERIFIER_SLOT`, `_GAS_POLICY_SLOT`, and `baseSlot+5` (ReentrancyGuard `_status`).
- **Critical observations**:
  - Does NOT clear `baseSlot+6` (Initializable `_initialized`/`_initializing`)
  - Does NOT clear mapping entries (keys, permissions, spendStore, idKeys)
  - The Initializable slot persistence is intentional — allows the `initializer` modifier to manage re-initialization independently

#### Execution.sol

**FUNCTION: `execute(bytes32 mode, bytes calldata executionData)`** (Lines 47-58)
- **Purpose**: The primary execution entry point per ERC-7821. Processes batched calls in two modes: `mode_1` (flat batch of `Call[]`) and `mode_3` (batch-of-batches as `bytes[]`).
- **Access control**: `nonReentrant` modifier + `_requireForExecute()` in body.
- **Invariants**:
  1. At most `MAX_TX` (9) low-level `call` operations per `execute` invocation.
  2. Cannot be re-entered while a batch is in progress.
  3. Only `msg.sender == address(this)` or `msg.sender == address(entryPoint())` can invoke.
  4. If any sub-call reverts, the entire `execute` reverts (no partial execution).

**FUNCTION: `_run(bytes32 mode, bytes memory data, uint256 counter)`** (Lines 82-119)
- **Purpose**: Recursive internal worker. Mode 3 decomposes batch-of-batches into individual mode-1 batches. Mode 1 iterates over `Call[]`, executing each via `_execute`.
- **Key observations**:
  - Counter is stack-passed (not stored in state) for gas efficiency.
  - `address(0)` target translates to `address(this)` per ERC-7821 spec (calldata compression).
  - Mode-3 always converts to mode-1 on recursion — max recursion depth is 2.
  - Each batch is length-checked by `_checkLength` (1 to MAX_TX elements).
- **Invariants**:
  1. Total `_execute` calls across all recursive `_run` invocations ≤ MAX_TX (9).
  2. Mode-3 always recurses into mode-1 (no mode-3-within-mode-3).
  3. Counter is monotonically non-decreasing across the recursive call chain.
  4. Unsupported modes (id == 0) always revert.

**FUNCTION: `_execute(address to, uint256 value, bytes memory data)`** (Lines 126-133)
- **Purpose**: Lowest-level execution primitive. Performs `to.call{value: value}(data)` and propagates revert data verbatim on failure.
- **Invariants**:
  1. Never silently swallows a failed call.
  2. No state in this contract is modified directly by `_execute`.

**FUNCTION: `_executionModeId(bytes32 mode)`** (Lines 142-146)
- **Purpose**: Pure helper extracting mode identifier from ERC-7821 mode word. Returns 0 (unsupported), 1 (flat batch), or 3 (batch-of-batches).
- **Mask**: `(uint256(mode) >> (22 * 8)) & 0xffff00000000ffffffff`

**FUNCTION: `_checkLength(uint256 txCount)`** (Lines 149-153)
- **Purpose**: Structural bounds check: `0 < txCount <= MAX_TX`.

#### UpgradeAddress.sol (Supporting Library)

**Storage Slots**:
- `_EP_SLOT = 0x4e696bb2fc09e5383cb7d4063d5fb8f6e0701a72d9523e5f996ae73b7c89e800`
- `_VERIFIER_SLOT = 0xfd39baddba6b1a9197cb18b09396db32f340e9b468af2bcc8f997735c03db200`
- `_GAS_POLICY_SLOT = 0xda9fe820be906bb4b68c951302595f7e1131563db95582cda480475cc85e6800`

**Packing Format**: `[1 bit MSB flag | 95 bits unused | 160-bit address]`. `_OVERRIDDEN_FLAG = 1 << 255`. When MSB is set, the packed address is used. When clear, the fallback immutable is used.

**Documentation Note**: NatSpec comments for `webAuthnVerifier()` (line 83) and `gasPolicy()` (line 92) are **swapped** — `webAuthnVerifier` is documented as "Gas Policy" and vice versa.

---

### Module B: KeysManager

**11 state-changing functions**, all gated by `_requireForExecute()`.

**FUNCTION: `registerKey(KeyDataReg memory _keyData)`** (Lines 84-93)
- **Purpose**: Public entry point for session key registration. Validates key data, enforces `mustHaveLimits()` (limits > 0), then delegates to `_addKey()`.
- **Key observation**: `mustHaveLimits()` prevents master key creation through this path (master keys require `limits == 0`).
- **Invariants**: After success, new key is active with `masterKey == false`.

**FUNCTION: `setCanCall(bytes32 _keyId, address _target, bytes4 _funSel, bool can)`** (Lines 101-115)
- **Purpose**: Whitelists or removes a (target, selector) permission for a session key.
- **Key observations**:
  - `validateKeyBefore()` rejects master keys — master keys cannot receive permission entries.
  - `checkTargetAddress()` blocks `address(0)` and `address(this)` as targets.
  - Capacity limit: 2048 entries per key (via `EnumerableSetLib.update`).
  - Setting `can = true` is idempotent (no revert on duplicate). Setting `can = false` is also idempotent.

**FUNCTION: `updateKeyData(bytes32 _keyId, uint48 _validUntil, uint48 _validAfter, uint48 _limits)`** (Lines 125-143)
- **Purpose**: Extends validity/limits for an existing session key. Cannot reduce — only extend.
- **Key observations**:
  - `validateTimestamps()` enforces: `validUntil > block.timestamp`, `validUntil > validAfter`, `!= type(uint48).max`, must strictly extend.
  - Limits are overwritten (not added) via `sKey.limits = _limits`.

**FUNCTION: `setTokenSpend(bytes32 _keyId, address _token, uint8 _period, uint256 _limit)`** (Lines 153-164)
- **Purpose**: Creates a new token spend limit for a session key.
- **Key observations**:
  - Capacity limit: 64 tokens per key.
  - Reverts if token already has a spend rule (`KeyManager__TokenSpendAlreadySet`).
  - Resets `spent` and `lastUpdated` to 0.

**FUNCTION: `updateTokenSpend(bytes32 _keyId, address _token, uint8 _period, uint256 _limit)`** (Lines 173-183)
- **Purpose**: Modifies an existing token spend rule. Reverts if not found.
- **Key observation**: Resets `spent` and `lastUpdated` to 0 on update.

**FUNCTION: `revokeKey(bytes32 _keyId)`** (Lines 203-214)
- **Purpose**: Permanently revokes a session key. Deactivates, wipes key data, clears all permissions and spend rules.
- **Key observations**:
  - `_revoke()` zeroes all KeyData fields. `masterKey` is NOT explicitly zeroed but master keys are blocked by `validateKeyBefore()`.
  - Calls `clearExecutePermissions()` and `clearSpendPermissions()` (public functions with redundant `_requireForExecute()` checks).
  - `idKeys` mapping is NOT cleared — preserves historical index.
  - Revoked key can be re-registered (same keyId, new `id` index).

**FUNCTION: `removeTokenSpend(bytes32 _keyId, address _token)`** (Lines 223-231)
- **Purpose**: Removes a single token spend rule. Reverts if not found.

**FUNCTION: `pauseKey(bytes32 _keyId)`** (Lines 509-516)
- **Purpose**: Soft-disables a key by setting `isActive = false` without wiping data.
- **Critical observation**: Does NOT use `validateKeyBefore()` — **master keys CAN be paused**. This is intentional for emergency scenarios.
- **Invariants**: All permissions and spend rules remain intact.

**FUNCTION: `unpauseKey(bytes32 _keyId)`** (Lines 523-530)
- **Purpose**: Re-activates a paused key.
- **Key observation**: No check for whether key was actually registered. Unpausing a non-existent key sets `isActive = true` on a zeroed struct, but downstream validation (`isRegistered()` checks `validUntil != 0`) prevents actual use.

**FUNCTION: `clearSpendPermissions(bytes32 _keyId)`** (Lines 537-547)
- **Purpose**: Removes ALL token spend rules for a key. Backward iteration (O(1) per removal).
- **Key observation**: No `validateKeyBefore()` — callable for any keyId (master, inactive, non-existent).

**FUNCTION: `clearExecutePermissions(bytes32 _keyId)`** (Lines 554-564)
- **Purpose**: Removes ALL (target, selector) permissions. Same backward iteration pattern.
- **Key observation**: Up to 2048 iterations at max capacity.

#### Internal: `_addKey(KeyDataReg memory _keyData)` (Lines 246-283)

- **Purpose**: Core key registration logic. Computes deterministic `keyId`, checks for active duplicates, stores all fields, conditionally initializes gas policy for custodial keys.
- **Critical details**:
  - Duplicate check uses `sKey.isActive` (not `validUntil`) — revoked keys can be re-registered.
  - `masterKey = (limits == 0)` — sole mechanism for master key designation.
  - Custodial keys trigger external call: `IUserOpPolicy(GAS_POLICY).initializeGasPolicy(address(this), keyId, uint256(limits))`.
  - `idKeys[id] = keyId` then `id++` in unchecked block.

#### Key Lifecycle State Machine

```
[Not Registered] --registerKey()--> [Active Session Key] --revokeKey()--> [Revoked (data zeroed)]
                                    |                                      |
                                    |--pauseKey()--> [Paused]              |--registerKey()--> [Active]
                                    |                |
                                    |<--unpauseKey()--|
                                    |
                                    |--updateKeyData()--> [Active, extended]

[Not Registered] --initialize()/_addKey()--> [Active Master Key] --pauseKey()--> [Paused Master]
                                                                  --unpauseKey()--> [Active Master]
```

Master keys CANNOT be revoked through `revokeKey()` (blocked by `validateKeyBefore()`). They can only be replaced during recovery.

#### Capacity Constraints

| Data Structure | Max Size | Enforcement |
|---|---|---|
| `permissions[keyId].canExecute` (Bytes32Set) | 2048 entries | `update(..., 2048)` |
| `spendStore[keyId].tokens` (AddressSet) | 64 entries | `add(_token, 64)` |
| `id` counter | uint256 max | Practically infinite |
| `KeyData.limits` (tx quota) | uint48 max (281T) | Type constraint |
| `TokenSpendPeriod.limit` | uint256 max | Type constraint |

---

### Module C: OPF7702 Signature Validation

**FUNCTION: `_validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)`**
- **Purpose**: ERC-4337 signature validation entry point. Decodes `(KeyType, bytes)` envelope from `userOp.signature`, dispatches to type-specific validators (EOA/WEBAUTHN/P256/P256NONKEY).
- **Key observations**:
  - EOA: `signer == address(this)` → immediate success (7702 delegated EOA, master key by definition).
  - Master key: returns `SIG_VALIDATION_SUCCESS` (no time bounds packed).
  - Session key: validates via `isValidKey()` → only recognizes `execute(bytes32,bytes)` selector `0xe9ae5c53`.
  - Session key validation chain: `isValidKey()` → `_validateExecuteCall()` → `_validateCall()` per call in batch.

**FUNCTION: `_validateCall(KeyData storage sKey, bytes32 _keyId, address _target, uint256 _value, bytes calldata _data)`**
- **Purpose**: Per-call permission enforcement for session keys.
- **Key observations**:
  - Blocks `target == address(this)` — session keys cannot self-call.
  - Checks `hasQuota()`, `_isCanCall()`, token spend, then `consumeQuota()`.
  - `_isCanCall()` checks against packed set: exact match → `ANY_FN_SEL` → `ANY_TARGET` + selector → `ANY_TARGET` + `ANY_FN_SEL`.

**FUNCTION: `_isTokenSpend()`**
- **Purpose**: Recognizes token-spending function selectors.
- **Recognized selectors**: `transfer(0xa9059cbb)`, `transferFrom(0x23b872dd)`, `approve(0x095ea7b3)`, plus native ETH transfers.

**FUNCTION: `isValidSignature(bytes32 hash, bytes calldata signature)` (ERC-1271)**
- **Purpose**: On-chain signature validation.
- **Critical observation**: Only validates **master keys** — session keys are explicitly excluded to prevent Permit2 bypass.
- `_decodeWebAuthn1271()` is `external pure` — used via `try/catch` for safe ABI decoding.

---

### Module D: OPF7702Recoverable + OPFMain

**FUNCTION: `initialize(KeyDataReg, KeyDataReg, bytes32, bytes)`** (Lines 101-127)
- **Purpose**: One-time account setup. Clears storage, validates master key, verifies EIP-712 signature from EOA owner, registers master key, optionally registers session key, initializes guardians.
- **Flow**: `initializer` modifier → `_requireForExecute()` → `_clearStorage()` → `_masterKeyValidation()` → `getDigestToInit()` → `_checkSignature()` → `_addKey()` → optional `registerKey()` → `RECOVERY_MANAGER.initializeGuardians()`.
- **Key observations**:
  - `INIT_TYPEHASH = 0x82dc6262fca76342c646d126714aa4005dfcd866448478747905b2e7b9837183`
  - Session key registration is optional (checked by `_sessionKeyData.key.length > 0`).
  - `_clearStorage()` runs before key registration to ensure clean slate.

**FUNCTION: `completeRecovery(bytes[] calldata _signatures)`** (Lines 137-143)
- **Purpose**: Finalizes guardian-based recovery.
- **Critical observation**: **NO access control** — anyone can call. Security is delegated entirely to `RECOVERY_MANAGER.completeRecovery()` which validates timelock and guardian signatures.
- **Flow**: `RECOVERY_MANAGER.completeRecovery()` → `_deleteOldKeys()` → `_setNewMasterKey()`.

**FUNCTION: `_deleteOldKeys()`** (Lines 146-154)
- **Purpose**: Removes old master key during recovery.
- **Critical observation**: Only deletes `keys[keyId]` and `idKeys[0]` — does NOT delete `permissions[keyId]` or `spendStore[keyId]` for the old key.
- The `id` counter is NOT decremented.

**FUNCTION: `_setNewMasterKey(KeyDataReg memory recoveryOwner)`** (Lines 158-174)
- **Purpose**: Registers new master key after recovery. Uses `_addMasterKey()` (private) instead of `_addKey()` (internal).
- **Key observation**: Bypasses `id` counter increment — the new master key reuses index 0 without advancing the counter.

**Master key constraints** (enforced by `_masterKeyValidation`):
1. `key.length > 0`
2. `limits == 0` (unlimited quota)
3. `validAfter == 0` (immediately active)
4. `validUntil == type(uint48).max` (never expires)
5. `keyControl == KeyControl.Self` (cannot be custodial)
6. `keyType != P256` and `keyType != P256NONKEY` (must be EOA or WEBAUTHN)

**FUNCTION: `upgradeProxyDelegation(address newImplementation)`** (OPFMain.sol Lines 57-60)
- **Purpose**: Updates the EIP-7702 delegation target.
- **Key observation**: Session keys cannot call this (blocked by `_validateCall` target == address(this) check).

---

### Module E: SocialRecoveryManager

**Contract**: `SocialRecoveryManager` (SocialRecover.sol)
**Architecture**: Standalone contract managing guardians and recovery for all OPF7702 accounts.
**Immutable timelocks**: `recoveryPeriod`, `lockPeriod`, `securityPeriod`, `securityWindow`.

#### Guardian Lifecycle

```
[None] --proposeGuardian()--> [Proposed] --confirmGuardianProposal()--> [Active]
                                                                        |
                              [Cancelled] <--cancelGuardianProposal()---|
                                                                        |
                              [Revocation Pending] <--revokeGuardian()--|
                                                                        |
                              [Removed] <--confirmGuardianRevocation()--|
```

- **Proposal**: `proposeGuardian()` — account-only (`msg.sender == _account`), rejects duplicates.
- **Confirmation**: `confirmGuardianProposal()` — account-only, requires `securityPeriod` elapsed within `securityWindow`.
- **Revocation**: Two-step: `revokeGuardian()` → `confirmGuardianRevocation()` (both account-only, with timelock).

#### Recovery Flow

**FUNCTION: `startRecovery(address _account, KeyDataReg calldata _newOwner)`**
- **Access**: Guardian-only. Checks `isGuardian()` for `msg.sender.computeHash()`.
- **Effects**: Stores `recoveryData[_account]`, locks wallet via `_setWalletLock(block.timestamp + lockPeriod)`.

**FUNCTION: `completeRecovery(address _account, bytes[] calldata _signatures)`**
- **Access**: **NO msg.sender check** — anyone can call directly.
- **Security**: Validated by `_validateSignatures()` which requires quorum of guardian signatures.
- **Quorum**: `ceil(guardianCount / 2)` — majority required.
- **Timelock**: `block.timestamp >= recoveryData.executeAfter` (recoveryPeriod must have passed).
- **Effects**: Clears recovery data, unlocks wallet, returns `KeyDataReg` for new master key.

**FUNCTION: `_validateSignatures(address _account, bytes[] calldata _signatures)`**
- **Purpose**: Verifies ECDSA signatures from distinct active guardians in strictly ascending guardian-hash order.
- **Key observations**:
  - `guardianHash > lastGuardianHash` — strict ascending prevents duplicates.
  - Uses `ECDSA.recover` from OpenZeppelin (handles s-value malleability).
  - Returns `false` (not reverts) on invalid signatures.

---

### Module F: GasPolicy

**Contract**: `GasPolicy is IUserOpPolicy` (GasPolicy.sol)
**Architecture**: Singleton policy enforcement. Double mapping `gasLimitConfigs[configId][account]`.

**FUNCTION: `checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)`** (Lines 100-139)
- **Purpose**: Runtime gas budget enforcement during ERC-4337 validation.
- **Key observations**:
  - `msg.sender != userOp.sender` returns `VALIDATION_FAILED` (not revert) — prevents third-party budget draining.
  - Computes gas envelope from all 5 legs: preVerificationGas, verificationGasLimit, callGasLimit, paymasterVerificationGas, postOpGas.
  - **Optimistic accounting**: Increments `gasUsed` even if UserOp later fails. Gas budget is monotonically consumed.
  - Never reverts — all failure paths return `VALIDATION_FAILED`.
  - `SAFETY_BPS = 12_000` (+20% safety margin on auto-computed gas envelopes).

**FUNCTION: `initializeGasPolicy(address, bytes32, bytes16)` (manual overload)** (Lines 149-160)
- **Purpose**: Manual initialization with explicit gas limit.
- Requires `account == msg.sender`, not already initialized, non-zero limit.

**FUNCTION: `initializeGasPolicy(address, bytes32, uint256)` (auto overload)** (Lines 172-195)
- **Purpose**: Auto-initialization using default gas estimates.
- Formula: `gasLimit = ceil((DEFAULT_PVG + DEFAULT_VGL + DEFAULT_CGL + DEFAULT_PMV + DEFAULT_PO) * 1.2) * limit`
- Limit constraint: `limit > 0 && limit <= type(uint32).max`.

---

### Module G: WebAuthn Verifiers

**WebAuthnVerifier.sol** — All `view` functions, no state-changing entry points.
- `verifySignature()`: WebAuthn verification via Solady's `WebAuthn.verify`.
- `verifyP256Signature()`: Direct P256 verification via `P256.verifySignature`.

**WebAuthnVerifierV2.sol** — All `view` functions, no state-changing entry points.
- Alternative verifier accepting `bytes32` (uint256-friendly) coordinates instead of `uint256`.
- Internal `toBytes()` helper converts `bytes32` challenge to `bytes memory`.

---

## Phase 3 — Global System Understanding

### 3.1 End-to-End Workflows

#### Workflow 1: Account Initialization
```
User → Bundler → EntryPoint.handleOps()
  → Account.validateUserOp() [validateSignature: EOA recovery → SIG_VALIDATION_SUCCESS]
  → Account.execute(mode_1, [Call(address(this), 0, initialize(...))])
    → _requireForExecute() [msg.sender == entryPoint ✓]
    → initialize()
      → initializer modifier [_initialized == 0 ✓]
      → _requireForExecute() [msg.sender == address(this) via execute self-call ✓]
      → _clearStorage() [zero 5 slots]
      → _masterKeyValidation() [limits=0, validAfter=0, validUntil=max, Self, EOA/WEBAUTHN]
      → getDigestToInit() → _checkSignature() [ECDSA verify EOA owner signed init params]
      → _addKey(_keyData) [master key at id=0]
      → registerKey(_sessionKeyData) [optional session key at id=1]
      → RECOVERY_MANAGER.initializeGuardians() [set initial guardian]
```

#### Workflow 2: Session Key Operation
```
User → Bundler → EntryPoint.handleOps()
  → Account.validateUserOp()
    → _validateSignature() [decode (KeyType, bytes)]
      → type-specific validator (EOA/WEBAUTHN/P256)
        → _keyValidation() [isRegistered + isActive + time bounds]
        → isValidKey() [session key path: validates execute selector 0xe9ae5c53]
          → _validateExecuteCall() [decode mode + Call[]]
            → _validateCall() per call:
              → block target == address(this)
              → hasQuota()
              → _isCanCall() [check packed whitelist]
              → _isTokenSpend() [check transfer/approve patterns]
              → _manageTokenSpend() [period accounting, limit check]
              → consumeQuota() [decrement limits]
    → IF custodial: GAS_POLICY.checkUserOpPolicy() [gas budget check]
    → Return packed validationData (sigFailed | validAfter | validUntil)
  → Account.execute(mode, executionData)
    → _requireForExecute() → _run() → _execute() per call
```

#### Workflow 3: Social Recovery
```
Guardian → SocialRecoveryManager.startRecovery(_account, _newOwner)
  → isGuardian check
  → Store recoveryData[_account] = (newOwner, executeAfter=now+recoveryPeriod, nonce++)
  → Lock wallet (lock = now + lockPeriod)

[Wait recoveryPeriod]

Anyone → Account.completeRecovery(_signatures)
  → RECOVERY_MANAGER.completeRecovery(address(this), _signatures)
    → _validateSignatures() [quorum of guardian sigs, ascending hash order]
    → Timelock check [block.timestamp >= executeAfter]
    → Clear recovery data, unlock wallet
    → Return KeyDataReg
  → _deleteOldKeys() [delete keys[oldKeyId], delete idKeys[0]]
  → _setNewMasterKey(recoveryOwner)
    → _masterKeyValidation()
    → _addMasterKey() [write to idKeys[0], bypass id counter]
```

#### Workflow 4: EIP-7702 Upgrade
```
Owner → Bundler → EntryPoint.handleOps()
  → Account.execute(mode_1, [Call(address(this), 0, upgradeProxyDelegation(newImpl))])
    → _requireForExecute()
    → upgradeProxyDelegation(newImpl)
      → _requireForExecute()
      → LibEIP7702.upgradeProxyDelegation(newImpl)
```

### 3.2 Trust Boundary Map

```
┌─────────────────────────────────────────────────────────────┐
│                     TRUSTED ZONE                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  EntryPoint   │  │ RECOVERY_MGR │  │   GAS_POLICY     │  │
│  │  (immutable)  │  │  (immutable)  │  │   (immutable)    │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         │                  │                    │             │
│  ┌──────▼──────────────────▼────────────────────▼──────────┐│
│  │              OPFMain (Account)                           ││
│  │  ┌─────────────┐ ┌──────────┐ ┌────────────────────┐   ││
│  │  │  Master Key  │ │ Session  │ │  WebAuthnVerifier  │   ││
│  │  │  (id=0)     │ │  Keys    │ │  (immutable/upgr.) │   ││
│  │  └─────────────┘ └──────────┘ └────────────────────┘   ││
│  └──────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                         │
            ─────────────┼──────────────── Trust Boundary
                         │
┌─────────────────────────────────────────────────────────────┐
│                   SEMI-TRUSTED ZONE                          │
│  ┌──────────────┐  ┌──────────────────┐                     │
│  │  Guardians    │  │  External Targets │                    │
│  │  (quorum)     │  │  (via execute)    │                    │
│  └──────────────┘  └──────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
                         │
            ─────────────┼──────────────── Trust Boundary
                         │
┌─────────────────────────────────────────────────────────────┐
│                   UNTRUSTED ZONE                             │
│  ┌──────────────┐  ┌──────────────┐                         │
│  │  Anyone       │  │  Bundlers    │                         │
│  │  (ETH send,   │  │  (relay ops) │                         │
│  │  completRecov)│  │              │                         │
│  └──────────────┘  └──────────────┘                         │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 System-Wide Critical Invariants

1. **Master key is always at `idKeys[0]`** — Set during `initialize()` (first `_addKey` call), preserved during recovery (`_setNewMasterKey` writes to `idKeys[0]`).

2. **`masterKey == true` iff `limits == 0`** — Enforced in `_addKey()` line 258: `sKey.masterKey = (_keyData.limits == 0)`. `registerKey()` enforces `limits > 0`, preventing master key creation through that path.

3. **Session keys cannot self-call** — Enforced at two levels: `_validateCall()` blocks `target == address(this)`, and `checkTargetAddress()` blocks `address(this)` at permission-setting time.

4. **Session keys excluded from ERC-1271** — `isValidSignature()` only validates master keys, preventing Permit2 bypass via session key signatures.

5. **`execute()` is non-reentrant** — `ReentrancyGuard` modifier on `execute()`. Sub-calls within the batch cannot re-enter `execute`.

6. **At most 9 low-level calls per `execute`** — `MAX_TX = 9`, enforced by counter in `_run()`.

7. **Mode-3 always flattens to mode-1** — Line 88: `mode = mode_1` before recursion. Max recursion depth is 2.

8. **Gas budget is monotonically consumed** — `gasUsed` in `GasPolicy` is incremented but never decremented. Optimistic accounting means even failed UserOps consume budget.

9. **Guardian signatures must be in ascending hash order** — `_validateSignatures()` enforces `guardianHash > lastGuardianHash`, preventing duplicate signers.

10. **`_clearStorage` does NOT clear Initializable slot** — `baseSlot+6` persists across storage clears. The `initializer` modifier independently manages re-initialization.

11. **Recovery does NOT clear permissions/spendStore for old key** — `_deleteOldKeys()` only deletes `keys[keyId]` and `idKeys[0]`. Old key's permissions and spend data remain in storage (orphaned but unreferenceable since the keyId is no longer active).

12. **Recovery bypasses `id` counter** — `_setNewMasterKey()` uses `_addMasterKey()` (private) which does not increment `id`. The new master key at `idKeys[0]` reuses the slot without advancing the counter.

### 3.4 Complexity / Fragility Clusters

#### Cluster 1: Signature Validation Dispatch (OPF7702.sol)
- **Complexity**: 4 key types x 2 paths (master/session) x multiple validation steps.
- **Why fragile**: Each key type has subtly different encoding, length checks, and verification logic. A mismatch in any step could allow invalid signatures to pass or valid ones to be rejected.

#### Cluster 2: Session Key Permission Model (KeysManager + OPF7702)
- **Complexity**: `_validateCall()` checks: self-call block → quota → can-call whitelist (4-level fallback: exact → ANY_FN_SEL → ANY_TARGET+sel → ANY_TARGET+ANY_FN_SEL) → token spend → quota consumption.
- **Why fragile**: The `ANY_TARGET` and `ANY_FN_SEL` wildcards create a wide permission surface. Token spend detection relies on recognizing specific selectors (`transfer`, `transferFrom`, `approve`) — custom token functions that move tokens would not be caught.

#### Cluster 3: Recovery + Key Replacement (OPF7702Recoverable + SocialRecover)
- **Complexity**: Two contracts, cross-contract calls, timelocks, signature validation, key deletion + re-creation.
- **Why fragile**: `completeRecovery()` has no access control on the account side. The security relies entirely on the recovery manager's signature validation and timelock enforcement. The `_deleteOldKeys()` incomplete cleanup (no permissions/spendStore deletion) leaves orphaned data.

#### Cluster 4: Gas Policy Accounting (GasPolicy + OPF7702)
- **Complexity**: Optimistic accounting, 5 gas legs, two init paths (manual/auto), safety margin calculation.
- **Why fragile**: The gas budget is consumed even when UserOps fail. The `checkUserOpPolicy` never reverts (returns failure codes), so a misconfigured caller that ignores the return value would bypass gas limits.

#### Cluster 5: Storage Layout + Upgradeable Addresses (BaseOPF7702 + UpgradeAddress + ERC7201)
- **Complexity**: ERC-7201 namespaced storage + MSB-flag override slots + forked Initializable + `layout at` directive.
- **Why fragile**: Multiple storage mechanisms coexist. `_clearStorage()` selectively zeroes some slots but not others. The `setEntryPoint()` function creates a circular dependency (changing the authority that controls changes).

#### Cluster 6: ERC-7821 Batch Execution + Recursion (Execution.sol)
- **Complexity**: Two modes (flat + nested), recursive dispatch, counter accumulation, address(0) translation.
- **Why fragile**: The `address(0) → address(this)` translation combined with self-call ability means batch operations can trigger administrative functions on the account itself. The counter is stack-passed, making it correct but harder to reason about across recursion levels.

### 3.5 Cross-Contract Dependency Map

```
SocialRecoveryManager ←──── OPF7702Recoverable
  ↑ initializeGuardians()       ↓ completeRecovery()
  ↑ (bidirectional)             ↓
  ↓ keyAt(0), isKeyActive()     ↑ _deleteOldKeys() + _setNewMasterKey()

GasPolicy ←──── KeysManager._addKey() [custodial init]
  ↑ initializeGasPolicy()
  ↑
  ↓ checkUserOpPolicy() ←──── OPF7702._validateSignature() [runtime check]

WebAuthnVerifier ←──── OPF7702._validateKeyTypeWEBAUTHN()
  ↑ verifySignature()
  ↑
  ↓ verifyP256Signature() ←──── OPF7702._validateKeyTypeP256()

EntryPoint ←──── All validate/execute flows
  ↑ validateUserOp()
  ↑ execute()
```

### 3.6 Shared State Summary

| State Variable | Written by | Read by (KeysManager) | Read by (OPF7702) |
|---|---|---|---|
| `id` | `_addKey` | `keyCount()`, `keyAt()` | — |
| `idKeys` | `_addKey`, `_deleteOldKeys`, `_setNewMasterKey` | `keyAt()` | `_deleteOldKeys()` |
| `keys` | `_addKey`, `_addMasterKey`, `_revoke`, `updateKeyData`, `pauseKey`, `unpauseKey` | `validateKeyBefore`, `getKey`, `isRegistered`, `isKeyActive` | `_keyValidation`, `_validateCall`, all signature validators |
| `permissions` | `_setCanCall`, `clearExecutePermissions` | `canExecutePackedInfos`, `hasCanCall` | `_isCanCall` |
| `spendStore` | `_setTokenSpend`, `_removeTokenSpend`, `clearSpendPermissions` | `spendTokens`, `hasTokenSpend` | `_isTokenSpend`, `_manageTokenSpend` |

---

## Files Analyzed

### Core Contracts
- `src/core/BaseOPF7702.sol`
- `src/core/Execution.sol`
- `src/core/KeysManager.sol`
- `src/core/OPF7702.sol`
- `src/core/OPF7702Recoverable.sol`
- `src/core/OPFMain.sol`

### Utility Contracts
- `src/utils/SocialRecover.sol`
- `src/utils/GasPolicy.sol`
- `src/utils/WebAuthnVerifier.sol`
- `src/utils/WebAuthnVerifierV2.sol`
- `src/utils/ERC7201.sol`

### Libraries
- `src/libs/KeysManagerLib.sol`
- `src/libs/KeyDataValidationLib.sol`
- `src/libs/SigLengthLib.sol`
- `src/libs/Initializable.sol`
- `src/libs/UpgradeAddress.sol`

### Interfaces
- `src/interfaces/IKey.sol`
- `src/interfaces/IKeysManager.sol`
- `src/interfaces/ISocialRecoveryManager.sol`
- `src/interfaces/IPolicy.sol`
- `src/interfaces/IWebAuthnVerifier.sol`
- `src/interfaces/IERC7821.sol`
- `src/interfaces/IExecution.sol`
- `src/interfaces/iOPF7702Recoverable.sol`
