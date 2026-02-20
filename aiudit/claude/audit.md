# Vulnerability Report: Openfort 7702 Account

**Date:** 2026-02-19
**Auditor:** Claude Opus 4.6 (Automated Security Analysis)
**Scope:** `src/core/`, `src/utils/`, `src/libs/` — Openfort EIP-7702 + ERC-4337 smart wallet
**Methodology:** Source-level verification of 14 candidate findings from codebase exploration, cross-referenced against `audit/Progress/FixFile.txt`

---

## Executive Summary

After line-by-line verification of 14 candidate vulnerabilities across 9 source files, **8 findings were confirmed** and **6 were refuted**. Of the confirmed findings:

| Severity | Count | Summary |
|----------|-------|---------|
| **HIGH** | 1 | Token spend bypass via unrecognized selectors |
| **MEDIUM** | 4 | Guardian griefing, master key pause, no timelocks, stale storage |
| **LOW** | 2 | Ghost key activation, stale idKeys entries |
| **INFORMATIONAL** | 1 | `completeRecovery()` callable by anyone (by design) |

No **CRITICAL** findings survived verification. The original V-1 (P256 master key fast-path) was refuted because `_masterKeyValidation()` explicitly rejects P256/P256NONKEY as master key types.

---

## Findings Summary

| ID | Title | Severity | Status | File |
|----|-------|----------|--------|------|
| V-1 | P256 Master Key Missing Fast-Path | ~~CRITICAL~~ | **REFUTED** | `OPF7702.sol` |
| V-2 | Token Spend Bypass via Unrecognized Selectors | **HIGH** | **CONFIRMED** | `OPF7702.sol:479-512` |
| V-3 | Incomplete Key Cleanup on Recovery | ~~HIGH~~ LOW | **PARTIALLY CONFIRMED** | `OPF7702Recoverable.sol:146-154` |
| V-4 | Single Guardian Wallet Lock Griefing | **MEDIUM** | **CONFIRMED** | `SocialRecover.sol:280-323` |
| V-5 | `pauseKey()` Can Pause Master Key | **MEDIUM** | **CONFIRMED** | `KeysManager.sol:509-516` |
| V-6 | No Timelock on Critical Upgrades | **MEDIUM** | **CONFIRMED** | `BaseOPF7702.sol:91-127`, `OPFMain.sol:57-60` |
| V-7 | GasPolicy uint128 Overflow | ~~HIGH~~ | **REFUTED** | `GasPolicy.sol` |
| V-8 | `unpauseKey()` Activates Non-Existent Keys | **LOW** | **CONFIRMED** | `KeysManager.sol:523-530` |
| V-9 | `revokeKey()` Leaves Stale idKeys | **LOW** | **CONFIRMED** | `KeysManager.sol:203-214` |
| V-10 | Re-Registration of Revoked Keys | ~~MEDIUM~~ | **REFUTED** (by design) | `KeysManager.sol` |
| V-11 | Recovery ID Counter Bypass | ~~MEDIUM~~ | **REFUTED** (by design) | `OPF7702Recoverable.sol` |
| V-12 | Guardian Lifecycle Race Conditions | ~~MEDIUM~~ | **REFUTED** | `SocialRecover.sol` |
| V-13 | `_clearStorage()` Doesn't Clear Mappings | **MEDIUM** | **CONFIRMED** | `BaseOPF7702.sol:140-160` |
| V-14 | `completeRecovery()` No Access Control | **INFO** | **BY DESIGN** | `OPF7702Recoverable.sol:137-143` |

---

## Detailed Findings

---

### V-2: Token Spend Bypass via Unrecognized ERC-20 Selectors
✅ Valid
**Severity:** HIGH
**File:** `src/core/OPF7702.sol:479-512`
**Status:** CONFIRMED
**Prior Audit Reference:** Partially addressed by OPF-4 and OPF-6 (off-chain only)

#### Description

The `_isTokenSpend()` function recognizes only four selector patterns: empty calldata (native ETH), `transfer(0xa9059cbb)`, `transferFrom(0x23b872dd)`, and `approve(0x095ea7b3)`. Any other selector leaves `tokenAmout = 0`, which passes `_manageTokenSpend()` without incrementing the spend counter.

```solidity
// OPF7702.sol:493-507
uint256 tokenAmout;  // initialized to 0

if (fnSel == EMPTY_CALLDATA_FN_SEL) {
    tokenAmout = _value;
    _target = NATIVE_ADDRESS;
} else if (fnSel == 0xa9059cbb) {
    tokenAmout = uint256(LibBytes.load(_data, 0x24));
} else if (fnSel == 0x23b872dd) {
    tokenAmout = uint256(LibBytes.load(_data, 0x44));
} else if (fnSel == 0x095ea7b3) {
    tokenAmout = uint256(LibBytes.load(_data, 0x24));
}
// For any other selector: tokenAmout remains 0

if (!_manageTokenSpend(_keyId, _target, tokenAmout)) return false;
// ^^ passes with tokenAmout=0 as long as spent < limit
```

#### Impact

If a session key is configured with:
1. A `canExecute` permission for `(tokenAddress, nonStandardSelector)`, AND
2. A token spend rule for `tokenAddress`

The session key can invoke non-standard functions (e.g., `permit()`, `increaseAllowance()`, or proxy fallback functions) on the token contract. The spend counter is NOT incremented, effectively allowing unlimited token operations through unrecognized selectors.

#### PoC Scenario

1. Admin registers session key with `canExecute(USDC, 0x12345678)` and `tokenSpend(USDC, 1000 USDC/day)`
2. Session key calls `USDC.0x12345678(...)` — a non-standard function
3. `_isTokenSpend` is invoked (because `hasTokenSpend(keyId, USDC)` is true)
4. `tokenAmout = 0` since `0x12345678` is unrecognized
5. `_manageTokenSpend(keyId, USDC, 0)` returns `true` — spend counter unchanged
6. Session key repeats indefinitely without hitting the spend limit

#### Mitigation Note

OPF-6 states this is mitigated off-chain: "If SpendTokenInfo is set, the system automatically installs the canonical ERC-20 spending selectors and rejects any additional or unrelated selectors." However, **no on-chain enforcement exists**. The `setCanCall()` function does not cross-check against `spendStore` entries.

#### Recommendation

**Option A (Strict):** In `_isTokenSpend()`, return `false` for any unrecognized selector when a token spend rule exists for `_target`. This blocks all non-standard calls to tokens with spend limits.

```solidity
// After the if/else chain for known selectors:
if (tokenAmout == 0 && fnSel != EMPTY_CALLDATA_FN_SEL) {
    return false; // Block unrecognized selectors on tracked tokens
}
```

**Option B (Defensive):** Add an on-chain check in `setCanCall()` that rejects non-standard selectors for tokens that have spend rules.

---

### V-4: Single Guardian Wallet Lock Griefing

**Severity:** MEDIUM
**File:** `src/utils/SocialRecover.sol:280-323`
**Status:** CONFIRMED

#### Description

`startRecovery()` requires only a single active guardian to initiate, immediately locking the wallet for the full `lockPeriod`. During lock, guardian management functions (`proposeGuardian`, `revokeGuardian`, `confirmGuardianProposal`, `confirmGuardianRevocation`) all revert with `OPF7702Recoverable__AccountLocked`.

```solidity
// SocialRecover.sol:280-284
function startRecovery(address _account, IKey.KeyDataReg calldata _recoveryKey)
    external override
{
    if (!isGuardian(_account, msg.sender.computeHash())) {
        revert OPF7702Recoverable__MustBeGuardian();
    }
    // ... only single guardian check, no quorum ...
    _setLock(_account, block.timestamp + lockPeriod);
}
```

#### Impact

A single rogue guardian can grief the wallet owner through a cycle of:
1. Rogue guardian calls `startRecovery()` -> wallet locks
2. Owner calls `cancelRecovery()` -> wallet unlocks
3. Owner initiates `revokeGuardian(rogueGuardian)` -> securityPeriod countdown starts
4. Rogue guardian immediately calls `startRecovery()` again -> wallet locks
5. Owner cannot `confirmGuardianRevocation()` while locked

The owner CAN mitigate this by batching `cancelRecovery()` + `confirmGuardianRevocation()` in a single `execute()` call (after the security period has elapsed), since `execute()` is not blocked by the lock. However, this requires user sophistication and awareness.

#### Recommendation

Consider requiring a minimum quorum (e.g., 2 guardians or ceil(n/3)) to initiate recovery, rather than allowing any single guardian. Alternatively, add a grace period after `cancelRecovery()` during which `startRecovery()` cannot be called again (cooldown).

---

### V-5: `pauseKey()` Can Pause Master Key (Self-DOS)

**Severity:** MEDIUM
**File:** `src/core/KeysManager.sol:509-516`
**Status:** CONFIRMED
✅ Valid
#### Description

`pauseKey()` has no guard against pausing the master key:

```solidity
// KeysManager.sol:509-516
function pauseKey(bytes32 _keyId) public {
    _requireForExecute();
    KeyData storage sKey = keys[_keyId];
    if (!sKey.isActive) revert KeyManager__KeyAlreadyPaused();
    sKey.isActive = false;  // Master key can be paused!
    emit KeyPaused(_keyId);
}
```

After pausing, `_keyValidation()` returns `false` because `sKey.isActive == false`. The master key owner is locked out — signature validation fails for all subsequent UserOps.

#### Impact

Self-DOS: the wallet owner inadvertently (or via a malicious batched call) pauses their master key. All master-key-signed operations fail. Recovery is possible through `completeRecovery()` (guardian-based social recovery), which replaces the master key without requiring the old key to be active.

#### Recommendation

Add a master key guard to `pauseKey()`:
```solidity
function pauseKey(bytes32 _keyId) public {
    _requireForExecute();
    KeyData storage sKey = keys[_keyId];
    if (sKey.masterKey) revert KeyManager__CannotPauseMasterKey();
    if (!sKey.isActive) revert KeyManager__KeyAlreadyPaused();
    sKey.isActive = false;
    emit KeyPaused(_keyId);
}
```

---

### V-6: No Timelock on Critical Infrastructure Upgrades

**Severity:** MEDIUM
**File:** `src/core/BaseOPF7702.sol:91-127`, `src/core/OPFMain.sol:57-60`
**Status:** CONFIRMED

#### Description

Four critical setter functions execute instantly without timelock or multi-sig delay:

| Function | File | Effect |
|----------|------|--------|
| `setEntryPoint()` | `BaseOPF7702.sol:91` | Changes the trusted EntryPoint — controls which contract can dispatch UserOps |
| `setWebAuthnVerifier()` | `BaseOPF7702.sol:105` | Changes the signature verifier — controls what signatures are accepted |
| `setGasPolicy()` | `BaseOPF7702.sol:119` | Changes the gas policy — controls session key gas budgets |
| `upgradeProxyDelegation()` | `OPFMain.sol:57` | Replaces the entire implementation — full code takeover |

All are gated by `_requireForExecute()` (self-call or EntryPoint), meaning only master key holders can invoke them. However, if a master key is temporarily compromised (e.g., via phishing), these changes are irreversible without recovery.

#### Impact

A compromised master key can instantly:
- Point the EntryPoint to a malicious contract (hijack all future operations)
- Replace the WebAuthn verifier (accept any signature)
- Upgrade the proxy to a malicious implementation (full takeover)

With a timelock, guardians or the legitimate owner would have a window to cancel the malicious change.

#### Recommendation

Implement a 2-step process with a configurable delay for `setEntryPoint`, `setWebAuthnVerifier`, and `upgradeProxyDelegation`:
1. `propose<Change>(newAddress)` — stores the proposal with a timestamp
2. `confirm<Change>()` — executes after the timelock elapses

At minimum, `upgradeProxyDelegation` should have a timelock since it enables full code replacement.

---

### V-8: `unpauseKey()` Activates Non-Existent Keys

**Severity:** LOW
**File:** `src/core/KeysManager.sol:523-530`
**Status:** CONFIRMED

#### Description

```solidity
// KeysManager.sol:523-530
function unpauseKey(bytes32 _keyId) public {
    _requireForExecute();
    KeyData storage sKey = keys[_keyId];
    if (sKey.isActive) revert KeyManager__KeyAlreadyActive();
    sKey.isActive = true;  // Sets isActive on a zeroed struct
    emit KeyUnpaused(_keyId);
}
```

For a `_keyId` that was never registered, `keys[_keyId]` is a zeroed struct where `isActive == false`. The check passes, and `isActive` is set to `true` on an otherwise empty struct (all other fields are zero/default).

#### Impact

**Low.** The ghost key cannot be exploited because `_keyValidation()` checks both `sKey.isRegistered()` (which requires `validUntil != 0`) AND `sKey.isActive`. Since `validUntil == 0` for the ghost key, validation still fails. However, `isKeyActive(_keyId)` would incorrectly return `true` for a non-existent key, potentially confusing off-chain monitoring.

#### Recommendation

Add a registration check:
```solidity
function unpauseKey(bytes32 _keyId) public {
    _requireForExecute();
    KeyData storage sKey = keys[_keyId];
    if (sKey.validUntil == 0) revert KeyManager__KeyNotRegistered();
    if (sKey.isActive) revert KeyManager__KeyAlreadyActive();
    sKey.isActive = true;
    emit KeyUnpaused(_keyId);
}
```

---

### V-9: `revokeKey()` Leaves Stale `idKeys` Entries

**Severity:** LOW
**File:** `src/core/KeysManager.sol:203-214`
**Status:** CONFIRMED

#### Description

When `revokeKey()` is called, it invokes `_revoke(sKey)` to clear the `KeyData` struct and then clears permissions and spend data. However, `idKeys[index]` still maps the old index to the now-revoked `keyId`. The `id` counter is never decremented.

```solidity
// KeysManager.sol:291-299 (_revoke)
function _revoke(KeyData storage _sKey) internal {
    _sKey.isActive = false;
    _sKey.isDelegatedControl = false;
    _sKey.validUntil = 0;
    _sKey.validAfter = 0;
    _sKey.limits = 0;
    delete _sKey.key;
    delete _sKey.keyType;
    // idKeys[?] NOT cleared
}
```

#### Impact

**Low.** `keyAt(index)` returns the keyId of a revoked key whose `KeyData` is zeroed. Off-chain tools iterating `0..id-1` will see stale entries. No on-chain security impact since the key data is wiped.

#### Recommendation

Document this behavior clearly (monotonic counter for key indices, revoked keys remain in enumeration). Alternatively, zero out the `idKeys` entry during revocation — though this requires tracking the reverse mapping (keyId -> index).

---

### V-13: `_clearStorage()` Cannot Clear Solidity Mappings

**Severity:** MEDIUM
**File:** `src/core/BaseOPF7702.sol:140-160`
**Status:** CONFIRMED
**Prior Audit Reference:** Acknowledged in OPF-5 (re-delegation storage persistence)

#### Description

`_clearStorage()` zeroes specific storage slots via assembly:
- `baseSlot` (= `id` counter, reset to 0)
- `_EP_SLOT`, `_VERIFIER_SLOT`, `_GAS_POLICY_SLOT` (upgrade address slots)
- `baseSlot + 5` (reentrancy guard)

Critically, it does **not** and **cannot** clear the Solidity mappings at:
- `baseSlot+1`: `idKeys` (mapping(uint256 => bytes32))
- `baseSlot+2`: `keys` (mapping(bytes32 => KeyData))
- `baseSlot+3`: `permissions` (mapping(bytes32 => ExecutePermissions))
- `baseSlot+4`: `spendStore` (mapping(bytes32 => SpendStorage))

Solidity mappings store entries at `keccak256(key . slot)`, so zeroing the root slot has no effect on existing entries.

#### Impact

In the EIP-7702 re-delegation scenario:
1. User delegates to Implementation A, initializes with keys/permissions
2. User re-delegates to Implementation B (non-OPF), which writes to storage
3. User re-delegates back to a new OPF implementation
4. `initialize()` calls `_clearStorage()`, resets `id` to 0
5. Old keys, permissions, and spendStore entries from step 1 **persist** in storage

If the same key material is re-registered (same `keyId`), it could inherit stale permissions or spend data from the previous initialization.

#### Mitigation Note

OPF-5 acknowledges this: "If a user chooses to delegate to a non-OPF implementation before returning to OPF, any storage poisoning performed by that third party is outside OPF's ability to prevent." This is inherent to EIP-7702's storage model.

#### Recommendation

- Document that OPF security guarantees apply only when delegating to official OPF implementations from day zero
- During `_addKey()` after re-initialization, explicitly clear `permissions[keyId]` and `spendStore[keyId]` to prevent stale data inheritance
- Consider adding a storage version/nonce that gets checked during key validation, invalidating all pre-existing entries

---

### V-3: Incomplete Key Cleanup on Recovery (Session Keys Survive)

**Severity:** LOW
**File:** `src/core/OPF7702Recoverable.sol:146-154`
**Status:** PARTIALLY CONFIRMED

#### Description

`_deleteOldKeys()` only deletes the master key at index 0:

```solidity
// OPF7702Recoverable.sol:146-154
function _deleteOldKeys() private {
    (bytes32 keyId,) = keyAt(0);
    delete keys[keyId];
    delete idKeys[0];
}
```

Session keys (indices 1, 2, 3, ...) remain fully active with all their permissions and spend rules intact after recovery.

#### Impact

**Low/By Design.** The original hypothesis (stale `permissions`/`spendStore` for the master key) is a non-issue since master keys never have canExecute or spendStore entries. However, session keys registered by the old (potentially compromised) owner survive recovery. Since session keys have independent cryptographic material, this is only exploitable if the attacker also possesses a session key's private key.

#### Recommendation

Consider whether `completeRecovery()` should revoke all existing session keys (clear indices 1..id-1) as a security hardening measure. This prevents any session keys that may have been registered by a compromised master key from remaining active.

---

### V-14: `completeRecovery()` Callable by Anyone

**Severity:** INFORMATIONAL
**File:** `src/core/OPF7702Recoverable.sol:137-143`
**Status:** BY DESIGN

#### Description

`OPF7702Recoverable.completeRecovery()` has no `_requireForExecute()` check — anyone can call it. Security is delegated entirely to `SocialRecoveryManager.completeRecovery()`, which validates:
1. Active recovery exists (`_requireRecovery(_account, true)`)
2. Recovery period elapsed (`r.executeAfter <= block.timestamp`)
3. Correct number of valid guardian signatures (`_validateSignatures`)

This is correct design for social recovery: guardians should be able to complete recovery even if the original owner has lost all access. The guardian signatures ARE the access control.

---

## Refuted Findings

### V-1: P256 Master Key Missing Fast-Path — REFUTED

**Reason:** `_masterKeyValidation()` at `KeysManager.sol:567-574` explicitly rejects `KeyType.P256` and `KeyType.P256NONKEY` as master key types:

```solidity
if (
    _keyData.limits != 0 || _keyData.validAfter != 0
        || _keyData.validUntil != type(uint48).max || _keyData.keyControl != KeyControl.Self
        || _keyData.keyType == KeyType.P256 || _keyData.keyType == KeyType.P256NONKEY
) revert IKeysManager.KeyManager__InvalidMasterKeyReg(_keyData);
```

Since P256 keys can never be registered as master keys, the missing fast-path in `_validateKeyTypeP256()` is a non-issue. Only session keys use P256, and session keys always go through `isValidKey()`.

### V-7: GasPolicy uint128 Overflow — REFUTED

**Reason:** The overflow cannot occur because:
1. `cfg.gasLimit` is always > 0 (enforced at initialization: `if (gasLimit == 0) revert GasPolicy__ZeroBudgets()`)
2. The check `cfg.gasUsed + envelopeUnits > cfg.gasLimit` uses uint256 arithmetic (no overflow)
3. If the check passes (doesn't revert), then `cfg.gasUsed + envelopeUnits <= cfg.gasLimit <= type(uint128).max`
4. Therefore the unchecked `cfg.gasUsed += uint128(envelopeUnits)` cannot overflow

### V-10: Re-Registration of Revoked Keys — REFUTED (By Design)

**Reason:** Re-registration goes through `_addKey()` which requires `!sKey.isActive` (satisfied after revocation) and enforces all validation (timestamps, limits, key type). The re-registered key gets a fresh `idKeys` entry at the current `id` index. This is intentional behavior — the same key material can be re-used for a new session.

### V-11: Recovery ID Counter Bypass — REFUTED (By Design)

**Reason:** `_setNewMasterKey()` intentionally hardcodes `idKeys[0] = keyId` and uses `_addMasterKey()` instead of `_addKey()`. The master key is always at index 0 by design. The `id` counter only tracks session keys (indices 1+). This is correct architecture.

### V-12: Guardian Lifecycle Race Conditions — REFUTED

**Reason:** All guardian state transitions have proper guards:
- `proposeGuardian`: checks `!gi.isActive`, `gi.pending` expiry
- `confirmGuardianProposal`: checks `gi.pending != 0`, time bounds, `!gi.isActive`
- `revokeGuardian`: checks `gi.isActive`, `gi.pending` expiry
- `confirmGuardianRevocation`: checks `gi.pending != 0`, time bounds, `gi.isActive`
- `cancel*`: properly resets `gi.pending = 0`

No concrete path to inconsistent guardian counts was found. The array push/pop with swap-removal in `confirmGuardianRevocation` correctly maintains the index mapping.

---

## Cross-Reference with Prior Audit

| Prior Fix | Relevance to Current Findings |
|-----------|-------------------------------|
| **OPF-4** | Partially addresses V-2 (token spend) — natspec clarification only, no on-chain enforcement |
| **OPF-5** | Directly relevant to V-13 (`_clearStorage` mapping persistence) — acknowledged as out-of-scope |
| **OPF-6** | Partially addresses V-2 — off-chain validation blocks non-standard selectors, but on-chain gap remains |
| **OPF-7** | Not related to current findings (signature length validation) |
| **OPF-9** | Confirms V-1 refutation — `_masterKeyValidation` rejects P256 master keys |

---

## Severity Definitions

| Severity | Definition |
|----------|------------|
| **CRITICAL** | Direct loss of funds or permanent account takeover without extraordinary prerequisites |
| **HIGH** | Bypass of security controls that could lead to fund loss under realistic conditions |
| **MEDIUM** | Security degradation, griefing, or defense-in-depth gaps requiring specific conditions |
| **LOW** | Data inconsistency, cosmetic issues, or theoretical concerns with no direct exploit path |
| **INFORMATIONAL** | Design observations, documentation gaps, or acknowledged behavior |
