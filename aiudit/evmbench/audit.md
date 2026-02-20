# V-001 ✅

## high

## Session keys can bypass the self-call restriction by setting call.target to address(0)

The runtime executor treats Call.target == address(0) as address(this), but the session-key validator only forbids Call.target == address(this). A session key with broad can-call permissions can therefore execute arbitrary self-calls (including changing EntryPoint/verifier/policy), resulting in complete account takeover and loss of funds.

### Affected Locations

#### …/core/Execution.sol

L101-116

Execution._run remaps Call.target == address(0) to address(this) before performing the low-level call:

```solidity
address to = c.target == address(0) ? address(this) : c.target;
```

This creates a special "self-call via zero address" execution path.

#### …/core/OPF7702.sol

L394-414

OPF7702._validateCall only rejects call.target == address(this) and does not reject call.target == address(0).

As a result, a session key can pass validation with call.target = address(0) and later have the executor call into address(this) at runtime.

#### …/core/BaseOPF7702.sol

L87-99

Once a session key can self-call, it can invoke privileged configuration functions guarded by _requireForExecute() via msg.sender == address(this), e.g. setEntryPoint(...) which can point entryPoint() to an attacker-controlled contract.

### Impact

A compromised (or overly-permissive) session key can escalate into full account control. For example, it can self-call setEntryPoint(attackerControlled) and then the attacker-controlled EntryPoint becomes authorized by _requireForExecute(), enabling arbitrary execute(...) calls to drain ETH/tokens and to change key/guardian configuration permanently. This is a direct loss-of-funds vector.

### Proof of concept

1. Victim registers a session key with can-call wildcard (ANY_TARGET, ANY_FN_SEL) (a common pattern for dApp sessions, relying on spend limits).
2. Attacker obtains that session key.
3. Attacker submits a UserOp whose outer call is execute(mode_1, abi.encode([Call({target: address(0), value: 0, data: abi.encodeCall(BaseOPF7702.setEntryPoint, (attackerEntryPoint))})])).
4. Validation passes because call.target != address(this) and (ANY_TARGET, ANY_FN_SEL) matches.
5. Runtime execution remaps address(0) to address(this) and performs the self-call, overriding the EntryPoint.
6. Attacker uses the new EntryPoint to execute arbitrary transfers and drain the account.

### Remediation

Treat Call.target == address(0) as a self-call during validation and forbid it for session keys (e.g., if (call.target == address(this) || call.target == address(0)) return false;). Alternatively, remove the address(0) -> address(this) remapping from Execution._run and require explicit self-call targets (so checkTargetAddress can consistently prevent them), or implement an explicit, separately-authorized self-call mode.

# V-002 ❌ 
```ts
Session keys surviving recovery is by design, not a vulnerability.                                                                                                                                                                                                        
                                                                                                                                                                                                                                                                        
Recovery targets the master key only. It restores account control to the rightful owner by rotating the master key via _deleteOldKeys() + _recovery(). Session key management is a separate concern.
                                                                                                                                                                                                                                                                        
After recovery completes, the new master key owner can immediately call revokeKey() for any compromised session key — this can be batched into a single UserOp as the first post-recovery action.                                                                       
                                                                                                                                                                                                                                                                        
The scenario requires an unlikely conjunction: the master key is lost and a session key is simultaneously compromised and that session key still has remaining quota and hasn't expired. Even in this edge case, the damage is bounded by the session key's permissions   
(canCall restrictions), spend limits (tokenSpend), transaction quota (limits), and validity window (validUntil). Session keys cannot escalate to master-level access — they cannot call registerKey, revokeKey, or any self-call on the account.

Auto-invalidating all session keys on recovery would be a gas-expensive design tradeoff that breaks legitimate active sessions. The current design correctly separates master key recovery from session key lifecycle, and provides revokeKey() as the tool to handle
revocation post-recovery.

Classification: Informational — known design constraint, not a security vulnerability.
```

## high

## Social recovery does not revoke existing session keys, so recovery cannot remove compromised keys

Social recovery does not revoke existing session keys, so recovery cannot remove compromised keys
Completing social recovery only deletes the old master key, leaving all previously registered session keys (and their permissions/spend rules) intact. An attacker holding any pre-recovery session key can continue executing operations after recovery and drain funds.

### Affected Locations

#### …/core/OPF7702Recoverable.sol

L137-174

After completeRecovery, the wallet deletes only the old master key entry (keyAt(0)) and overwrites idKeys[0] with the new master key. No attempt is made to revoke/disable keys at indices 1..id-1, nor to clear their permissions/spend configurations.

#### …/core/OPF7702.sol

L149-170

Session-key validation loads KeyData from the keys mapping by keyId and only requires it to remain registered/active (_keyValidation). Since recovery does not touch session keys, any compromised session key remains valid post-recovery.

### Impact

Users expect social recovery to restore control after compromise. However, if an attacker has obtained a session key before recovery (e.g., through malware, leaked WebAuthn/P256 material, or delegated control), the attacker can continue submitting valid UserOps after recovery and drain ETH/tokens. This defeats the primary safety purpose of the recovery mechanism and can lead to total loss of assets even after a successful recovery event.

### Proof of concept

1. Attacker compromises a victim's session key with a remaining quota and permissive can-call rules.
2. Victim initiates and completes social recovery, rotating the master key.
3. Attacker keeps submitting UserOps signed by the old session key; validation still succeeds because the session key entry in keys[keyId] was never revoked.
4. Attacker drains the account via execute calls that remain allowed for that session key.

### Remediation

On recovery completion, invalidate all non-master keys. If you rely on idKeys as an index of registered keys, iterate for (i = 1; i < id; ++i) and revoke each keys[idKeys[i]], clearing permissions and spendStore for each keyId. If on-chain iteration can become too expensive, introduce an epoch/version (e.g., keysEpoch) that is incorporated into computeKeyId or into validation (reject keys from previous epochs) so recovery can invalidate all existing session keys in O(1).

# V-003  ✅

## high

## Token spend limits are bypassable because spend accounting only recognizes a small set of ERC-20 selectors and only when calling the token contract directly

Token spend limits are bypassable because spend accounting only recognizes a small set of ERC-20 selectors and only when calling the token contract directly
The spend limiter only extracts amounts for transfer, transferFrom, and approve (plus native transfers). Calls that move value via other selectors (e.g., increaseAllowance, permit, token multicall, or custom transfer methods) are treated as spending 0, and calls to non-token contracts (DEX routers, bridges, vaults) are not associated with the underlying tokens at all. This allows session keys to exceed intended spend caps and drain assets.

### Affected Locations

#### …/core/OPF7702.sol

L403-409

Spend rules are only considered for token = (call.value > 0) ? NATIVE_ADDRESS : call.target. This means spend limiting is only applied when the account directly calls a token contract (or sends native ETH). Any token movement triggered by calling other contracts (routers, vaults, bridges, aggregators) is invisible to the limiter.

#### …/core/OPF7702.sol

L479-512

_isTokenSpend only extracts tokenAmout for a small set of selectors:

```text
transfer(address,uint256)
transferFrom(address,address,uint256)
approve(address,uint256)
```

For any other selector, tokenAmout remains 0 but _manageTokenSpend is still called and (typically) succeeds without consuming limit. This enables bypasses such as setting allowance via increaseAllowance (or token-specific permit/authorization functions) without counting against the spend limit, then draining via a third party.

### Impact

Session keys that are supposed to be constrained by per-token spend limits can still cause loss of funds by moving tokens through unaccounted selectors or via non-token contracts. In practice, this enables draining the wallet by:

granting unlimited allowance without it being charged against the spend cap (selector bypass), then pulling funds via transferFrom; or
swapping/bridging tokens by calling routers/vaults directly (target association bypass), exceeding the configured token limit.
Because these flows are common for dApp interactions, this is a realistic loss-of-funds risk.

### Proof of concept

Selector bypass example:

1. Victim sets a spend rule for USDC of 100e6 per day and allows a session key to call USDC with a broad selector policy.
2. Attacker uses the session key to call USDC.increaseAllowance(attacker, type(uint256).max).
3. _isTokenSpend does not recognize the selector, so tokenAmout = 0 and the spend rule is not meaningfully consumed.
4. Attacker pulls all USDC using transferFrom(victim, attacker, ...) from their EOA/contract.

Target association bypass example:

1. Victim configures a spend rule for USDC and allows the session key to call a DEX router.
2. Attacker uses the session key to call the router to swap all USDC to another asset.
3. Since call.target is the router, not USDC, the USDC spend rule is not applied and the wallet can be drained.

### Remediation

If the design goal is strict spend caps, enforce spend based on observable balance deltas (pre/post balances) for relevant tokens and ETH, or integrate a dedicated policy module per target that can correctly account spends for routers/vaults. At minimum, extend _isTokenSpend to handle widely-used allowance-changing and token-moving methods (e.g., increaseAllowance, decreaseAllowance, and known permit variants), and consider disallowing or heavily restricting session-key access to non-token contracts unless those targets are explicitly modeled and audited for spend accounting.

Fix:
```solidity
  function _isTokenSpend(bytes32 _keyId, address _target, uint256 _value, bytes memory _data)                                                                                                                                                   
      internal                                                                                                                                                                                                                                  
      returns (bool)                                                                                                                                                                                                                            
  {                                                                                                                                                                                                                                             
      bytes4 fnSel = ANY_FN_SEL;                                                                                                                                                                                                                

      if (_data.length >= 4) {
          assembly {
              fnSel := mload(add(_data, 0x20))
          }
      }

      if (_data.length == uint256(0)) fnSel = EMPTY_CALLDATA_FN_SEL;

      uint256 tokenAmout;

      if (fnSel == EMPTY_CALLDATA_FN_SEL) {
          tokenAmout = _value;
          _target = NATIVE_ADDRESS;
      } else if (fnSel == 0xa9059cbb) {
          tokenAmout = uint256(LibBytes.load(_data, 0x24));
      } else if (fnSel == 0x23b872dd) {
          tokenAmout = uint256(LibBytes.load(_data, 0x44));
      } else if (fnSel == 0x095ea7b3) {
          tokenAmout = uint256(LibBytes.load(_data, 0x24));
      } else {
          return false; // <-- reject unrecognized selectors on spend-limited tokens
      }

      if (!_manageTokenSpend(_keyId, _target, tokenAmout)) return false;

      return true;
  }
```

# V-004

## high

## Guardians can be added instantly after initialization because initializeGuardians has no one-time restriction

Guardians can be added instantly after initialization because initializeGuardians has no one-time restriction
SocialRecoveryManager.initializeGuardians can be called by the account at any time and unconditionally adds a guardian immediately. Any entity that can make the account call this function (e.g., a compromised session key with permission to call the recovery manager) can add themselves as a guardian without the security delay and then execute recovery to take over the account and steal funds.

### Affected Locations

#### …/utils/SocialRecover.sol

L87-101

initializeGuardians only checks msg.sender == _account and _initialGuardian != 0, then immediately pushes _initialGuardian and marks it active. There is no check that the guardian set is uninitialized/empty, and no timelock or window is applied.

#### …/utils/SocialRecover.sol

L280-323

Recovery initiation (startRecovery) only requires the caller to be an active guardian and no ongoing recovery/lock. Therefore, once an attacker can add themselves as a guardian immediately, they can trigger recovery and ultimately rotate the master key to one they control.

### Impact

A session key intended to be limited (by quota and spend rules) can become a permanent account takeover vector if it can call the recovery manager. The attacker can add themselves as a guardian immediately (no securityPeriod), then proceed through recovery to install a new master key under their control and drain all funds. This is a direct loss-of-funds risk and undermines the security period guarantees described by the recovery module.

### Proof of concept

1. Victim has a session key that can call RECOVERY_MANAGER (e.g., via (ANY_TARGET, ANY_FN_SEL) can-call).
2. Attacker obtains the session key.
3. Attacker submits a UserOp that makes the wallet call SocialRecoveryManager.initializeGuardians(address(this), attackerHash).
4. Attacker is now an active guardian immediately.
5. Attacker calls startRecovery as the guardian, waits recoveryPeriod, and completes recovery with the required signatures/quorum to install a new master key they control.
6. Attacker drains assets using the new master key.

### Remediation

Make initializeGuardians a true one-time initializer: require guardiansData[_account].guardians.length == 0 (or a dedicated initialized flag) and revert otherwise. Consider further restricting it so it can only be called during the account's initialize(...) flow (e.g., by having the account call a recovery-manager initializeGuardians that verifies a wallet-provided initialization nonce or uses a dedicated initialization-only entrypoint).

# V-005

## high

## The account’s EOA address is an unremovable super-admin because signatures by address(this) always succeed

The account’s EOA address is an unremovable super-admin because signatures by address(this) always succeed
The signature validator unconditionally accepts ECDSA signatures that recover to address(this) (the EIP-7702 EOA authority address), regardless of what keys are registered as the master key. This makes the EOA private key a permanent backdoor that cannot be rotated away, undermining WebAuthn master keys and social recovery and enabling loss of funds if the EOA key is compromised.

### Affected Locations

#### …/core/OPF7702.sol

L137-147

_validateKeyTypeEOA returns SIG_VALIDATION_SUCCESS immediately when ECDSA.recover(userOpHash, signature) == address(this), bypassing the keys[...] master-key registry entirely.

#### …/core/OPF7702.sol

L592-600

The ERC-1271 path similarly returns valid when tryRecover(_hash, _signature) yields address(this), enabling signature-based token flows (e.g., Permit2/permit) even if the configured on-chain master key is intended to be WebAuthn-only.

### Impact

If users rely on a WebAuthn master key or social recovery to regain control after an EOA compromise, this design prevents that: the compromised EOA private key can always authorize new operations and drain the wallet. This can lead to total loss of funds despite recovery being completed successfully.

### Proof of concept

1. Wallet is initialized with a WebAuthn master key (and/or later recovered to a WebAuthn key).
2. The EOA private key corresponding to the wallet address is compromised.
3. Attacker signs UserOps with the EOA key. _validateKeyTypeEOA accepts them via signer == address(this) even though the EOA is not the registered master key.
4. Attacker drains funds via execute calls; neither key rotation nor social recovery can remove this capability.

### Remediation

Remove the unconditional signer == address(this) success path, or gate it behind an explicit opt-in/opt-out flag stored in state (e.g., only allow it before initialization, or allow it only when the registered master key is explicitly the EOA authority). If the intent is to support non-EOA master keys (WebAuthn/P256), the validator should require that the EOA key is actually registered as (or authorized by) the current master key, so it can be rotated away during recovery.
