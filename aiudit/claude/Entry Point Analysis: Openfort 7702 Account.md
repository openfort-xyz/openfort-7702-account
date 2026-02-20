Entry Point Analysis: Openfort 7702 Account

  Analyzed: 2026-02-19
  Scope: src/ (full codebase)
  Languages: Solidity
  Focus: State-changing functions only (view/pure excluded)
  Tooling: Manual analysis (Slither not available)

  Summary

  ┌──────────────────────────────┬───────┐
  │           Category           │ Count │
  ├──────────────────────────────┼───────┤
  │ Public (Unrestricted)        │ 3     │
  ├──────────────────────────────┼───────┤
  │ Role-Restricted              │ 28    │
  ├──────────────────────────────┼───────┤
  │ Restricted (Review Required) │ 2     │
  ├──────────────────────────────┼───────┤
  │ Contract-Only                │ 0     │
  ├──────────────────────────────┼───────┤
  │ Total                        │ 33    │
  └──────────────────────────────┴───────┘

  ---
  Public Entry Points (Unrestricted)

  State-changing functions callable by anyone — prioritize for attack surface analysis.

  Function: fallback()
  File: src/core/BaseOPF7702.sol:L75
  Notes: Receives ETH, no-op
  ────────────────────────────────────────
  Function: receive()
  File: src/core/BaseOPF7702.sol:L79
  Notes: Receives ETH, emits DepositAdded
  ────────────────────────────────────────
  Function: completeRecovery(bytes[])
  File: src/core/OPF7702Recoverable.sol:L137
  Notes: No access modifier. Delegates to RECOVERY_MANAGER which validates guardian signatures + timelock.
  Replaces
    master key.

  ---
  Role-Restricted Entry Points

  Self / EntryPoint (_requireForExecute)

  All functions below require msg.sender == address(this) || msg.sender == entryPoint(). These are the account's
  privileged operations — only the owner (via UserOp through EntryPoint) or a self-call can invoke them.

  Function: setEntryPoint(address)
  File: src/core/BaseOPF7702.sol:L91
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: setWebAuthnVerifier(address)
  File: src/core/BaseOPF7702.sol:L105
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: setGasPolicy(address)
  File: src/core/BaseOPF7702.sol:L119
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: execute(bytes32, bytes)
  File: src/core/Execution.sol:L47
  Restriction: _requireForExecute() + nonReentrant
  ────────────────────────────────────────
  Function: registerKey(KeyDataReg)
  File: src/core/KeysManager.sol:L84
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: setTokenSpend(bytes32, address, uint256, SpendPeriod)
  File: src/core/KeysManager.sol:L105
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: setCanCall(bytes32, address, bytes4, bool)
  File: src/core/KeysManager.sol:L130
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: updateKeyData(bytes32, uint48, uint48)
  File: src/core/KeysManager.sol:L153
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: updateTokenSpend(bytes32, address, uint256, SpendPeriod)
  File: src/core/KeysManager.sol:L178
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: revokeKey(bytes32)
  File: src/core/KeysManager.sol:L203
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: removeTokenSpend(bytes32, address)
  File: src/core/KeysManager.sol:L223
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: pauseKey(bytes32)
  File: src/core/KeysManager.sol:L509
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: unpauseKey(bytes32)
  File: src/core/KeysManager.sol:L523
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: clearSpendPermissions(bytes32)
  File: src/core/KeysManager.sol:L537
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: clearExecutePermissions(bytes32)
  File: src/core/KeysManager.sol:L554
  Restriction: _requireForExecute()
  ────────────────────────────────────────
  Function: initialize(KeyDataReg, KeyDataReg, bytes, bytes32)
  File: src/core/OPF7702Recoverable.sol:L98
  Restriction: _requireForExecute() + initializer (one-time)
  ────────────────────────────────────────
  Function: upgradeProxyDelegation(address)
  File: src/core/OPFMain.sol:L57
  Restriction: _requireForExecute() — HIGH PRIVILEGE: upgrades implementation

  Account-Only (msg.sender == _account)

  Functions on SocialRecoveryManager callable only by the account itself (wallet address).

  Function: initializeGuardians(address, bytes32)
  File: src/utils/SocialRecover.sol:L87
  Restriction: msg.sender != _account revert
  ────────────────────────────────────────
  Function: proposeGuardian(address, bytes32)
  File: src/utils/SocialRecover.sol:L108
  Restriction: msg.sender != _account revert + !isLocked
  ────────────────────────────────────────
  Function: confirmGuardianProposal(address, bytes32)
  File: src/utils/SocialRecover.sol:L144
  Restriction: msg.sender != _account revert + timelock
  ────────────────────────────────────────
  Function: cancelGuardianProposal(address, bytes32)
  File: src/utils/SocialRecover.sol:L177
  Restriction: msg.sender != _account revert
  ────────────────────────────────────────
  Function: revokeGuardian(address, bytes32)
  File: src/utils/SocialRecover.sol:L198
  Restriction: msg.sender != _account revert + !isLocked
  ────────────────────────────────────────
  Function: confirmGuardianRevocation(address, bytes32)
  File: src/utils/SocialRecover.sol:L220
  Restriction: msg.sender != _account revert + timelock
  ────────────────────────────────────────
  Function: cancelGuardianRevocation(address, bytes32)
  File: src/utils/SocialRecover.sol:L256
  Restriction: msg.sender != _account revert
  ────────────────────────────────────────
  Function: cancelRecovery(address)
  File: src/utils/SocialRecover.sol:L370
  Restriction: msg.sender != _account revert

  Account-Sender (msg.sender == account)

  Functions on GasPolicy callable only by the account that owns the budget.

  Function: initializeGasPolicy(address, bytes32, bytes16)
  File: src/utils/GasPolicy.sol:L149
  Restriction: account == msg.sender require
  ────────────────────────────────────────
  Function: initializeGasPolicy(address, bytes32, uint256)
  File: src/utils/GasPolicy.sol:L172
  Restriction: account == msg.sender require

  Guardian

  Function: startRecovery(address, KeyDataReg)
  File: src/utils/SocialRecover.sol:L280
  Restriction: isGuardian(_account, msg.sender.computeHash()) + !isLocked + !ongoingRecovery

  ---
  Restricted (Review Required)

  Functions with access control patterns that need manual verification.

  Function: checkUserOpPolicy(bytes32, PackedUserOperation)
  File: src/utils/GasPolicy.sol:L100
  Pattern: msg.sender != userOp.sender early return
  Why Review: Returns VALIDATION_FAILED (not revert) if sender mismatch — any caller can invoke without revert,
  but
    only the account itself can succeed. Mutates gas counters.
  ────────────────────────────────────────
  Function: completeRecovery(address, bytes[])
  File: src/utils/SocialRecover.sol:L331
  Pattern: No msg.sender check
  Why Review: Anyone can call this directly on the manager (not just the wallet). Requires valid guardian
    signatures + timelock. Deletes recovery data and unlocks wallet. If called directly (bypassing the wallet's
    completeRecovery), old keys remain and new master key is NOT set on the wallet.

  ---
  Contract-Only (Internal Integration Points)

  No callback-style contract-only entry points detected. Token receiver callbacks (onERC721Received,
  onERC1155Received, onERC1155BatchReceived, tokensReceived) are all inherited as view/pure and excluded.

  Note: _decodeWebAuthn1271(bytes) at src/core/OPF7702.sol:L689 is external pure — used via
  this._decodeWebAuthn1271() try/catch pattern for safe ABI decoding. Excluded (pure).

  ---
  Files Analyzed

  File: src/core/BaseOPF7702.sol
  State-Changing Entry Points: 5 (fallback, receive, setEntryPoint, setWebAuthnVerifier, setGasPolicy)
  ────────────────────────────────────────
  File: src/core/Execution.sol
  State-Changing Entry Points: 1 (execute)
  ────────────────────────────────────────
  File: src/core/KeysManager.sol
  State-Changing Entry Points: 11 (registerKey, setTokenSpend, setCanCall, updateKeyData, updateTokenSpend,
    revokeKey, removeTokenSpend, pauseKey, unpauseKey, clearSpendPermissions, clearExecutePermissions)
  ────────────────────────────────────────
  File: src/core/OPF7702.sol
  State-Changing Entry Points: 0 (all new functions are view/pure; inherits from Execution)
  ────────────────────────────────────────
  File: src/core/OPF7702Recoverable.sol
  State-Changing Entry Points: 2 (initialize, completeRecovery)
  ────────────────────────────────────────
  File: src/core/OPFMain.sol
  State-Changing Entry Points: 1 (upgradeProxyDelegation)
  ────────────────────────────────────────
  File: src/utils/SocialRecover.sol
  State-Changing Entry Points: 10 (initializeGuardians, proposeGuardian, confirmGuardianProposal,
    cancelGuardianProposal, revokeGuardian, confirmGuardianRevocation, cancelGuardianRevocation, startRecovery,
    completeRecovery, cancelRecovery)
  ────────────────────────────────────────
  File: src/utils/GasPolicy.sol
  State-Changing Entry Points: 3 (checkUserOpPolicy, initializeGasPolicy x2)
  ────────────────────────────────────────
  File: src/utils/WebAuthnVerifier.sol
  State-Changing Entry Points: 0 (all view)
  ────────────────────────────────────────
  File: src/utils/WebAuthnVerifierV2.sol
  State-Changing Entry Points: 0 (all view)
  ────────────────────────────────────────
  File: src/utils/ERC7201.sol
  State-Changing Entry Points: 0 (all pure/view)
  ────────────────────────────────────────
  File: src/libs/*
  State-Changing Entry Points: 0 (libraries/abstract, no external entry points)
  ────────────────────────────────────────
  File: src/mocks/*
  State-Changing Entry Points: Excluded from analysis (test helpers)

  ---
  Analysis Warnings

  - Mocks excluded: MockERC20, ERC721Mock, ERC1155Mock, SimpleContract are test helpers and were not included in
  the main analysis.
  - Inheritance: OPFMain is the concrete deployment contract inheriting the full chain: OPFMain →
  OPF7702Recoverable → OPF7702 → Execution → KeysManager → BaseOPF7702. All 19 entry points from the core
  contracts are callable on the OPFMain instance.
  - _requireForExecute is defined in BaseOPF7702.sol:L193 as msg.sender == address(this) || msg.sender ==
  address(entryPoint()). This is the primary auth gate for all wallet operations.
