/*
░░      ░░░░      ░░░░      ░░░        ░░░      ░░░  ░░░░░░░░░░░░░░       ░░░        ░░░      ░░░░      ░░░  ░░░░  ░░        ░░       ░░░  ░░░░  ░░░░░░░░  ░░░░  ░░░      ░░░   ░░░  ░░░      ░░░░      ░░░        ░░       ░░
▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒▒   ▒▒   ▒▒  ▒▒▒▒  ▒▒    ▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒
▓▓      ▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓       ▓▓▓      ▓▓▓▓  ▓▓▓▓▓▓▓▓  ▓▓▓▓  ▓▓▓  ▓▓  ▓▓▓      ▓▓▓▓       ▓▓▓▓▓    ▓▓▓▓▓▓▓▓▓▓        ▓▓  ▓▓▓▓  ▓▓  ▓  ▓  ▓▓  ▓▓▓▓  ▓▓  ▓▓▓   ▓▓      ▓▓▓▓       ▓▓
███████  ██  ████  ██  ████  █████  █████        ██  ██████████████  ███  ███  ████████  ████  ██  ████  ████    ████  ████████  ███  ██████  ███████████  █  █  ██        ██  ██    ██        ██  ████  ██  ████████  ███  ██
██      ████      ████      ███        ██  ████  ██        ████████  ████  ██        ███      ████      ██████  █████        ██  ████  █████  ███████████  ████  ██  ████  ██  ███   ██  ████  ███      ███        ██  ████  █
*/

// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {KeysManagerLib} from "src/libs/KeysManagerLib.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {IOPF7702Recoverable} from "src/interfaces/IOPF7702Recoverable.sol";
import {ISocialRecoveryManager} from "src/interfaces/ISocialRecoveryManager.sol";
import {Math} from "lib/openzeppelin-contracts/contracts/utils/math/Math.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

/// @title SocialRecover (Guardian Manager & Recovery Orchestrator)
/// @author Openfort@0xKoiner
/// @notice External module that manages guardians and coordinates social recovery for OPF 7702 accounts.
/// @dev
///  - Maintains a guardian set with proposal/revocation timelocks (`securityPeriod`) and an execution window (`securityWindow`).
///  - Orchestrates recovery by proposing a new master key and finalizing with EIP-712 guardian approvals.
///  - Enforces an account lock during recovery (`lockPeriod`) and period relations:
///      * `lockPeriod >= recoveryPeriod`
///      * `recoveryPeriod >= securityPeriod + securityWindow`
///  - Integrates with OPF accounts via `IOPF7702Recoverable`/`IOPF7702` interfaces.
/// @custom:security
///  - Guardian signatures must be strictly ordered (by guardian hash) to prevent duplicates.
///  - Zero guardian IDs are rejected; the account itself or its current master key cannot be a guardian.
///  - Recovery cannot complete before `recoveryPeriod` elapses and requires the exact quorum.
contract SocialRecoveryManager is EIP712, ISocialRecoveryManager {
    using ECDSA for bytes32;
    using KeysManagerLib for *;

    /// @dev EIP‑712 type hash for the Recovery struct.
    bytes32 private constant RECOVER_TYPEHASH =
        0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;

    /// @notice Seconds a recovery proposal must wait before it can be executed.
    uint256 internal immutable recoveryPeriod;
    /// @notice Seconds the wallet remains locked after a recovery proposal is submitted.
    uint256 internal immutable lockPeriod;
    /// @notice Seconds that a guardian proposal/revoke must wait before it can be confirmed.
    uint256 internal immutable securityPeriod;
    /// @notice Seconds after `securityPeriod` during which the proposal/revoke can be confirmed.
    uint256 internal immutable securityWindow;

    /// @notice Recovery flow state variables.
    mapping(address => IOPF7702Recoverable.RecoveryData) public recoveryData;
    /// @notice Encapsulates guardian related state.
    mapping(address => IOPF7702Recoverable.GuardiansData) internal guardiansData;

    /**
     * @param _recoveryPeriod  Delay (seconds) before guardians can execute recovery.
     * @param _lockPeriod      Period (seconds) that the wallet stays locked after recovery starts.
     * @param _securityPeriod  Timelock (seconds) for guardian add/remove actions.
     * @param _securityWindow  Window (seconds) after the timelock where the action must be executed.
     */
    constructor(
        uint256 _recoveryPeriod,
        uint256 _lockPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow
    ) EIP712("SocialRecoveryManager", "1") {
        if (_lockPeriod < _recoveryPeriod || _recoveryPeriod < _securityPeriod + _securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable_InsecurePeriod();
        }
        recoveryPeriod = _recoveryPeriod;
        lockPeriod = _lockPeriod;
        securityPeriod = _securityPeriod;
        securityWindow = _securityWindow;
    }

    /**
     * @notice Configure the first guardian during `initialize`.
     * @param _account         Account whose guardian set is being bootstrapped.
     * @param _initialGuardian Guardian hash to register (must be non-zero).
     * @dev Sets `isActive = true`, `index = 0`, clears `pending`, and emits `GuardianAdded`.
     *      Reverts `AddressCantBeZero` if `_initialGuardian == 0x0`.
     */
    function initializeGuardians(address _account, bytes32 _initialGuardian) external override {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        if (_initialGuardian == bytes32(0)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }
        guardiansData[_account].guardians.push(_initialGuardian);
        IOPF7702Recoverable.GuardianIdentity storage gi =
            guardiansData[_account].data[_initialGuardian];

        emit IOPF7702Recoverable.GuardianAdded(_initialGuardian);

        gi.isActive = true;
        gi.index = 0;
        gi.pending = 0;
    }

    /**
     * @notice Proposes adding a new guardian. Must be confirmed after the security period.
     * @param _account  Account managing its guardian set.
     * @param _guardian Guardian hash to add.
     */
    function proposeGuardian(address _account, bytes32 _guardian) external override {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        if (_guardian == bytes32(0)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (_account.computeHash() == _guardian) {
            revert IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeAddressThis();
        }

        (bytes32 keyId,) = IKeysManager(_account).keyAt(0);

        if (keyId == _guardian) {
            revert IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeCurrentMasterKey();
        }

        if (gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian();

        if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedProposal();
        }

        gi.pending = block.timestamp + securityPeriod;

        emit IOPF7702Recoverable.GuardianProposed(_guardian, gi.pending);
    }

    /**
     * @notice Finalizes a previously proposed guardian after the timelock.
     * @param _account  Account whose guardian proposal is being confirmed.
     * @param _guardian Guardian hash to activate.
     */
    function confirmGuardianProposal(address _account, bytes32 _guardian) external override {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        _requireRecovery(_account, false);
        if (_guardian == bytes32(0)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownProposal();
        if (block.timestamp < gi.pending) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingProposalNotOver();
        }
        if (block.timestamp > gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingProposalExpired();
        }

        if (gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian();

        emit IOPF7702Recoverable.GuardianAdded(_guardian);

        gi.isActive = true;
        gi.pending = 0;
        gi.index = guardiansData[_account].guardians.length;
        guardiansData[_account].guardians.push(_guardian);
    }

    /**
     * @notice Cancels a guardian addition proposal before it is confirmed.
     * @param _account  Account revoking the pending guardian addition.
     * @param _guardian Guardian hash whose proposal should be cancelled.
     */
    function cancelGuardianProposal(address _account, bytes32 _guardian) external override {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        _requireRecovery(_account, false);
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownProposal();

        if (gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian();

        emit IOPF7702Recoverable.GuardianProposalCancelled(_guardian);

        gi.pending = 0;
    }

    /**
     * @notice Initiates guardian removal. Must be confirmed after the security period.
     * @param _account  Account scheduling the guardian revocation.
     * @param _guardian Guardian hash to revoke.
     */
    function revokeGuardian(address _account, bytes32 _guardian) external override {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (!gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();

        if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedRevoke();
        }

        gi.pending = block.timestamp + securityPeriod;

        emit IOPF7702Recoverable.GuardianRevocationScheduled(_guardian, gi.pending);
    }

    /**
     * @notice Confirms guardian removal after the timelock.
     * @param _account  Account finalizing the guardian removal.
     * @param _guardian Guardian hash to remove permanently.
     */
    function confirmGuardianRevocation(address _account, bytes32 _guardian) external override {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownRevoke();

        if (block.timestamp < gi.pending) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingRevokeNotOver();
        }
        if (block.timestamp > gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingRevokeExpired();
        }
        if (!gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();

        uint256 lastIndex = guardiansData[_account].guardians.length - 1;
        bytes32 lastHash = guardiansData[_account].guardians[lastIndex];
        uint256 targetIndex = gi.index;

        if (_guardian != lastHash) {
            guardiansData[_account].guardians[targetIndex] = lastHash;
            guardiansData[_account].data[lastHash].index = targetIndex;
        }
        emit IOPF7702Recoverable.GuardianRemoved(_guardian);

        guardiansData[_account].guardians.pop();

        delete guardiansData[_account].data[_guardian];
    }

    /**
     * @notice Cancels a pending guardian removal.
     * @param _account  Account revoking the pending guardian removal.
     * @param _guardian Guardian hash whose removal should be cancelled.
     */
    function cancelGuardianRevocation(address _account, bytes32 _guardian) external override {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (!gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();
        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownRevoke();

        emit IOPF7702Recoverable.GuardianRevocationCancelled(_guardian);

        guardiansData[_account].data[_guardian].pending = 0;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                           Recovery flow (guardians)
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @notice Guardians initiate account recovery by proposing a new master key.
     * @dev The caller must be an active guardian. Wallet enters locked state immediately.
     * @param _account     Account undergoing recovery.
     * @param _recoveryKey New master key to set once recovery succeeds.
     */
    function startRecovery(address _account, IKey.KeyDataReg calldata _recoveryKey)
        external
        override
    {
        if (!isGuardian(_account, msg.sender.computeHash())) {
            revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();
        }
        if (
            _recoveryKey.keyType == IKey.KeyType.P256
                || _recoveryKey.keyType == IKey.KeyType.P256NONKEY
        ) {
            revert IOPF7702Recoverable.OPF7702Recoverable__UnsupportedKeyType();
        }

        _requireRecovery(_account, false);
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        _recoveryKey.keyCantBeZero();

        bytes32 keyId = _recoveryKey.computeKeyId();

        bool isActive = IKeysManager(_account).isKeyActive(keyId);

        if (isActive) {
            revert IOPF7702Recoverable.OPF7702Recoverable__RecoverCannotBeActiveKey();
        }

        if (isGuardian(_account, keyId)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeOwner();
        }

        uint64 executeAfter = SafeCast.toUint64(block.timestamp + recoveryPeriod);
        uint32 quorum = SafeCast.toUint32(Math.ceilDiv(guardianCount(_account), 2));

        emit IOPF7702Recoverable.RecoveryStarted(executeAfter, quorum);

        recoveryData[_account] = IOPF7702Recoverable.RecoveryData({
            key: _recoveryKey,
            executeAfter: executeAfter,
            guardiansRequired: quorum
        });

        _setLock(_account, block.timestamp + lockPeriod);
    }

    /**
     * @notice Completes recovery after the timelock by providing the required guardian signatures.
     * @param _account    Account whose recovery is being finalized.
     * @param _signatures Encoded guardian signatures approving the recovery.
     * @return recoveryOwner Key data that becomes the new master key.
     */
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

        require(
            r.guardiansRequired > 0,
            IOPF7702Recoverable.OPF7702Recoverable__NoGuardiansSetOnWallet()
        );

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

    /**
     * @notice Cancels an ongoing recovery and unlocks the wallet.
     * @param _account Account cancelling its recovery flow.
     */
    function cancelRecovery(address _account) external override {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        _requireRecovery(_account, true);
        emit IOPF7702Recoverable.RecoveryCancelled();
        delete recoveryData[_account];
        _setLock(_account, 0);
    }

    /// @dev Ensures recovery state matches the expectation.
    /// @param _account    Account whose recovery status is checked.
    /// @param _isRecovery True if function requires an ongoing recovery.
    function _requireRecovery(address _account, bool _isRecovery) internal view {
        if (_isRecovery && recoveryData[_account].executeAfter == 0) {
            revert IOPF7702Recoverable.OPF7702Recoverable__NoOngoingRecovery();
        }
        if (!_isRecovery && recoveryData[_account].executeAfter > 0) {
            revert IOPF7702Recoverable.OPF7702Recoverable__OngoingRecovery();
        }
    }

    /// @dev Sets the global lock timestamp.
    /// @param _account      Account whose wallet lock is updated.
    /// @param _releaseAfter Timestamp when the lock should be lifted (0 = unlock).
    function _setLock(address _account, uint256 _releaseAfter) internal {
        emit IOPF7702Recoverable.WalletLocked(_releaseAfter != 0);
        guardiansData[_account].lock = _releaseAfter;
    }

    /**
     * @notice Returns all guardian hashes currently active.
     * @param _account Account whose guardian set is queried.
     * @return Array of guardian hashes.
     */
    function getGuardians(address _account) external view override returns (bytes32[] memory) {
        bytes32[] memory guardians = new bytes32[](guardiansData[_account].guardians.length);
        uint256 i;
        for (i; i < guardiansData[_account].guardians.length;) {
            guardians[i] = guardiansData[_account].guardians[i];
            unchecked {
                ++i;
            }
        }
        return guardians;
    }

    /**
     * @notice Returns the pending timestamp (if any) for guardian proposal/revoke.
     * @param _account  Account whose guardian workflow is queried.
     * @param _guardian Guardian hash to query.
     * @return Timestamp until which the action is pending (0 if none).
     */
    function getPendingStatusGuardians(address _account, bytes32 _guardian)
        external
        view
        override
        returns (uint256)
    {
        return guardiansData[_account].data[_guardian].pending;
    }

    /**
     * @notice Checks whether the wallet is currently locked due to recovery flow.
     * @param _account Account to check for lock status.
     * @return True if locked, false otherwise.
     */
    function isLocked(address _account) public view override returns (bool) {
        return guardiansData[_account].lock > block.timestamp;
    }

    /**
     * @notice Checks if an address is an active guardian.
     * @param _account  Account whose guardian set is queried.
     * @param _guardian Guardian hash to query.
     * @return True if active guardian.
     */
    function isGuardian(address _account, bytes32 _guardian) public view override returns (bool) {
        return guardiansData[_account].data[_guardian].isActive;
    }

    /**
     * @notice Returns the number of active guardians.
     * @param _account Account whose guardian count is requested.
     */
    function guardianCount(address _account) public view override returns (uint256) {
        return guardiansData[_account].guardians.length;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                           Utility view functions
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @notice Returns the EIP‑712 digest guardians must sign to approve recovery.
     * @param _account Account undergoing recovery.
     * @return digest  Typed data hash for guardians to sign.
     */
    function getDigestToSign(address _account) public view override returns (bytes32 digest) {
        bytes32 structHash = keccak256(
            abi.encode(
                RECOVER_TYPEHASH,
                recoveryData[_account].key,
                recoveryData[_account].executeAfter,
                recoveryData[_account].guardiansRequired
            )
        );

        digest = _hashTypedDataV4(structHash);
    }

    /// @dev Validates guardian signatures for recovery completion.
    /// @param _account    Account whose guardian signatures are verified.
    /// @param _signatures Encoded signatures supplied by guardians.
    /// @return True if all signatures are valid and unique.
    function _validateSignatures(address _account, bytes[] calldata _signatures)
        internal
        view
        returns (bool)
    {
        bytes32 digest = getDigestToSign(_account);
        bytes32 lastGuardianHash;

        unchecked {
            for (uint256 i; i < _signatures.length; ++i) {
                bytes32 guardianHash;

                address signer = digest.recover(_signatures[i]);
                guardianHash = signer.computeHash();

                if (!guardiansData[_account].data[guardianHash].isActive) return false;

                if (guardianHash <= lastGuardianHash) return false;
                lastGuardianHash = guardianHash;
            }
        }
        return true;
    }
}
