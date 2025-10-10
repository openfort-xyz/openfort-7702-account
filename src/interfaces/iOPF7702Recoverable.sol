// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IKey} from "./IKey.sol";
import {IOPF7702} from "./IOPF7702.sol";

/// @title IOPF7702Recoverable
/// @notice Interface extension for the guardian-recoverable variant of the Openfort 7702 account.
interface IOPF7702Recoverable is IOPF7702 {
    // =============================================================
    //                              STRUCTS
    // =============================================================

    /// @notice Metadata tracked for each guardian hash.
    struct GuardianIdentity {
        bool isActive;
        uint256 index;
        uint256 pending;
    }

    /// @notice Aggregate guardian state maintained by the Social Recovery manager.
    struct GuardiansData {
        bytes32[] guardians;
        mapping(bytes32 hashAddress => GuardianIdentity guardianIdentity) data;
        uint256 lock;
    }

    /// @notice Snapshot of an active recovery flow.
    struct RecoveryData {
        IKey.KeyDataReg key;
        uint64 executeAfter;
        uint32 guardiansRequired;
    }

    // =============================================================
    //                              ERRORS
    // =============================================================

    /// @notice The wallet is temporarily locked.
    error OPF7702Recoverable__AccountLocked();
    /// @notice Guardian revocation data not found.
    error OPF7702Recoverable__UnknownRevoke();
    /// @notice Recovery timing parameters violate security constraints.
    error OPF7702Recoverable_InsecurePeriod();
    /// @notice Caller must be an active guardian.
    error OPF7702Recoverable__MustBeGuardian();
    /// @notice Guardian proposal data not found.
    error OPF7702Recoverable__UnknownProposal();
    /// @notice Recovery already in progress.
    error OPF7702Recoverable__OngoingRecovery();
    /// @notice Duplicate guardian revocation detected.
    error OPF7702Recoverable__DuplicatedRevoke();
    /// @notice No recovery in progress.
    error OPF7702Recoverable__NoOngoingRecovery();
    /// @notice Zero address/identifier supplied where not allowed.
    error OPF7702Recoverable__AddressCantBeZero();
    /// @notice Duplicate guardian proposal detected.
    error OPF7702Recoverable__DuplicatedProposal();
    /// @notice Guardian already active.
    error OPF7702Recoverable__DuplicatedGuardian();
    /// @notice Provided key type is unsupported for recovery.
    error OPF7702Recoverable__UnsupportedKeyType();
    /// @notice Guardian revocation timelock not elapsed yet.
    error OPF7702Recoverable__PendingRevokeNotOver();
    /// @notice Guardian revocation confirmation window expired.
    error OPF7702Recoverable__PendingRevokeExpired();
    /// @notice Proposed recovery owner is already a guardian.
    error OPF7702Recoverable__GuardianCannotBeOwner();
    /// @notice Wallet has no guardians configured.
    error OPF7702Recoverable__NoGuardiansSetOnWallet();
    /// @notice Guardian proposal confirmation window expired.
    error OPF7702Recoverable__PendingProposalExpired();
    /// @notice Number of guardian signatures supplied is incorrect.
    error OPF7702Recoverable__InvalidSignatureAmount();
    /// @notice Guardian proposal timelock not elapsed yet.
    error OPF7702Recoverable__PendingProposalNotOver();
    /// @notice Caller is not authorized to perform the requested action.
    error OPF7702Recoverable__Unauthorized();
    /// @notice Recovery cannot target a key that is currently active on the wallet.
    error OPF7702Recoverable__RecoverCannotBeActiveKey();
    /// @notice Guardian signatures failed validation.
    error OPF7702Recoverable__InvalidRecoverySignatures();
    /// @dev Thrown when guardian address equals the wallet itself.
    error OPF7702Recoverable__GuardianCannotBeAddressThis();
    /// @dev Thrown when guardian equals the current master key.
    error OPF7702Recoverable__GuardianCannotBeCurrentMasterKey();

    // =============================================================
    //                             EVENTS
    // =============================================================

    /// @notice Emitted when guardians initiate a recovery flow.
    /// @param executeAfter  Timestamp after which recovery can be executed.
    /// @param guardiansRequired Number of guardian signatures required.
    event RecoveryStarted(uint64 executeAfter, uint32 guardiansRequired);

    /// @notice Emitted when a recovery flow successfully completes.
    event RecoveryCompleted();

    /// @notice Emitted when an in-progress recovery is cancelled.
    event RecoveryCancelled();

    /// @notice Emitted when a guardian hash is activated.
    event GuardianAdded(bytes32 indexed guardian);
    /// @notice Emitted when a guardian hash is proposed for activation.
    event GuardianProposed(bytes32 indexed guardian, uint256 pendingUntil);
    /// @notice Emitted when a guardian proposal is withdrawn.
    event GuardianProposalCancelled(bytes32 indexed guardian);
    /// @notice Emitted when a guardian revocation is scheduled.
    event GuardianRevocationScheduled(bytes32 indexed guardian, uint256 pendingUntil);
    /// @notice Emitted when a guardian is removed.
    event GuardianRemoved(bytes32 indexed guardian);
    /// @notice Emitted when a scheduled guardian revocation is cancelled.
    event GuardianRevocationCancelled(bytes32 indexed guardian);
    /// @notice Emitted whenever the wallet lock state toggles.
    /// @param locked True when the wallet becomes locked; false when unlocked.
    event WalletLocked(bool indexed locked);

    // =============================================================
    //                         EXTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice Initialize the account with a master key, optional session key, and seed guardian set.
     * @param _keyData         Master-key registration payload.
     * @param _sessionKeyData  Optional session-key registration payload (ignored if `.key` is empty).
     * @param _signature       Signature by the contract authorizing initialization.
     * @param _initialGuardian Guardian hash to seed in the social recovery manager.
     */
    function initialize(
        IKey.KeyDataReg calldata _keyData,
        IKey.KeyDataReg calldata _sessionKeyData,
        bytes memory _signature,
        bytes32 _initialGuardian
    ) external;

    /**
     * @notice Finalize recovery by supplying guardian approvals obtained off-chain.
     * @param _signatures Encoded guardian signatures authorizing the new master key.
     * @return recoveryOwner The master-key registration data that was activated.
     */
    function completeRecovery(bytes[] calldata _signatures)
        external
        returns (IKey.KeyDataReg memory recoveryOwner);

    /**
     * @notice Return the EIP-712 digest that must be signed to authorize `initialize`.
     * @param _keyData         Master-key registration payload.
     * @param _sessionKeyData  Session-key registration payload.
     * @param _initialGuardian Guardian hash supplied during initialization.
     * @return digest Typed data hash for the initialization payload.
     */
    function getDigestToInit(
        IKey.KeyDataReg calldata _keyData,
        IKey.KeyDataReg calldata _sessionKeyData,
        bytes32 _initialGuardian
    ) external view returns (bytes32 digest);

    /**
     * @notice Address of the SocialRecoveryManager contract bound to this account.
     */
    function RECOVERY_MANAGER() external view returns (address);
}
