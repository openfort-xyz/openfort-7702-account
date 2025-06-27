// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IKey} from "./IKey.sol";
import {IOPF7702} from "./IOPF7702.sol";
import {SpendLimit} from "../utils/SpendLimit.sol";

/// @title Interface for OPF7702Recoverable
/// @notice Extends the core IOPF7702 with guardian‐based recovery functions.
interface IOPF7702Recoverable is IOPF7702 {
    // ──────────────────────────────────────────────────────────────────────────────
    //                                 Structs
    // ──────────────────────────────────────────────────────────────────────────────

    /// @notice Metadata kept for each guardian.
    /// @param isActive    Whether the guardian is currently active.
    /// @param index       Index of the guardian hash inside `guardians` array (for O(1) removal).
    /// @param pending     Timestamp after which a proposal/revoke can be executed (0 = none).
    struct GuardianIdentity {
        bool isActive;
        uint256 index;
        uint256 pending;
    }

    /// @notice Encapsulates guardian related state.
    /// @param guardians  Array of guardian identifiers (hashes) in insertion order.
    /// @param data       Mapping from guardian hash to metadata.
    /// @param lock       Global lock timestamp – wallet is locked until this moment.
    struct GuardiansData {
        bytes32[] guardians;
        mapping(bytes32 hashAddress => GuardianIdentity guardianIdentity) data;
        uint256 lock;
    }

    /// @notice Recovery flow state variables.
    /// @param key                The new master key proposed by guardians.
    /// @param executeAfter       Timestamp after which recovery can be executed.
    /// @param guardiansRequired  Number of guardian signatures required to complete recovery.
    struct RecoveryData {
        Key key;
        uint64 executeAfter;
        uint32 guardiansRequired;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                                 Errors
    // ──────────────────────────────────────────────────────────────────────────────

    /// @dev Thrown when the account is in a temporary locked state.
    error OPF7702Recoverable__AccountLocked();
    /// @dev Thrown when a guardian revocation is unknown for the given guardian.
    error OPF7702Recoverable__UnknownRevoke();
    /// @dev Thrown when the caller must be an active guardian but is not.
    error OPF7702Recoverable__MustBeGuardian();
    /// @dev Thrown when a guardian addition proposal is unknown.
    error OPF7702Recoverable__UnknownProposal();
    /// @dev Thrown when another recovery flow is already in progress.
    error OPF7702Recoverable__OngoingRecovery();
    /// @dev Thrown when trying to revoke a guardian twice in the same security window.
    error OPF7702Recoverable__DuplicatedRevoke();
    /// @dev Thrown when no recovery is currently active but one is required.
    error OPF7702Recoverable__NoOngoingRecovery();
    /// @dev Thrown when both address in a guardian are zero values.
    error OPF7702Recoverable__AddressCantBeZero();
    /// @dev Thrown when a duplicate guardian proposal is submitted in the security window.
    error OPF7702Recoverable__DuplicatedProposal();
    /// @dev Thrown when attempting to add a guardian that is already active.
    error OPF7702Recoverable__DuplicatedGuardian();
    /// @dev Thrown when a key type different from EOA or WebAuthn is supplied where unsupported.
    error OPF7702Recoverable__UnsupportedKeyType();
    /// @dev Thrown when the revoke window has not elapsed yet.
    error OPF7702Recoverable__PendingRevokeNotOver();
    /// @dev Thrown when the revoke confirmation window has expired.
    error OPF7702Recoverable__PendingRevokeExpired();
    /// @dev Thrown when the recovery address is already a guardian.
    error OPF7702Recoverable__GuardianCannotBeOwner();
    /// @dev Thrown when no guardians are configured on the wallet.
    error OPF7702Recoverable__NoGuardiansSetOnWallet();
    /// @dev Thrown when the proposal confirmation window has expired.
    error OPF7702Recoverable__PendingProposalExpired();
    /// @dev Thrown when the amount of guardian signatures provided is incorrect.
    error OPF7702Recoverable__InvalidSignatureAmount();
    /// @dev Thrown when attempting to confirm a proposal before the timelock elapses.
    error OPF7702Recoverable__PendingProposalNotOver();
    /// @dev Thrown when recovery equals the current key.
    error OPF7702Recoverable__RecoverCannotBeActiveKey();
    /// @dev Thrown when guardian-supplied signatures are invalid.
    error OPF7702Recoverable__InvalidRecoverySignatures();
    /// @dev Thrown when guardian address equals the wallet itself.
    error OPF7702Recoverable__GuardianCannotBeAddressThis();
    /// @dev Thrown when guardian equals the current master key.
    error OPF7702Recoverable__GuardianCannotBeCurrentMasterKey();

    // ──────────────────────────────────────────────────────────────────────────────
    //                                 Events
    // ──────────────────────────────────────────────────────────────────────────────

    /// @notice Emitted when a new guardian proposal is created.
    event GuardianProposed(bytes32 indexed guardianHash, uint256 executeAfter);
    /// @notice Emitted when a guardian proposal is confirmed and guardian becomes active.
    event GuardianAdded(bytes32 indexed guardianHash);
    /// @notice Emitted when a guardian proposal is cancelled.
    event GuardianProposalCancelled(bytes32 indexed guardianHash);
    /// @notice Emitted when a guardian revocation is scheduled.
    event GuardianRevocationScheduled(bytes32 indexed guardianHash, uint256 executeAfter);
    /// @notice Emitted when guardian revocation is confirmed and guardian removed.
    event GuardianRemoved(bytes32 indexed guardianHash);
    /// @notice Emitted when a scheduled revocation is cancelled.
    event GuardianRevocationCancelled(bytes32 indexed guardianHash);
    /// @notice Emitted when guardians start the recovery process.
    event RecoveryStarted(uint64 executeAfter, uint32 guardiansRequired);
    /// @notice Emitted when recovery completes and a new master key is set.
    event RecoveryCompleted();
    /// @notice Emitted when an ongoing recovery is cancelled.
    event RecoveryCancelled();
    /// @notice Emitted when the wallet is locked.
    event WalletLocked(bool isLocked);

    // ──────────────────────────────────────────────────────────────────────────────
    //                             Public / External
    // ──────────────────────────────────────────────────────────────────────────────

    /// @notice Initialize with a master key + first guardian
    function initialize(
        Key calldata _key,
        KeyReg calldata _keyData,
        bytes memory _signature,
        bytes32 _initialGuardian
    ) external;

    /// @notice Propose a new guardian (after securityPeriod)
    function proposeGuardian(bytes32 _guardian) external;

    /// @notice Confirm a previously proposed guardian
    function confirmGuardianProposal(bytes32 _guardian) external;

    /// @notice Cancel a guardian proposal
    function cancelGuardianProposal(bytes32 _guardian) external;

    /// @notice Schedule removal of an existing guardian
    function revokeGuardian(bytes32 _guardian) external;

    /// @notice Confirm a scheduled guardian removal
    function confirmGuardianRevocation(bytes32 _guardian) external;

    /// @notice Cancel a guardian removal
    function cancelGuardianRevocation(bytes32 _guardian) external;

    /// @notice Start recovery by proposing a new master key (guardian signatures to follow)
    function startRecovery(IKey.Key calldata _recoveryKey) external;

    /// @notice Complete recovery with guardian signatures
    function completeRecovery(bytes[] calldata _signatures) external;

    /// @notice Cancel an in-progress recovery
    function cancelRecovery() external;

    // ──────────────────────────────────────────────────────────────────────────────
    //                              View / Getter
    // ──────────────────────────────────────────────────────────────────────────────

    /// @notice Current recovery proposal data
    function recoveryData()
        external
        view
        returns (IKey.Key memory key, uint64 executeAfter, uint32 guardiansRequired);

    /// @notice All active guardian hashes
    function getGuardians() external view returns (bytes32[] memory);

    /// @notice Pending timestamp for a guardian’s proposal/revocation
    function getPendingStatusGuardians(bytes32 _guardian) external view returns (uint256);

    /// @notice Whether the wallet is currently locked
    function isLocked() external view returns (bool);

    /// @notice True if the given address is an active guardian
    function isGuardian(bytes32 _guardian) external view returns (bool);

    /// @notice Number of active guardians
    function guardianCount() external view returns (uint256);

    /// @notice EIP-712 digest that guardians must sign for recovery
    function getDigestToSign() external view returns (bytes32);
}
