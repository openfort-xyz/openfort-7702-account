// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IKey} from "./IKey.sol";

/// @title ISocialRecoveryManager
/// @notice Interface for the guardian management and recovery orchestrator module.
interface ISocialRecoveryManager {
    /**
     * @notice Bootstrap the guardian set for an account during initialization.
     * @param _account         Account invoking the setup (must be `msg.sender`).
     * @param _initialGuardian Guardian hash to activate immediately.
     */
    function initializeGuardians(address _account, bytes32 _initialGuardian) external;

    /**
     * @notice Propose a new guardian; must be confirmed after the security period.
     * @param _account  Account managing its guardian set (must be `msg.sender`).
     * @param _guardian Guardian hash to add.
     */
    function proposeGuardian(address _account, bytes32 _guardian) external;

    /**
     * @notice Finalize a proposed guardian once the timelock expires.
     * @param _account  Account confirming the addition (must be `msg.sender`).
     * @param _guardian Guardian hash to activate.
     */
    function confirmGuardianProposal(address _account, bytes32 _guardian) external;

    /**
     * @notice Cancel a pending guardian proposal.
     * @param _account  Account cancelling the proposal (must be `msg.sender`).
     * @param _guardian Guardian hash whose proposal is cancelled.
     */
    function cancelGuardianProposal(address _account, bytes32 _guardian) external;

    /**
     * @notice Schedule the removal of an active guardian.
     * @param _account  Account managing the removal (must be `msg.sender`).
     * @param _guardian Guardian hash to revoke.
     */
    function revokeGuardian(address _account, bytes32 _guardian) external;

    /**
     * @notice Finalize guardian removal after the security period.
     * @param _account  Account confirming the removal (must be `msg.sender`).
     * @param _guardian Guardian hash to remove.
     */
    function confirmGuardianRevocation(address _account, bytes32 _guardian) external;

    /**
     * @notice Cancel a scheduled guardian revocation.
     * @param _account  Account cancelling the revocation (must be `msg.sender`).
     * @param _guardian Guardian hash whose revocation is cancelled.
     */
    function cancelGuardianRevocation(address _account, bytes32 _guardian) external;

    /**
     * @notice Start recovery by proposing a new master key.
     * @param _account     Account undergoing recovery.
     * @param _recoveryKey Master-key registration payload proposed by guardians.
     */
    function startRecovery(address _account, IKey.KeyDataReg calldata _recoveryKey) external;

    /**
     * @notice Complete recovery with guardian signatures.
     * @param _account    Account finalizing recovery.
     * @param _signatures Guardian signatures approving the proposed key.
     * @return recoveryOwner Master-key registration payload activated by the recovery.
     */
    function completeRecovery(address _account, bytes[] calldata _signatures)
        external
        returns (IKey.KeyDataReg memory recoveryOwner);

    /**
     * @notice Cancel an ongoing recovery and unlock the wallet.
     * @param _account Account cancelling its recovery.
     */
    function cancelRecovery(address _account) external;

    /**
     * @notice Return all active guardian hashes for an account.
     * @param _account Account whose guardians are requested.
     * @return Array of guardian hashes.
     */
    function getGuardians(address _account) external view returns (bytes32[] memory);

    /**
     * @notice Return pending timestamp (if any) for a guardian proposal or revocation.
     * @param _account  Account whose guardian workflow is queried.
     * @param _guardian Guardian hash being inspected.
     * @return Pending timestamp (0 if no action pending).
     */
    function getPendingStatusGuardians(address _account, bytes32 _guardian)
        external
        view
        returns (uint256);

    /**
     * @notice Report whether an account is currently locked due to recovery.
     * @param _account Account to query.
     * @return True if locked, false otherwise.
     */
    function isLocked(address _account) external view returns (bool);

    /**
     * @notice Check if a guardian hash is active for an account.
     * @param _account  Account to query.
     * @param _guardian Guardian hash to inspect.
     * @return True if the guardian is active.
     */
    function isGuardian(address _account, bytes32 _guardian) external view returns (bool);

    /**
     * @notice Return the count of active guardians for an account.
     * @param _account Account to query.
     */
    function guardianCount(address _account) external view returns (uint256);

    /**
     * @notice EIP-712 digest guardians must sign to approve recovery.
     * @param _account Account undergoing recovery.
     * @return digest Typed data hash representing the recovery payload.
     */
    function getDigestToSign(address _account) external view returns (bytes32 digest);
}
