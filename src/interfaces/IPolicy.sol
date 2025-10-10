// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import "lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title IPolicy
/// @notice Marker interface for policy contracts that expose ERC-165 discovery.
interface IPolicy is IERC165 {}

/// @title IUserOpPolicy
/// @notice Interface for per-account / per-config gas budgeting on ERC-4337 UserOperations.
/// @dev Implementations maintain a cumulative “envelope units” budget per `configId`,
///
interface IUserOpPolicy is IPolicy {
    /// @notice Provided gas limit is malformed or outside acceptable bounds.
    error GasPolicy__BadLimit();
    /// @notice Provided gas limit exceeds the implementation’s maximum allowed cap.
    error GasPolicy_GasLimitHigh();
    /// @notice All envelope budgets are zero, which is considered invalid for initialization.
    error GasPolicy__ZeroBudgets();
    /// @notice Attempted to (re)initialize an already existing `configId`.
    error GasPolicy__IdExistAlready();
    /// @notice Caller must be the account whose policy is being checked/updated (`msg.sender == account`).
    error GasPolicy__AccountMustBeSender();
    /// @notice Initialization parameters are inconsistent or incomplete for the requested operation.
    error GasPolicy__InitializationIncorrect();

    // ---------------------- Events ----------------------

    /// @notice Emitted when a gas policy is initialized (explicitly or lazily).
    /// @param configId  Policy/config identifier (e.g., session key hash).
    /// @param account   The account (7702/SCA) this policy is bound to.
    /// @param gasLimit  Cumulative envelope units budget assigned to this config.
    /// @param autoInit  True if lazily initialized during the first policy check; false if explicitly initialized.
    event GasPolicyInitialized(
        bytes32 indexed configId, address indexed account, uint256 gasLimit, bool autoInit
    );

    /// @notice Emitted when envelope units are accounted against a policy.
    /// @param configId      Policy/config identifier.
    /// @param account       The account whose policy was charged.
    /// @param envelopeUnits Envelope units consumed in this operation (PVG+VGL+CGL+PM).
    /// @param gasUsedTotal  New cumulative envelope units used after accounting.
    event GasPolicyAccounted(
        bytes32 indexed configId,
        address indexed account,
        uint256 envelopeUnits,
        uint256 gasUsedTotal
    );

    /// @notice Per-config cumulative gas budget and usage state.
    /// @dev Envelope units correspond to PVG + VGL + CGL + PM legs of a UserOperation.
    struct GasLimitConfig {
        /// @notice Total budget of envelope units for this `configId`.
        uint128 gasLimit;
        /// @notice Cumulative envelope units used so far.
        uint128 gasUsed;
        /// @notice True once the policy has been initialized.
        bool initialized;
    }

    /**
     * @notice Validate a `PackedUserOperation` against configured gas budgets and account usage.
     * @param id     Session/policy identifier (e.g., keccak256 over session public key).
     * @param userOp The packed user operation being validated and accounted.
     * @return validationCode `0` on success, `1` on failure (ERC-4337 policy semantics).
     * @dev
     * - Access: Only the account (`userOp.sender`) may call; prevents 3rd-party budget griefing.
     * - Behavior: Computes the gas envelope (PVG+VGL+[PMV]+CGL+[PO]), checks cumulative gas and tx caps,
     *   and increments usage counters optimistically.
     * - Paymaster note: Only considered when `paymasterAndData.length >= PAYMASTER_DATA_OFFSET`.
     */
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        returns (uint256);

    /**
     * @notice Initialize budgets manually for a given (configId, account).
     * @param account  The 7702 account or SCA whose budgets are being set. Must be the caller.
     * @param configId Session key / policy identifier.
     * @param gasLimitBE Gas budget values.
     * @dev Reverts if already initialized, or if `gasLimit` are zero.
     */
    function initializeGasPolicy(address account, bytes32 configId, bytes16 gasLimitBE) external;

    /**
     * @notice Initialize budgets using conservative defaults scaled by a tx `limit` (gas-only).
     * @param account  The 7702 account or SCA whose budgets are being set. Must be the caller.
     * @param configId Session key / policy identifier.
     * @param limit    Number of UserOperations allowed in this session (0 < limit ≤ 2^32-1).
     * @dev
     *  - Derives per-op envelope by summing DEFAULT_* legs and applying `SAFETY_BPS`.
     *  - No price/wei math; only gas-unit limits are configured.
     */
    function initializeGasPolicy(address account, bytes32 configId, uint256 limit) external;

    /// @notice Read a compact view of gas budgets and usage for (configId, account).
    /// @param configId      Session/policy identifier.
    /// @param userOpSender  The account whose config is queried.
    /// @return gasLimit  Cumulative gas units allowed.
    /// @return gasUsed   Gas units consumed so far.
    function getGasConfig(bytes32 configId, address userOpSender)
        external
        view
        returns (uint128 gasLimit, uint128 gasUsed);

    /**
     * @notice Read the full `GasLimitConfig` struct for (configId, account).
     * @param configId  Session/policy identifier.
     * @param userOpSender The account address whose config is queried.
     * @return The full GasLimitConfig stored at (configId, userOpSender).
     */
    function getGasConfigEx(bytes32 configId, address userOpSender)
        external
        view
        returns (GasLimitConfig memory);
}
