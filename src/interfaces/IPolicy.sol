// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import "lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

interface IPolicy is IERC165 {}

interface IUserOpPolicy is IPolicy {
    error GasPolicy__BadLimit();
    error GasPolicy_GasLimitHigh();
    error GasPolicy__ZeroBudgets();
    error GasPolicy__IdExistAlready();
    error GasPolicy__AccountMustBeSender();
    error GasPolicy__InitializationIncorrect();

    // ---------------------- Events ----------------------
    /// @custom:remove-ignore-by-lint (uncomment to count txs)   uint256 txLimit
    event GasPolicyInitialized(
        bytes32 indexed configId,
        address indexed account,
        uint256 gasLimit,
        bool autoInit
    );


    // cumulative gas units used
    // cumulative ops used
    /// @custom:remove-ignore-by-lint (uncomment to count txs) uint256 txUsedTotal
    event GasPolicyAccounted(
        bytes32 indexed configId,
        address indexed account,
        uint256 envelopeUnits,
        uint256 gasUsedTotal
    );

    struct InitData {
        uint128 gasLimit;
        uint32 txLimit; // 0 = disabled
    }

    struct GasLimitConfig {
        uint128 gasLimit; // cumulative envelope units budget (PVG+VGL+CGL+PM legs)
        uint128 gasUsed;
        // uint32 txLimit; /// @custom:remove-ignore-by-lint (uncomment to count txs)
        // uint32 txUsed;  /// @custom:remove-ignore-by-lint (uncomment to count txs)
        bool initialized;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        returns (uint256);

    function initializeGasPolicy(address account, bytes32 configId, uint256 limit) external;

    function initializeGasPolicy(address account, bytes32 configId, bytes calldata initData)
        external;

    function getGasConfig(bytes32 configId, address userOpSender)
        external
        view
        returns (uint128 gasLimit, uint128 gasUsed);

    function getGasConfigEx(bytes32 configId, address userOpSender)
        external
        view
        returns (GasLimitConfig memory);
}
