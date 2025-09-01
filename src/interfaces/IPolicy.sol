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
    event GasPolicyInitialized(
        bytes32 indexed configId,
        address indexed account,
        uint256 gasLimit,
        uint256 txLimit,
        bool autoInit
    );

    // cumulative gas units used
    // cumulative ops used
    event GasPolicyAccounted(
        bytes32 indexed configId,
        address indexed account,
        uint256 envelopeUnits,
        uint256 gasUsedTotal,
        uint256 txUsedTotal
    );

    struct InitData {
        uint128 gasLimit;
        uint32 txLimit; // 0 = disabled
    }

    struct GasLimitConfig {
        uint128 gasLimit; // cumulative envelope units budget (PVG+VGL+CGL+PM legs)
        uint128 gasUsed;
        uint32 txLimit; // optional tx count cap (0 = disabled)
        uint32 txUsed;
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
        returns (uint128 gasLimit, uint128 gasUsed, uint32 txLimit, uint32 txUsed);

    function getGasConfigEx(bytes32 configId, address userOpSender)
        external
        view
        returns (GasLimitConfig memory);
}
