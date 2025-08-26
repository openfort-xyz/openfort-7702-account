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
    error GasPolicy_CostLimitHigh();
    error GasPolicy_PerOpCostHigh();
    error GasPolicy__IdExistAlready();
    error GasPolicy_PerOpCostOverflow();
    error GasPolicy__AccountMustBeSender();
    error GasPolicy__InitializationIncorrect();

    // ---------------------- Events ----------------------
    event GasPolicyInitialized(
        bytes32 indexed configId,
        address indexed account,
        uint256 gasLimit,
        uint256 costLimit,
        uint256 perOpMaxCostWei,
        uint256 txLimit,
        uint256 penaltyBps,
        uint256 penaltyThreshold,
        bool autoInit
    );

    event GasPolicyAccounted(
        bytes32 indexed configId,
        address indexed account,
        uint256 envelopeUnits,
        uint256 priceWei,
        uint256 penaltyGas,
        uint256 worstCaseWei,
        uint256 gasUsedTotal,
        uint256 costUsedTotal,
        uint256 txUsedTotal
    );

    struct InitData {
        uint128 gasLimit;
        uint128 costLimit;
        uint128 perOpMaxCostWei; // 0 = disabled
        uint32 txLimit; // 0 = disabled
        uint16 penaltyBps; // 0 -> default 10%
        uint32 penaltyThreshold; // 0 -> default 40_000
    }

    struct GasLimitConfig {
        uint128 gasLimit; // cumulative envelope units budget (PVG+VGL+CGL+PM legs)
        uint128 gasUsed;
        uint128 costLimit; // cumulative worst-case wei budget
        uint128 costUsed;
        uint128 perOpMaxCostWei; // optional per-op cap (0 = disabled)
        uint32 txLimit; // optional tx count cap (0 = disabled)
        uint32 txUsed;
        uint16 penaltyBps; // default 1000 (10%)
        uint32 penaltyThreshold; // default 40,000 (EP v0.8)
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
        returns (uint128 gasLimit, uint128 gasUsed, uint128 costLimit, uint128 costUsed);

    function getGasConfigEx(bytes32 configId, address userOpSender)
        external
        view
        returns (GasLimitConfig memory);
}
