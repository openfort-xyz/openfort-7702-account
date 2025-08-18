// SPDX-License-Identifier: MIR

pragma solidity ^0.8.29;

interface ISpendLimit {
    /**
     * @notice Token spending limit information
     * @param token ERC20 Token Address
     * @param limit Spending Limit
     */
    struct SpendTokenInfo {
        address token;
        uint256 limit;
    }
}
