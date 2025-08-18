// SPDX-License-Identifier: MIR

pragma solidity ^0.8.0;

import {IKey} from "src/interfaces/IKey.sol";

abstract contract SpendLimit {
    /**
     * @notice Token spending limit information
     * @param token ERC20 Token Address
     * @param limit Spending Limit
     */
    struct SpendTokenInfo {
        address token;
        uint256 limit;
    }

    /**
    * @notice Validates and debits ERC-20 token spend for a session key.
    * @dev Calldata expectation: `innerData` is ABI-encoded for an ERC-20 method
    *      whose **last parameter is the token amount (uint256)**, e.g.:
    *        - transfer(address to, uint256 amount)          // selector 0xa9059cbb
    *        - transferFrom(address from, address to, uint256 amount) // 0x23b872dd
    *
    *      We read the final 32-byte word of `innerData` as `amount`, require
    *      `amount <= key.spendTokenInfo.limit`, and then decrement the limit by `amount`.
    *
    *      Out of scope (not interpreted here): ERC-777, ERC-1363, ERC-4626, permit flows,
    *      or any function where the amount is not the last argument. Such selectors must be
    *      blocked elsewhere (e.g., via allowed selectors) to avoid mis-accounting.
    *
    * @param key       Storage reference to the key’s data (limit is read/decremented).
    * @param innerData Full ABI-encoded token call; last 32 bytes must be `amount`.
    * @return True if within limit and debited; false if it exceeds.
    */
    function _validateTokenSpend(IKey.KeyData storage key, bytes memory innerData)
        internal
        virtual
        returns (bool)
    {
        uint256 startPos = innerData.length - 32;
        bytes32 value;
        assembly {
            value := mload(add(add(innerData, 0x20), startPos))
        }

        if (uint256(value) > key.spendTokenInfo.limit) return false;

        if (uint256(value) > 0) {
            key.spendTokenInfo.limit = key.spendTokenInfo.limit - uint256(value);
        }

        return true;
    }
}
