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
     * @notice Validates token spending against limits
     * @param key Key data
     * @param innerData Call data containing token transfer details
     * @return True if the token spend is valid, false otherwise
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
