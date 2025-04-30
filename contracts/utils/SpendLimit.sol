// SPDX-License-Identifier: MIR

pragma solidity ^0.8.0;

import {ISessionKey} from "contracts/interfaces/ISessionKey.sol";

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
     * @param sessionKey Session key data
     * @param innerData Call data containing token transfer details
     * @return True if the token spend is valid, false otherwise
     */
    function _validateTokenSpend(ISessionKey.SessionKey storage sessionKey, bytes memory innerData)
        internal
        returns (bool)
    {
        uint256 startPos = innerData.length - 32;
        bytes32 value;
        assembly {
            value := mload(add(add(innerData, 0x20), startPos))
        }

        if (uint256(value) > sessionKey.spendTokenInfo.limit) return false;

        if (uint256(value) > 0) {
            sessionKey.spendTokenInfo.limit = sessionKey.spendTokenInfo.limit - uint256(value);
        }

        return true;
    }
}
