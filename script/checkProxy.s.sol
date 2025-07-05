// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "lib/forge-std/src/Script.sol";
import {console2 as console} from "lib/forge-std/src/console2.sol";

contract CheckGetters is Script {
    function run() external view {
        address proxy = 0xb37874843350e3BFE1de2B50bd3ef381c3D8e6C2;
        bytes[] memory callDatas = new bytes[](3);

        callDatas[0] = abi.encodeWithSignature("id()");
        callDatas[1] = abi.encodeWithSignature("guardianCount()");
        callDatas[2] = abi.encodeWithSignature("getKeyById(uint256)", 0);

        for (uint256 i = 0; i < callDatas.length; i++) {
            (bool v, bytes memory res) = proxy.staticcall(callDatas[i]);
            console.log("v", v);
            console.logBytes(res);
        }
    }
}
