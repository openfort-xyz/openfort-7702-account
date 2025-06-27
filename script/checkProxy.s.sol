// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "forge-std/Script.sol";

contract CheckGetters is Script {
    function run() external view {
        address proxy = 0xA97Ca015ACe1F3eD63EAE764336dB62258B84E5F;

        // Call your specific getters
        (bool success, bytes memory data) =
            proxy.staticcall(abi.encodeWithSignature("_OPENFORT_CONTRACT_ADDRESS()"));

        if (success) {
            address entryPoint = abi.decode(data, (address));
            console.log("EntryPoint:", entryPoint);
        }
    }
}
