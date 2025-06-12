// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {OpenfortBaseAccount7702V1} from "contracts/core/OpenfortBaseAccount7702V1.sol";

contract OpenfortBaseAccount7702V1Deployer is Script {
    function run() external returns (OpenfortBaseAccount7702V1) {
        vm.startBroadcast();
        OpenfortBaseAccount7702V1 openfortBaseAccount = new OpenfortBaseAccount7702V1();
        vm.stopBroadcast();
        return openfortBaseAccount;
    }
}
