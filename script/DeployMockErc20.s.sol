// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {MockERC20} from "src/mocks/MockERC20.sol";
import {Script, console2 as console} from "lib/forge-std/src/Script.sol";

contract DeployMockERC20 is Script {
    function run() public {
        vm.startBroadcast();

        MockERC20 token = deployWithCreate2();

        console.log("MockERC20 deployed at:", address(token));

        vm.stopBroadcast();
    }

    function deployWithCreate2() public returns (MockERC20) {
        bytes32 SALT = keccak256("MockERC20");

        bytes memory bytecode = abi.encodePacked(type(MockERC20).creationCode);

        address deployedAddress;
        assembly {
            deployedAddress := create2(0, add(bytecode, 0x20), mload(bytecode), SALT)
        }

        require(deployedAddress != address(0), "CREATE2 deployment failed");

        return MockERC20(deployedAddress);
    }
}

/// forge script DeployMockERC20 --rpc-url https://polygon-amoy-bor-rpc.publicnode.com --account BURNER_KEY --verify
/// --etherscan-api-key $ETHERSCAN_KEY --broadcast
/// forge script DeployMockERC20 --rpc-url https://subnets.avax.network/beam/testnet/rpc --account BURNER_KEY --verify
/// --etherscan-api-key $ETHERSCAN_KEY --broadcast

// forge verify-contract --watch --chain 11155111 --verifier etherscan 0xb4C8cd302d061311373D0e6C11780F208bAA9220
// src/core/OPFMain.sol:OPFMain -e QNAZY35DJPVNWFA9G1Y1ITGQ4H4YK8WB1J -a v2 --constructor-args
// 0000000000000000000000004337084d9e255ff0702461cf8895ce9e3b5ff10800000000000000000000000083b7acb5a6aa8a34a97bda13182aea787ac3f10d000000000000000000000000000000000000000000000000000000000002a3000000000000000000000000000000000000000000000000000000000000069780000000000000000000000000000000000000000000000000000000000001fa40000000000000000000000000000000000000000000000000000000000000a8c0
// forge verify-contract --watch --chain 13337 --verifier etherscan 0xef147ed8bb07a2a0e7df4c1ac09e96dec459ffac
// src/mocks/MockERC20.sol -e QNAZY35DJPVNWFA9G1Y1ITGQ4H4YK8WB1J -a v2
