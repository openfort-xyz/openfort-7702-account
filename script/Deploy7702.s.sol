// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {OPFMain} from "src/core/OPFMain.sol";
import {Script, console2 as console} from "lib/forge-std/src/Script.sol";

contract Deploy7702 is Script {
    address constant WEBAUTHN_VERIFIER = 0x83b7acb5A6aa8A34A97bdA13182aEA787AC3f10d;
    uint256 constant RECOVERY_PERIOD = 2 days;
    uint256 constant LOCK_PERIOD = 5 days;
    uint256 constant SECURITY_PERIOD = 1.5 days;
    uint256 constant SECURITY_WINDOW = 0.5 days;

    function run() public {
        vm.startBroadcast();

        OPFMain opf = deployWithCreate2();

        console.log("Address:", address(opf));

        vm.stopBroadcast();
    }

    function deployWithCreate2() public returns (OPFMain) {
        bytes32 SALT = keccak256("OPFMain7702");
        address entryPoint = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;

        bytes memory byteCode = abi.encodePacked(
            type(OPFMain).creationCode,
            abi.encode(
                entryPoint,
                WEBAUTHN_VERIFIER,
                RECOVERY_PERIOD,
                LOCK_PERIOD,
                SECURITY_PERIOD,
                SECURITY_WINDOW
            )
        );

        address payable deployedAddress;
        assembly {
            deployedAddress := create2(0, add(byteCode, 0x20), mload(byteCode), SALT)
        }

        require(deployedAddress != address(0), "CREATE2 deployment failed");

        return OPFMain(deployedAddress);
    }
}

// forge script Deploy7702 --rpc-url https://eth-sepolia.g.alchemy.com/v2/EIOmdDtOw7ulufI5S27isOfZfW51PQXB --account
// BURNER_KEY --verify --etherscan-api-key $ETHERSCAN_KEY --broadcast
// forge script Deploy7702 --rpc-url https://opt-sepolia.g.alchemy.com/v2/EIOmdDtOw7ulufI5S27isOfZfW51PQXB --account
// BURNER_KEY --verify --etherscan-api-key $ETHERSCAN_KEY --broadcast
// forge script Deploy7702 --rpc-url https://arb-sepolia.g.alchemy.com/v2/EIOmdDtOw7ulufI5S27isOfZfW51PQXB --account
// BURNER_KEY --verify --etherscan-api-key $ETHERSCAN_KEY --broadcast
// forge script Deploy7702 --rpc-url https://base-sepolia.g.alchemy.com/v2/EIOmdDtOw7ulufI5S27isOfZfW51PQXB --account
// BURNER_KEY --verify --etherscan-api-key $ETHERSCAN_KEY --broadcast

// forge verify-contract --watch --chain 11155111 --verifier etherscan 0xb4C8cd302d061311373D0e6C11780F208bAA9220
// src/core/OPFMain.sol:OPFMain -e QNAZY35DJPVNWFA9G1Y1ITGQ4H4YK8WB1J -a v2 --constructor-args
// 0000000000000000000000004337084d9e255ff0702461cf8895ce9e3b5ff10800000000000000000000000083b7acb5a6aa8a34a97bda13182aea787ac3f10d000000000000000000000000000000000000000000000000000000000002a3000000000000000000000000000000000000000000000000000000000000069780000000000000000000000000000000000000000000000000000000000001fa40000000000000000000000000000000000000000000000000000000000000a8c0
// forge verify-contract --watch --chain 11155420 --verifier etherscan 0xb4C8cd302d061311373D0e6C11780F208bAA9220
// src/core/OPFMain.sol:OPFMain -e QNAZY35DJPVNWFA9G1Y1ITGQ4H4YK8WB1J -a v2 --constructor-args
// 0000000000000000000000004337084d9e255ff0702461cf8895ce9e3b5ff10800000000000000000000000083b7acb5a6aa8a34a97bda13182aea787ac3f10d000000000000000000000000000000000000000000000000000000000002a3000000000000000000000000000000000000000000000000000000000000069780000000000000000000000000000000000000000000000000000000000001fa40000000000000000000000000000000000000000000000000000000000000a8c0
// forge verify-contract --watch --chain 421614 --verifier etherscan 0xb4C8cd302d061311373D0e6C11780F208bAA9220
// src/core/OPFMain.sol:OPFMain -e QNAZY35DJPVNWFA9G1Y1ITGQ4H4YK8WB1J -a v2 --constructor-args
// 0000000000000000000000004337084d9e255ff0702461cf8895ce9e3b5ff10800000000000000000000000083b7acb5a6aa8a34a97bda13182aea787ac3f10d000000000000000000000000000000000000000000000000000000000002a3000000000000000000000000000000000000000000000000000000000000069780000000000000000000000000000000000000000000000000000000000001fa40000000000000000000000000000000000000000000000000000000000000a8c0
// forge verify-contract --watch --chain 421614 --verifier etherscan 0xb4C8cd302d061311373D0e6C11780F208bAA9220
// src/core/OPFMain.sol:OPFMain -e QNAZY35DJPVNWFA9G1Y1ITGQ4H4YK8WB1J -a v2 --constructor-args
// 0000000000000000000000004337084d9e255ff0702461cf8895ce9e3b5ff10800000000000000000000000083b7acb5a6aa8a34a97bda13182aea787ac3f10d000000000000000000000000000000000000000000000000000000000002a3000000000000000000000000000000000000000000000000000000000000069780000000000000000000000000000000000000000000000000000000000001fa40000000000000000000000000000000000000000000000000000000000000a8c0
