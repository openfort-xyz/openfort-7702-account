// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {Script, console2 as console} from "lib/forge-std/src/Script.sol";

contract DeployWebAuthnVerifierV2 is Script {
    bytes32 constant salt = 0x00000000000000000000000000000000000000000000000000000000053c9a0a;
    address owner = 0xA84E4F9D72cb37A8276090D3FC50895BD8E5Aaf1;
    address manager = 0x25B10f9CAdF3f9F7d3d57921fab6Fdf64cC8C7f4;
    address private CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function run() public {
        vm.startBroadcast();

        // Get creation code with constructor args
        bytes memory creationCode = abi.encodePacked(type(WebAuthnVerifierV2).creationCode);
        console.logBytes(creationCode);
        // console.logBytes(creationCode);

        // Calculate the expected address using vm.computeCreate2Address
        address expectedAddress =
            vm.computeCreate2Address(salt, keccak256(creationCode), CREATE2_DEPLOYER);

        console.log("Expected deployment address:", expectedAddress);
        console.log("Using salt:", vm.toString(salt));
        console.log("CREATE2 Deployer:", CREATE2_DEPLOYER);

        // Check if already deployed
        if (expectedAddress.code.length > 0) {
            console.log("Contract already deployed at:", expectedAddress);
            vm.stopBroadcast();
            return;
        }

        // Deploy via CREATE2 deployer
        // The CREATE2 deployer expects: salt (32 bytes) + creationCode
        bytes memory deploymentData = abi.encodePacked(salt, creationCode);

        (bool success,) = CREATE2_DEPLOYER.call(deploymentData);

        require(success, "CREATE2 deployment failed");

        console.log("Contract deployed successfully!");
        console.log("Deployed to expected address:", expectedAddress);

        // Verify the deployment by checking code exists
        require(expectedAddress.code.length > 0, "No code at deployed address");

        console.log("Deployment completed successfully!");

        vm.stopBroadcast();
    }
}

/**
 * forge verify-contract --chain-id 84532 0x0000256A4eB4642E668CD371aeDE4b004295ad65 src/utils/WebAuthnVerifierV2.sol:WebAuthnVerifierV2 -e $ETHERSCAN_KEY --verifier etherscan
 */
