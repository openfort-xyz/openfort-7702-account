// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {GasPolicy} from "src/utils/GasPolicy.sol";
import {Script, console2 as console} from "lib/forge-std/src/Script.sol";

contract DeployWebAuthnVerifierV2 is Script {
    bytes32 constant salt = 0x00000000000000000000000000000000000000000000000000000000214d5d6e;
    address owner = 0xA84E4F9D72cb37A8276090D3FC50895BD8E5Aaf1;
    address manager = 0x25B10f9CAdF3f9F7d3d57921fab6Fdf64cC8C7f4;
    address private CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    uint256 constant DEFAULT_PVG = 110_000; // packaging/bytes for P-256/WebAuthn-ish signatures
    uint256 constant DEFAULT_VGL = 360_000; // validation (session key checks, EIP-1271/P-256 parsing)
    uint256 constant DEFAULT_CGL = 240_000; // ERC20 transfer/batch-ish execution
    uint256 constant DEFAULT_PMV = 60_000; // paymaster validate (if used)
    uint256 constant DEFAULT_PO = 60_000; // postOp (token charge/refund)

    function run() public {
        vm.startBroadcast();

        // Get creation code with constructor args
        bytes memory constructorArgs =
            abi.encodePacked(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        console.logBytes(constructorArgs);

        bytes memory creationCode = abi.encodePacked(type(GasPolicy).creationCode, constructorArgs);
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
 * forge verify-contract --chain-id 84532 0x0000FEeaB9F73EAa49583aC15357a8673098D971 src/utils/GasPolicy.sol:GasPolicy -e $ETHERSCAN_KEY --verifier etherscan --constructor-args 0x000000000000000000000000000000000000000000000000000000000001adb00000000000000000000000000000000000000000000000000000000000057e40000000000000000000000000000000000000000000000000000000000003a980000000000000000000000000000000000000000000000000000000000000ea60000000000000000000000000000000000000000000000000000000000000ea60
 */
