// // SPDX_License-Identifier: MIT

// pragma solidity 0.8.29;

// import {Base} from "test/Base.sol";
// import {OPFMain} from "src/core/OPFMain.sol";
// import {GasPolicy} from "src/utils/GasPolicy.sol";
// import {LibEIP7702} from "lib/solady/src/accounts/LibEIP7702.sol";
// import {Script, console2 as console} from "lib/forge-std/src/Script.sol";

// contract DeployUpgradeable is Script {
//     address constant SEPOLIA_ENTRYPOINT = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
//     address constant SEPOLIA_WEBAUTHN = 0xeD43b3a3D00d791BC0B353666b5780B0F9245CC1;
//     uint256 constant RECOVERY_PERIOD = 2 days;
//     uint256 constant LOCK_PERIOD = 5 days;
//     uint256 constant SECURITY_PERIOD = 1.5 days;
//     uint256 constant SECURITY_WINDOW = 0.5 days;
//     GasPolicy public gasPolicy;

//     function run() public {
//         vm.startBroadcast();
//         gasPolicy = new GasPolicy(110_000, 360_000, 240_000, 60_000, 60_000);

//         OPFMain opf = new OPFMain(
//             SEPOLIA_ENTRYPOINT,
//             SEPOLIA_WEBAUTHN,
//             RECOVERY_PERIOD,
//             LOCK_PERIOD,
//             SECURITY_PERIOD,
//             SECURITY_WINDOW,
//             address(gasPolicy)
//         );

//         address proxy = LibEIP7702.deployProxy(address(opf), address(0));

//         console.log("Proxy:", proxy);

//         vm.stopBroadcast();
//     }
// }
