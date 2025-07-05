// SPDX_License-Identifier: MIT

pragma solidity 0.8.29;

import {Base} from "test/Base.sol";
import {OPFMain} from "src/core/OPFMain.sol";
import {LibEIP7702} from "lib/solady/src/accounts/LibEIP7702.sol";
import {Script, console2 as console} from "lib/forge-std/src/Script.sol";

contract Deploy is Script {
    address constant SEPOLIA_ENTRYPOINT = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address constant SEPOLIA_WEBAUTHN = 0x83b7acb5A6aa8A34A97bdA13182aEA787AC3f10d;
    uint256 constant RECOVERY_PERIOD = 2 days;
    uint256 constant LOCK_PERIOD = 5 days;
    uint256 constant SECURITY_PERIOD = 1.5 days;
    uint256 constant SECURITY_WINDOW = 0.5 days;

    function run() public {
        vm.startBroadcast();

        OPFMain opf = new OPFMain(
            SEPOLIA_ENTRYPOINT,
            SEPOLIA_WEBAUTHN,
            RECOVERY_PERIOD,
            LOCK_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW
        );

        address proxy = LibEIP7702.deployProxy(address(opf), address(0));

        console.log("Proxy:", proxy);

        vm.stopBroadcast();
    }
}
