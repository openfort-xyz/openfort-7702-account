// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { OPFMain } from "src/core/OPFMain.sol";
import { Constants } from "../data/Constants.sol";
import { Helpers } from "./../helpers/Helpers.t.sol";
import { ERC7579Module } from "src/utils/ERC7579Module.sol";
import { EmailAuthMsg } from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import {
    UniversalEmailRecoveryModule
} from "zk-email-recovery-contracts/email-recovery/src/modules/UniversalEmailRecoveryModule.sol";
import {
    GuardianStorage,
    GuardianStatus
} from "zk-email-recovery-contracts/email-recovery/src/libraries/EnumerableGuardianMap.sol";

import { console2 as console } from "lib/forge-std/src/console2.sol";

contract TestZKEmailRecovery is Helpers {
    address[] guardians;
    uint256[] weights;
    uint256 executeAfter;

    KeyDataReg internal newOwnerKey;

    bytes internal recoveryData;
    bytes32 internal recoveryDataHash;

    function setUp() public override {
        _enableFork();
        super.setUp();

        // Load all proofs (acceptance + recovery)
        _loadAllProofs(ProofType.EOA_KEY_TYPE);
        _loadAllRecoveryProofs(ProofType.EOA_KEY_TYPE);

        _deal(__OWNER_7702_ADDRESS, 10 ether);
        _deal(__RELAYER_ADDRESS, 10 ether);

        // Etch the 7579-compatible account implementation
        _etch7702(__OWNER_7702_ADDRESS, address(implementation));
        _depositStake(__OWNER_7702_ADDRESS, 0.5 ether, 860);

        // Install MockValidator on the account (as TYPE_VALIDATOR)
        _installValidator();
    }

    function _installValidator() internal {
        vm.prank(__OWNER_7702_ADDRESS);
        OPFMain(payable(__OWNER_7702_ADDRESS))
            .installModule(Constants.MODULE_TYPE_VALIDATOR, address(erc7579Module), bytes(""));
    }
}
