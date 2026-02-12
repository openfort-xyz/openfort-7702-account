// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {OPFMain} from "src/core/OPFMain.sol";
import {Constants} from "../data/Constants.sol";
import {Helpers} from "./../helpers/Helpers.t.sol";
import {ERC7579Module} from "src/utils/ERC7579Module.sol";
import {EmailAuthMsg} from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import {
    UniversalEmailRecoveryModule
} from "zk-email-recovery-contracts/email-recovery/src/modules/UniversalEmailRecoveryModule.sol";
import {
    GuardianStorage,
    GuardianStatus
} from "zk-email-recovery-contracts/email-recovery/src/libraries/EnumerableGuardianMap.sol";

import {console2 as console} from "lib/forge-std/src/console2.sol";

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

    function test_recovery_full_cycle_with_key_proofs() external {
        _initNewOwnerKeyEOA();

        // Register guardians using startRecovery(Key) selector
        _registerGuardiansForKeyRecovery();

        // // Register Guardians DKIM
        // _registerDKIM();

        // // Accept guardians
        // _acceptGuardians();

        // // Verify guardians
        // _assertAcception();

        // _computeRecoveryDataHash();

        // uint256 executeAfter = _requestRecovery();
        // // Warp past delay period
        // vm.warp(executeAfter + 1);

        // // Execute recovery - calls startRecovery(Key) on MockValidator
        // // MockValidator forwards to account's startRecovery(Key)
        // universalEmailRecoveryModule.completeRecovery(__OWNER_7702_ADDRESS, recoveryData);
    }

    function _installValidator() internal {
        vm.prank(__OWNER_7702_ADDRESS);
        OPFMain(payable(__OWNER_7702_ADDRESS))
            .installModule(Constants.MODULE_TYPE_VALIDATOR, address(erc7579Module), bytes(""));
    }

    function _initNewOwnerKeyEOA() internal {
        newOwnerKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: abi.encode(__NEW_OWNER_7702_ADDRESS),
            keyControl: KeyControl.Self
        });
    }

    function _registerGuardiansForKeyRecovery() internal {
        address guardian1 = _computeGuardianAddress(__OWNER_7702_ADDRESS, __GUARDIAN_1_ACCOUNT_SALT);
        address guardian2 = _computeGuardianAddress(__OWNER_7702_ADDRESS, __GUARDIAN_2_ACCOUNT_SALT);

        guardians.push(guardian1);
        guardians.push(guardian2);

        weights.push(1);
        weights.push(1);

        // Use constant MockValidator with startRecovery(Key) selector
        bytes memory installData =
            _createInstallDataForKeyRecovery(address(erc7579Module), guardians, weights);

        _installModule(Constants.MODULE_TYPE_EXECUTOR, address(universalEmailRecoveryModule), installData);

        _verifyGuardianConfig(guardians, Constants.THRESHOLD);
    }

    function _installModule(uint256 _moduleType, address _emailRecoveryModule, bytes memory _installData) internal {
        vm.prank(__OWNER_7702_ADDRESS);
        OPFMain(payable(__OWNER_7702_ADDRESS)).installModule(_moduleType, _emailRecoveryModule, _installData);
    }

    function _verifyGuardianConfig(address[] memory _guardians, uint256 expectedThreshold) internal view {
        (uint256 guardianCount, uint256 totalWeight, uint256 acceptedWeight, uint256 thresholdValue) =
            _getGuardianConfig(__OWNER_7702_ADDRESS);

        assertEq(guardianCount, _guardians.length, "Guardian count mismatch");
        assertEq(totalWeight, _guardians.length, "Total weight mismatch");
        assertEq(thresholdValue, expectedThreshold, "Threshold mismatch");
        assertEq(acceptedWeight, 0, "Accepted weight should be 0 initially");

        for (uint256 i = 0; i < _guardians.length; i++) {
            (uint256 status, uint256 weight) = _getGuardianStatus(__OWNER_7702_ADDRESS, _guardians[i]);
            assertEq(status, 1, "Guardian status should be REQUESTED (1)");
            assertEq(weight, 1, "Guardian weight mismatch");
        }
    }
}
