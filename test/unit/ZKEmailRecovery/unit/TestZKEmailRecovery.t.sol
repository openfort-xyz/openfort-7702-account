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

        // Register Guardians DKIM
        _registerDKIM();

        // Accept guardians
        _acceptGuardians();

        // Verify guardians
        _assertAcception();

        _computeRecoveryDataHash();

        uint256 executeAfter = _requestRecovery();
        // Warp past delay period
        vm.warp(executeAfter + 1);

        // Execute recovery - calls startRecovery(Key) on MockValidator
        // MockValidator forwards to account's startRecovery(Key)
        vm.prank(__RELAYER_ADDRESS);
        universalEmailRecoveryModule.completeRecovery(__OWNER_7702_ADDRESS, recoveryData);

        _assertRecovery();
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

    function _registerDKIM() internal {
        _registerDKIMPublicKeyHash(guardian1_Proof.DOMAIN, guardian1_Proof.PUBLIC_KEY_HASH, __OWNER_7702_ADDRESS);
        _registerDKIMPublicKeyHash(guardian2_Proof.DOMAIN, guardian2_Proof.PUBLIC_KEY_HASH, __OWNER_7702_ADDRESS);
    }

    function _acceptGuardians() internal {
        _acceptGuardianReal(
            guardian1_Proof.ACCOUNT_SALT,
            guardian1_Proof.DOMAIN,
            guardian1_Proof.PUBLIC_KEY_HASH,
            guardian1_Proof.EMAIL_NULLIFIER,
            guardian1_Proof.IS_CODE_EXIST,
            guardian1_Proof.TIMESTAMP,
            guardian1_Proof.PROOF
        );

        _acceptGuardianReal(
            guardian2_Proof.ACCOUNT_SALT,
            guardian2_Proof.DOMAIN,
            guardian2_Proof.PUBLIC_KEY_HASH,
            guardian2_Proof.EMAIL_NULLIFIER,
            guardian2_Proof.IS_CODE_EXIST,
            guardian2_Proof.TIMESTAMP,
            guardian2_Proof.PROOF
        );
    }

    function _acceptGuardianReal(
        bytes32 _accountSalt,
        string memory _domain,
        bytes32 _publicKeyHash,
        bytes32 _emailNullifier,
        bool _isCodeExist,
        uint256 _timestamp,
        bytes memory _zkProof
    )
        internal
    {
        EmailAuthMsg memory emailAuthMsg = _buildEmailAuthMsgReal(
            __OWNER_7702_ADDRESS,
            _domain,
            _publicKeyHash,
            _timestamp,
            _accountSalt,
            _emailNullifier,
            _isCodeExist,
            _zkProof
        );

        vm.prank(__RELAYER_ADDRESS);
        universalEmailRecoveryModule.handleAcceptance(emailAuthMsg, 0);
    }

    function _assertAcception() internal view {
        (uint256 status1,) = _getGuardianStatus(__OWNER_7702_ADDRESS, guardians[0]);
        assertEq(status1, 2, "Guardian 1 should be ACCEPTED (2)");

        (uint256 status2,) = _getGuardianStatus(__OWNER_7702_ADDRESS, guardians[1]);
        assertEq(status2, 2, "Guardian 2 should be ACCEPTED (2)");

        (,, uint256 acceptedWeight2,) = _getGuardianConfig(__OWNER_7702_ADDRESS);
        assertEq(acceptedWeight2, 2, "Accepted weight should be 2");
    }

    function _computeRecoveryDataHash() internal {
        // Compute hash using startRecovery(Key) - MUST match proof generation
        (recoveryData, recoveryDataHash) = _computeRecoveryDataHashForKey(
            address(erc7579Module), // Must match proof's validator
            newOwnerKey // EOA Key struct
        );
    }

    function _requestRecovery() internal returns (uint256) {
        // Guardian 1 votes
        EmailAuthMsg memory emailAuthMsg1 = _buildRecoveryEmailAuthMsgGuardian1(__OWNER_7702_ADDRESS, recoveryDataHash);
        vm.prank(__RELAYER_ADDRESS);
        universalEmailRecoveryModule.handleRecovery(emailAuthMsg1, 0);

        // Guardian 2 votes
        EmailAuthMsg memory emailAuthMsg2 = _buildRecoveryEmailAuthMsgGuardian2(__OWNER_7702_ADDRESS, recoveryDataHash);
        vm.prank(__RELAYER_ADDRESS);
        universalEmailRecoveryModule.handleRecovery(emailAuthMsg2, 0);

        // Get recovery request details
        (uint256 executeAfter,, uint256 currentWeight,) = _getRecoveryRequest(__OWNER_7702_ADDRESS);

        // Verify threshold is met
        (,,, uint256 threshold) = _getGuardianConfig(__OWNER_7702_ADDRESS);
        assertGe(currentWeight, threshold, "Threshold should be met");

        return executeAfter;
    }

    function _assertRecovery() internal view {
        bytes32 keyId = _computeKeyId(newOwnerKey.keyType, newOwnerKey.key);
        // Verify owner changed to full Key struct
        KeyData memory currentOwner = OPFMain(payable(__OWNER_7702_ADDRESS)).getKey(keyId);
        assertEq(uint8(currentOwner.keyType), uint8(newOwnerKey.keyType), "Owner keyType should match");
        assertTrue(currentOwner.isActive, "Owner key should be active"); 
        assertTrue(currentOwner.masterKey, "Owner key should be master key"); 
        assertFalse(currentOwner.isDelegatedControl, "Owner key should not be delegated control"); 
        assertEq(currentOwner.validUntil, newOwnerKey.validUntil, "Owner validUntil should match"); 
        assertEq(currentOwner.validAfter, newOwnerKey.validAfter, "Owner validAfter should match");
        assertEq(currentOwner.limits, newOwnerKey.limits, "Owner limits should match"); 
        assertEq(keccak256(currentOwner.key), keccak256(newOwnerKey.key), "Owner key should match"); 
        console.log("SUCCESS: Full Key-based recovery cycle completed with real ZK proofs");
    }

    function _computeKeyId(KeyType _keyType, bytes memory _key)
        internal
        pure
        returns (bytes32 result)
    {
        uint256 v0 = uint8(_keyType);
        uint256 v1 = uint256(keccak256(_key));
        assembly {
            mstore(0x00, v0)
            mstore(0x20, v1)
            result := keccak256(0x00, 0x40)
        }
    }
}
