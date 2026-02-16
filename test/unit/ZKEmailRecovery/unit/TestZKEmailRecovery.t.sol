// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "../interfaces/IKeyV2.sol";
import {OPFMain} from "src/core/OPFMain.sol";
import {Constants} from "../data/Constants.sol";
import {Helpers} from "./../helpers/Helpers.t.sol";
import {Simple7702AccountIndi} from "../mocks/Simple7702AccountIndi.sol";
import {EmailAuthMsg} from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
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

    IKeyV2.KeyDataReg internal newOwner;

    bytes internal recoveryData;
    bytes32 internal recoveryDataHash;

    address private STUB_MOCK_VALIDATOR_FOR_KEY_RECOVERY =
        0x0000000000000000000000000000000000000002;

    function setUp() public override {
        _enableFork("https://ethereum-sepolia-rpc.publicnode.com");
        super.setUp();

        // Load all proofs (acceptance + recovery)
        _loadAllProofs(ProofType.EOA_KEY_TYPE);
        _loadAllRecoveryProofs(ProofType.ELSE);

        _deal(__OWNER_7702_ADDRESS, 10 ether);
        _deal(__RELAYER_ADDRESS, 10 ether);

        // Etch the non-ERC7579 account implementation (uses shim functions instead)
        _etch7702(__OWNER_7702_ADDRESS, address(implementation));
        _depositStake(__OWNER_7702_ADDRESS, 0.5 ether, 860);
    }

    function test_recovery_full_cycle_with_key_proofs() external {
        _initNewOwnerEOA();

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

        // Execute recovery — module calls account.executeFromExecutor directly
        // Account decodes KeyDataReg and updates masterKeyData (no MockValidator forwarding)
        vm.prank(__RELAYER_ADDRESS);
        universalEmailRecoveryModule.completeRecovery(__OWNER_7702_ADDRESS, recoveryData);

        _assertRecovery();
    }

    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================

    function _initNewOwnerEOA() internal {
        newOwner = IKeyV2.KeyDataReg({
            keyType: IKeyV2.KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: abi.encode(__NEW_OWNER_7702_ADDRESS),
            keyControl: IKeyV2.KeyControl.Self
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
        bytes memory installData = _createInstallDataForKeyRecovery(
            STUB_MOCK_VALIDATOR_FOR_KEY_RECOVERY, guardians, weights
        );

        // Non-ERC7579: call onInstall directly on the module instead of account.installModule
        vm.prank(__OWNER_7702_ADDRESS);
        universalEmailRecoveryModule.onInstall(installData);

        _verifyGuardianConfig(guardians, Constants.THRESHOLD);
    }

    function _verifyGuardianConfig(address[] memory _guardians, uint256 expectedThreshold)
        internal
        view
    {
        (
            uint256 guardianCount,
            uint256 totalWeight,
            uint256 acceptedWeight,
            uint256 thresholdValue
        ) = _getGuardianConfig(__OWNER_7702_ADDRESS);

        assertEq(guardianCount, _guardians.length, "Guardian count mismatch");
        assertEq(totalWeight, _guardians.length, "Total weight mismatch");
        assertEq(thresholdValue, expectedThreshold, "Threshold mismatch");
        assertEq(acceptedWeight, 0, "Accepted weight should be 0 initially");

        for (uint256 i = 0; i < _guardians.length; i++) {
            (uint256 status, uint256 weight) =
                _getGuardianStatus(__OWNER_7702_ADDRESS, _guardians[i]);
            assertEq(status, 1, "Guardian status should be REQUESTED (1)");
            assertEq(weight, 1, "Guardian weight mismatch");
        }
    }

    function _registerDKIM() internal {
        _registerDKIMPublicKeyHash(
            guardian1_Proof.DOMAIN, guardian1_Proof.PUBLIC_KEY_HASH, __OWNER_7702_ADDRESS
        );
        _registerDKIMPublicKeyHash(
            guardian2_Proof.DOMAIN, guardian2_Proof.PUBLIC_KEY_HASH, __OWNER_7702_ADDRESS
        );
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
    ) internal {
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
            STUB_MOCK_VALIDATOR_FOR_KEY_RECOVERY, // Must match proof's validator
            newOwner // EOA Key struct
        );
    }

    function _requestRecovery() internal returns (uint256) {
        // Guardian 1 votes
        EmailAuthMsg memory emailAuthMsg1 =
            _buildRecoveryEmailAuthMsgGuardian1(__OWNER_7702_ADDRESS, recoveryDataHash);
        vm.prank(__RELAYER_ADDRESS);
        universalEmailRecoveryModule.handleRecovery(emailAuthMsg1, 0);

        // Guardian 2 votes
        EmailAuthMsg memory emailAuthMsg2 =
            _buildRecoveryEmailAuthMsgGuardian2(__OWNER_7702_ADDRESS, recoveryDataHash);
        vm.prank(__RELAYER_ADDRESS);
        universalEmailRecoveryModule.handleRecovery(emailAuthMsg2, 0);

        // Get recovery request details
        (uint256 executeAfter,, uint256 currentWeight,) = _getRecoveryRequest(__OWNER_7702_ADDRESS);

        // Verify threshold is met
        (,,, uint256 threshold) = _getGuardianConfig(__OWNER_7702_ADDRESS);
        assertGe(currentWeight, threshold, "Threshold should be met");

        return executeAfter;
    }

    function _assertRecovery() internal {
        // Compute expected keyId using same algorithm as OPFMain's KeysManagerLib.computeKeyId
        bytes32 expectedKeyId = _computeKeyId(KeyType(uint8(newOwner.keyType)), newOwner.key);

        // Use low-level call to avoid type conflicts between test IKey and src IKey
        (bool success, bytes memory result) = __OWNER_7702_ADDRESS.staticcall(
            abi.encodeWithSignature("getKey(bytes32)", expectedKeyId)
        );
        assertTrue(success, "getKey call failed");

        IKeyV2.KeyData memory keyData = abi.decode(result, (IKeyV2.KeyData));

        assertEq(uint8(keyData.keyType), uint8(newOwner.keyType), "KeyType should match");
        assertTrue(keyData.isActive, "Key should be active");
        assertTrue(keyData.masterKey, "Should be master key");
        assertFalse(keyData.isDelegatedControl, "Should not be delegated control");
        assertEq(keyData.validUntil, type(uint48).max, "validUntil should match");
        assertEq(keyData.validAfter, 0, "validAfter should match");
        assertEq(keyData.limits, 0, "Limits should match");
        assertEq(keyData.key, newOwner.key, "Key bytes should match");
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
