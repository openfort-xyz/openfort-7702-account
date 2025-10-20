// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "../Deploy.t.sol";

contract RecoverableGuardiansFuzz is Deploy {
    PubKey internal pK;

    function setUp() public override {
        super.setUp();

        _populateWebAuthn("keysmanager.json", ".keys_register");

        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );

        _createQuickFreshKey(false);
        _initializeAccount();
    }

    function testFuzz_proposeAndConfirmGuardian(address candidate) external {
        bytes32 guardianId = _prepareGuardian(candidate);

        uint256 originalCount = recoveryManager.guardianCount(address(account));

        _proposeGuardian(guardianId);

        uint256 pending = recoveryManager.getPendingStatusGuardians(address(account), guardianId);
        assertGt(pending, block.timestamp);

        vm.warp(pending + 1);
        _confirmGuardian(guardianId);

        assertTrue(recoveryManager.isGuardian(address(account), guardianId));
        assertEq(
            recoveryManager.guardianCount(address(account)),
            originalCount + 1,
            "guardian count mismatch"
        );
    }

    function testFuzz_cancelGuardianProposal(address candidate) external {
        bytes32 guardianId = _prepareGuardian(candidate);

        _proposeGuardian(guardianId);
        uint256 pendingBefore =
            recoveryManager.getPendingStatusGuardians(address(account), guardianId);
        assertGt(pendingBefore, 0);

        _cancelGuardianProposal(guardianId);

        uint256 pendingAfter =
            recoveryManager.getPendingStatusGuardians(address(account), guardianId);
        assertEq(pendingAfter, 0);
        assertFalse(recoveryManager.isGuardian(address(account), guardianId));
    }

    function testFuzz_revokeGuardian(address candidate) external {
        bytes32 guardianId = _prepareGuardian(candidate);

        _proposeGuardian(guardianId);
        uint256 addPending = recoveryManager.getPendingStatusGuardians(address(account), guardianId);

        vm.warp(addPending + 1);
        _confirmGuardian(guardianId);
        assertTrue(recoveryManager.isGuardian(address(account), guardianId));

        _revokeGuardian(guardianId);
        uint256 revokePending =
            recoveryManager.getPendingStatusGuardians(address(account), guardianId);
        assertGt(revokePending, block.timestamp);

        vm.warp(revokePending + 1);
        _confirmGuardianRevocation(guardianId);

        assertFalse(recoveryManager.isGuardian(address(account), guardianId));
    }

    function _prepareGuardian(address candidate) internal view returns (bytes32 guardianId) {
        vm.assume(candidate != address(0));
        vm.assume(candidate != owner);
        vm.assume(candidate != guardian);
        vm.assume(candidate != address(account));

        guardianId = keccak256(abi.encode(candidate));

        vm.assume(guardianId != _initialGuardian);
        vm.assume(guardianId != _computeKeyId(mkReg));
        vm.assume(guardianId != _computeKeyId(skReg));
    }
}
