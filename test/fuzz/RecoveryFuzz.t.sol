// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "../Deploy.t.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {Math} from "lib/openzeppelin-contracts/contracts/utils/math/Math.sol";

contract RecoveryFuzz is Deploy {
    /// @dev Maps computeHash → private key for signing
    mapping(bytes32 => uint256) internal guardianKeys;

    /// @dev Tracks all guardian addresses + PKs for signature collection
    address[] internal allGuardians;
    uint256[] internal allGuardianPKs;

    function setUp() public override {
        super.setUp();
        _createQuickFreshKey(true);
        _createQuickFreshKey(false);
        _initializeAccount();

        // _initializeAccount registers guardian with keccak256(abi.encode(guardian)) format
        // but startRecovery checks keccak256(abi.encodePacked(guardian)) (computeHash)
        // Register guardian with computeHash format for startRecovery compatibility
        bytes32 guardianComputeHash = keccak256(abi.encodePacked(guardian));
        _proposeGuardian(guardianComputeHash);
        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardianComputeHash);

        guardianKeys[guardianComputeHash] = guardianPK;
        allGuardians.push(guardian);
        allGuardianPKs.push(guardianPK);

        assertTrue(recoveryManager.isGuardian(address(account), guardianComputeHash));
    }

    function testFuzz_startRecovery(address newOwner) external {
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != owner);
        vm.assume(newOwner != guardian);
        vm.assume(newOwner != address(account));
        vm.assume(newOwner != sender);

        KeyDataReg memory recoveryKey = _buildEOARecoveryKey(newOwner);

        vm.prank(guardian);
        recoveryManager.startRecovery(address(account), recoveryKey);

        assertTrue(recoveryManager.isLocked(address(account)));

        uint256 gCount = recoveryManager.guardianCount(address(account));
        uint32 expectedQuorum = uint32(Math.ceilDiv(gCount, 2));
        assertTrue(expectedQuorum > 0);
    }

    function testFuzz_completeRecovery(address newOwner, uint8 extraGuardians) external {
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != owner);
        vm.assume(newOwner != guardian);
        vm.assume(newOwner != address(account));
        vm.assume(newOwner != sender);

        uint256 addCount = bound(uint256(extraGuardians), 0, 4);
        for (uint256 i; i < addCount; ++i) {
            (address addr, uint256 pk) = makeAddrAndKey(string.concat("guardian-", vm.toString(i)));
            _addGuardianWithKey(addr, pk);
        }

        KeyDataReg memory recoveryKey = _buildEOARecoveryKey(newOwner);

        vm.prank(guardian);
        recoveryManager.startRecovery(address(account), recoveryKey);

        assertTrue(recoveryManager.isLocked(address(account)));

        uint256 gCount = recoveryManager.guardianCount(address(account));
        uint32 quorum = uint32(Math.ceilDiv(gCount, 2));

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);

        bytes[] memory signatures = _collectGuardianSignatures(quorum);

        vm.prank(sender);
        recoveryManager.completeRecovery(address(account), signatures);

        // Verify recovery data cleared
        assertFalse(recoveryManager.isLocked(address(account)));

        // Apply recovery to account via mock validator
        address validatorAddr = _installFakeValidator();
        _etch();
        vm.prank(validatorAddr);
        account.completeRecovery(recoveryKey);

        // Verify new master key
        (bytes32 keyId, KeyData memory newMaster) = account.keyAt(0);
        assertEq(keyId, _computeKeyId(recoveryKey));
        assertTrue(newMaster.masterKey);
        assertTrue(newMaster.isActive);
        assertEq(uint8(newMaster.keyType), uint8(recoveryKey.keyType));
        assertEq(newMaster.key, recoveryKey.key);
    }

    // ──────────────────────────────────────────────────────────────────────
    //                          Internal helpers
    // ──────────────────────────────────────────────────────────────────────

    function _addGuardianWithKey(address newGuardian, uint256 pk) internal {
        bytes32 guardianHash = keccak256(abi.encodePacked(newGuardian));
        if (guardianKeys[guardianHash] != 0) return;

        _proposeGuardian(guardianHash);
        uint256 pending = recoveryManager.getPendingStatusGuardians(address(account), guardianHash);
        vm.warp(pending + 1);
        _confirmGuardian(guardianHash);

        guardianKeys[guardianHash] = pk;
        allGuardians.push(newGuardian);
        allGuardianPKs.push(pk);
    }

    function _collectGuardianSignatures(uint32 required)
        internal
        view
        returns (bytes[] memory sigs)
    {
        uint256 count = allGuardians.length;
        require(required <= count, "insufficient guardians");

        bytes32[] memory hashes = new bytes32[](count);
        uint256[] memory pks = new uint256[](count);

        for (uint256 i; i < count; ++i) {
            hashes[i] = keccak256(abi.encodePacked(allGuardians[i]));
            pks[i] = allGuardianPKs[i];
        }

        // Sort ascending by hash (required by _validateSignatures strict ordering)
        for (uint256 i; i < count; ++i) {
            for (uint256 j = i + 1; j < count; ++j) {
                if (hashes[j] < hashes[i]) {
                    (hashes[i], hashes[j]) = (hashes[j], hashes[i]);
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }

        bytes32 digest = recoveryManager.getDigestToSign(address(account));
        sigs = new bytes[](required);
        for (uint256 i; i < required; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], digest);
            sigs[i] = abi.encodePacked(r, s, v);
        }
    }

    function _buildEOARecoveryKey(address newOwner) internal pure returns (KeyDataReg memory) {
        return KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: abi.encode(newOwner),
            keyControl: KeyControl.Self
        });
    }

    function _installFakeValidator() internal returns (address validatorAddr) {
        MockValidatorForFuzz mockVal = new MockValidatorForFuzz();
        _etch();
        vm.prank(owner);
        account.installModule(1, address(mockVal), bytes(""));
        validatorAddr = address(mockVal);
    }
}

/// @dev Minimal mock validator that satisfies IERC7579Module interface for installModule
contract MockValidatorForFuzz {
    function isModuleType(uint256 _moduleTypeId) external pure returns (bool) {
        return _moduleTypeId == 1;
    }

    function onInstall(bytes calldata) external {}
    function onUninstall(bytes calldata) external {}
}
