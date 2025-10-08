// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "../Deploy.t.sol";
import {IKey} from "src/interfaces/IKey.sol";

contract RecoveryFuzz is Deploy {
    PubKey internal masterPk;
    mapping(bytes32 => uint256) internal guardianKeys;

    function setUp() public override {
        super.setUp();

        _populateWebAuthn("keysmanager.json", ".keys_register");

        masterPk = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(masterPk), KeyControl.Self
        );

        _createQuickFreshKey(false);
        _initializeAccount();

        guardianKeys[_initialGuardian] = guardianPK;
        _addGuardianWithKey(guardian, guardianPK);

        bytes32 guardianHashPacked = keccak256(abi.encodePacked(guardian));
        assertTrue(recoveryManager.isGuardian(address(account), guardianHashPacked));
    }

    function testFuzz_startRecovery(address newOwner) external {
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != owner);
        vm.assume(newOwner != guardian);
        vm.assume(newOwner != address(account));
        vm.assume(newOwner != sender);

        IKey.KeyDataReg memory recoveryKey = _buildEOARecoveryKey(newOwner);

        vm.prank(guardian);
        recoveryManager.startRecovery(address(account), recoveryKey);

        (IKey.KeyDataReg memory stored, uint64 executeAfter, uint32 quorum) =
            recoveryManager.recoveryData(address(account));

        assertEq(uint8(stored.keyType), uint8(recoveryKey.keyType));
        assertEq(stored.key, recoveryKey.key);
        assertEq(stored.validUntil, recoveryKey.validUntil);
        assertEq(stored.limits, recoveryKey.limits);
        assertEq(executeAfter, uint64(block.timestamp + RECOVERY_PERIOD));

        uint256 guardianCount = recoveryManager.guardianCount(address(account));
        uint32 expectedQuorum = uint32((guardianCount + 1) / 2);
        assertEq(quorum, expectedQuorum);
        assertTrue(recoveryManager.isLocked(address(account)));
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

            vm.assume(addr != address(0));
            vm.assume(addr != owner);
            vm.assume(addr != guardian);
            vm.assume(addr != address(account));
            vm.assume(addr != sender);
            vm.assume(addr != newOwner);

            _addGuardianWithKey(addr, pk);
        }

        IKey.KeyDataReg memory recoveryKey = _buildEOARecoveryKey(newOwner);

        vm.prank(guardian);
        recoveryManager.startRecovery(address(account), recoveryKey);

        (IKey.KeyDataReg memory stored, uint64 executeAfter, uint32 quorum) =
            recoveryManager.recoveryData(address(account));
        assertEq(stored.key, recoveryKey.key);
        assertEq(quorum, uint32((recoveryManager.guardianCount(address(account)) + 1) / 2));

        vm.warp(executeAfter + 1);

        bytes[] memory signatures = _collectGuardianSignatures(quorum);

        vm.prank(sender);
        account.completeRecovery(signatures);

        (stored, executeAfter, quorum) = recoveryManager.recoveryData(address(account));
        assertEq(executeAfter, 0);
        assertEq(quorum, 0);
        assertEq(stored.key.length, 0);
        assertFalse(recoveryManager.isLocked(address(account)));

        (bytes32 keyId, IKey.KeyData memory newMaster) = account.keyAt(0);
        assertEq(keyId, _computeKeyId(recoveryKey));
        assertTrue(newMaster.masterKey);
        assertTrue(newMaster.isActive);
        assertEq(uint8(newMaster.keyType), uint8(recoveryKey.keyType));
        assertEq(newMaster.key, recoveryKey.key);
    }

    function _collectGuardianSignatures(uint32 required)
        internal
        view
        returns (bytes[] memory sigs)
    {
        bytes32[] memory hashes = recoveryManager.getGuardians(address(account));
        require(required <= hashes.length, "insufficient guardians");

        _sort(hashes);

        bytes32 digest = recoveryManager.getDigestToSign(address(account));

        sigs = new bytes[](required);
        bytes32[] memory used = new bytes32[](hashes.length);
        uint256 collected;

        for (uint256 i; i < hashes.length && collected < required; ++i) {
            uint256 pk = guardianKeys[hashes[i]];
            if (pk == 0) continue;

            bytes32 signerHash = keccak256(abi.encodePacked(vm.addr(pk)));
            bool seen;
            for (uint256 j; j < collected; ++j) {
                if (used[j] == signerHash) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
            sigs[collected] = abi.encodePacked(r, s, v);
            used[collected] = signerHash;
            collected++;
        }

        require(collected == required, "insufficient unique guardians");
    }

    function _addGuardianWithKey(address newGuardian, uint256 pk) internal {
        bytes32 guardianHash = keccak256(abi.encodePacked(newGuardian));

        if (guardianHash == _initialGuardian) {
            guardianKeys[guardianHash] = pk;
            guardianKeys[keccak256(abi.encode(newGuardian))] = pk;
            return;
        }

        if (guardianKeys[guardianHash] != 0) {
            return;
        }

        _proposeGuardian(guardianHash);
        uint256 pending = recoveryManager.getPendingStatusGuardians(address(account), guardianHash);

        vm.warp(pending + 1);
        _confirmGuardian(guardianHash);

        guardianKeys[guardianHash] = pk;
        guardianKeys[keccak256(abi.encode(newGuardian))] = pk;
    }

    function _buildEOARecoveryKey(address newOwner)
        internal
        pure
        returns (IKey.KeyDataReg memory)
    {
        return IKey.KeyDataReg({
            keyType: IKey.KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: abi.encode(newOwner),
            keyControl: IKey.KeyControl.Self
        });
    }

    function _sort(bytes32[] memory data) internal pure {
        uint256 len = data.length;
        for (uint256 i; i < len; ++i) {
            for (uint256 j = i + 1; j < len; ++j) {
                if (data[j] < data[i]) {
                    (data[i], data[j]) = (data[j], data[i]);
                }
            }
        }
    }
}
