// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IOPF7702Recoverable} from "src/interfaces/IOPF7702Recoverable.sol";
import {Math} from "lib/openzeppelin-contracts/contracts/utils/math/Math.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";

contract RecoverableReverts is Deploy {
    PubKey internal pK;
    address[] guardians;
    uint256[] guardiansPK;
    bytes32[] guardiansID;
    bytes[] _signatures;

    PubKey internal pKR;
    KeyDataReg internal recoveryKey;

    modifier createGuardians(uint256 _indx) {
        _createGuardians(_indx);
        _;
    }

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

    function test_proposeGuardianRevertDuplicatedProposal() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__DuplicatedProposal.selector);
        _proposeGuardian(guardiansID[0]);
    }

    function test_proposeGuardianRevertDuplicatedGuardian() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian.selector);
        _proposeGuardian(guardiansID[0]);
    }

    function test_confirmGuardianRevertDuplicatedGuardian() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        _revokeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian.selector);
        _confirmGuardian(guardiansID[0]);
    }

    function test_confirmGuardianRevertPendingProposalNotOver() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__PendingProposalNotOver.selector);
        _confirmGuardian(guardiansID[0]);
    }

    function test_confirmGuardianRevertPendingProposalExpiredr() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + 100 days);
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__PendingProposalExpired.selector);
        _confirmGuardian(guardiansID[0]);
    }

    function test_confirmGuardianRevertAddressCantBeZero() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero.selector);
        _confirmGuardian(bytes32(0));
    }

    function test_cancelGuardianRevertDuplicatedGuardian() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        _revokeGuardian(guardiansID[0]);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian.selector);
        _cancelGuardianProposal(guardiansID[0]);
    }

    function test_revokeGuardianRevertDuplicatedRevoke() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        _revokeGuardian(guardiansID[0]);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__DuplicatedRevoke.selector);
        _revokeGuardian(guardiansID[0]);
    }

    function test_confirmGuardianRevocationRevertPendingRevokeNotOverAndPendingRevokeExpired()
        external
        createGuardians(3)
    {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        _revokeGuardian(guardiansID[0]);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__PendingRevokeNotOver.selector);
        _confirmGuardianRevocation(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 100 days);
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__PendingRevokeExpired.selector);
        _confirmGuardianRevocation(guardiansID[0]);
    }

    function test_startRecoveryRevertMustBeGuardianAndUnsupportedKeyTypeAndRecoverCannotBeActiveKey(
    ) external createGuardians(3) {
        bytes memory _key;
        pKR = PubKey({x: keccak256("x.NewOner"), y: keccak256("y.NewOner")});
        _key = _getKeyP256(pKR);

        recoveryKey = KeyDataReg({
            keyType: KeyType.P256,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _key,
            keyControl: KeyControl.Self
        });

        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian.selector);
        vm.prank(owner);
        recoveryManager.startRecovery(address(account), recoveryKey);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__UnsupportedKeyType.selector);
        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);

        pKR = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _key = _getKeyP256(pKR);

        recoveryKey = KeyDataReg({
            keyType: KeyType.WEBAUTHN,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _key,
            keyControl: KeyControl.Self
        });

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__RecoverCannotBeActiveKey.selector);
        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);

        _proposeGuardian(guardiansID[1]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[1]);

        recoveryKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(guardians[0]),
            keyControl: KeyControl.Self
        });

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeOwner.selector);
        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);
    }

    function test_completeRecoveryReverts() external createGuardians(3) {
        bytes memory _key;
        pKR = PubKey({x: keccak256("x.NewOner"), y: keccak256("y.NewOner")});
        _key = _getKeyP256(pKR);

        recoveryKey = KeyDataReg({
            keyType: KeyType.WEBAUTHN,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _key,
            keyControl: KeyControl.Self
        });

        _proposeGuardian(guardiansID[0]);
        _proposeGuardian(guardiansID[1]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);
        _confirmGuardian(guardiansID[1]);

        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);

        _signGuardians(1);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__OngoingRecovery.selector);
        _etch();
        vm.prank(sender);
        account.completeRecovery(_signatures);

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__InvalidSignatureAmount.selector);
        _etch();
        vm.prank(sender);
        account.completeRecovery(_signatures);
    }

    function test_completeRecoveryRevertsInvalidRecoverySignature() external createGuardians(3) {
        bytes memory _key;
        pKR = PubKey({x: keccak256("x.NewOner"), y: keccak256("y.NewOner")});
        _key = _getKeyP256(pKR);

        recoveryKey = KeyDataReg({
            keyType: KeyType.WEBAUTHN,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _key,
            keyControl: KeyControl.Self
        });

        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);

        _signBadGuardians(1);
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__InvalidRecoverySignatures.selector);
        _etch();
        vm.prank(sender);
        account.completeRecovery(_signatures);
    }

    function test_requireRecovery_NoOngoingRecovery_cancelRecovery() external {
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__NoOngoingRecovery.selector);
        _cancelRecovery();
    }

    function test_requireRecovery_NoOngoingRecovery_completeRecovery()
        external
        createGuardians(1)
    {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        _signBadGuardians(1);

        _etch();
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__NoOngoingRecovery.selector);
        account.completeRecovery(_signatures);
    }

    function test_requireRecovery_OngoingRecovery_confirmGuardianProposal()
        external
        createGuardians(1)
    {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        KeyDataReg memory rk = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(makeAddr("newOwner")),
            keyControl: KeyControl.Self
        });

        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), rk);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__OngoingRecovery.selector);
        _confirmGuardian(guardiansID[0]);
    }

    function _createGuardians(uint256 _index) internal {
        for (uint256 i = 0; i < _index; i++) {
            (address addr, uint256 pk) = makeAddrAndKey(string.concat("guardian", vm.toString(i)));
            guardians.push(addr);
            guardiansPK.push(pk);
            guardiansID.push(keccak256(abi.encodePacked(addr)));
            guardiansID.push(_computeKeyId(KeyType.EOA, _getKeyEOA(addr)));
            deal(addr, 1e18);
        }
    }

    function _signGuardians(uint32 _quorom) internal {
        bytes32 digest = recoveryManager.getDigestToSign(address(account));
        bytes32[] memory hashes = new bytes32[](_quorom);
        uint256[] memory pks = new uint256[](_quorom);

        for (uint256 i; i < _quorom;) {
            hashes[i] = keccak256(abi.encodePacked(guardians[i]));
            pks[i] = guardiansPK[i];
            unchecked {
                ++i;
            }
        }

        for (uint256 i; i < hashes.length; ++i) {
            for (uint256 j = i + 1; j < hashes.length; ++j) {
                if (hashes[j] < hashes[i]) {
                    (hashes[i], hashes[j]) = (hashes[j], hashes[i]);
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }

        for (uint256 i; i < _quorom;) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], digest);
            bytes memory sig = abi.encodePacked(r, s, v);
            _signatures.push(sig);
            unchecked {
                ++i;
            }
        }
    }

    function _signBadGuardians(uint32 _quorom) internal {
        bytes32 digest = keccak256("Bad-Sig");

        for (uint256 i = 0; i < _quorom;) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardiansPK[i], digest);
            bytes memory sig = abi.encodePacked(r, s, v);
            _signatures.push(sig);

            unchecked {
                ++i;
            }
        }
    }
}
