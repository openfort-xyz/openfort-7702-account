// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IOPF7702Recoverable} from "src/interfaces/IOPF7702Recoverable.sol";
import {Math} from "lib/openzeppelin-contracts/contracts/utils/math/Math.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";

contract Recoverable is Deploy {
    PubKey internal pK;
    address[] guardians;
    uint256[] guardiansPK;
    bytes32[] guardiansID;
    bytes[] _signatures;

    PubKey internal pKR;
    KeyDataReg internal recoveryKey;

    enum GuardianAction {
        PROPOSE,
        CONFIRM_PROPOSAL,
        CANCEL_PROPOSAL,
        REVOKE,
        CONFIRM_REVOCATION,
        CANCEL_REVOCATION,
        START_RECOVERY,
        CANCEL_RECOVERY
    }

    modifier createGuardians(uint256 _indx) {
        _createGuardians(_indx);
        _;
    }

    modifier createNewOner(KeyType kT) {
        bytes memory _key;
        if (kT == KeyType.EOA) {
            _key = _getKeyEOA(makeAddr(("New Onwer")));
        } else if (kT == KeyType.WEBAUTHN) {
            pKR = PubKey({x: keccak256("x.NewOner"), y: keccak256("y.NewOner")});
            _key = _getKeyP256(pKR);
        }
        recoveryKey = KeyDataReg({
            keyType: KeyType.WEBAUTHN,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _key,
            keyControl: KeyControl.Self
        });
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

    function test_proposeGuardianWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
    }

    function test_RevertOPF7702Recoverable__AddressCantBeZeroAndGuardianCannotBeAddressThis()
        external
    {
        _etch();
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero.selector);
        vm.prank(owner);
        account.proposeGuardian(bytes32(0));

        _etch();
        vm.expectRevert(
            IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeAddressThis.selector
        );
        vm.prank(owner);
        account.proposeGuardian(keccak256(abi.encodePacked(owner)));

        _etch();
        vm.expectRevert(
            IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeCurrentMasterKey.selector
        );
        vm.prank(owner);
        account.proposeGuardian(_computeKeyId(KeyType.WEBAUTHN, _getKeyP256(pK)));
    }

    function test_proposeGuardianAAWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, _getCalls(GuardianAction.PROPOSE, guardiansID.length)),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
    }

    function test_confirmGuardianProposalWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CONFIRM_PROPOSAL, 3);
        _assertConfirmGuardians(3);
        _assertGuardianCount(4);
    }

    function test_confirmGuardianProposalAAWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, _getCalls(GuardianAction.PROPOSE, guardiansID.length)),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);

        userOp.nonce = _getNonce();
        userOp.callData =
            _packCallData(mode_1, _getCalls(GuardianAction.CONFIRM_PROPOSAL, guardiansID.length));
        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _relayUserOp(userOp);

        _assertConfirmGuardians(3);
        _assertGuardianCount(4);
    }

    function test_cancelGuardianProposalWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CANCEL_PROPOSAL, 3);
        _assertPendingGuardians(3, false);
    }

    function test_cancelGuardianProposalAAWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, _getCalls(GuardianAction.PROPOSE, guardiansID.length)),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);

        userOp.nonce = _getNonce();
        userOp.callData =
            _packCallData(mode_1, _getCalls(GuardianAction.CANCEL_PROPOSAL, guardiansID.length));
        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertPendingGuardians(3, false);
    }

    function test_revokeGuardianProposalWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CONFIRM_PROPOSAL, 3);
        _assertConfirmGuardians(3);
        _assertGuardianCount(4);
        _executeGuardianAction(GuardianAction.REVOKE, 3);
        _assertPendingGuardians(3, true);
    }

    function test_revokeGuardianProposalAAWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, _getCalls(GuardianAction.PROPOSE, guardiansID.length)),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);

        userOp.nonce = _getNonce();
        userOp.callData =
            _packCallData(mode_1, _getCalls(GuardianAction.CONFIRM_PROPOSAL, guardiansID.length));
        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _relayUserOp(userOp);

        _assertConfirmGuardians(3);
        _assertGuardianCount(4);

        userOp.nonce = _getNonce();
        userOp.callData =
            _packCallData(mode_1, _getCalls(GuardianAction.REVOKE, guardiansID.length));
        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertPendingGuardians(3, true);
    }

    function test_confirmGuardianRevocationWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CONFIRM_PROPOSAL, 3);
        _assertConfirmGuardians(3);
        _assertGuardianCount(4);
        _executeGuardianAction(GuardianAction.REVOKE, 3);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CONFIRM_REVOCATION, 3);
        _assertGuardianCount(1);
    }

    function test_confirmGuardianRevocationAAWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, _getCalls(GuardianAction.PROPOSE, guardiansID.length)),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);

        userOp.nonce = _getNonce();
        userOp.callData =
            _packCallData(mode_1, _getCalls(GuardianAction.CONFIRM_PROPOSAL, guardiansID.length));
        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _relayUserOp(userOp);

        _assertConfirmGuardians(3);
        _assertGuardianCount(4);

        userOp.nonce = _getNonce();
        userOp.callData =
            _packCallData(mode_1, _getCalls(GuardianAction.REVOKE, guardiansID.length));
        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertPendingGuardians(3, true);

        userOp.nonce = _getNonce();
        userOp.callData =
            _packCallData(mode_1, _getCalls(GuardianAction.CONFIRM_REVOCATION, guardiansID.length));
        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _relayUserOp(userOp);

        _assertGuardianCount(1);
    }

    function test_cancelGuardianRevocationWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CONFIRM_PROPOSAL, 3);
        _assertConfirmGuardians(3);
        _assertGuardianCount(4);
        _executeGuardianAction(GuardianAction.REVOKE, 3);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CANCEL_REVOCATION, 3);
        _assertPendingGuardians(3, false);
    }

    function test_cancelGuardianRevocationAAWithRootKey() external createGuardians(3) {
        _assertGuardianCount(1);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, _getCalls(GuardianAction.PROPOSE, guardiansID.length)),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);

        userOp.nonce = _getNonce();
        userOp.callData =
            _packCallData(mode_1, _getCalls(GuardianAction.CONFIRM_PROPOSAL, guardiansID.length));
        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _relayUserOp(userOp);

        _assertConfirmGuardians(3);
        _assertGuardianCount(4);

        userOp.nonce = _getNonce();
        userOp.callData =
            _packCallData(mode_1, _getCalls(GuardianAction.REVOKE, guardiansID.length));
        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertPendingGuardians(3, true);

        userOp.nonce = _getNonce();
        userOp.callData =
            _packCallData(mode_1, _getCalls(GuardianAction.CANCEL_REVOCATION, guardiansID.length));
        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertPendingGuardians(3, false);
    }

    function test_startRecoveryWithRootKeyNewOwnerEOA()
        external
        createGuardians(3)
        createNewOner(KeyType.EOA)
    {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CONFIRM_PROPOSAL, 3);
        _assertConfirmGuardians(3);
        _assertGuardianCount(4);
        _executeGuardianAction(GuardianAction.START_RECOVERY, 1);
        _assretStartRecovery();
    }

    function test_confirmRecoveryWithRootKeyNewOwnerEOA()
        external
        createGuardians(3)
        createNewOner(KeyType.EOA)
    {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CONFIRM_PROPOSAL, 3);
        _assertConfirmGuardians(3);
        _assertGuardianCount(4);
        _executeGuardianAction(GuardianAction.START_RECOVERY, 1);
        _assretStartRecovery();
        _signGuardians(2);
        _executeConfirmRecovery();
        _assretConfirmRecovery();
    }

    function test_startRecoveryWithRootKeyNewOwnerWebAuthn()
        external
        createGuardians(3)
        createNewOner(KeyType.WEBAUTHN)
    {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CONFIRM_PROPOSAL, 3);
        _assertConfirmGuardians(3);
        _assertGuardianCount(4);
        _executeGuardianAction(GuardianAction.START_RECOVERY, 1);
        _assretStartRecovery();
    }

    function test_confirmRecoveryWithRootKeyNewOwnerWebAuthn()
        external
        createGuardians(3)
        createNewOner(KeyType.WEBAUTHN)
    {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CONFIRM_PROPOSAL, 3);
        _assertConfirmGuardians(3);
        _assertGuardianCount(4);
        _executeGuardianAction(GuardianAction.START_RECOVERY, 1);
        _assretStartRecovery();
        _signGuardians(2);
        _executeConfirmRecovery();
        _assretConfirmRecovery();
    }

    function test_cancelRecoveryWithRootKey()
        external
        createGuardians(3)
        createNewOner(KeyType.EOA)
    {
        _assertGuardianCount(1);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(1);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(GuardianAction.CONFIRM_PROPOSAL, 3);
        _assertConfirmGuardians(3);
        _assertGuardianCount(4);
        _executeGuardianAction(GuardianAction.START_RECOVERY, 1);
        _assretStartRecovery();
        _executeGuardianAction(GuardianAction.CANCEL_RECOVERY, 1);
        _assertCancelRecovery();
    }

    function _assertGuardianCount(uint256 _count) internal view {
        uint256 guardianCount = account.guardianCount();
        assertEq(guardianCount, _count);
    }

    function _assertPendingGuardians(uint256 _count, bool _isPending) internal view {
        for (uint256 i = 0; i < _count;) {
            uint256 getPendingStatusGuardians = account.getPendingStatusGuardians(guardiansID[i]);
            if (_isPending) {
                assert(getPendingStatusGuardians > 0);
            } else {
                assert(getPendingStatusGuardians == 0);
            }
            unchecked {
                ++i;
            }
        }
    }

    function _assertConfirmGuardians(uint256 _count) internal view {
        for (uint256 i = 0; i < _count;) {
            uint256 getPendingStatusGuardians = account.getPendingStatusGuardians(guardiansID[i]);
            assert(getPendingStatusGuardians == 0);
            assertTrue(account.isGuardian(guardiansID[i]));
            unchecked {
                ++i;
            }
        }
    }

    function _assretStartRecovery() internal view {
        uint64 _executeAfter = SafeCast.toUint64(block.timestamp + RECOVERY_PERIOD);
        (KeyDataReg memory kDR, uint64 executeAfter, uint32 quorum) = account.recoveryData();
        assertEq(quorum, SafeCast.toUint32(Math.ceilDiv(account.guardianCount(), 2)));
        assertEq(_executeAfter, executeAfter);
        assertEq(kDR.key, recoveryKey.key);
        assertEq(uint8(kDR.keyControl), uint8(recoveryKey.keyControl));
        assertEq(kDR.limits, recoveryKey.limits);
        assertEq(kDR.validAfter, recoveryKey.validAfter);
        assertEq(kDR.validUntil, recoveryKey.validUntil);
        assertEq(uint8(kDR.keyType), uint8(recoveryKey.keyType));
    }

    function _assretConfirmRecovery() internal view {
        (KeyDataReg memory kDR, uint64 executeAfter, uint32 quorum) = account.recoveryData();
        assertEq(executeAfter, 0);
        assertEq(quorum, 0);
        assertEq(kDR.key.length, 0);
        assertEq(uint8(kDR.keyControl), 0);
        assertEq(uint8(kDR.keyType), 0);
        assertEq(kDR.limits, 0);
        assertEq(kDR.validAfter, 0);
        assertEq(kDR.validUntil, 0);

        (bytes32 keyId, KeyData memory data) = account.keyAt(0);
        assertEq(keyId, _computeKeyId(recoveryKey));
        assertTrue(data.isActive);
        assertTrue(data.masterKey);
        assertFalse(data.isDelegatedControl);
        assertEq(data.key, recoveryKey.key);
        assertEq(data.limits, recoveryKey.limits);
        assertEq(data.validAfter, recoveryKey.validAfter);
        assertEq(data.validUntil, recoveryKey.validUntil);
        assertEq(uint8(data.keyType), uint8(recoveryKey.keyType));
    }

    function _assertCancelRecovery() internal view {
        (KeyDataReg memory kDR, uint64 executeAfter, uint32 quorum) = account.recoveryData();
        assertEq(executeAfter, 0);
        assertEq(quorum, 0);
        assertEq(kDR.key.length, 0);
        assertEq(uint8(kDR.keyControl), 0);
        assertEq(uint8(kDR.keyType), 0);
        assertEq(kDR.limits, 0);
        assertEq(kDR.validAfter, 0);
        assertEq(kDR.validUntil, 0);
        assertFalse(account.isLocked());
    }

    function _createGuardians(uint256 _index) internal {
        for (uint256 i = 0; i < _index; i++) {
            (address addr, uint256 pk) = makeAddrAndKey(string.concat("guardian", vm.toString(i)));
            guardians.push(addr);
            guardiansPK.push(pk);
            guardiansID.push(keccak256(abi.encodePacked(addr)));
            deal(addr, 1e18);
        }
    }

    function _signGuardians(uint32 _quorom) internal {
        (,, uint32 quorum) = account.recoveryData();
        if (_quorom < quorum) revert("Increase Quorom");

        bytes32 digest = account.getDigestToSign();

        for (uint256 i = 0; i < _quorom;) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardiansPK[i], digest);
            bytes memory sig = abi.encodePacked(r, s, v);
            _signatures.push(sig);

            unchecked {
                ++i;
            }
        }
    }

    function _executeGuardianAction(GuardianAction action, uint256 _count) internal {
        if (
            action == GuardianAction.CONFIRM_PROPOSAL || action == GuardianAction.CONFIRM_REVOCATION
        ) {
            vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        }

        if (action == GuardianAction.START_RECOVERY) {
            vm.warp(block.timestamp + 1);
            _etch();
            vm.prank(guardians[_count]);
            account.startRecovery(recoveryKey);
        }

        if (action == GuardianAction.CANCEL_RECOVERY) {
            _etch();
            vm.prank(owner);
            account.cancelRecovery();
        }

        for (uint256 i = 0; i < _count;) {
            _etch();
            vm.prank(owner);

            if (action == GuardianAction.PROPOSE) {
                account.proposeGuardian(guardiansID[i]);
            } else if (action == GuardianAction.CONFIRM_PROPOSAL) {
                account.confirmGuardianProposal(guardiansID[i]);
            } else if (action == GuardianAction.CANCEL_PROPOSAL) {
                account.cancelGuardianProposal(guardiansID[i]);
            } else if (action == GuardianAction.REVOKE) {
                account.revokeGuardian(guardiansID[i]);
            } else if (action == GuardianAction.CONFIRM_REVOCATION) {
                account.confirmGuardianRevocation(guardiansID[i]);
            } else if (action == GuardianAction.CANCEL_REVOCATION) {
                account.cancelGuardianRevocation(guardiansID[i]);
            }
            unchecked {
                ++i;
            }
        }
    }

    function _getCalls(GuardianAction action, uint256 _count)
        internal
        view
        returns (Call[] memory)
    {
        Call[] memory calls = new Call[](_count);

        if (action == GuardianAction.START_RECOVERY) {
            bytes memory data = abi.encodeWithSelector(account.startRecovery.selector, recoveryKey);
            calls[0] = _createCall(owner, 0, data);
        }

        for (uint256 i = 0; i < _count;) {
            if (action == GuardianAction.PROPOSE) {
                bytes memory data =
                    abi.encodeWithSelector(account.proposeGuardian.selector, guardiansID[i]);
                calls[i] = _createCall(owner, 0, data);
            } else if (action == GuardianAction.CONFIRM_PROPOSAL) {
                bytes memory data =
                    abi.encodeWithSelector(account.confirmGuardianProposal.selector, guardiansID[i]);
                calls[i] = _createCall(owner, 0, data);
            } else if (action == GuardianAction.CANCEL_PROPOSAL) {
                bytes memory data =
                    abi.encodeWithSelector(account.cancelGuardianProposal.selector, guardiansID[i]);
                calls[i] = _createCall(owner, 0, data);
            } else if (action == GuardianAction.REVOKE) {
                bytes memory data =
                    abi.encodeWithSelector(account.revokeGuardian.selector, guardiansID[i]);
                calls[i] = _createCall(owner, 0, data);
            } else if (action == GuardianAction.CONFIRM_REVOCATION) {
                bytes memory data = abi.encodeWithSelector(
                    account.confirmGuardianRevocation.selector, guardiansID[i]
                );
                calls[i] = _createCall(owner, 0, data);
            } else if (action == GuardianAction.CANCEL_REVOCATION) {
                bytes memory data = abi.encodeWithSelector(
                    account.cancelGuardianRevocation.selector, guardiansID[i]
                );
                calls[i] = _createCall(owner, 0, data);
            }
            unchecked {
                ++i;
            }
        }

        return calls;
    }

    function _executeConfirmRecovery() internal {
        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);
        _etch();
        vm.prank(sender);
        account.completeRecovery(_signatures);
    }

    function _relayUserOp(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }
}
