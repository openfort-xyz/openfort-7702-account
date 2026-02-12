// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {IOPF7702Recoverable} from "src/interfaces/IOPF7702Recoverable.sol";
import {IBaseOPF7702} from "src/interfaces/IBaseOPF7702.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {
    MessageHashUtils
} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

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
        _createQuickFreshKey(true);
        _createQuickFreshKey(false);

        _initializeAccount();
    }

    // ============================================================================
    // completeRecovery: Unauthorized caller reverts
    // ============================================================================

    function test_completeRecovery_RevertUnauthorizedCaller() external {
        KeyDataReg memory newKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(makeAddr("newOwner")),
            keyControl: KeyControl.Self
        });

        // Random address (not a validator) calls completeRecovery
        address randomCaller = makeAddr("randomCaller");
        _etch();
        vm.expectRevert(IBaseOPF7702.OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(randomCaller);
        account.completeRecovery(newKey);
    }

    function test_completeRecovery_RevertUnauthorizedCaller_Owner() external {
        KeyDataReg memory newKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(makeAddr("newOwner")),
            keyControl: KeyControl.Self
        });

        // Even the owner (not in _validators) should revert
        _etch();
        vm.expectRevert(IBaseOPF7702.OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(owner);
        account.completeRecovery(newKey);
    }

    // ============================================================================
    // completeRecovery: Invalid master key registration reverts
    // ============================================================================

    function test_completeRecovery_RevertInvalidMasterKeyReg_NonZeroLimits() external {
        // Install a validator so completeRecovery's auth check passes
        address validatorAddr = _installFakeValidator();

        KeyDataReg memory badKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 10, // Must be 0 for master key
            key: _getKeyEOA(makeAddr("newOwner")),
            keyControl: KeyControl.Self
        });

        _etch();
        vm.expectRevert(
            abi.encodeWithSelector(IKeysManager.KeyManager__InvalidMasterKeyReg.selector, badKey)
        );
        vm.prank(validatorAddr);
        account.completeRecovery(badKey);
    }

    function test_completeRecovery_RevertInvalidMasterKeyReg_NonZeroValidAfter() external {
        address validatorAddr = _installFakeValidator();

        KeyDataReg memory badKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 100, // Must be 0 for master key
            limits: 0,
            key: _getKeyEOA(makeAddr("newOwner")),
            keyControl: KeyControl.Self
        });

        _etch();
        vm.expectRevert(
            abi.encodeWithSelector(IKeysManager.KeyManager__InvalidMasterKeyReg.selector, badKey)
        );
        vm.prank(validatorAddr);
        account.completeRecovery(badKey);
    }

    function test_completeRecovery_RevertInvalidMasterKeyReg_WrongValidUntil() external {
        address validatorAddr = _installFakeValidator();

        KeyDataReg memory badKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: uint48(block.timestamp + 30 days), // Must be type(uint48).max
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(makeAddr("newOwner")),
            keyControl: KeyControl.Self
        });

        _etch();
        vm.expectRevert(
            abi.encodeWithSelector(IKeysManager.KeyManager__InvalidMasterKeyReg.selector, badKey)
        );
        vm.prank(validatorAddr);
        account.completeRecovery(badKey);
    }

    function test_completeRecovery_RevertInvalidMasterKeyReg_CustodialControl() external {
        address validatorAddr = _installFakeValidator();

        KeyDataReg memory badKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(makeAddr("newOwner")),
            keyControl: KeyControl.Custodial // Must be Self
        });

        _etch();
        vm.expectRevert(
            abi.encodeWithSelector(IKeysManager.KeyManager__InvalidMasterKeyReg.selector, badKey)
        );
        vm.prank(validatorAddr);
        account.completeRecovery(badKey);
    }

    function test_completeRecovery_RevertInvalidMasterKeyReg_P256KeyType() external {
        address validatorAddr = _installFakeValidator();

        KeyDataReg memory badKey = KeyDataReg({
            keyType: KeyType.P256, // P256 not allowed for master key
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: abi.encode(keccak256("x"), keccak256("y")),
            keyControl: KeyControl.Self
        });

        _etch();
        vm.expectRevert(
            abi.encodeWithSelector(IKeysManager.KeyManager__InvalidMasterKeyReg.selector, badKey)
        );
        vm.prank(validatorAddr);
        account.completeRecovery(badKey);
    }

    function test_completeRecovery_RevertInvalidMasterKeyReg_P256NONKEYKeyType() external {
        address validatorAddr = _installFakeValidator();

        KeyDataReg memory badKey = KeyDataReg({
            keyType: KeyType.P256NONKEY, // P256NONKEY not allowed for master key
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: abi.encode(keccak256("x"), keccak256("y")),
            keyControl: KeyControl.Self
        });

        _etch();
        vm.expectRevert(
            abi.encodeWithSelector(IKeysManager.KeyManager__InvalidMasterKeyReg.selector, badKey)
        );
        vm.prank(validatorAddr);
        account.completeRecovery(badKey);
    }

    // ============================================================================
    // completeRecovery: Key already registered reverts
    // ============================================================================

    function test_completeRecovery_RevertKeyAlreadyRegistered() external {
        address validatorAddr = _installFakeValidator();

        // Register an EOA session key on the account
        address existingKeyAddr = makeAddr("existingKey");
        KeyDataReg memory sessionKeyReg = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: uint48(block.timestamp + 10 days),
            validAfter: 0,
            limits: 10,
            key: _getKeyEOA(existingKeyAddr),
            keyControl: KeyControl.Self
        });

        _etch();
        vm.prank(owner);
        account.registerKey(sessionKeyReg);

        // Now try recovery with the same EOA key (master key params)
        // _deleteOldKeys only deletes master key at index 0, so this session key stays active
        // _setNewMasterKey checks sKey.isActive and reverts with KeyRegistered
        KeyDataReg memory duplicateKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(existingKeyAddr),
            keyControl: KeyControl.Self
        });

        _etch();
        vm.expectRevert(IKeysManager.KeyManager__KeyRegistered.selector);
        vm.prank(validatorAddr);
        account.completeRecovery(duplicateKey);
    }

    // ============================================================================
    // Guardian management: proposeGuardian reverts
    // ============================================================================

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

    function test_proposeGuardianRevertAddressCantBeZero() external {
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero.selector);
        _proposeGuardian(bytes32(0));
    }

    // ============================================================================
    // Guardian management: confirmGuardianProposal reverts
    // ============================================================================

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

    function test_confirmGuardianRevertPendingProposalExpired() external createGuardians(3) {
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

    // ============================================================================
    // Guardian management: cancelGuardianProposal reverts
    // ============================================================================

    function test_cancelGuardianProposalRevertDuplicatedGuardian() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        _revokeGuardian(guardiansID[0]);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian.selector);
        _cancelGuardianProposal(guardiansID[0]);
    }

    // ============================================================================
    // Guardian management: revokeGuardian reverts
    // ============================================================================

    function test_revokeGuardianRevertMustBeGuardian() external createGuardians(3) {
        // guardiansID[0] is not yet an active guardian (only proposed, not confirmed)
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian.selector);
        _revokeGuardian(guardiansID[0]);
    }

    function test_revokeGuardianRevertDuplicatedRevoke() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        _revokeGuardian(guardiansID[0]);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__DuplicatedRevoke.selector);
        _revokeGuardian(guardiansID[0]);
    }

    // ============================================================================
    // Guardian management: confirmGuardianRevocation reverts
    // ============================================================================

    function test_confirmGuardianRevocationRevertPendingRevokeNotOverAndExpired()
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

    // ============================================================================
    // Recovery flow: startRecovery reverts
    // ============================================================================

    function test_startRecoveryRevertMustBeGuardian() external createGuardians(3) {
        // Register guardian with computeHash format (guardiansID[0])
        _proposeGuardian(guardiansID[0]);
        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        recoveryKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(makeAddr("newOwner")),
            keyControl: KeyControl.Self
        });

        // Non-guardian tries to start recovery
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian.selector);
        vm.prank(owner);
        recoveryManager.startRecovery(address(account), recoveryKey);
    }

    function test_startRecoveryRevertUnsupportedKeyType() external createGuardians(3) {
        // guardiansID[0] = keccak256(abi.encodePacked(guardians[0])) - matches computeHash
        _proposeGuardian(guardiansID[0]);
        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        pKR = PubKey({x: keccak256("x.NewOwner"), y: keccak256("y.NewOwner")});

        recoveryKey = KeyDataReg({
            keyType: KeyType.P256, // P256 not supported for recovery
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyP256(pKR),
            keyControl: KeyControl.Self
        });

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__UnsupportedKeyType.selector);
        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);
    }

    function test_startRecoveryRevertUnsupportedKeyType_P256NONKEY() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);
        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        pKR = PubKey({x: keccak256("x.NewOwner"), y: keccak256("y.NewOwner")});

        recoveryKey = KeyDataReg({
            keyType: KeyType.P256NONKEY, // P256NONKEY not supported for recovery
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyP256(pKR),
            keyControl: KeyControl.Self
        });

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__UnsupportedKeyType.selector);
        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);
    }

    function test_startRecoveryRevertRecoverCannotBeActiveKey() external createGuardians(3) {
        _proposeGuardian(guardiansID[0]);
        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        // Use the current master key (already active)
        recoveryKey = KeyDataReg({
            keyType: mkReg.keyType,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: mkReg.key,
            keyControl: KeyControl.Self
        });

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__RecoverCannotBeActiveKey.selector);
        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);
    }

    function test_startRecoveryRevertGuardianCannotBeOwner() external createGuardians(3) {
        // Register both hash formats for guardian[0]:
        // guardiansID[0] = computeHash (for startRecovery's isGuardian(msg.sender))
        // guardiansID[1] = keyId (for isGuardian(account, recoveryKey.computeKeyId()))
        _proposeGuardian(guardiansID[0]);
        _proposeGuardian(guardiansID[1]);
        // Also register guardian[1]'s computeHash so we have enough guardians
        _proposeGuardian(guardiansID[2]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);
        _confirmGuardian(guardiansID[1]);
        _confirmGuardian(guardiansID[2]);

        // Try to set guardian[0] as the new owner
        // startRecovery checks isGuardian(account, keyId) where keyId = _recoveryKey.computeKeyId()
        // keyId matches guardiansID[1] which was registered as a guardian
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

    // ============================================================================
    // Recovery flow: completeRecovery (SocialRecoveryManager) reverts
    // ============================================================================

    function test_socialCompleteRecovery_RevertOngoingRecovery() external createGuardians(3) {
        // guardiansID[0] = computeHash(guardians[0]), guardiansID[2] = computeHash(guardians[1])
        _proposeGuardian(guardiansID[0]);
        _proposeGuardian(guardiansID[2]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);
        _confirmGuardian(guardiansID[2]);

        pKR = PubKey({x: keccak256("x.NewOwner"), y: keccak256("y.NewOwner")});
        recoveryKey = KeyDataReg({
            keyType: KeyType.WEBAUTHN,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyP256(pKR),
            keyControl: KeyControl.Self
        });

        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);

        _signGuardians(1);

        // Recovery period not over yet
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__OngoingRecovery.selector);
        vm.prank(sender);
        recoveryManager.completeRecovery(address(account), _signatures);
    }

    function test_socialCompleteRecovery_RevertInvalidSignatureAmount()
        external
        createGuardians(3)
    {
        // Register all 3 guardians so guardianCount=3, quorum=ceil(3/2)=2
        _proposeGuardian(guardiansID[0]);
        _proposeGuardian(guardiansID[2]);
        _proposeGuardian(guardiansID[4]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);
        _confirmGuardian(guardiansID[2]);
        _confirmGuardian(guardiansID[4]);

        pKR = PubKey({x: keccak256("x.NewOwner"), y: keccak256("y.NewOwner")});
        recoveryKey = KeyDataReg({
            keyType: KeyType.WEBAUTHN,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyP256(pKR),
            keyControl: KeyControl.Self
        });

        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);

        // Only sign with 1 guardian but quorum requires ceil(3/2) = 2
        _signGuardians(1);

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__InvalidSignatureAmount.selector);
        vm.prank(sender);
        recoveryManager.completeRecovery(address(account), _signatures);
    }

    function test_socialCompleteRecovery_RevertInvalidRecoverySignatures()
        external
        createGuardians(3)
    {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        pKR = PubKey({x: keccak256("x.NewOwner"), y: keccak256("y.NewOwner")});
        recoveryKey = KeyDataReg({
            keyType: KeyType.WEBAUTHN,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyP256(pKR),
            keyControl: KeyControl.Self
        });

        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);

        _signBadGuardians(1);
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__InvalidRecoverySignatures.selector);
        vm.prank(sender);
        recoveryManager.completeRecovery(address(account), _signatures);
    }

    // ============================================================================
    // Recovery flow: cancelRecovery reverts
    // ============================================================================

    function test_cancelRecovery_RevertNoOngoingRecovery() external {
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__NoOngoingRecovery.selector);
        _cancelRecovery();
    }

    function test_socialCompleteRecovery_RevertNoOngoingRecovery() external createGuardians(1) {
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        _signBadGuardians(1);

        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__NoOngoingRecovery.selector);
        vm.prank(sender);
        recoveryManager.completeRecovery(address(account), _signatures);
    }

    // ============================================================================
    // Recovery flow: OngoingRecovery blocks guardian operations
    // ============================================================================

    function test_ongoingRecovery_BlocksConfirmGuardianProposal() external createGuardians(2) {
        // Register guardian[0] with computeHash format
        _proposeGuardian(guardiansID[0]);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        _confirmGuardian(guardiansID[0]);

        recoveryKey = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: _getKeyEOA(makeAddr("newOwner")),
            keyControl: KeyControl.Self
        });

        vm.prank(guardians[0]);
        recoveryManager.startRecovery(address(account), recoveryKey);

        // During ongoing recovery, confirmGuardianProposal should revert
        // Use guardian[1]'s computeHash (guardiansID[2]) for a new proposal attempt
        vm.expectRevert(IOPF7702Recoverable.OPF7702Recoverable__OngoingRecovery.selector);
        _confirmGuardian(guardiansID[2]);
    }

    // ============================================================================
    // Internal helpers
    // ============================================================================

    function _createGuardians(uint256 _index) internal {
        for (uint256 i = 0; i < _index; i++) {
            (address addr, uint256 pk) = makeAddrAndKey(string.concat("guardian", vm.toString(i)));
            guardians.push(addr);
            guardiansPK.push(pk);
            // Index 2*i: computeHash format (used by startRecovery's isGuardian check)
            guardiansID.push(keccak256(abi.encodePacked(addr)));
            // Index 2*i+1: keyId format (used by GuardianCannotBeOwner check)
            guardiansID.push(_computeKeyId(KeyType.EOA, _getKeyEOA(addr)));
            deal(addr, 1e18);
        }
    }

    function _signGuardians(uint32 _quorum) internal {
        bytes32 digest = recoveryManager.getDigestToSign(address(account));
        bytes32[] memory hashes = new bytes32[](_quorum);
        uint256[] memory pks = new uint256[](_quorum);

        for (uint256 i; i < _quorum;) {
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

        for (uint256 i; i < _quorum;) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], digest);
            bytes memory sig = abi.encodePacked(r, s, v);
            _signatures.push(sig);
            unchecked {
                ++i;
            }
        }
    }

    function _signBadGuardians(uint32 _quorum) internal {
        bytes32 digest = keccak256("Bad-Sig");

        for (uint256 i = 0; i < _quorum;) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardiansPK[i], digest);
            bytes memory sig = abi.encodePacked(r, s, v);
            _signatures.push(sig);

            unchecked {
                ++i;
            }
        }
    }

    function _installFakeValidator() internal returns (address validatorAddr) {
        // Install a mock validator module via account's installModule
        // We need a contract that implements isModuleType(1) = true and has onInstall/onUninstall
        MockValidatorForTest mockVal = new MockValidatorForTest();

        _etch();
        vm.prank(owner);
        account.installModule(1, address(mockVal), bytes(""));

        validatorAddr = address(mockVal);
    }
}

/// @dev Minimal mock validator that satisfies IERC7579Module interface for installModule
contract MockValidatorForTest {
    function isModuleType(uint256 _moduleTypeId) external pure returns (bool) {
        return _moduleTypeId == 1;
    }

    function onInstall(bytes calldata) external {}
    function onUninstall(bytes calldata) external {}
}
