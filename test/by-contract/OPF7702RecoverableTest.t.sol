// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {BaseContract} from "test/by-contract/BaseContract.t.sol";

contract OPF7702RecoverableTest is BaseContract {
    uint256 internal proposalTimestamp;
    bytes[] internal _signatures;
    bytes4[] selEmpt;

    function test_proposeGuardianRevertAddressCantBeZero() public {
        _etch();

        vm.expectRevert(OPF7702Recoverable__AddressCantBeZero.selector);
        vm.prank(owner);
        account.proposeGuardian(bytes32(0));
    }

    function test_proposeGuardianRevertGuardianCannotBeAddressThis() public {
        _etch();

        vm.expectRevert(OPF7702Recoverable__GuardianCannotBeAddressThis.selector);
        vm.prank(owner);
        account.proposeGuardian(keccak256(abi.encodePacked(owner)));
    }

    function test_proposeGuardianRevertGuardianCannotBeCurrentMasterKey() public {
        _etch();

        Key memory k = account.getKeyById(0);
        vm.expectRevert(OPF7702Recoverable__GuardianCannotBeCurrentMasterKey.selector);
        vm.prank(owner);
        account.proposeGuardian(keccak256(abi.encodePacked(k.eoaAddress)));
    }

    function test_proposeGuardianRevertDuplicatedGuardian() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _etch();

        vm.expectRevert(OPF7702Recoverable__DuplicatedGuardian.selector);
        vm.prank(owner);
        account.proposeGuardian(keccak256(abi.encodePacked(sender)));
    }

    function test_proposeGuardianRevertDuplicatedProposal() public {
        _proposeGuardian(sender);

        _etch();

        vm.expectRevert(OPF7702Recoverable__DuplicatedProposal.selector);
        vm.prank(owner);
        account.proposeGuardian(keccak256(abi.encodePacked(sender)));
    }

    function test_confirmGuardianProposalRevertAddressCantBeZero() public {
        _etch();

        vm.expectRevert(OPF7702Recoverable__AddressCantBeZero.selector);
        vm.prank(owner);
        account.confirmGuardianProposal(bytes32(0));
    }

    function test_confirmGuardianPendingProposalNotOver() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp+ 1);

        _etch();

        vm.expectRevert(OPF7702Recoverable__PendingProposalNotOver.selector);
        vm.prank(owner);
        account.confirmGuardianProposal(keccak256(abi.encodePacked(sender)));
    }

    function test_confirmGuardianPendingProposalExpired() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + 60 days);

        _etch();

        vm.expectRevert(OPF7702Recoverable__PendingProposalExpired.selector);
        vm.prank(owner);
        account.confirmGuardianProposal(keccak256(abi.encodePacked(sender)));
    }

    function test_confirmGuardianDuplicatedGuardian() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _etch();

        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        vm.expectRevert(OPF7702Recoverable__UnknownProposal.selector);
        vm.prank(owner);
        account.confirmGuardianProposal(keccak256(abi.encodePacked(sender)));
    }

    function test_cancelGuardianProposalDuplicatedGuardian() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _etch();

        vm.expectRevert(OPF7702Recoverable__UnknownProposal.selector);
        vm.prank(owner);
        account.cancelGuardianProposal(keccak256(abi.encodePacked(sender)));
    }

    function test_revokeGuardianDuplicatedGuardian() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _revoke(sender);

        _etch();

        vm.expectRevert(OPF7702Recoverable__DuplicatedRevoke.selector);
        vm.prank(owner);
        account.revokeGuardian(keccak256(abi.encodePacked(sender)));
    }

    function test_confirmGuardianRevocationPendingRevokeNotOver() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _revoke(sender);

        _etch();

        vm.expectRevert(OPF7702Recoverable__PendingRevokeNotOver.selector);
        vm.prank(owner);
        account.confirmGuardianRevocation(keccak256(abi.encodePacked(sender)));
    }

    function test_confirmGuardianRevocationPendingRevokeExpired() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _revoke(sender);

        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + 30 days);
        
        _etch();
        vm.expectRevert(OPF7702Recoverable__PendingRevokeExpired.selector);
        vm.prank(owner);
        account.confirmGuardianRevocation(keccak256(abi.encodePacked(sender)));
    }

    function test_startRecoveryMustBeGuardian() public {
        Key memory _recoveryKey = _getKey(bytes32(0), bytes32(0), ETH_RECIVE, KeyType.EOA);
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _etch();

        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        vm.expectRevert(OPF7702Recoverable__MustBeGuardian.selector);
        vm.prank(ENTRYPOINT_V8);
        account.startRecovery(_recoveryKey);
    }

    function test_startRecoveryUnsupportedKeyType() public {
        Key memory _recoveryKey = _getKey(bytes32(0), bytes32(0), ETH_RECIVE, KeyType.P256);
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _etch();

        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        vm.expectRevert(OPF7702Recoverable__UnsupportedKeyType.selector);
        vm.prank(sender);
        account.startRecovery(_recoveryKey);
    }

    function test_startRecoveryAddressCantBeZero() public {
        Key memory _recoveryKey = _getKey(bytes32(0), bytes32(0), address(0), KeyType.EOA);
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _etch();

        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        vm.expectRevert(OPF7702Recoverable__AddressCantBeZero.selector);
        vm.prank(sender);
        account.startRecovery(_recoveryKey);
    }

    function test_startRecoveryRecoverCannotBeActiveKey() public {
        Key memory _recoveryKey = account.getKeyById(0);
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _etch();

        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        vm.expectRevert(OPF7702Recoverable__RecoverCannotBeActiveKey.selector);
        vm.prank(sender);
        account.startRecovery(_recoveryKey);
    }

    function test_startRecoveryGuardianCannotBeOwner() public {
        Key memory _recoveryKey = _getKey(bytes32(0), bytes32(0), sender, KeyType.EOA);
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _etch();

        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        vm.expectRevert(OPF7702Recoverable__GuardianCannotBeOwner.selector);
        vm.prank(sender);
        account.startRecovery(_recoveryKey);
    }

    function test_completeRecoveryOngoingRecovery() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _startRecovery();

        _etch();

        vm.expectRevert(OPF7702Recoverable__OngoingRecovery.selector);
        vm.prank(sender);
        account.completeRecovery(_signatures);
    }

    function test_completeRecoveryInvalidSignatureAmount() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _startRecovery();

        _etch();
        
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + RECOVERY_PERIOD + 1);

        vm.expectRevert(OPF7702Recoverable__InvalidSignatureAmount.selector);
        vm.prank(sender);
        account.completeRecovery(_signatures);
    }

    function test_completeRecoveryInvalidRecoverySignatures() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _startRecovery();

        bytes32 digest = keccak256("digest");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPK, digest);

        _signatures.push(abi.encodePacked(r, s, v));
        _etch();
        
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + RECOVERY_PERIOD + 1);

        vm.expectRevert(OPF7702Recoverable__InvalidRecoverySignatures.selector);
        vm.prank(sender);
        account.completeRecovery(_signatures);
    }

    function test_completeRecoveryKeyRegistered() public {
        _proposeGuardian(sender);
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);
        _confirmGuardianProposal(sender);

        _startRecovery();

        bytes32 digest = account.getDigestToSign();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPK, digest);

        (, Key memory k, KeyReg memory kReg) = _createAnyKey(
            bytes32(0),
            bytes32(0),
            GUARDIAN_EOA_ADDRESS,
            KeyType.EOA,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            0,
            10,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();
        vm.prank(owner);
        account.registerKey(k, kReg);

        _signatures.push(abi.encodePacked(r, s, v));

        _etch();
        
        proposalTimestamp = block.timestamp;
        _wrap(proposalTimestamp + RECOVERY_PERIOD + 1);

        vm.expectRevert(KeyManager__KeyRegistered.selector);
        vm.prank(sender);
        account.completeRecovery(_signatures);
    }

    function test_getGuardians() public view {
        bytes32[] memory guardians = account.getGuardians();

        assertEq(initialGuardian, guardians[0]);
    }

    function _proposeGuardian(address _guardian) internal {
        _etch();

        vm.prank(owner);
        account.proposeGuardian(keccak256(abi.encodePacked(_guardian)));
    }

    function _confirmGuardianProposal(address _guardian) internal {
        _etch();

        vm.prank(owner);
        account.confirmGuardianProposal(keccak256(abi.encodePacked(_guardian)));
    }

    function _revoke(address _guardian) internal {
        _etch();

        vm.prank(owner);
        account.revokeGuardian(keccak256(abi.encodePacked(_guardian)));
    }

    function _startRecovery() internal {
        Key memory _recoveryKey = _getKey(bytes32(0), bytes32(0), GUARDIAN_EOA_ADDRESS, KeyType.EOA);

        _wrap(proposalTimestamp + SECURITY_PERIOD + 1);

        _etch();

        vm.prank(sender);
        account.startRecovery(_recoveryKey);
    }

    function _wrap(uint256 _time) internal {
        vm.warp(_time);
    }

    function _getKey(bytes32 _x, bytes32 _y, address  _eoa, KeyType keyType) internal pure returns (Key memory recoveryKey) {
        recoveryKey = Key({
            pubKey: PubKey({x: _x, y: _y}),
            eoaAddress:_eoa ,
            keyType: keyType
        });
    }
}

