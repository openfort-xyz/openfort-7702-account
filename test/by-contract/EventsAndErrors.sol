// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

abstract contract EventsAndErrors {
    error NotFromEntryPoint();
    error KeyManager__KeyInactive();
    error KeyManager__UsedChallenge();
    error KeyManager__KeyRegistered();
    error KeyManager__RevertGasPolicy();
    error KeyManager__InvalidTimestamp();
    error KeyManager__AddressCantBeZero();
    error KeyManager__MustIncludeLimits();
    error KeyManager__SelectorsListTooBig();
    error UpgradeAddress__AddressCantBeZero();
    error OPF7702Recoverable__MustBeGuardian();
    error KeyManager__InvalidSignatureLength();
    error UpgradeAddress__AddressNotCanonical();
    error OPF7702Recoverable__OngoingRecovery();
    error OPF7702Recoverable__UnknownProposal();
    error OPF7702Recoverable__DuplicatedRevoke();
    error OPF7702Recoverable__NoOngoingRecovery();
    error OPF7702Recoverable__AddressCantBeZero();
    error OPF7702Recoverable__DuplicatedProposal();
    error OPF7702Recoverable__UnsupportedKeyType();
    error OPF7702Recoverable__DuplicatedGuardian();
    error OPF7702Recoverable__PendingRevokeExpired();
    error OPF7702Recoverable__PendingRevokeNotOver();
    error OPF7702Recoverable__GuardianCannotBeOwner();
    error OPF7702Recoverable__InvalidSignatureAmount();
    error OPF7702Recoverable__PendingProposalExpired();
    error OPF7702Recoverable__PendingProposalNotOver();
    error OPF7702Recoverable__RecoverCannotBeActiveKey();
    error OpenfortBaseAccount7702V1__UnsupportedOpData();
    error OpenfortBaseAccount7702V1_UnauthorizedCaller();
    error OPF7702Recoverable__InvalidRecoverySignatures();
    error OPF7702Recoverable__GuardianCannotBeAddressThis();
    error OpenfortBaseAccount7702V1__UnsupportedExecutionMode();
    error OpenfortBaseAccount7702V1__InvalidTransactionLength();
    error OPF7702Recoverable__GuardianCannotBeCurrentMasterKey();
    error OpenfortBaseAccount7702V1__TooManyCalls(uint256 total, uint256 max);

    event KeyRevoked(bytes32 indexed key);
    event KeyRegistrated(bytes32 indexed key);
    event DepositAdded(address indexed source, uint256 amount);
    event EntryPointUpdated(address indexed previous, address indexed current);
    event WebAuthnVerifierUpdated(address indexed previous, address indexed current);
}
