// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

abstract contract EventsAndErrors {
    error NotFromEntryPoint();
    error KeyManager__KeyInactive();
    error KeyManager__KeyRegistered();
    error KeyManager__InvalidTimestamp();
    error KeyManager__AddressCantBeZero();
    error KeyManager__MustIncludeLimits();
    error KeyManager__SelectorsListTooBig();
    error UpgradeAddress__AddressCantBeZero();
    error KeyManager__InvalidSignatureLength();
    error UpgradeAddress__AddressNotCanonical();
    error OpenfortBaseAccount7702V1__UnsupportedOpData();
    error OpenfortBaseAccount7702V1_UnauthorizedCaller();
    error OpenfortBaseAccount7702V1__UnsupportedExecutionMode();
    error OpenfortBaseAccount7702V1__InvalidTransactionLength();
    error OpenfortBaseAccount7702V1__TooManyCalls(uint256 total, uint256 max);

    event KeyRevoked(bytes32 indexed key);
    event KeyRegistrated(bytes32 indexed key);
    event DepositAdded(address indexed source, uint256 amount);
    event EntryPointUpdated(address indexed previous, address indexed current);
    event WebAuthnVerifierUpdated(address indexed previous, address indexed current);
}
