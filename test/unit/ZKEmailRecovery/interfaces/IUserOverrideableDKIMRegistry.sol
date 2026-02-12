// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/**
 * @notice Interface for UserOverrideableDKIMRegistry
 * @dev Used to register DKIM public key hashes for email domains
 */
interface IUserOverrideableDKIMRegistry {
    function setDKIMPublicKeyHash(
        string memory domainName,
        bytes32 publicKeyHash,
        address authorizer,
        bytes memory signature
    ) external;

    function isDKIMPublicKeyHashValid(
        string memory domainName,
        bytes32 publicKeyHash,
        address authorizer
    ) external view returns (bool);

    function mainAuthorizer() external view returns (address);
}
