// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @title IERC7201
/// @notice Minimal ERC-7201 metadata helper used by Openfort contracts.
interface IERC7201 {
    /**
     * @notice Returns the logical namespace + semantic version encoded for storage layout.
     */
    function namespaceAndVersion() external pure returns (string memory);

    /**
     * @notice Returns the deterministic storage root associated with the namespace.
     */
    function CUSTOM_STORAGE_ROOT() external pure returns (bytes32);
}
