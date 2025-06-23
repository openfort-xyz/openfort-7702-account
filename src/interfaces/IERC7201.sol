// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

interface IERC7201 {
    /// @notice Returns the namespace and version of the contract
    function namespaceAndVersion() external pure returns (string memory);
    /// @notice Returns the current custom storage root of the contract
    function CUSTOM_STORAGE_ROOT() external pure returns (bytes32);
}
