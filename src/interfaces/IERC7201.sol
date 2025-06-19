// SPDX-License-Identifier: MIT
// @audit-info ⚠️: Fixed Pragma -> ^0.8.29
pragma solidity ^0.8.0;

interface IERC7201 {
    /// @notice Returns the namespace and version of the contract
    // @audit-info ⚠️: src/utils/ERC7201.sol the function is pure -> change to pure
    function namespaceAndVersion() external view returns (string memory);
    /// @notice Returns the current custom storage root of the contract
    // @audit-info ⚠️: constant CUSTOM_STORAGE_ROOT is constant -> change to pure
    function CUSTOM_STORAGE_ROOT() external view returns (bytes32);
}

/// @audit-first-round: ✅
