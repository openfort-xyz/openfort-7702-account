// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7201} from "src/interfaces/IERC7201.sol";

/// @title ERC-7201
/// @notice Public getters for the ERC7201 calculated storage root, namespace, and version
contract ERC7201 is IERC7201 {
    /// @notice Storage root computed in compliance with ERC-7201 standard
    /// @dev This constant value is hardcoded in CaliburEntry.sol for compile-time determinism.
    /// It is equal to: keccak256(abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)) &
    /// ~bytes32(uint256(0xff))
    bytes32 public constant CUSTOM_STORAGE_ROOT =
        0xeddd36aac8c71936fe1d5edb073ff947aa7c1b6174e87c15677c96ab9ad95400;

    /**
     * @notice Exposes the storage namespace and semantic version encoded for ERC-7201.
     * @return Namespace string of the form `openfort.baseAccount.7702.v1`.
     */
    function namespaceAndVersion() external pure returns (string memory) {
        return "openfort.baseAccount.7702.v1";
    }
}
