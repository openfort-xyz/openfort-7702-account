// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

/**
 * @title IValidation Interface
 * @author Openfort@0xkoiner
 * @notice Interface defining validation structures for signature verification
 * @dev Contains structs used for signature validation in account initialization
 */
interface IValidation {
    /**
     * @notice Structure containing signature and validation data
     * @dev Used for general signature validation
     */
    struct Validation {
        uint256 nonce;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 validUntil;
    }
}
