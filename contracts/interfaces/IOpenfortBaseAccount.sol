// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {IValidation} from "contracts/interfaces/IValidation.sol";

struct Transaction {
    address to;
    uint256 value;
    bytes data;
}

/**
 * @title IOpenfortBaseAccount Interface
 * @author Openfort@0xkoiner
 * @notice Interface for the Openfort Base Account implementation
 * @dev Defines the basic structure and functions that must be implemented by account contracts
 */
interface IOpenfortBaseAccount {
    /**
     * @notice Initializes the account with an owner and validates the signature
     * @dev Sets up the account and verifies the provided signature
     * @param _owner The address to set as the owner of this account
     * @param _validation The validation struct containing signature and validation data
     */
    function initialize(address _owner, IValidation.Validation calldata _validation) external;

    /**
     * @notice Executes a batch of transactions if called by the owner
     * @dev Should verify the caller and execute the transactions
     * @param _transactions An array of transactions to execute
     */
    function execute(Transaction[] calldata _transactions) external payable;
}
