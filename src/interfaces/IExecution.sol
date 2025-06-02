// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {KeysManager} from "src/core/KeysManager.sol";

/// @title IExecution
/// @notice Interface for the `Execution` abstract contract, which provides single‐ and batch‐transaction execution functionality.
/// @dev Declares all externally‐visible functions, events, and errors. Uses `KeysManager.Call` for transaction data.
interface IExecution {
    // =============================================================
    //                         PUBLIC FUNCTIONS
    // =============================================================

    /// @notice Executes a batch of transactions in a single call.
    /// @dev Can only be called by this contract itself (via EntryPoint) or by an authorized signer in `KeysManager`.
    ///      Reverts with `InvalidTransactionLength` if the number of transactions is zero or exceeds `MAX_TX`.
    /// @param _transactions An array of `KeysManager.Call` structs, each specifying:
    ///        - `target`: the address to call,
    ///        - `value`: the Ether (in wei) to send,
    ///        - `data`: the calldata to execute.
    function execute(KeysManager.Call[] calldata _transactions) external payable;

    /// @notice Executes a single transaction.
    /// @dev Can only be called by this contract itself (via EntryPoint) or by an authorized signer in `KeysManager`.
    ///      Delegates to an internal `_executeCall`, which emits `TransactionExecuted` and reverts on failure.
    /// @param _target The address to call.
    /// @param _value  The amount of Ether (in wei) to send with the call.
    /// @param _data   The calldata payload to send to `_target`.
    function execute(address _target, uint256 _value, bytes calldata _data) external;

    /// @notice Executes a sequence of transactions given by parallel arrays.
    /// @dev Can only be called by this contract itself (via EntryPoint) or by an authorized signer in `KeysManager`.
    ///      Requires that all input arrays (`_target`, `_value`, `_data`) have the same non‐zero length ≤ `MAX_TX`.
    ///      Reverts with `InvalidTransactionLength` if conditions are not met.
    /// @param _target Array of addresses to call.
    /// @param _value  Array of Ether amounts (in wei) to send with each call.
    /// @param _data   Array of calldata payloads corresponding to each `target`.
    function executeBatch(
        address[] calldata _target,
        uint256[] calldata _value,
        bytes[] calldata _data
    ) external payable;
}
