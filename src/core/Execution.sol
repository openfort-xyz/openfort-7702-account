/*
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░     ░░░░░░        ░░░         ░    ░░░░░   ░        ░░░░░░     ░░░░░░        ░░░░░           ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
▒▒▒   ▒▒▒▒   ▒▒▒   ▒▒▒▒   ▒   ▒▒▒▒▒▒▒  ▒   ▒▒▒   ▒   ▒▒▒▒▒▒▒▒▒   ▒▒▒▒   ▒▒▒   ▒▒▒▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒      ▒   ▒      ▒   ▒▒▒▒▒   ▒▒▒▒▒▒▒   ▒  ▒▒▒
▒   ▒▒▒▒▒▒▒▒   ▒   ▒▒▒▒   ▒   ▒▒▒▒▒▒▒   ▒   ▒▒   ▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒   ▒   ▒▒▒▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒   ▒▒▒▒   ▒▒   ▒▒▒  ▒▒▒▒▒   
▓   ▓▓▓▓▓▓▓▓   ▓        ▓▓▓       ▓▓▓   ▓▓   ▓   ▓       ▓▓▓   ▓▓▓▓▓▓▓▓   ▓  ▓   ▓▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓   ▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓
▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓  ▓   ▓   ▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓   ▓▓▓▓▓▓   ▓▓▓▓   ▓▓▓▓
▓▓▓   ▓▓▓▓▓   ▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓▓  ▓  ▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓   ▓▓   ▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓   ▓▓▓▓   ▓▓▓   ▓▓▓▓▓▓
█████     ██████   ████████         █   ██████   █   ███████████     ██████   ██████   █████   █████████   ████████   ████████    █████         █
█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
 */

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {KeysManager} from "src/core/KeysManager.sol";
import {ReentrancyGuard} from "lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

/// @title Execution
/// @author Openfort@0xkoiner
/// @notice Provides functionality to execute single or batched transactions from this account.
/// @dev Inherits from KeysManager (for key-based access control) and ReentrancyGuard (to prevent reentrant calls).
abstract contract Execution is KeysManager, ReentrancyGuard {
    // =============================================================
    //                          CONSTANTS
    // =============================================================

    /// @notice Maximum number of transactions allowed in one batch
    uint8 internal constant MAX_TX = 9;

    /// @notice Function selector for `execute(address,uint256,bytes)`
    bytes4 internal constant EXECUTE_SELECTOR = 0xb61d27f6;
    /// @notice Function selector for `executeBatch(address[],uint256[],bytes[])`
    bytes4 internal constant EXECUTEBATCH_SELECTOR = 0x47e1da2a;

    // =============================================================
    //                             EVENTS
    // =============================================================

    /// @notice Emitted whenever a transaction is successfully executed.
    /// @param target The address of the contract or account being called.
    /// @param value The amount of Ether (in wei) sent with the call.
    /// @param data The calldata for the call.
    event TransactionExecuted(address indexed target, uint256 value, bytes data);

    // =============================================================
    //                         PUBLIC FUNCTIONS
    // =============================================================

    /// @notice Executes a batch of transactions in a single call.
    /// @dev Can only be called by this contract itself (e.g., via EntryPoint) or an authorized signer in KeysManager.
    ///      Reverts if the number of transactions is zero or exceeds `MAX_TX`.
    /// @param _transactions An array of `Call` structs, each specifying:
    ///        - `target`: the address to call,
    ///        - `value`: the Ether (in wei) to send,
    ///        - `data`: the calldata to execute.
    function execute(Call[] calldata _transactions) external payable virtual nonReentrant {
        _requireForExecute();

        uint256 txCount = _transactions.length;
        if (txCount == 0 || txCount > MAX_TX) {
            revert OpenfortBaseAccount7702V1__InvalidTransactionLength();
        }

        for (uint256 i = 0; i < txCount;) {
            Call calldata callItem = _transactions[i];
            _executeCall(callItem.target, callItem.value, callItem.data);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Executes a single transaction.
    /// @dev Can only be called by this contract itself (e.g., via EntryPoint) or an authorized signer in KeysManager.
    ///      Delegates to internal `_executeCall`, which reverts on failure and emits `TransactionExecuted`.
    /// @param _target The address to call.
    /// @param _value  The amount of Ether (in wei) to send with the call.
    /// @param _data   The calldata payload to send to `_target`.
    function execute(address _target, uint256 _value, bytes calldata _data)
        public
        virtual
        override
        nonReentrant
    {
        _requireForExecute();
        _executeCall(_target, _value, _data);
    }

    /// @notice Executes a sequence of transactions given by parallel arrays.
    /// @dev Can only be called by this contract itself (e.g., via EntryPoint) or an authorized signer in KeysManager.
    ///      Requires that all input arrays (`_target`, `_value`, `_data`) have the same non-zero length ≤ `MAX_TX`.
    ///      Reverts with `InvalidTransactionLength` if conditions are not met.
    /// @param _target Array of addresses to call.
    /// @param _value  Array of Ether amounts (in wei) to send with each call.
    /// @param _data   Array of calldata payloads corresponding to each target.
    function executeBatch(
        address[] calldata _target,
        uint256[] calldata _value,
        bytes[] calldata _data
    ) public payable virtual nonReentrant {
        _requireForExecute();

        uint256 batchLength = _target.length;
        if (
            batchLength == 0 || batchLength > MAX_TX || batchLength != _value.length
                || batchLength != _data.length
        ) {
            revert OpenfortBaseAccount7702V1__InvalidTransactionLength();
        }

        for (uint256 i = 0; i < batchLength;) {
            _executeCall(_target[i], _value[i], _data[i]);
            unchecked {
                ++i;
            }
        }
    }

    // =============================================================
    //                        INTERNAL FUNCTIONS
    // =============================================================

    /// @notice Internal helper to perform a low-level call to `_target`.
    /// @dev Emits `TransactionExecuted`, checks that `_target` is not this contract, and bubbles up revert reason on failure.
    /// @param _target The address to call.
    /// @param _value  The Ether (in wei) amount to send.
    /// @param _data   The calldata payload for the call.
    function _executeCall(address _target, uint256 _value, bytes calldata _data) internal virtual {
        if (_target == address(this)) {
            revert OpenfortBaseAccount7702V1__InvalidTransactionTarget();
        }

        emit TransactionExecuted(_target, _value, _data);
        (bool success, bytes memory returnData) = _target.call{value: _value}(_data);
        if (!success) {
            revert OpenfortBaseAccount7702V1__TransactionFailed(returnData);
        }
    }
}
