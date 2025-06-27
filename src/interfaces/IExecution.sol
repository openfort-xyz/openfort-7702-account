// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {KeysManager} from "src/core/KeysManager.sol";

/// @title IExecution
/// @notice Interface for the `Execution` abstract contract, which provides single‐ and batch‐transaction execution functionality.
/// @dev Declares all externally‐visible functions, events, and errors. Uses `KeysManager.Call` for transaction data.
interface IExecution {
    // =============================================================
    //                            ERRORS
    // =============================================================

    /// @dev The execution mode is not supported.
    error OpenfortBaseAccount7702V1__UnsupportedExecutionMode();
    /// @notice Thrown when the provided transaction length is invalid.
    error OpenfortBaseAccount7702V1__InvalidTransactionLength();
    /// @dev Thrown when `opData`‑aware mode is requested but not yet
    ///      implemented.
    error OpenfortBaseAccount7702V1__UnsupportedOpData();

    /// @dev Thrown when the sum of executed calls exceeds `MAX_TX`.
    error OpenfortBaseAccount7702V1__TooManyCalls(uint256 total, uint256 max);

    // =============================================================
    //                         PUBLIC FUNCTIONS
    // =============================================================

    /// @notice Execute a batch (or batch‑of‑batches) described by
    ///         `executionData` under the selected `mode`.
    /// @param  mode Execution‑mode word (see ERC‑7821 draft).
    /// @param  executionData ABI‑encoded payload whose shape depends on
    ///         `mode`.
    function execute(bytes32 mode, bytes memory executionData) external payable;

    /// @dev Convenience helper for wallets / bundlers to pre‑check
    ///      whether a specific `mode` is understood.
    function supportsExecutionMode(bytes32 mode) external view returns (bool);
}
