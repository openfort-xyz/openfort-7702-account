// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

/// @dev Interface for minimal batch executor.
interface IERC7821 {
    /// @dev Executes the calls in `executionData`.
    /// Reverts and bubbles up error if any call fails.
    ///
    /// `executionData` encoding (single batch):
    /// - If `opData` is empty, `executionData` is simply `abi.encode(calls)`.
    /// - Else, `executionData` is `abi.encode(calls, opData)`.
    ///   See: https://eips.ethereum.org/EIPS/eip-7579
    ///
    /// `executionData` encoding (batch of batches):
    /// - `executionData` is `abi.encode(bytes[])`, where each element in `bytes[]`
    ///   is an `executionData` for a single batch.
    ///
    /// Supported modes:
    /// - `0x01000000000000000000...`: Single batch. Does not support optional `opData`.
    /// - `0x01000000000078210001...`: Single batch. Supports optional `opData`.
    /// - `0x01000000000078210002...`: Batch of batches. The mode is optional.
    ///
    /// For the "batch of batches" mode, each batch will be recursively passed into
    /// `execute` internally with mode `0x01000000000078210001...`.
    /// Useful for passing in batches signed by different signers.
    ///
    /// Authorization checks:
    /// - If `opData` is empty, the implementation SHOULD require that
    ///   `msg.sender == address(this)`.
    /// - If `opData` is not empty, the implementation SHOULD use the signature
    ///   encoded in `opData` to determine if the caller can perform the execution.
    /// - If `msg.sender` is an authorized entry point, then `execute` MAY accept
    ///   calls from the entry point, and MAY use `opData` for specialized logic.
    ///
    /// `opData` may be used to store additional data for authentication,
    /// paymaster data, gas limits, etc.
    ///
    /// For calldata compression efficiency, if a Call.to is `address(0)`,
    /// it will be replaced with `address(this)`.
    function execute(bytes32 mode, bytes calldata executionData) external payable;

    /// @dev Provided for execution mode support detection.
    /// Only returns true for:
    /// - `0x01000000000000000000...`: Single batch. Does not support optional `opData`.
    /// - `0x01000000000078210001...`: Single batch. Supports optional `opData`.
    /// - `0x01000000000078210002...`: Batch of batches. The mode is optional.
    function supportsExecutionMode(bytes32 mode) external view returns (bool);
}
