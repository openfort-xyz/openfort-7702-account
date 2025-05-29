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

abstract contract Execution7821 is KeysManager, ReentrancyGuard {
    bytes4 internal constant EXECUTE_SELECTOR = 0xb61d27f6;
    bytes4 internal constant EXECUTEBATCH_SELECTOR = 0x47e1da2a;

    /// @dev The execution mode is not supported.
    error UnsupportedExecutionMode();

    /// @dev Executes the calls in `executionData`.
    /// Reverts and bubbles up error if any call fails.
    function execute(bytes32 mode, bytes memory executionData) public payable virtual {
        uint256 id = _executionModeId(mode);
        if (id == 3) {
            mode ^= bytes32(uint256(3 << (22 * 8)));
            bytes[] memory batches = abi.decode(executionData, (bytes[]));
            for (uint256 i; i < batches.length; ++i) {
                execute(mode, batches[i]);
            }
            return;
        }
        if (id == uint256(0)) revert UnsupportedExecutionMode();
        bool tryWithOpData;
        /// @solidity memory-safe-assembly
        assembly {
            let t := gt(mload(add(executionData, 0x20)), 0x3f)
            let executionDataLength := mload(executionData)
            tryWithOpData := and(eq(id, 2), and(gt(executionDataLength, 0x3f), t))
        }
        Call[] memory calls;
        bytes memory opData;
        if (tryWithOpData) {
            (calls, opData) = abi.decode(executionData, (Call[], bytes));
        } else {
            calls = abi.decode(executionData, (Call[]));
        }
        _execute(calls, opData);
    }

    /// @dev Provided for execution mode support detection.
    function supportsExecutionMode(bytes32 mode) public view virtual returns (bool result) {
        return _executionModeId(mode) != 0;
    }

    /// @dev 0: invalid mode, 1: no `opData` support, 2: with `opData` support, 3: batch of batches.
    function _executionModeId(bytes32 mode) internal view virtual returns (uint256 id) {
        uint256 m = (uint256(mode) >> (22 * 8)) & 0xffff00000000ffffffff;
        if (m == 0x01000000000078210002) id = 3;
        if (m == 0x01000000000078210001) id = 2;
        if (m == 0x01000000000000000000) id = 1;
    }

    /// @dev Executes the calls and returns the results.
    /// Reverts and bubbles up error if any call fails.
    function _execute(Call[] memory calls, bytes memory opData) internal virtual {
        if (opData.length == uint256(0)) {
            _requireForExecute();
            return _execute(calls);
        }
        revert();
    }

    /// @dev Executes the calls.
    /// Reverts and bubbles up error if any call fails.
    function _execute(Call[] memory calls) internal virtual {
        for (uint256 i; i < calls.length; ++i) {
            Call memory c = calls[i];
            address to = c.target == address(0) ? address(this) : c.target;
            _execute(to, c.value, c.data);
        }
    }

    /// @dev Executes the call.
    /// Reverts and bubbles up error if the call fails.
    function _execute(address to, uint256 value, bytes memory data) internal virtual {
        (bool success, bytes memory result) = to.call{value: value}(data);
        if (success) return;
        /// @solidity memory-safe-assembly
        assembly {
            // Bubble up the revert if the call reverts.
            revert(add(result, 0x20), mload(result))
        }
    }
}
