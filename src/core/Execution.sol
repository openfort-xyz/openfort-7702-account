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
import {IExecution} from "src/interfaces/IExecution.sol";
import {ReentrancyGuardUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";

/// @title Execution
/// @author Openfort@0xkoiner
/// @notice Minimal ERC‑7821 batch‑executor implementation with explicit
///         protection against auth‑bypass, re‑entrancy and gas‑grief.
/// @dev    Inherits from `KeysManager` for key‑based access control and
///         `ReentrancyGuard` for one‑shot external entry protection.
abstract contract Execution is KeysManager, ReentrancyGuardUpgradeable {
    /* ────────────────────────────────────────────────────────────── */
    /*  CONSTANTS                                                    */
    /* ────────────────────────────────────────────────────────────── */

    /// @notice Maximum **total** low‑level calls allowed per *outer*
    ///         transaction (across every recursion level).
    uint8 internal constant MAX_TX = 9;

    bytes32 internal constant mode_1 = bytes32(uint256(0x01000000000000000000) << (22 * 8));
    bytes32 internal constant mode_3 = bytes32(uint256(0x01000000000078210002) << (22 * 8));

    /* ────────────────────────────────────────────────────────────── */
    /*  PUBLIC ENTRY – one per user‑op / tx                          */
    /* ────────────────────────────────────────────────────────────── */

    /// @notice Execute a batch (or batch‑of‑batches) described by
    ///         `executionData` under the selected `mode`.
    /// @param  mode Execution‑mode word (see ERC‑7821 draft).
    /// @param  executionData ABI‑encoded payload whose shape depends on
    ///         `mode`.
    function execute(bytes32 mode, bytes memory executionData)
        public
        payable
        virtual
        nonReentrant
    {
        // Authenticate *once* for the whole recursive run.
        _requireForExecute();

        // Run the worker; revert if overall call‑count > MAX_TX.
        _run(mode, executionData, 0);
    }

    /* ────────────────────────────────────────────────────────────── */
    /*  ERC‑165 helper                                               */
    /* ────────────────────────────────────────────────────────────── */

    /// @dev Convenience helper for wallets / bundlers to pre‑check
    ///      whether a specific `mode` is understood.
    function supportsExecutionMode(bytes32 mode) public view virtual returns (bool) {
        return _executionModeId(mode) != 0;
    }

    /* ────────────────────────────────────────────────────────────── */
    /*  INTERNAL RECURSIVE WORKER                                    */
    /* ────────────────────────────────────────────────────────────── */

    /// @dev Recursively process `executionData`.
    /// @param mode     Execution‑mode selector (top 10 bytes).
    /// @param data     ABI‑encoded batch or batch‑of‑batches.
    /// @param counter  Running total of low‑level calls executed so far.
    /// @return counter Updated running total.
    function _run(bytes32 mode, bytes memory data, uint256 counter) internal returns (uint256) {
        uint256 id = _executionModeId(mode);

        /* -------- mode 3 : batch‑of‑batches ----------------------- */
        if (id == 3) {
            // Clear the top‑level mode‑3 flag so inner batches can be
            // parsed as mode 1 or 2.
            mode ^= bytes32(uint256(3 << (22 * 8)));

            bytes[] memory batches = abi.decode(data, (bytes[]));
            _checkLength(batches.length); // per‑batch structural cap

            for (uint256 i; i < batches.length; ++i) {
                counter = _run(mode, batches[i], counter);
            }
            return counter;
        }

        /* -------- flat batch (mode 1 or 2) ------------------------ */
        if (id == 0) revert IExecution.OpenfortBaseAccount7702V1__UnsupportedExecutionMode();

        bool withOpData;
        /// @solidity memory-safe-assembly
        assembly {
            let len := mload(data)
            let flag := gt(mload(add(data, 0x20)), 0x3f)
            withOpData := and(eq(id, 2), and(gt(len, 0x3f), flag))
        }

        Call[] memory calls;
        bytes memory opData;
        if (withOpData) {
            (calls, opData) = abi.decode(data, (Call[], bytes));
        } else {
            calls = abi.decode(data, (Call[]));
        }

        _checkLength(calls.length); // per‑batch structural cap
        if (opData.length != 0) revert IExecution.OpenfortBaseAccount7702V1__UnsupportedOpData();

        for (uint256 i; i < calls.length; ++i) {
            Call memory c = calls[i];
            address to = c.target == address(0) ? address(this) : c.target;
            _execute(to, c.value, c.data);

            // ---- global counter enforcement -------------------- //
            if (++counter > MAX_TX) {
                revert IExecution.OpenfortBaseAccount7702V1__TooManyCalls(counter, MAX_TX);
            }
        }
        return counter;
    }

    /* ────────────────────────────────────────────────────────────── */
    /*  LOW-LEVEL EXECUTION PRIMITIVES                               */
    /* ────────────────────────────────────────────────────────────── */

    /// @dev Perform the actual call; bubble up any revert reason.
    function _execute(address to, uint256 value, bytes memory data) internal virtual {
        (bool success, bytes memory result) = to.call{value: value}(data);
        if (success) return;
        /// @solidity memory-safe-assembly
        assembly {
            revert(add(result, 0x20), mload(result))
        }
    }

    /* ────────────────────────────────────────────────────────────── */
    /*  HELPERS                                                      */
    /* ────────────────────────────────────────────────────────────── */

    /// @dev Derive a small integer ID from the 10‑byte execution mode.
    ///      0: unsupported, 1: flat batch, 2: flat batch + opData,
    ///      3: batch‑of‑batches.
    function _executionModeId(bytes32 mode) internal pure returns (uint256 id) {
        uint256 m = (uint256(mode) >> (22 * 8)) & 0xffff00000000ffffffff;
        if (m == 0x01000000000078210002) id = 3;
        if (m == 0x01000000000078210001) id = 2;
        if (m == 0x01000000000000000000) id = 1;
    }

    /// @dev Enforces `0 < txCount ≤ MAX_TX`.
    function _checkLength(uint256 txCount) internal pure {
        if (txCount == 0 || txCount > MAX_TX) {
            revert IExecution.OpenfortBaseAccount7702V1__InvalidTransactionLength();
        }
    }
}
