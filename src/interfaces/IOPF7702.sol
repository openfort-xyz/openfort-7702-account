// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IExecution} from "src/interfaces/IExecution.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {IERC1271} from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {IERC165} from "lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";

/// @title IOPF7702
/// @notice Interface for the `OPF7702` contract, combining execution, key‐management, and ERC-1271 logic.
/// @dev Extends `IExecution`, `IKeysManager`, `IERC1271`, and `IERC165`. Declares all externally‐callable members.
interface IOPF7702 is IExecution, IKeysManager, IERC1271, IERC165 {
    // =============================================================
    //                             EVENTS
    // =============================================================

    /// @notice Emitted when the account is initialized with a masterKey
    event Initialized(Key indexed masterKey);

    // =============================================================
    //                         EXTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice ERC-1271 on-chain signature validation entrypoint.
     * @dev
     *  • Reads the leading `KeyType` from `_signature` to dispatch to WebAuthn, P256, or ECDSA validation paths.
     *  • Returns `isValidSignature.selector` on success; otherwise `0xffffffff`.
     *
     * @param _hash       The hash that was signed.
     * @param _signature  The signature blob to verify.
     * @return Magic value (`0x1626ba7e`) if valid; otherwise `0xffffffff`.
     */
    function isValidSignature(bytes32 _hash, bytes calldata _signature)
        external
        view
        returns (bytes4);
}
