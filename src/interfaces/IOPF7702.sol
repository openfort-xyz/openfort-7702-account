// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {IExecution} from "src/interfaces/IExecution.sol";
import {IBaseOPF7702} from "src/interfaces/IBaseOPF7702.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";

/// @title IOPF7702
/// @notice Interface for the `OPF7702` contract, combining execution, key‐management, and ERC-1271 logic.
/// @dev Extends `IBaseOPF7702`, `IExecution`, `IKeysManager`, and exposes additional helpers.
interface IOPF7702 is IBaseOPF7702, IExecution, IKeysManager, IKey {
    // =============================================================
    //                             EVENTS
    // =============================================================

    /// @notice Emitted when the account is initialized with a master key.
    event Initialized(IKey.KeyDataReg indexed masterKey);

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

    /**
     * @notice Rounds a timestamp down to the start of the specified spend period.
     * @param unixTimestamp Timestamp to round.
     * @param period        Period granularity defined in {IKeysManager.SpendPeriod}.
     * @return Rounded timestamp aligned to the requested bucket.
     */
    function startOfSpendPeriod(uint256 unixTimestamp, SpendPeriod period)
        external
        pure
        returns (uint256);

    /**
     * @notice Address of the implementation contract (immutable at deployment).
     */
    function _OPENFORT_CONTRACT_ADDRESS() external view returns (address);
}
