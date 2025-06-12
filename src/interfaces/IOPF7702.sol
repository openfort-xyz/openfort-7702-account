// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IExecution} from "src/interfaces/IExecution.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {IERC1271} from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {IERC165} from "lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";

/// @title IOPF7702
/// @notice Interface for the `OPF7702` contract, combining execution, key‐management, and ERC-1271 logic.
/// @dev Extends `IExecution`, `IKeysManager`, `IERC1271`, and `IERC165`. Declares all externally‐callable members.
interface IOPF7702 is IExecution, IKeysManager, IERC1271, IERC165 {
    // =============================================================
    //                         EXTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice Initializes the account with a “master” key (no spending or whitelist restrictions).
     * @dev
     *  • Callable only via EntryPoint or a self-call.
     *  • Clears previous storage, checks nonce & expiration, verifies signature.
     *  • Registers the provided `_key` as a master key:
     *     - validUntil = max (never expires)
     *     - validAfter  = 0
     *     - limit       = 0  (master)
     *     - whitelisting = false
     *     - DEAD_ADDRESS placeholder in whitelistedContracts
     *  • Emits `Initialized(_key)`.
     *
     * @param _key              The `Key` struct (master key).
     * @param _spendTokenInfo   Token limit info (ignored for master).
     * @param _allowedSelectors Unused selectors (ignored for master).
     * @param _hash             Hash to sign (EIP-712 or UserOp hash).
     * @param _signature        Signature over `_hash` by this contract.
     * @param _validUntil       Expiration timestamp for this initialization.
     * @param _nonce            Nonce to prevent replay.
     */
    function initialize(
        Key calldata _key,
        SpendLimit.SpendTokenInfo calldata _spendTokenInfo,
        bytes4[] calldata _allowedSelectors,
        bytes32 _hash,
        bytes calldata _signature,
        uint256 _validUntil,
        uint256 _nonce
    ) external;

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
