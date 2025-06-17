// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IKeysManager} from "src/interfaces/IKeysManager.sol";

/**
 * @title ValidationLib
 * @notice Consolidates the most common guard-clauses used across `KeysManager` into a single place.
 * @dev  – Re-uses the **exact** custom errors already declared in `IKeysManager`,
 *       keeping external behaviour 100 % untouched while shrinking byte-code size
 *       and making intent explicit.
 *       – Every function is `pure` or `view`, so the optimiser can inline the
 *       reverted condition efficiently.
 *       – `MAX_SELECTORS` is mirrored from `KeysManager` so the check remains
 *       consistent without having to import the whole contract.
 */
library ValidationLib {
    /// @dev Mirror of `KeysManager.MAX_SELECTORS`. Keep in sync!
    uint256 internal constant MAX_SELECTORS = 10;

    /**
     * @notice Reverts when `_limit == 0`, preventing master-key impersonation
     *         for sub-keys.
     */
    function ensureLimit(uint48 _limit) internal pure {
        if (_limit == 0) revert IKeysManager.KeyManager__MustIncludeLimits();
    }

    /**
     * @notice Validates time bounds in the same way `KeysManager` originally did.
     */
    function ensureValidTimestamps(uint48 _after, uint48 _until) internal view {
        if (_until <= block.timestamp || _after > _until) {
            revert IKeysManager.KeyManager__InvalidTimestamp();
        }
    }

    /**
     * @notice Guard-clause against the ubiquitous zero-address footgun.
     */
    function ensureNotZero(address _addr) internal pure {
        if (_addr == address(0)) revert IKeysManager.KeyManager__AddressCantBeZero();
    }

    /**
     * @notice Makes sure we never exceed the hard cap defined for selectors.
     */
    function ensureSelectorsLen(uint256 _len) internal pure {
        if (_len > MAX_SELECTORS) revert IKeysManager.KeyManager__SelectorsListTooBig();
    }
}
