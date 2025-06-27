// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IKey} from "src/interfaces/IKey.sol"; // Brings in KeyData / SpendTokenInfo structs

/**
 * @title KeyDataValidationLib
 * @notice Small helper‑library that consolidates the *five* recurrent state checks every
 *         `OPF7702` call path performs on a `KeyData` record.  Re‑using these predicates
 *         makes intent explicit while shaving a couple of hundred deployment bytes and
 *         keeping the hot‑paths branch‑minimal.
 *
 *         **No external behaviour changes** – we still *return* booleans instead of
 *         reverting, just like the original in‑line checks, preserving the public API.
 *
 * @dev Layout‑agnostic: we only read public fields already used in OPF7702, so any later
 *      additions to `KeyData` won’t break the lib as long as storage ordering is kept.
 */
library KeyDataValidationLib {
    /// @notice “Burn” address used as placeholder
    address internal constant DEAD_ADDRESS = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;

    /*════════════════════════════ PUBLIC HELPERS ════════════════════════════*/

    /// @return true when the key was registered by *this* contract (index ≠ 0) and not wiped.
    function isRegistered(IKey.KeyData storage sKey) internal view returns (bool) {
        return sKey.validUntil != 0;
    }

    /// @return true when the key is flagged active *and* still inside its [after, until] window.
    function isLive(IKey.KeyData storage sKey) internal view returns (bool) {
        //             ─────── registered ───────      ─ current window ─
        return sKey.isActive && block.timestamp >= sKey.validAfter
            && block.timestamp <= sKey.validUntil;
    }

    /// @dev Master‑keys have unlimited tx budget; sub‑keys consume one unit per tx.
    /// @return true if the caller *may* execute one more tx right now.
    function hasQuota(IKey.KeyData storage sKey) internal view returns (bool) {
        return sKey.masterKey || sKey.limit > 0;
    }

    /// @return true if `weiValue` is within the key’s ETH spend allowance.
    function withinEthLimit(IKey.KeyData storage sKey, uint256 weiValue)
        internal
        view
        returns (bool)
    {
        return sKey.ethLimit >= weiValue;
    }

    /// @notice Decrements the tx counter for sub‑keys in an unchecked block (gas).
    function consumeQuota(IKey.KeyData storage sKey) internal {
        if (!sKey.masterKey && sKey.limit > 0) {
            unchecked {
                sKey.limit -= 1;
            }
        }
    }

    /*════════════════════════════ BUNDLE HELPERS ═══════════════════════════*/

    /// @return true when ALL baseline conditions to even inspect a signature are met.
    function passesBaseChecks(IKey.KeyData storage sKey) internal view returns (bool) {
        return isRegistered(sKey) && isLive(sKey);
    }

    /// @return ok True when the key survives *every* guard used by `_validateCall`.
    function passesCallGuards(IKey.KeyData storage sKey, uint256 weiValue)
        internal
        view
        returns (bool ok)
    {
        ok = hasQuota(sKey) && withinEthLimit(sKey, weiValue);
    }

    /// @return ok True when the key not Empty.
    function checkKey(IKey.Key memory sKey) internal pure returns (bool ok) {
        bool hasAddress = sKey.eoaAddress != address(0) && sKey.eoaAddress != DEAD_ADDRESS;
        bool hasPubKey = sKey.pubKey.x != bytes32(0) || sKey.pubKey.y != bytes32(0);

        ok = !hasAddress && !hasPubKey; // Returns true when BOTH are false (empty)
    }
}
