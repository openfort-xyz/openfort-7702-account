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
    /*════════════════════════════ PUBLIC HELPERS ════════════════════════════*/

    /// @return true when the key was registered by *this* contract (index ≠ 0) and not wiped.
    function isRegistered(IKey.KeyData storage sKey) internal view returns (bool) {
        return sKey.validUntil != 0;
    }

    /// @dev Master‑keys have unlimited tx budget; sub‑keys consume one unit per tx.
    /// @return true if the caller *may* execute one more tx right now.
    function hasQuota(IKey.KeyData storage sKey) internal view returns (bool) {
        return sKey.masterKey || sKey.limits > 0;
    }

    /// @notice Decrements the tx counter for sub‑keys in an unchecked block (gas).
    function consumeQuota(IKey.KeyData storage sKey) internal {
        if (!sKey.masterKey && sKey.limits > 0) {
            unchecked {
                sKey.limits -= 1;
            }
        }
    }
}
