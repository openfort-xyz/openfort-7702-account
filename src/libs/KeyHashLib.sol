// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";

/**
 * @title KeyHashLib
 * @notice Pure helper library for deriving the canonical `keyId` used by
 *         `KeysManager`. Centralising the hashing logic eliminates code
 *         duplication and makes the system easier to audit.
 * @dev Attach with `using KeyHashLib for IKey.Key;` or call the helpers
 *      directly. All functions are `internal` and `pure`, therefore they incur
 *      **zero** storage reads/writes and no external calls.
 *
 * ## Usage example
 * ```solidity
 * using KeyHashLib for IKey.Key;
 * bytes32 keyId = _key.computeKeyId();
 * ```
 */
library KeyHashLib {
    /*//////////////////////////////////////////////////////////////////////////
                                  HIGH‑LEVEL ROUTER
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @notice Computes the `keyId` for a full {IKey.Key} struct.
     * @dev Internally routes to the appropriate helper based on `key.keyType`.
     * @param key The key whose identifier should be derived.
     * @return keyId Deterministic identifier (`keccak256` hash) for the key.
     */
    function computeKeyId(IKey.Key memory key) internal pure returns (bytes32 keyId) {
        if (key.keyType == IKey.KeyType.EOA) {
            keyId = computeKeyId(key.eoaAddress);
        } else {
            keyId = computeKeyId(key.pubKey);
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                                 LOW‑LEVEL HELPERS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @notice Computes the `keyId` for an EOA key.
     * @param eoa The external‑owned account address to hash.
     * @return keyId keccak256 hash of the packed address.
     */
    function computeKeyId(address eoa) internal pure returns (bytes32 keyId) {
        keyId = keccak256(abi.encodePacked(eoa));
    }

    /**
     * @notice Computes the `keyId` for a WebAuthn / P‑256 / P‑256NONKEY key.
     * @param pubKey The public‑key coordinates (x, y) as an {IKey.PubKey} struct.
     * @return keyId keccak256 hash of the packed coordinates.
     */
    function computeKeyId(IKey.PubKey memory pubKey) internal pure returns (bytes32 keyId) {
        keyId = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
    }
}
