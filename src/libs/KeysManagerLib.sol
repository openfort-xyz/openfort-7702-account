// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

/// @title KeysManagerLib
/// @author Openfort@0xkoiner
/// @notice Library with validation, ID computation, and permission packing helpers for KeysManager.
/// @dev Used by KeysManager/OPF7702. Encoding: EOA keys → `abi.encode(address)`,
///      P-256/WebAuthn keys → `abi.encode(bytes32 x, bytes32 y)`.
import {IKey} from "src/interfaces/IKey.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";

library KeysManagerLib {
    // ============================================================
    //                      VALIDATION HELPERS
    // ============================================================

    /**
     * @notice Reverts if the registration payload’s `key` is empty.
     * @dev Expects `k.key` to be non-zero-length (EOA/P-256/WebAuthn encodings).
     */
    function keyCantBeZero(IKey.KeyDataReg memory k) internal pure {
        if (k.key.length == 0) revert IKeysManager.KeyManager__KeyCantBeZero();
    }

    /**
     * @notice Returns whether a raw `bytes` key is non-empty.
     * @dev Convenience predicate used in a few call sites.
     * @return True if `k.length > 0`, else false.
     */
    function checkKey(bytes memory k) internal pure returns (bool) {
        return k.length > 0;
    }

    /**
     * @notice Reverts if `addr` is the zero address.
     */
    function checkAddress(address addr) internal pure {
        if (addr == address(0)) revert IKeysManager.KeyManager__AddressZero();
    }

    /**
     * @notice Reverts if the registration payload has zero `limits`.
     * @dev Session keys must have non-zero quota; master keys are handled separately.
     */
    function mustHaveLimits(IKey.KeyDataReg calldata k) internal pure {
        if (k.limits == 0) revert IKeysManager.KeyManager__MustHaveLimits();
    }

    /**
     * @notice Ensures the stored key is active and not the master key.
     * @dev Reverts with:
     *      - `KeyManager__KeyNotActive()` if `!sKey.isActive`.
     *      - `KeyManager__MasterKeyCanDoAll()` if `sKey.masterKey == true`.
     */
    function validateKeyBefore(IKey.KeyData storage sKey) internal view {
        if (!sKey.isActive) revert IKeysManager.KeyManager__KeyNotActive();
        if (sKey.masterKey) revert IKeysManager.KeyManager__MasterKeyCanDoAll();
    }

    /**
     * @notice Validates a proposed validity window and, when updating, enforces extension.
     * @dev Reverts `KeyManager__BadTimestamps()` if any:
     *      - `isExpired`:      `_validUntil <= block.timestamp`
     *      - `isInvalidRange`: `_validUntil < _validAfter`
     *      - `isMaxValue`:     `_validUntil == type(uint48).max` (reserved for master key)
     *      - `isNotExtending`: `isUpdate && (_validUntil <= _currentValidUntil)`
     * @param _validUntil         Proposed inclusive expiry.
     * @param _validAfter         Proposed not-before.
     * @param _currentValidUntil  Current expiry (only meaningful when `isUpdate == true`).
     * @param isUpdate            Whether this is an update (must strictly extend expiry).
     */
    function validateTimestamps(
        uint48 _validUntil,
        uint48 _validAfter,
        uint48 _currentValidUntil,
        bool isUpdate
    ) internal view {
        bool isExpired = _validUntil <= block.timestamp;
        bool isInvalidRange = _validUntil < _validAfter;
        bool isMaxValue = _validUntil == type(uint48).max;
        bool isNotExtending = isUpdate && (_validUntil <= _currentValidUntil);

        if (isExpired || isInvalidRange || isMaxValue || isNotExtending) {
            revert IKeysManager.KeyManager__BadTimestamps();
        }
    }

    /**
     * @notice Validates a target address for can-call rules.
     * @dev Reverts if `addr == address(0)` or `addr == address(this)` (self-calls forbidden).
     *      Note: in a library-inlined context, `address(this)` is the calling contract.
     */
    function checkTargetAddress(address addr) internal view {
        checkAddress(addr);
        if (addr == address(this)) revert IKeysManager.KeyManager__TargetIsThis();
    }

    /**
     * @notice Reverts if `limits == 0`.
     * @dev Used for session-key tx quota and token spend limits.
     */
    function checkLimits(uint256 limits) internal pure {
        if (limits == 0) revert IKeysManager.KeyManager__MustHaveLimits();
    }

    // ============================================================
    //                      COMPUTATION HELPERS
    // ============================================================

    /**
     * @notice Computes a stable key identifier from `(keyType, keyBytes)`.
     * @dev `result = keccak256(abi.encode(uint8(keyType), keccak256(keyBytes)))`.
     * @param _keyType  Cryptographic key type.
     * @param _key      Encoded key material.
     * @return result   Key identifier (bytes32).
     */
    function computeKeyId(IKey.KeyType _keyType, bytes memory _key)
        internal
        pure
        returns (bytes32 result)
    {
        uint256 v0 = uint8(_keyType);
        uint256 v1 = uint256(keccak256(_key));
        assembly {
            mstore(0x00, v0)
            mstore(0x20, v1)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @notice Convenience overload to compute a keyId from a registration payload.
     * @return Key identifier derived from `_keyData.keyType` and `_keyData.key`.
     */
    function computeKeyId(IKey.KeyDataReg memory _keyData) internal pure returns (bytes32) {
        return computeKeyId(_keyData.keyType, _keyData.key);
    }

    /**
     * @notice Computes a compact hash for an EOA address.
     * @dev `keccak256(abi.encodePacked(eoa))`. Used where a lightweight address hash is needed.
     * @return keyId Hash of the provided EOA.
     */
    function computeHash(address eoa) internal pure returns (bytes32 keyId) {
        keyId = keccak256(abi.encodePacked(eoa));
    }

    /**
     * @notice Packs `(target, selector)` into a single `bytes32` for set membership.
     * @dev Layout: high 20 bytes = `target`, low 4 bytes = `selector`.
     * @param target Target contract/EOA.
     * @param fnSel  Function selector (or special sentinel).
     * @return result Packed composite key.
     */
    function packCanExecute(address target, bytes4 fnSel) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            result := or(shl(96, target), shr(224, fnSel))
        }
    }

    /**
     * @notice Unpacks a `bytes32` composite into `(target, selector)`.
     * @dev Inverse of {packCanExecute}.
     * @param packed The packed composite key.
     * @return target Target address.
     * @return fnSel  Function selector.
     */
    function unpackCanExecute(bytes32 packed)
        internal
        pure
        returns (address target, bytes4 fnSel)
    {
        assembly ("memory-safe") {
            target := shr(96, packed)
            fnSel := shl(224, packed)
        }
    }
}
