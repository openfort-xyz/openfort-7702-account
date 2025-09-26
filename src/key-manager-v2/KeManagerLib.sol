// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {IKey} from "././IKey.sol";
import {IKeyManager} from "././IKeyManager.sol";

type KeyId is bytes32;

library KeyManagerLib {
    // ============================================================
    //                      VALIDATION HELPERS
    // ============================================================

    function keyCantBeZero(IKey.KeyDataReg calldata k) internal pure {
        if (k.key.length == 0) revert IKeyManager.KeyManager__KeyCantBeZero();
    }

    function checkAddress(address addr) internal pure {
        if (addr == address(0)) revert IKeyManager.KeyManager__AddressZero();
    }

    function mustHaveLimits(IKey.KeyDataReg calldata k) internal pure {
        if (k.limits == 0) revert IKeyManager.KeyManager__MustHaveLimits();
    }

    function validateKeyBefore(IKey.KeyData storage sKey) internal view {
        if (!sKey.isActive) revert IKeyManager.KeyManager__KeyNotActive();
        if (sKey.masterKey) revert IKeyManager.KeyManager__MasterKeyCanDoAll();
    }

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
            revert IKeyManager.KeyManager__BadTimestamps();
        }
    }

    function checkTargetAddress(address addr) internal view {
        checkAddress(addr);
        if (addr == address(this)) revert IKeyManager.KeyManager__TargetIsThis();
    }

    function checkLimits(uint256 limits) internal pure {
        if (limits == 0) revert IKeyManager.KeyManager__MustHaveLimits();
    }

    // ============================================================
    //                      COMPUTATION HELPERS
    // ============================================================

    function computeKeyId(IKey.KeyType _keyType, bytes calldata _key)
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

    function packCanExecute(address target, bytes4 fnSel) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            result := or(shl(96, target), shr(224, fnSel))
        }
    }

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
