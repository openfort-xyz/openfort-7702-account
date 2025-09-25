// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {IKey} from "././IKey.sol";
import {IKeyManager} from "././IKeyManager.sol";

type KeyId is bytes32;

library KeManagerLib {
    function keyCantBeZero(IKey.KeyDataReg calldata k) internal pure {
        if (k.key.length == 0) revert IKeyManager.KeyManager__KeyCantBeZero();
    }

    function mustHaveLimits(IKey.KeyDataReg calldata k) internal pure {
        if (k.limits == 0) revert IKeyManager.KeyManager__MustHaveLimits();
    }
}
