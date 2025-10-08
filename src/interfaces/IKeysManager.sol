// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {IKey} from "././IKey.sol";
import {EnumerableSetLib} from "lib/solady/src/utils/EnumerableSetLib.sol";

interface IKeysManager {
    // =============================================================
    //                     TYPES AND STRUCTS
    // =============================================================

    enum SpendPeriod {
        Minute,
        Hour,
        Day,
        Week,
        Month,
        Year,
        Forever
    }

    struct ExecutePermissions {
        EnumerableSetLib.Bytes32Set canExecute;
    }

    struct TokenSpendPeriod {
        SpendPeriod period;
        uint256 limit;
        uint256 spent;
        uint256 lastUpdated;
    }

    struct SpendStorage {
        EnumerableSetLib.AddressSet tokens;
        mapping(address => TokenSpendPeriod) tokenData;
    }

    // =============================================================
    //                     CUSTOM ERRORS
    // =============================================================

    error KeyManager__AddressZero();
    error KeyManager__KeyNotActive();
    error KeyManager__TargetIsThis();
    error KeyManager__KeyCantBeZero();
    error KeyManager__BadTimestamps();
    error KeyManager__KeyRegistered();
    error KeyManager__MustHaveLimits();
    error KeyManager__InvalidKeyType();
    error KeyManager__KeyAlreadyPaused();
    error KeyManager__KeyAlreadyActive();
    error KeyManager__TokenSpendNotSet();
    error KeyManager__MasterKeyCanDoAll();
    error KeyManager__TokenSpendAlreadySet();
    error KeyManager__InvalidSignatureLength();
    error KeyManager__InvalidMasterKeyReg(IKey.KeyDataReg _keyData_);

    // =============================================================
    //                            EVENTS
    // =============================================================

    event KeyRegistered(
        bytes32 indexed keyId,
        IKey.KeyControl indexed keyControl,
        IKey.KeyType keyType,
        bool masterKey,
        uint48 validAfter,
        uint48 validUntil,
        uint48 limits
    );
    event KeyRevoked(bytes32 indexed keyId);
    event KeyPaused(bytes32 indexed keyId);
    event KeyUnpaused(bytes32 indexed keyId);
    event KeyUpdated(bytes32 indexed keyId, uint48 validUntil, uint48 limits);

    event CanCallSet(bytes32 indexed keyId, address indexed target, bytes4 fnSel, bool can);
    event ExecutePermissionsCleared(bytes32 indexed keyId);

    event CallCheckerSet(bytes32 indexed keyId, address indexed target, address checker);
    event CallCheckerRemoved(bytes32 indexed keyId, address indexed target);

    event TokenSpendSet(
        bytes32 indexed keyId, address indexed token, SpendPeriod period, uint256 limit
    );
    event TokenSpendRemoved(bytes32 indexed keyId, address indexed token);
    event SpendPermissionsCleared(bytes32 indexed keyId);

    function keyAt(uint256 i) external view returns (bytes32 keyId, IKey.KeyData memory data);
    function isKeyActive(bytes32 _keyId) external view returns (bool);
}
