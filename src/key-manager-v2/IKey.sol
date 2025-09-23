// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

interface IKey {
    // =============================================================
    //                     TYPES AND STRUCTS
    // =============================================================
    
    enum KeyType {
        EOA,
        WEBAUTHN,
        P256,
        P256NONKEY
    }

    struct KeyData {
        KeyType keyType;
        bool isActive;
        bool masterKey;
        uint48 validUntil;
        uint48 validAfter;
        uint48 limits;
        bytes key;
    }

    struct KeyDataReg {
        KeyType keyType;
        uint48 validUntil;
        uint48 validAfter;
        uint48 limits;
        bytes key;
    }
}
