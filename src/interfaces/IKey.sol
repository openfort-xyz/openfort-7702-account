// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {ISpendLimit} from "src/interfaces/ISpendLimit.sol";

interface IKey {
    /**
     * @notice Types of keys supported by the account.
     * @dev
     * - EOA:        secp256k1 ECDSA signatures (r,s,v). Standard Ethereum accounts.
     * - WEBAUTHN:   FIDO2/WebAuthn P-256 (secp256r1) with authenticatorData/clientDataJSON;
     *               validated via the WebAuthn verifier.
     * - P256:       Raw P-256 (secp256r1) signatures over the message, using an extractable
     *               public key provided on registration (`PubKey{x,y}`).
     * - P256NONKEY: P-256 signatures produced by non-extractable WebCrypto keys; message is
     *               prehashed on-chain with SHA-256 before verification to match the key’s usage.
     */
    enum KeyType {
        EOA,
        WEBAUTHN,
        P256,
        P256NONKEY
    }

    struct PubKey {
        bytes32 x;
        bytes32 y;
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
