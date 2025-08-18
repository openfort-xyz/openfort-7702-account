// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {SpendLimit} from "src/utils/SpendLimit.sol";

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

    /**
     * @notice Public key structure for P256 curve used in WebAuthn
     * @param x X-coordinate of the public key
     * @param y Y-coordinate of the public key
     */
    struct PubKey {
        bytes32 x;
        bytes32 y;
    }

    /**
     * @notice Key structure containing all necessary key information
     * @param pubKey Public key information for WebAuthn keys
     * @param eoaAddress EOA address for standard Ethereum accounts
     * @param keyType Type of the key (EOA or WebAuthn)
     */
    struct Key {
        PubKey pubKey;
        address eoaAddress;
        KeyType keyType;
    }

    /**
     * @notice Key data structure containing permissions and limits
     * @param pubKey Public key information
     * @param isActive Whether the key is currently active
     * @param validUntil Timestamp until which the key is valid
     * @param validAfter Timestamp after which the key becomes valid
     * @param limit Number of transactions allowed (0 for unlimited/master key)
     * @param masterKey Whether this is a master key with unlimited permissions
     * @param whitelisting Whether contract address whitelisting is enabled
     * @param whitelist Mapping of whitelisted contract addresses
     * @param spendTokenInfo Token spending limit information
     * @param allowedSelectors List of allowed function selectors
     * @param ethLimit Maximum amount of ETH that can be spent
     */
    struct KeyData {
        PubKey pubKey;
        bool isActive;
        uint48 validUntil;
        uint48 validAfter;
        uint48 limit;
        bool masterKey;
        bool whitelisting;
        mapping(address contractAddress => bool allowed) whitelist;
        SpendLimit.SpendTokenInfo spendTokenInfo;
        bytes4[] allowedSelectors;
        uint256 ethLimit;
    }

    /**
     * @notice KeyReg data structure containing permissions and limits
     * @param validUntil Timestamp until which the key is valid
     * @param validAfter Timestamp after which the key becomes valid
     * @param limit Number of transactions allowed (0 for unlimited/master key)
     * @param whitelisting Whether contract address whitelisting is enabled
     * @param contractAddress Whitelisted contract addresses
     * @param spendTokenInfo Token spending limit information
     * @param allowedSelectors List of allowed function selectors
     * @param ethLimit Maximum amount of ETH that can be spent
     */
    struct KeyReg {
        uint48 validUntil;
        uint48 validAfter;
        uint48 limit;
        bool whitelisting;
        address contractAddress;
        SpendLimit.SpendTokenInfo spendTokenInfo;
        bytes4[] allowedSelectors;
        uint256 ethLimit;
    }
}
