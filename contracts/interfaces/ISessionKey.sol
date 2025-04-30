// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {SpendLimit} from "contracts/utils/SpendLimit.sol";

interface ISessionKey {
    /**
     * @notice Types of session keys supported by the contract
     * @param EOA Standard Ethereum account key
     * @param WEBAUTHN WebAuthn-based key (using P256 curve)
     */
    enum KeyType {
        EOA,
        WEBAUTHN
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
     * @notice Session key data structure containing permissions and limits
     * @param pubKey Public key information
     * @param isActive Whether the session key is currently active
     * @param validUntil Timestamp until which the key is valid
     * @param validAfter Timestamp after which the key becomes valid
     * @param limit Number of transactions allowed (0 for unlimited/master key)
     * @param masterSessionKey Whether this is a master session key with unlimited permissions
     * @param whitelisting Whether contract address whitelisting is enabled
     * @param whitelist Mapping of whitelisted contract addresses
     * @param spendTokenInfo Token spending limit information
     * @param allowedSelectors List of allowed function selectors
     * @param ethLimit Maximum amount of ETH that can be spent
     * @param whoRegistrated Address that registered this session key
     */
    struct SessionKey {
        PubKey pubKey;
        bool isActive;
        uint48 validUntil;
        uint48 validAfter;
        uint48 limit;
        bool masterSessionKey;
        bool whitelisting;
        mapping(address contractAddress => bool allowed) whitelist;
        SpendLimit.SpendTokenInfo spendTokenInfo;
        bytes4[] allowedSelectors;
        uint256 ethLimit;
        address whoRegistrated;
    }
}
