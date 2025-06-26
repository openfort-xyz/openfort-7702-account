/*
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░     ░░░░░░        ░░░         ░    ░░░░░   ░        ░░░░░░     ░░░░░░        ░░░░░           ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
▒▒▒   ▒▒▒▒   ▒▒▒   ▒▒▒▒   ▒   ▒▒▒▒▒▒▒  ▒   ▒▒▒   ▒   ▒▒▒▒▒▒▒▒▒   ▒▒▒▒   ▒▒▒   ▒▒▒▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒      ▒   ▒      ▒   ▒▒▒▒▒   ▒▒▒▒▒▒▒   ▒  ▒▒▒
▒   ▒▒▒▒▒▒▒▒   ▒   ▒▒▒▒   ▒   ▒▒▒▒▒▒▒   ▒   ▒▒   ▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒   ▒   ▒▒▒▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒   ▒▒▒▒   ▒▒   ▒▒▒  ▒▒▒▒▒   
▓   ▓▓▓▓▓▓▓▓   ▓        ▓▓▓       ▓▓▓   ▓▓   ▓   ▓       ▓▓▓   ▓▓▓▓▓▓▓▓   ▓  ▓   ▓▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓   ▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓
▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓  ▓   ▓   ▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓   ▓▓▓▓▓▓   ▓▓▓▓   ▓▓▓▓
▓▓▓   ▓▓▓▓▓   ▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓▓  ▓  ▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓   ▓▓   ▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓   ▓▓▓▓   ▓▓▓   ▓▓▓▓▓▓
█████     ██████   ████████         █   ██████   █   ███████████     ██████   ██████   █████   █████████   ████████   ████████    █████         █
█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
 */

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {KeyHashLib} from "src/libs/KeyHashLib.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {BaseOPF7702} from "src/core/BaseOPF7702.sol";
import {ValidationLib} from "src/libs/ValidationLib.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";

/// @title KeysManager
/// @author Openfort@0xkoiner
/// @notice Manages registration, revocation, and querying of keys (WebAuthn/P256/EOA) with spending limits and whitelisting support.
/// @dev Inherits BaseOPF7702 for account abstraction, IKey interface, and SpendLimit for token/ETH limits.
abstract contract KeysManager is BaseOPF7702, IKey, SpendLimit {
    using KeyHashLib for Key;
    using ValidationLib for *;

    // =============================================================
    //                          CONSTANTS
    // =============================================================

    /// @notice Maximum number of allowed function selectors per key
    uint256 internal constant MAX_SELECTORS = 10;
    /// @notice “Burn” address used as placeholder
    address internal constant DEAD_ADDRESS = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;

    // =============================================================
    //                          STATE VARIABLES
    // =============================================================

    /// @notice Incremental ID for WebAuthn/P256/P256NONKEY keys
    /// @dev Id = 0 always saved for MasterKey (Admin)
    uint256 public id;

    /// @notice Mapping from key ID to Key struct (WebAuthn/P256/P256NONKEY)
    mapping(uint256 => Key) public idKeys;
    /// @notice Mapping from hashed public key to Key struct (WebAuthn/P256/P256NONKEY)
    mapping(bytes32 => KeyData) public keys;
    /// @notice Tracks used challenges (to prevent replay) in WebAuthn
    mapping(bytes32 => bool) public usedChallenges;

    // =============================================================
    //                 PUBLIC / EXTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice Registers a new  key with specified permissions and limits.
     * @dev Only callable by ADMIN_ROLE via `_requireForExecute()`. Supports both WebAuthn/P256/P256NONKEY and EOA key types.
     *      - For WebAuthn/P256/P256NONKEY, computes `keyId = keccak256(pubKey.x, pubKey.y)`.
     *      - For EOA, uses `eoaAddress` as `keyId`.
     *      Requires `_validUntil > block.timestamp`, `_validAfter ≤ _validUntil`, and that the key is not active.
     *      Emits `KeyRegistrated(keyId)`.
     *
     * @param _key             Struct containing key information (PubKey or EOA).
     * @param _keyData KeyReg data structure containing permissions and limits
     */
    function registerKey(Key calldata _key, KeyReg calldata _keyData) public {
        _requireForExecute();
        // Must have limit checks to prevent register masterKey
        _keyData.limit.ensureLimit();

        // Validate timestamps
        ValidationLib.ensureValidTimestamps(_keyData.validAfter, _keyData.validUntil);

        bytes32 keyId = _key.computeKeyId();

        KeyData storage sKey = keys[keyId];

        if (sKey.isActive) {
            revert IKeysManager.KeyManager__KeyRegistered();
        }

        _addKey(sKey, _key, _keyData);

        // Store Key struct by ID and increment
        idKeys[id] = _key;
        unchecked {
            id++;
        }

        emit IKeysManager.KeyRegistrated(keyId);
    }

    /**
     * @notice Revokes a specific key, marking it inactive and clearing its parameters.
     * @dev Only callable by ADMIN_ROLE via `_requireForExecute()`. Works for both WebAuthn/P256/P256NONKEY and EOA keys.
     *      Emits `KeyRevoked(keyId)`.
     *
     * @param _key Struct containing key information to revoke:
     *             • For WebAuthn/P256/P256NONKEY: uses `pubKey` to compute `keyId`.
     *             • For EOA: uses `eoaAddress` (must be non‐zero).
     */
    function revokeKey(Key calldata _key) external {
        _requireForExecute();

        bytes32 keyId = _key.computeKeyId();

        KeyData storage sKey = keys[keyId];
        _revokeKey(sKey);
        emit IKeysManager.KeyRevoked(keyId);
    }

    /**
     * @notice Revokes all registered keys (WebAuthn/P256/P256NONKEY and EOA).
     * @dev Only callable by ADMIN_ROLE via `_requireForExecute()`. Iterates through all IDs and revokes each.
     *      Emits `KeyRevoked(keyId)` for each.
     */
    function revokeAllKeys() external {
        _requireForExecute();
        /// @dev i = 1 --> id = 0 always saved for MasterKey (Admin)
        // Revoke WebAuthn/P256/P256NONKEY/EOA keys
        for (uint256 i = 1; i < id;) {
            Key memory k = idKeys[i];

            bytes32 keyId = k.computeKeyId();

            KeyData storage sKey = keys[keyId];

            if (!sKey.isActive) {
                unchecked {
                    ++i;
                }
                continue;
            }

            _revokeKey(sKey);
            emit IKeysManager.KeyRevoked(keyId);
            unchecked {
                ++i;
            }
        }
    }

    // =============================================================
    //                 INTERNAL / PRIVATE HELPERS
    // =============================================================

    /**
     * @notice Internal helper to configure a newly registered key’s parameters.
     * @dev Sets common fields on `KeyData` storage, enforces whitelisting and spend‐limit logic.
     *      Only called from `registerKey`.
     *
     * @param sKey             Storage reference to the `KeyData` being populated.
     * @param _key             Struct containing key information (PubKey or EOA).
     * @param _keyData KeyReg data structure containing permissions and limits
     */
    function _addKey(KeyData storage sKey, Key memory _key, KeyReg memory _keyData) internal {
        sKey.pubKey = _key.pubKey;
        sKey.isActive = true;
        sKey.validUntil = _keyData.validUntil;
        sKey.validAfter = _keyData.validAfter;
        sKey.limit = _keyData.limit;
        sKey.masterKey = (_keyData.limit == 0);

        // Only enforce limits if _limit > 0
        if (_keyData.limit > 0) {
            sKey.whitelisting = _keyData.whitelisting;
            sKey.ethLimit = _keyData.ethLimit;

            // Whitelist contract and token if requested
            if (_keyData.whitelisting) {
                _keyData.contractAddress.ensureNotZero();
                // Add the contract itself
                sKey.whitelist[_keyData.contractAddress] = true;

                // Validate token address
                address tokenAddr = _keyData.spendTokenInfo.token;
                tokenAddr.ensureNotZero();
                sKey.whitelist[tokenAddr] = true;

                uint256 selCount = _keyData.allowedSelectors.length;
                selCount.ensureSelectorsLen();
                for (uint256 i = 0; i < selCount;) {
                    sKey.allowedSelectors.push(_keyData.allowedSelectors[i]);
                    unchecked {
                        ++i;
                    }
                }
            } else {
                // Even if not whitelisting contracts, we must still validate token
                _keyData.spendTokenInfo.token.ensureNotZero();
            }

            // Configure spendTokenInfo regardless of whitelisting
            sKey.spendTokenInfo.token = _keyData.spendTokenInfo.token;
            sKey.spendTokenInfo.limit = _keyData.spendTokenInfo.limit;
        }
    }

    /**
     * @notice Internal helper to revoke a key’s data.
     * @dev Clears all `KeyData` struct fields, marks it inactive, resets limits and whitelists.
     *
     * @param sKey Storage reference to the `KeyData` being revoked.
     */
    function _revokeKey(KeyData storage sKey) internal {
        if (!sKey.isActive) {
            revert IKeysManager.KeyManager__KeyInactive();
        }
        sKey.isActive = false;
        sKey.validUntil = 0;
        sKey.validAfter = 0;
        sKey.limit = 0;
        sKey.masterKey = false;
        sKey.ethLimit = 0;

        delete sKey.allowedSelectors;
        delete sKey.spendTokenInfo;
    }

    // =============================================================
    //                   PUBLIC / EXTERNAL GETTERS
    // =============================================================

    /**
     * @notice Retrieves registration info for a given key ID.
     * @param _id       Identifier (index) of the key to query.
     * @return keyType       The type of the key that was registered.
     * @return isActive      Whether the key is currently active.
     */
    function getKeyRegistrationInfo(uint256 _id)
        external
        view
        returns (KeyType keyType, bool isActive)
    {
        Key memory k = idKeys[_id];
        bytes32 keyId = k.computeKeyId();

        KeyData storage sKey = keys[keyId];

        return (k.keyType, sKey.isActive);
    }

    /**
     * @notice Retrieves the `KeyData` struct stored at a given ID.
     * @param _id       Identifier index for the key to retrieve.
     * @return A `KeyData` struct containing key type and relevant public key or EOA address.
     */
    function getKeyById(uint256 _id) public view returns (Key memory) {
        return idKeys[_id];
    }

    /**
     * @notice Retrieves key metadata for a WebAuthn/P256/P256NONKEY key by its hash.
     * @param _keyHash  Keccak256 hash of public key coordinates (x, y).
     * @return isActive   Whether the key is active.
     * @return validUntil UNIX timestamp until which the key is valid.
     * @return validAfter UNIX timestamp after which the key is valid.
     * @return limit      Remaining number of transactions allowed.
     */
    function getKeyData(bytes32 _keyHash)
        external
        view
        returns (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit)
    {
        KeyData storage sKey = keys[_keyHash];
        return (sKey.isActive, sKey.validUntil, sKey.validAfter, sKey.limit);
    }

    /**
     * @notice Checks if a WebAuthn/P256/P256NONKEY key is active.
     * @param keyHash  Keccak256 hash of public key coordinates (x, y).
     * @return True if the key is active; false otherwise.
     */
    function isKeyActive(bytes32 keyHash) external view returns (bool) {
        return keys[keyHash].isActive;
    }

    /**
     * @notice Encodes WebAuthn signature parameters into a bytes payload for submission.
     * @param requireUserVerification Whether user verification is required.
     * @param authenticatorData       Raw authenticator data from WebAuthn device.
     * @param clientDataJSON          JSON‐formatted client data from WebAuthn challenge.
     * @param challengeIndex          Index in clientDataJSON for the challenge field.
     * @param typeIndex               Index in clientDataJSON for the type field.
     * @param r                       R component of the ECDSA signature (32 bytes).
     * @param s                       S component of the ECDSA signature (32 bytes).
     * @param pubKey                  Public key (x, y) used for verifying signature.
     * @return ABI‐encoded payload as:
     *         KeyType.WEBAUTHN, requireUserVerification, authenticatorData, clientDataJSON,
     *         challengeIndex, typeIndex, r, s, pubKey.
     */
    function encodeWebAuthnSignature(
        bool requireUserVerification,
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint256 challengeIndex,
        uint256 typeIndex,
        bytes32 r,
        bytes32 s,
        PubKey memory pubKey
    ) external pure returns (bytes memory) {
        return abi.encode(
            KeyType.WEBAUTHN,
            requireUserVerification,
            authenticatorData,
            clientDataJSON,
            challengeIndex,
            typeIndex,
            r,
            s,
            pubKey
        );
    }

    /**
     * @notice Encodes a P-256 signature payload (KeyType.P256 || KeyType.P256NONKEY).
     * @param r       R component of the P-256 signature (32 bytes).
     * @param s       S component of the P-256 signature (32 bytes).
     * @param pubKey  Public key (x, y) used for signing.
     * @param _keyType  KeyType of key.
     * @return ABI‐encoded payload as: KeyType.P256, abi.encode(r, s, pubKey).
     */
    function encodeP256Signature(bytes32 r, bytes32 s, PubKey memory pubKey, KeyType _keyType)
        external
        pure
        returns (bytes memory)
    {
        bytes memory inner = abi.encode(r, s, pubKey);
        return abi.encode(_keyType, inner);
    }

    /**
     * @notice Encodes an EOA signature for KeyType.EOA.
     * @param _signature Raw ECDSA signature bytes over the UserOperation digest.
     * @return ABI‐encoded payload as: KeyType.EOA, _signature.
     */
    function encodeEOASignature(bytes calldata _signature) external pure returns (bytes memory) {
        return abi.encode(KeyType.EOA, _signature);
    }
}
