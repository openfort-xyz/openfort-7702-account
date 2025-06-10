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

import {SpendLimit} from "src/utils/SpendLimit.sol";
import {BaseOPF7702} from "src/core/BaseOPF7702.sol";
import {IKey} from "src/interfaces/IKey.sol";

/// @title KeysManager
/// @author Openfort@0xkoiner
/// @notice Manages registration, revocation, and querying of keys (WebAuthn/P256/EOA) with spending limits and whitelisting support.
/// @dev Inherits BaseOPF7702 for account abstraction, IKey interface, and SpendLimit for token/ETH limits.
abstract contract KeysManager is BaseOPF7702, IKey, SpendLimit {
    // =============================================================
    //                            ERRORS
    // =============================================================

    /// @notice Thrown when a timestamp provided for key validity is invalid
    error KeyManager__InvalidTimestamp();
    /// @notice Thrown when registration does not include any usage or spend limits
    error KeyManager__MustIncludeLimits();
    /// @notice Thrown when an address parameter expected to be non-zero is zero
    error KeyManager__AddressCantBeZero();
    /// @notice Thrown when attempting to revoke or query a key that is already inactive
    error KeyManager__KeyInactive();
    /// @notice Thrown when the provided selectors list length exceeds MAX_SELECTORS
    error KeyManager__SelectorsListTooBig();
    /// @notice Thrown when attempting to register a key that is already active
    error KeyManager__KeyRegistered();

    // =============================================================
    //                          CONSTANTS
    // =============================================================

    /// @notice Maximum number of allowed function selectors per key
    uint256 public constant MAX_SELECTORS = 10;
    /// @notice “Burn” address used as placeholder
    address public constant DEAD_ADDRESS = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;

    // =============================================================
    //                          STATE VARIABLES
    // =============================================================

    /// @notice Incremental ID for WebAuthn/P256/P256NONKEY keys
    /// @dev Id = 0 always saved for MasterKey (Admin)
    uint256 public id;
    /// @notice Incremental ID for EOA keys
    /// @dev idEOA = 0 always saved for MasterKey (Admin)
    uint256 public idEOA;

    /// @notice Mapping from key ID to Key struct (WebAuthn/P256/P256NONKEY)
    mapping(uint256 => Key) public idKeys;
    /// @notice Mapping from hashed public key to Key struct (WebAuthn/P256/P256NONKEY)
    mapping(bytes32 => KeyData) public keys;
    /// @notice Tracks used challenges (to prevent replay) in WebAuthn
    mapping(bytes32 => bool) public usedChallenges;

    /// @notice Mapping from EOA key ID to Key struct
    mapping(uint256 => Key) public idKeysEOA;
    /// @notice Mapping from EOA address to Key struct
    mapping(address => KeyData) public keysEOA;

    // =============================================================
    //                             EVENTS
    // =============================================================

    /// @notice Emitted when a key is revoked
    /// @param Key The identifier (hash or address‐derived hash) of the revoked key
    event KeyRevoked(bytes32 indexed Key);
    /// @notice Emitted when a new key is registered
    /// @param Key The identifier (hash or address‐derived hash) of the newly registered key
    event KeyRegistrated(bytes32 indexed Key);

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
     * @param _key             Struct containing key information:
     *                         • `keyType`: one of {WEBAUTHN, P256, P256NONKEY, EOA}.
     *                         • For WebAuthn/P256/P256NONKEY: `pubKey` must be set.
     *                         • For EOA: `eoaAddress` must be non‐zero.
     * @param _validUntil      UNIX timestamp after which this key is invalid.
     * @param _validAfter      UNIX timestamp before which this key is not valid.
     * @param _limit           Maximum number of transactions allowed.
     * @param _whitelisting    If true, restrict calls to whitelisted contracts/tokens.
     * @param _contractAddress Initial contract to whitelist (ignored if !_whitelisting).
     * @param _spendTokenInfo  Struct specifying ERC‐20 token spending limit:
     *                         • `token`: ERC‐20 address (non‐zero if `_limit > 0`).
     *                         • `limit`: token amount allowed.
     * @param _allowedSelectors Array of allowed function selectors (length ≤ MAX_SELECTORS).
     * @param _ethLimit        Maximum ETH (wei) this key can spend.
     */
    function registerKey(
        Key calldata _key,
        uint48 _validUntil,
        uint48 _validAfter,
        uint48 _limit,
        bool _whitelisting,
        address _contractAddress,
        SpendTokenInfo calldata _spendTokenInfo,
        bytes4[] calldata _allowedSelectors,
        uint256 _ethLimit
    ) public {
        _requireForExecute();
        // Must have limit checks to prevent register masterKey
        if (_limit == 0) revert KeyManager__MustIncludeLimits();

        // Validate timestamps
        if (_validUntil <= block.timestamp || _validAfter > _validUntil) {
            revert KeyManager__InvalidTimestamp();
        }

        KeyType kt = _key.keyType;

        // WebAuthn / P256 / P256NONKEY path
        if (kt == KeyType.WEBAUTHN || kt == KeyType.P256 || kt == KeyType.P256NONKEY) {
            bytes32 keyId = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
            KeyData storage sKey = keys[keyId];

            if (sKey.isActive) {
                revert KeyManager__KeyRegistered();
            }

            _addKey(
                sKey,
                _key,
                _validUntil,
                _validAfter,
                _limit,
                _whitelisting,
                _contractAddress,
                _spendTokenInfo,
                _allowedSelectors,
                _ethLimit
            );

            // Store Key struct by ID and increment
            idKeys[id] = _key;
            unchecked {
                id++;
            }

            emit KeyRegistrated(keyId);

            // EOA path
        } else if (kt == KeyType.EOA) {
            address eoa = _key.eoaAddress;
            if (eoa == address(0)) {
                revert KeyManager__AddressCantBeZero();
            }
            KeyData storage sKey = keysEOA[eoa];

            if (sKey.isActive) {
                revert KeyManager__KeyRegistered();
            }

            _addKey(
                sKey,
                _key,
                _validUntil,
                _validAfter,
                _limit,
                _whitelisting,
                _contractAddress,
                _spendTokenInfo,
                _allowedSelectors,
                _ethLimit
            );

            idKeysEOA[idEOA] = _key;
            unchecked {
                idEOA++;
            }

            emit KeyRegistrated(keccak256(abi.encodePacked(eoa)));
        }
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
        // Todo: if masterKey? revert()? or user have to be resposable for execution.
        _requireForExecute();

        KeyType kt = _key.keyType;

        if (kt == KeyType.WEBAUTHN || kt == KeyType.P256 || kt == KeyType.P256NONKEY) {
            bytes32 keyId = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
            KeyData storage sKey = keys[keyId];
            _revokeKey(sKey);
            emit KeyRevoked(keyId);
        } else if (kt == KeyType.EOA) {
            address eoa = _key.eoaAddress;
            if (eoa == address(0)) {
                revert KeyManager__AddressCantBeZero();
            }
            KeyData storage sKey = keysEOA[eoa];
            _revokeKey(sKey);
            emit KeyRevoked(keccak256(abi.encodePacked(eoa)));
        }
    }

    /**
     * @notice Revokes all registered keys (WebAuthn/P256/P256NONKEY and EOA).
     * @dev Only callable by ADMIN_ROLE via `_requireForExecute()`. Iterates through all IDs and revokes each.
     *      Emits `KeyRevoked(keyId)` for each.
     */
    function revokeAllKeys() external {
        _requireForExecute();
        /// @dev i = 1 --> id = 0 always saved for MasterKey (Admin)
        // Revoke WebAuthn/P256/P256NONKEY keys
        for (uint256 i = 1; i < id;) {
            Key memory k = idKeys[i];
            KeyType kt = k.keyType;
            if (kt == KeyType.WEBAUTHN || kt == KeyType.P256 || kt == KeyType.P256NONKEY) {
                bytes32 keyId = keccak256(abi.encodePacked(k.pubKey.x, k.pubKey.y));
                KeyData storage sKey = keys[keyId];
                _revokeKey(sKey);
                emit KeyRevoked(keyId);
            }
            unchecked {
                ++i;
            }
        }

        /// @dev i = j --> idEOA = 0 always saved for MasterKey (Admin)
        // Revoke EOA keys
        for (uint256 j = 1; j < idEOA;) {
            Key memory k = idKeysEOA[j];
            if (k.keyType == KeyType.EOA && k.eoaAddress != address(0)) {
                bytes32 eoaId = keccak256(abi.encodePacked(k.eoaAddress));
                KeyData storage sKey = keysEOA[k.eoaAddress];
                _revokeKey(sKey);
                emit KeyRevoked(eoaId);
            }
            unchecked {
                ++j;
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
     * @param _validUntil      UNIX timestamp after which the key is invalid.
     * @param _validAfter      UNIX timestamp before which the key is not valid.
     * @param _limit           Maximum number of transactions (0 = unlimited/master).
     * @param _whitelisting    If true, enable contract and token whitelisting.
     * @param _contractAddress Initial contract to whitelist (non‐zero if whitelisting).
     * @param _spendTokenInfo  Struct for ERC‐20 token spending limit (`token` must be non‐zero if `_limit > 0`).
     * @param _allowedSelectors Array of allowed function selectors (length ≤ MAX_SELECTORS).
     * @param _ethLimit        Maximum ETH (wei) this key can send.
     */
    function _addKey(
        KeyData storage sKey,
        Key memory _key,
        uint48 _validUntil,
        uint48 _validAfter,
        uint48 _limit,
        bool _whitelisting,
        address _contractAddress,
        SpendTokenInfo memory _spendTokenInfo,
        bytes4[] memory _allowedSelectors,
        uint256 _ethLimit
    ) internal {
        sKey.pubKey = _key.pubKey;
        sKey.isActive = true;
        sKey.validUntil = _validUntil;
        sKey.validAfter = _validAfter;
        sKey.limit = _limit;
        sKey.masterKey = (_limit == 0);
        sKey.whoRegistrated = address(this);

        // Only enforce limits if _limit > 0
        if (_limit > 0) {
            sKey.whitelisting = _whitelisting;
            sKey.ethLimit = _ethLimit;

            // Whitelist contract and token if requested
            if (_whitelisting) {
                if (_contractAddress == address(0)) {
                    revert KeyManager__AddressCantBeZero();
                }
                // Add the contract itself
                sKey.whitelist[_contractAddress] = true;

                // Validate token address
                address tokenAddr = _spendTokenInfo.token;
                if (tokenAddr == address(0)) {
                    revert KeyManager__AddressCantBeZero();
                }
                sKey.whitelist[tokenAddr] = true;

                uint256 selCount = _allowedSelectors.length;
                if (selCount > MAX_SELECTORS) {
                    revert KeyManager__SelectorsListTooBig();
                }
                for (uint256 i = 0; i < selCount;) {
                    sKey.allowedSelectors.push(_allowedSelectors[i]);
                    unchecked {
                        ++i;
                    }
                }
            } else {
                // Even if not whitelisting contracts, we must still validate token
                if (_spendTokenInfo.token == address(0)) {
                    revert KeyManager__AddressCantBeZero();
                }
            }

            // Configure spendTokenInfo regardless of whitelisting
            sKey.spendTokenInfo.token = _spendTokenInfo.token;
            sKey.spendTokenInfo.limit = _spendTokenInfo.limit;
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
            revert KeyManager__KeyInactive();
        }
        sKey.isActive = false;
        sKey.validUntil = 0;
        sKey.validAfter = 0;
        sKey.limit = 0;
        sKey.masterKey = false;
        sKey.ethLimit = 0;
        sKey.whoRegistrated = address(0);

        sKey.spendTokenInfo.limit = 0;
        sKey.spendTokenInfo.token = address(0);

        delete sKey.allowedSelectors;
    }

    // =============================================================
    //                   PUBLIC / EXTERNAL GETTERS
    // =============================================================

    /**
     * @notice Retrieves registration info for a given key ID.
     * @param _id       Identifier (index) of the key to query.
     * @param _keyType  Enum indicating which key mapping to query (WEBAUTHN/P256/P256NONKEY vs. EOA).
     * @return keyType       The type of the key that was registered.
     * @return registeredBy  Address that performed the registration (should be this contract).
     * @return isActive      Whether the key is currently active.
     */
    function getKeyRegistrationInfo(uint256 _id, KeyType _keyType)
        external
        view
        returns (KeyType keyType, address registeredBy, bool isActive)
    {
        if (
            _keyType == KeyType.WEBAUTHN || _keyType == KeyType.P256
                || _keyType == KeyType.P256NONKEY
        ) {
            Key memory k = idKeys[_id];
            bytes32 keyId = keccak256(abi.encodePacked(k.pubKey.x, k.pubKey.y));
            KeyData storage sKey = keys[keyId];
            return (k.keyType, sKey.whoRegistrated, sKey.isActive);
        } else {
            Key memory k = idKeysEOA[_id];
            KeyData storage sKey = keysEOA[k.eoaAddress];
            return (k.keyType, sKey.whoRegistrated, sKey.isActive);
        }
    }

    /**
     * @notice Retrieves the `KeyData` struct stored at a given ID.
     * @param _id       Identifier index for the key to retrieve.
     * @param _keyType  Enum indicating which mapping to use (WEBAUTHN/P256/P256NONKEY vs. EOA).
     * @return A `KeyData` struct containing key type and relevant public key or EOA address.
     */
    function getKeyById(uint256 _id, KeyType _keyType) public view returns (Key memory) {
        if (
            _keyType == KeyType.WEBAUTHN || _keyType == KeyType.P256
                || _keyType == KeyType.P256NONKEY
        ) {
            return idKeys[_id];
        } else {
            return idKeysEOA[_id];
        }
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
     * @notice Retrieves key metadata for an EOA key by its address.
     * @param _key  EOA address corresponding to the key.
     * @return isActive   Whether the key is active.
     * @return validUntil UNIX timestamp until which the key is valid.
     * @return validAfter UNIX timestamp after which the key is valid.
     * @return limit      Remaining number of transactions allowed.
     */
    function getKeyData(address _key)
        external
        view
        returns (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit)
    {
        KeyData storage sKey = keysEOA[_key];
        return (sKey.isActive, sKey.validUntil, sKey.validAfter, sKey.limit);
    }

    /**
     * @notice Checks if an EOA key is active.
     * @param eoaKey  EOA address to check.
     * @return True if the key is active; false otherwise.
     */
    function isKeyActive(address eoaKey) external view returns (bool) {
        return keysEOA[eoaKey].isActive;
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
     * @notice Encodes a P-256 signature payload (KeyType.P256).
     * @param r       R component of the P-256 signature (32 bytes).
     * @param s       S component of the P-256 signature (32 bytes).
     * @param pubKey  Public key (x, y) used for signing.
     * @return ABI‐encoded payload as: KeyType.P256, abi.encode(r, s, pubKey).
     */
    function encodeP256Signature(bytes32 r, bytes32 s, PubKey memory pubKey)
        external
        pure
        returns (bytes memory)
    {
        bytes memory inner = abi.encode(r, s, pubKey);
        return abi.encode(KeyType.P256, inner);
    }

    /**
     * @notice Encodes a P-256 non-key signature payload (KeyType.P256NONKEY).
     * @param r       R component of the P-256 signature (32 bytes).
     * @param s       S component of the P-256 signature (32 bytes).
     * @param pubKey  Public key (x, y) used for signing.
     * @return ABI‐encoded payload as: KeyType.P256NONKEY, abi.encode(r, s, pubKey).
     */
    function encodeP256NonKeySignature(bytes32 r, bytes32 s, PubKey memory pubKey)
        external
        pure
        returns (bytes memory)
    {
        bytes memory inner = abi.encode(r, s, pubKey);
        return abi.encode(KeyType.P256NONKEY, inner);
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
