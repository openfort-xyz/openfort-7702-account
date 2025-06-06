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
import {ISessionkey} from "src/interfaces/ISessionkey.sol";

/// @title KeysManager
/// @author Openfort@0xkoiner
/// @notice Manages registration, revocation, and querying of session keys (WebAuthn/P256/EOA) with spending limits and whitelisting support.
/// @dev Inherits BaseOPF7702 for account abstraction, ISessionkey interface, and SpendLimit for token/ETH limits.
abstract contract KeysManager is BaseOPF7702, ISessionkey, SpendLimit {
    // =============================================================
    //                            ERRORS
    // =============================================================

    /// @notice Thrown when a timestamp provided for session key validity is invalid
    error SessionKeyManager__InvalidTimestamp();
    /// @notice Thrown when registration does not include any usage or spend limits
    error SessionKeyManager__MustIncludeLimits();
    /// @notice Thrown when an address parameter expected to be non-zero is zero
    error SessionKeyManager__AddressCantBeZero();
    /// @notice Thrown when attempting to revoke or query a session key that is already inactive
    error SessionKeyManager__SessionKeyInactive();
    /// @notice Thrown when the provided selectors list length exceeds MAX_SELECTORS
    error SessionKeyManager__SelectorsListTooBig();
    /// @notice Thrown when attempting to register a session key that is already active
    error SessionKeyManager__SessionKeyRegistered();

    // =============================================================
    //                          CONSTANTS
    // =============================================================

    /// @notice Maximum number of allowed function selectors per session key
    uint256 public constant MAX_SELECTORS = 10;
    /// @notice “Burn” address used as placeholder
    address public constant DEAD_ADDRESS = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;

    // =============================================================
    //                          STATE VARIABLES
    // =============================================================

    /// @notice Incremental ID for WebAuthn/P256/P256NONKEY session keys
    /// @dev Id = 0 always saved for MasterKey (Admin)
    uint256 public id;
    /// @notice Incremental ID for EOA session keys
    /// @dev idEOA = 0 always saved for MasterKey (Admin)
    uint256 public idEOA;

    /// @notice Mapping from session key ID to Key struct (WebAuthn/P256/P256NONKEY)
    mapping(uint256 => Key) public idSessionKeys;
    /// @notice Mapping from hashed public key to SessionKey struct (WebAuthn/P256/P256NONKEY)
    mapping(bytes32 => SessionKey) public sessionKeys;
    /// @notice Tracks used challenges (to prevent replay) in WebAuthn
    mapping(bytes32 => bool) public usedChallenges;

    /// @notice Mapping from EOA session key ID to Key struct
    mapping(uint256 => Key) public idSessionKeysEOA;
    /// @notice Mapping from EOA address to SessionKey struct
    mapping(address => SessionKey) public sessionKeysEOA;

    // =============================================================
    //                             EVENTS
    // =============================================================

    /// @notice Emitted when a session key is revoked
    /// @param sessionKey The identifier (hash or address‐derived hash) of the revoked key
    event SessionKeyRevoked(bytes32 indexed sessionKey);
    /// @notice Emitted when a new session key is registered
    /// @param sessionKey The identifier (hash or address‐derived hash) of the newly registered key
    event SessionKeyRegistrated(bytes32 indexed sessionKey);

    // =============================================================
    //                 PUBLIC / EXTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice Registers a new session key with specified permissions and limits.
     * @dev Only callable by ADMIN_ROLE via `_requireForExecute()`. Supports both WebAuthn/P256/P256NONKEY and EOA key types.
     *      - For WebAuthn/P256/P256NONKEY, computes `keyId = keccak256(pubKey.x, pubKey.y)`.
     *      - For EOA, uses `eoaAddress` as `keyId`.
     *      Requires `_validUntil > block.timestamp`, `_validAfter ≤ _validUntil`, and that the key is not active.
     *      Emits `SessionKeyRegistrated(keyId)`.
     *
     * @param _key             Struct containing key information:
     *                         • `keyType`: one of {WEBAUTHN, P256, P256NONKEY, EOA}.
     *                         • For WebAuthn/P256/P256NONKEY: `pubKey` must be set.
     *                         • For EOA: `eoaAddress` must be non‐zero.
     * @param _validUntil      UNIX timestamp after which this session key is invalid.
     * @param _validAfter      UNIX timestamp before which this session key is not valid.
     * @param _limit           Maximum number of transactions allowed.
     * @param _whitelisting    If true, restrict calls to whitelisted contracts/tokens.
     * @param _contractAddress Initial contract to whitelist (ignored if !_whitelisting).
     * @param _spendTokenInfo  Struct specifying ERC‐20 token spending limit:
     *                         • `token`: ERC‐20 address (non‐zero if `_limit > 0`).
     *                         • `limit`: token amount allowed.
     * @param _allowedSelectors Array of allowed function selectors (length ≤ MAX_SELECTORS).
     * @param _ethLimit        Maximum ETH (wei) this session key can spend.
     */
    function registerSessionKey(
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
        if (_limit == 0) revert SessionKeyManager__MustIncludeLimits();

        // Validate timestamps
        if (_validUntil <= block.timestamp || _validAfter > _validUntil) {
            revert SessionKeyManager__InvalidTimestamp();
        }

        KeyType kt = _key.keyType;

        // WebAuthn / P256 / P256NONKEY path
        if (kt == KeyType.WEBAUTHN || kt == KeyType.P256 || kt == KeyType.P256NONKEY) {
            bytes32 keyId = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
            SessionKey storage sKey = sessionKeys[keyId];

            if (sKey.isActive) {
                revert SessionKeyManager__SessionKeyRegistered();
            }

            _addSessionKey(
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
            idSessionKeys[id] = _key;
            unchecked {
                id++;
            }

            emit SessionKeyRegistrated(keyId);

            // EOA path
        } else if (kt == KeyType.EOA) {
            address eoa = _key.eoaAddress;
            if (eoa == address(0)) {
                revert SessionKeyManager__AddressCantBeZero();
            }
            SessionKey storage sKey = sessionKeysEOA[eoa];

            if (sKey.isActive) {
                revert SessionKeyManager__SessionKeyRegistered();
            }

            _addSessionKey(
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

            idSessionKeysEOA[idEOA] = _key;
            unchecked {
                idEOA++;
            }

            emit SessionKeyRegistrated(keccak256(abi.encodePacked(eoa)));
        }
    }

    /**
     * @notice Revokes a specific session key, marking it inactive and clearing its parameters.
     * @dev Only callable by ADMIN_ROLE via `_requireForExecute()`. Works for both WebAuthn/P256/P256NONKEY and EOA keys.
     *      Emits `SessionKeyRevoked(keyId)`.
     *
     * @param _key Struct containing key information to revoke:
     *             • For WebAuthn/P256/P256NONKEY: uses `pubKey` to compute `keyId`.
     *             • For EOA: uses `eoaAddress` (must be non‐zero).
     */
    function revokeSessionKey(Key calldata _key) external {
        _requireForExecute();

        KeyType kt = _key.keyType;

        if (kt == KeyType.WEBAUTHN || kt == KeyType.P256 || kt == KeyType.P256NONKEY) {
            bytes32 keyId = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
            SessionKey storage sKey = sessionKeys[keyId];
            _revokeSessionKey(sKey);
            emit SessionKeyRevoked(keyId);
        } else if (kt == KeyType.EOA) {
            address eoa = _key.eoaAddress;
            if (eoa == address(0)) {
                revert SessionKeyManager__AddressCantBeZero();
            }
            SessionKey storage sKey = sessionKeysEOA[eoa];
            _revokeSessionKey(sKey);
            emit SessionKeyRevoked(keccak256(abi.encodePacked(eoa)));
        }
    }

    /**
     * @notice Revokes all registered session keys (WebAuthn/P256/P256NONKEY and EOA).
     * @dev Only callable by ADMIN_ROLE via `_requireForExecute()`. Iterates through all IDs and revokes each.
     *      Emits `SessionKeyRevoked(keyId)` for each.
     */
    function revokeAllSessionKeys() external {
        _requireForExecute();
        /// @dev i = 1 --> id = 0 always saved for MasterKey (Admin)
        // Revoke WebAuthn/P256/P256NONKEY keys
        for (uint256 i = 1; i < id;) {
            Key memory k = idSessionKeys[i];
            KeyType kt = k.keyType;
            if (kt == KeyType.WEBAUTHN || kt == KeyType.P256 || kt == KeyType.P256NONKEY) {
                bytes32 keyId = keccak256(abi.encodePacked(k.pubKey.x, k.pubKey.y));
                SessionKey storage sKey = sessionKeys[keyId];
                _revokeSessionKey(sKey);
                emit SessionKeyRevoked(keyId);
            }
            unchecked {
                ++i;
            }
        }

        /// @dev i = j --> idEOA = 0 always saved for MasterKey (Admin)
        // Revoke EOA keys
        for (uint256 j = 1; j < idEOA;) {
            Key memory k = idSessionKeysEOA[j];
            if (k.keyType == KeyType.EOA && k.eoaAddress != address(0)) {
                bytes32 eoaId = keccak256(abi.encodePacked(k.eoaAddress));
                SessionKey storage sKey = sessionKeysEOA[k.eoaAddress];
                _revokeSessionKey(sKey);
                emit SessionKeyRevoked(eoaId);
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
     * @notice Internal helper to configure a newly registered session key’s parameters.
     * @dev Sets common fields on `SessionKey` storage, enforces whitelisting and spend‐limit logic.
     *      Only called from `registerSessionKey`.
     *
     * @param sKey             Storage reference to the `SessionKey` being populated.
     * @param _key             Struct containing key information (PubKey or EOA).
     * @param _validUntil      UNIX timestamp after which the key is invalid.
     * @param _validAfter      UNIX timestamp before which the key is not valid.
     * @param _limit           Maximum number of transactions (0 = unlimited/master).
     * @param _whitelisting    If true, enable contract and token whitelisting.
     * @param _contractAddress Initial contract to whitelist (non‐zero if whitelisting).
     * @param _spendTokenInfo  Struct for ERC‐20 token spending limit (`token` must be non‐zero if `_limit > 0`).
     * @param _allowedSelectors Array of allowed function selectors (length ≤ MAX_SELECTORS).
     * @param _ethLimit        Maximum ETH (wei) this session key can send.
     */
    function _addSessionKey(
        SessionKey storage sKey,
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
        sKey.masterSessionKey = (_limit == 0);
        sKey.whoRegistrated = address(this);

        // Only enforce limits if _limit > 0
        if (_limit > 0) {
            sKey.whitelisting = _whitelisting;
            sKey.ethLimit = _ethLimit;

            // Whitelist contract and token if requested
            if (_whitelisting) {
                if (_contractAddress == address(0)) {
                    revert SessionKeyManager__AddressCantBeZero();
                }
                // Add the contract itself
                sKey.whitelist[_contractAddress] = true;

                // Validate token address
                address tokenAddr = _spendTokenInfo.token;
                if (tokenAddr == address(0)) {
                    revert SessionKeyManager__AddressCantBeZero();
                }
                sKey.whitelist[tokenAddr] = true;

                uint256 selCount = _allowedSelectors.length;
                if (selCount > MAX_SELECTORS) {
                    revert SessionKeyManager__SelectorsListTooBig();
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
                    revert SessionKeyManager__AddressCantBeZero();
                }
            }

            // Configure spendTokenInfo regardless of whitelisting
            sKey.spendTokenInfo.token = _spendTokenInfo.token;
            sKey.spendTokenInfo.limit = _spendTokenInfo.limit;
        }
    }

    /**
     * @notice Internal helper to revoke a session key’s data.
     * @dev Clears all `SessionKey` struct fields, marks it inactive, resets limits and whitelists.
     *
     * @param sKey Storage reference to the `SessionKey` being revoked.
     */
    function _revokeSessionKey(SessionKey storage sKey) internal {
        if (!sKey.isActive) {
            revert SessionKeyManager__SessionKeyInactive();
        }
        sKey.isActive = false;
        sKey.validUntil = 0;
        sKey.validAfter = 0;
        sKey.limit = 0;
        sKey.masterSessionKey = false;
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
            Key memory k = idSessionKeys[_id];
            bytes32 keyId = keccak256(abi.encodePacked(k.pubKey.x, k.pubKey.y));
            SessionKey storage sKey = sessionKeys[keyId];
            return (k.keyType, sKey.whoRegistrated, sKey.isActive);
        } else {
            Key memory k = idSessionKeysEOA[_id];
            SessionKey storage sKey = sessionKeysEOA[k.eoaAddress];
            return (k.keyType, sKey.whoRegistrated, sKey.isActive);
        }
    }

    /**
     * @notice Retrieves the `Key` struct stored at a given ID.
     * @param _id       Identifier index for the key to retrieve.
     * @param _keyType  Enum indicating which mapping to use (WEBAUTHN/P256/P256NONKEY vs. EOA).
     * @return A `Key` struct containing key type and relevant public key or EOA address.
     */
    function getKeyById(uint256 _id, KeyType _keyType) public view returns (Key memory) {
        if (
            _keyType == KeyType.WEBAUTHN || _keyType == KeyType.P256
                || _keyType == KeyType.P256NONKEY
        ) {
            return idSessionKeys[_id];
        } else {
            return idSessionKeysEOA[_id];
        }
    }

    /**
     * @notice Retrieves session key metadata for a WebAuthn/P256/P256NONKEY key by its hash.
     * @param _keyHash  Keccak256 hash of public key coordinates (x, y).
     * @return isActive   Whether the session key is active.
     * @return validUntil UNIX timestamp until which the key is valid.
     * @return validAfter UNIX timestamp after which the key is valid.
     * @return limit      Remaining number of transactions allowed.
     */
    function getSessionKeyData(bytes32 _keyHash)
        external
        view
        returns (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit)
    {
        SessionKey storage sKey = sessionKeys[_keyHash];
        return (sKey.isActive, sKey.validUntil, sKey.validAfter, sKey.limit);
    }

    /**
     * @notice Retrieves session key metadata for an EOA key by its address.
     * @param _key  EOA address corresponding to the session key.
     * @return isActive   Whether the session key is active.
     * @return validUntil UNIX timestamp until which the key is valid.
     * @return validAfter UNIX timestamp after which the key is valid.
     * @return limit      Remaining number of transactions allowed.
     */
    function getSessionKeyData(address _key)
        external
        view
        returns (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit)
    {
        SessionKey storage sKey = sessionKeysEOA[_key];
        return (sKey.isActive, sKey.validUntil, sKey.validAfter, sKey.limit);
    }

    /**
     * @notice Checks if an EOA session key is active.
     * @param eoaKey  EOA address to check.
     * @return True if the session key is active; false otherwise.
     */
    function isSessionKeyActive(address eoaKey) external view returns (bool) {
        return sessionKeysEOA[eoaKey].isActive;
    }

    /**
     * @notice Checks if a WebAuthn/P256/P256NONKEY session key is active.
     * @param keyHash  Keccak256 hash of public key coordinates (x, y).
     * @return True if the session key is active; false otherwise.
     */
    function isSessionKeyActive(bytes32 keyHash) external view returns (bool) {
        return sessionKeys[keyHash].isActive;
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