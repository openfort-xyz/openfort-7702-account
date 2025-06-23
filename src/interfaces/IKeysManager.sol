// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";

/// @title IKeysManager
/// @notice Interface for `KeysManager`, which handles registration, revocation, and querying of keys (WebAuthn/P256/EOA) with spending limits and whitelisting support.
/// @dev Declares all externally‐visible functions, events, state getters, and errors.
///      Note: KeyData structs contain mappings, so individual field getters or composite “getKeyData” functions are exposed instead of returning the full struct.
interface IKeysManager is IKey {
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
    //                             EVENTS
    // =============================================================

    /// @notice Emitted when a key is revoked
    /// @param key The identifier (hash or address‐derived hash) of the revoked key
    event KeyRevoked(bytes32 indexed key);
    /// @notice Emitted when a new key is registered
    /// @param key The identifier (hash or address‐derived hash) of the newly registered key
    event KeyRegistrated(bytes32 indexed key);

    // =============================================================
    //                          STATE GETTERS
    // =============================================================

    /// @notice Incremental ID for WebAuthn/P256/P256NONKEY keys.
    function id() external view returns (uint256);

    /// @notice Retrieves the `Key` struct for a given WebAuthn/P256/P256NONKEY key ID.
    /// @param _id Identifier of the key.
    /// @return The stored `Key` (keyType, pubKey, eoaAddress).
    function idKeys(uint256 _id) external view returns (IKey.Key memory);

    /// @notice Checks whether a given WebAuthn challenge (by hash) has been used already.
    /// @param _challengeHash Keccak256 hash of a WebAuthn challenge.
    /// @return `true` if the challenge has been used; `false` otherwise.
    function usedChallenges(bytes32 _challengeHash) external view returns (bool);

    // =============================================================
    //                 EXTERNAL / PUBLIC FUNCTIONS
    // =============================================================

    /**
     * @notice Registers a new key with specified permissions and limits.
     * @dev Only callable by ADMIN_ROLE via `_requireForExecute()`.
     *      Supports WebAuthn/P256/P256NONKEY and EOA keys.
     *      Emits `KeyRegistrated(keyId)`.
     */
    function registerKey(IKey.Key calldata _key, KeyReg calldata _keyData) external;

    /**
     * @notice Revokes a specific key, marking it inactive and clearing its parameters.
     * @dev Only callable by ADMIN_ROLE via `_requireForExecute()`.
     *      Emits `KeyRevoked(keyId)`.
     */
    function revokeKey(IKey.Key calldata _key) external;

    /**
     * @notice Revokes all registered keys.
     * @dev Only callable by ADMIN_ROLE via `_requireForExecute()`.
     *      Emits `KeyRevoked(keyId)` per key.
     */
    function revokeAllKeys() external;

    /**
     * @notice Retrieves registration info for a given key ID.
     * @param _id       Identifier of the key to query.
     * @return keyType      The type of the key that was registered.
     * @return registeredBy Address that performed the registration.
     * @return isActive     Whether the key is currently active.
     */
    function getKeyRegistrationInfo(uint256 _id)
        external
        view
        returns (IKey.KeyType keyType, address registeredBy, bool isActive);

    /**
     * @notice Retrieves the `Key` struct stored at a given ID.
     * @param _id Identifier index for the key to retrieve.
     * @return The `Key` struct containing key type, public key, or EOA address.
     */
    function getKeyById(uint256 _id) external view returns (IKey.Key memory);

    /**
     * @notice Retrieves key metadata for a WebAuthn/P256/P256NONKEY key by its hash.
     * @param _keyHash Keccak256 hash of public key coordinates (x, y).
     * @return isActive   Whether the key is active.
     * @return validUntil UNIX timestamp until which the key is valid.
     * @return validAfter UNIX timestamp after which the key is valid.
     * @return limit      Remaining number of transactions allowed.
     */
    function getKeyData(bytes32 _keyHash)
        external
        view
        returns (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit);

    /**
     * @notice Checks if a WebAuthn/P256/P256NONKEY key is active.
     * @param keyHash Keccak256 hash of public key coordinates (x, y).
     * @return True if the key is active; false otherwise.
     */
    function isKeyActive(bytes32 keyHash) external view returns (bool);

    /**
     * @notice Encodes WebAuthn signature parameters into a bytes payload for submission.
     */
    function encodeWebAuthnSignature(
        bool requireUserVerification,
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint256 challengeIndex,
        uint256 typeIndex,
        bytes32 r,
        bytes32 s,
        IKey.PubKey memory pubKey
    ) external pure returns (bytes memory);

    /**
     * @notice Encodes a P-256 signature payload (KeyType.P256).
     */
    function encodeP256Signature(
        bytes32 r,
        bytes32 s,
        IKey.PubKey memory pubKey,
        IKey.KeyType _keyType
    ) external pure returns (bytes memory);

    /**
     * @notice Encodes an EOA signature for KeyType.EOA.
     */
    function encodeEOASignature(bytes calldata _signature) external pure returns (bytes memory);
}
