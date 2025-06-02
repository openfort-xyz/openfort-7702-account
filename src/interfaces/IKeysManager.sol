// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {SpendLimit} from "src/utils/SpendLimit.sol";
import {ISessionkey} from "src/interfaces/ISessionkey.sol";

/// @title IKeysManager
/// @notice Interface for `KeysManager`, which handles registration, revocation, and querying of session keys (WebAuthn/P256/EOA) with spending limits and whitelisting support.
/// @dev Declares all externally‐visible functions, events, state getters, constants, and errors.
///      Note: SessionKey structs contain mappings, so individual field getters or composite “getSessionKeyData” functions are exposed instead of returning the full struct.
interface IKeysManager is ISessionkey {
    // =============================================================
    //                          STATE GETTERS
    // =============================================================

    /// @notice Incremental ID for WebAuthn/P256/P256NONKEY session keys.
    function id() external view returns (uint256);

    /// @notice Incremental ID for EOA session keys.
    function idEOA() external view returns (uint256);

    /// @notice Retrieves the `Key` struct for a given WebAuthn/P256/P256NONKEY session key ID.
    /// @param _id Identifier of the key.
    /// @return The stored `Key` (keyType, pubKey, eoaAddress).
    function idSessionKeys(uint256 _id) external view returns (ISessionkey.Key memory);

    /// @notice Checks whether a given WebAuthn challenge (by hash) has been used already.
    /// @param _challengeHash Keccak256 hash of a WebAuthn challenge.
    /// @return `true` if the challenge has been used; `false` otherwise.
    function usedChallenges(bytes32 _challengeHash) external view returns (bool);

    /// @notice Retrieves the `Key` struct for a given EOA session key ID.
    /// @param _idEOA Identifier of the EOA key.
    /// @return The stored `Key` (keyType, pubKey, eoaAddress).
    function idSessionKeysEOA(uint256 _idEOA) external view returns (ISessionkey.Key memory);

    // =============================================================
    //                 EXTERNAL / PUBLIC FUNCTIONS
    // =============================================================

    /**
     * @notice Registers a new session key with specified permissions and limits.
     * @dev
     *   - Only callable by ADMIN_ROLE via `_requireForExecute()`.
     *   - Supports both WebAuthn/P256/P256NONKEY and EOA key types.
     *   - For WebAuthn/P256/P256NONKEY: computes `keyId = keccak256(pubKey.x, pubKey.y)`.
     *   - For EOA: uses `eoaAddress` as `keyId`.
     *   - Requires `_validUntil > block.timestamp` and `_validAfter ≤ _validUntil`.
     *   - Reverts with `SessionKeyManager__InvalidTimestamp` or `SessionKeyManager__SessionKeyRegistered` on failure.
     *   - Emits `SessionKeyRegistrated(keyId)` on success.
     *
     * @param _key             Struct containing key information:
     *                         • `keyType`: one of {WEBAUTHN, P256, P256NONKEY, EOA}.
     *                         • For WebAuthn/P256/P256NONKEY: `pubKey` must be set.
     *                         • For EOA: `eoaAddress` must be non-zero.
     * @param _validUntil      UNIX timestamp after which this session key is invalid.
     * @param _validAfter      UNIX timestamp before which this session key is not valid.
     * @param _limit           Maximum number of transactions allowed (0 = unlimited/master).
     * @param _whitelisting    If true, restrict calls to whitelisted contracts/tokens.
     * @param _contractAddress Initial contract to whitelist (ignored if !_whitelisting).
     * @param _spendTokenInfo  Struct specifying ERC-20 token spending limit:
     *                         • `token`: ERC-20 address (non-zero if `_limit > 0`).
     *                         • `limit`: token amount allowed.
     * @param _allowedSelectors Array of allowed function selectors (length ≤ MAX_SELECTORS).
     * @param _ethLimit        Maximum ETH (wei) this session key can spend.
     */
    function registerSessionKey(
        ISessionkey.Key calldata _key,
        uint48 _validUntil,
        uint48 _validAfter,
        uint48 _limit,
        bool _whitelisting,
        address _contractAddress,
        SpendLimit.SpendTokenInfo calldata _spendTokenInfo,
        bytes4[] calldata _allowedSelectors,
        uint256 _ethLimit
    ) external;

    /**
     * @notice Revokes a specific session key, marking it inactive and clearing its parameters.
     * @dev
     *   - Only callable by ADMIN_ROLE via `_requireForExecute()`.
     *   - Works for both WebAuthn/P256/P256NONKEY and EOA keys.
     *   - Emits `SessionKeyRevoked(keyId)` on success.
     *
     * @param _key Struct containing key information to revoke:
     *             • For WebAuthn/P256/P256NONKEY: uses `pubKey` to compute `keyId`.
     *             • For EOA: uses `eoaAddress` (must be non-zero).
     */
    function revokeSessionKey(ISessionkey.Key calldata _key) external;

    /**
     * @notice Revokes all registered session keys (WebAuthn/P256/P256NONKEY and EOA).
     * @dev
     *   - Only callable by ADMIN_ROLE via `_requireForExecute()`.
     *   - Iterates through all IDs and revokes each, emitting `SessionKeyRevoked(keyId)` per key.
     */
    function revokeAllSessionKeys() external;

    /**
     * @notice Retrieves registration info for a given key ID.
     * @param _id       Identifier (index) of the key to query.
     * @param _keyType  Enum indicating which key mapping to query (WEBAUTHN/P256/P256NONKEY vs. EOA).
     * @return keyType       The type of the key that was registered.
     * @return registeredBy  Address that performed the registration (should be this contract).
     * @return isActive      Whether the key is currently active.
     */
    function getKeyRegistrationInfo(uint256 _id, ISessionkey.KeyType _keyType)
        external
        view
        returns (ISessionkey.KeyType keyType, address registeredBy, bool isActive);

    /**
     * @notice Retrieves the `Key` struct stored at a given ID.
     * @param _id       Identifier index for the key to retrieve.
     * @param _keyType  Enum indicating which mapping to use (WEBAUTHN/P256/P256NONKEY vs. EOA).
     * @return The `Key` struct containing key type, public key, or EOA address.
     */
    function getKeyById(uint256 _id, ISessionkey.KeyType _keyType)
        external
        view
        returns (ISessionkey.Key memory);

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
        returns (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit);

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
        returns (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit);

    /**
     * @notice Checks if an EOA session key is active.
     * @param eoaKey  EOA address to check.
     * @return True if the session key is active; false otherwise.
     */
    function isSessionKeyActive(address eoaKey) external view returns (bool);

    /**
     * @notice Checks if a WebAuthn/P256/P256NONKEY session key is active.
     * @param keyHash  Keccak256 hash of public key coordinates (x, y).
     * @return True if the session key is active; false otherwise.
     */
    function isSessionKeyActive(bytes32 keyHash) external view returns (bool);

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
        ISessionkey.PubKey memory pubKey
    ) external pure returns (bytes memory);

    /**
     * @notice Encodes a P-256 signature payload (KeyType.P256).
     * @param r       R component of the P-256 signature (32 bytes).
     * @param s       S component of the P-256 signature (32 bytes).
     * @param pubKey  Public key (x, y) used for signing.
     * @return ABI‐encoded payload as: KeyType.P256, abi.encode(r, s, pubKey).
     */
    function encodeP256Signature(bytes32 r, bytes32 s, ISessionkey.PubKey memory pubKey)
        external
        pure
        returns (bytes memory);

    /**
     * @notice Encodes a P-256 non-key signature payload (KeyType.P256NONKEY).
     * @param r       R component of the P-256 signature (32 bytes).
     * @param s       S component of the P-256 signature (32 bytes).
     * @param pubKey  Public key (x, y) used for signing.
     * @return ABI‐encoded payload as: KeyType.P256NONKEY, abi.encode(r, s, pubKey).
     */
    function encodeP256NonKeySignature(bytes32 r, bytes32 s, ISessionkey.PubKey memory pubKey)
        external
        pure
        returns (bytes memory);

    /**
     * @notice Encodes an EOA signature for KeyType.EOA.
     * @param _signature Raw ECDSA signature bytes over the UserOperation digest.
     * @return ABI‐encoded payload as: KeyType.EOA, _signature.
     */
    function encodeEOASignature(bytes calldata _signature) external pure returns (bytes memory);
}
