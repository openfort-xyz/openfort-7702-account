// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {IKey} from "./IKey.sol";
import {EnumerableSetLib} from "lib/solady/src/utils/EnumerableSetLib.sol";

/// @title IKeysManager
/// @author Openfort
/// @notice Interface for managing registration, revocation, limits, and call permissions for keys (EOA/WebAuthn/P-256).
/// @dev Implemented by `KeysManager`. Events here are emitted by the implementation.
interface IKeysManager {
    // =============================================================
    //                     TYPES AND STRUCTS
    // =============================================================

    /// @notice Period buckets used to evaluate/reset per-token spend limits.
    /// @dev Counters reset at the start of each period; `Forever` does not reset.
    enum SpendPeriod {
        Minute, // Per-minute bucket
        Hour, // Per-hour bucket
        Day, // Per-day bucket
        Week, // Per-week bucket
        Month, // Per-month bucket
        Year, // Per-year bucket
        Forever // No reset; single running cap

    }

    /// @notice Per-key execute permissions.
    /// @dev Stores packed `(target, selector)` entries. Supports sentinels:
    ///      `ANY_TARGET`, `ANY_FN_SEL`, and `EMPTY_CALLDATA_FN_SEL`.
    struct ExecutePermissions {
        /// @notice Set of packed `(target, selector)` entries the key may call.
        EnumerableSetLib.Bytes32Set canExecute;
    }

    /// @notice Configuration and accounting for a single token’s spend policy.
    /// @dev Applied when validating calls that move value / tokens for a key.
    struct TokenSpendPeriod {
        /// @notice Spend period bucket (how often counters reset).
        SpendPeriod period;
        /// @notice Maximum amount allowed per period.
        uint256 limit;
        /// @notice Amount already spent in the current period.
        uint256 spent;
        /// @notice Start timestamp of the current period window (used to detect rollovers).
        uint256 lastUpdated;
    }

    /// @notice Aggregated spend rules and accounting for all tokens under a key.
    struct SpendStorage {
        /// @notice Set of tokens with configured spend rules (use NATIVE pseudo-address for ETH).
        EnumerableSetLib.AddressSet tokens;
        /// @notice Per-token spend configuration and counters.
        mapping(address => TokenSpendPeriod) tokenData;
    }

    // =============================================================
    //                     CUSTOM ERRORS
    // =============================================================

    /// @notice Zero address provided where non-zero is required.
    error KeyManager__AddressZero();
    /// @notice Operation requires an active key but the key is not active.
    error KeyManager__KeyNotActive();
    /// @notice Target address equals this contract; self-calls are forbidden.
    error KeyManager__TargetIsThis();
    /// @notice Registration payload contained an empty key.
    error KeyManager__KeyCantBeZero();
    /// @notice Invalid timestamp window (e.g., `validAfter > validUntil` or expired).
    error KeyManager__BadTimestamps();
    /// @notice Attempted to register a key that is already active/registered.
    error KeyManager__KeyRegistered();
    /// @notice Session-key registration requires non-zero `limits`.
    error KeyManager__MustHaveLimits();
    /// @notice Unsupported or disallowed key type in this context.
    error KeyManager__InvalidKeyType();
    /// @notice Attempted to pause a key that is already inactive.
    error KeyManager__KeyAlreadyPaused();
    /// @notice Attempted to unpause a key that is already active.
    error KeyManager__KeyAlreadyActive();
    /// @notice Token spend rule was expected but not found.
    error KeyManager__TokenSpendNotSet();
    /// @notice Master key bypasses permission checks (“can do all”).
    error KeyManager__MasterKeyCanDoAll();
    /// @notice Token spend rule already exists for the given key/token.
    error KeyManager__TokenSpendAlreadySet();
    /// @notice Signature length is invalid for the expected key type/format.
    error KeyManager__InvalidSignatureLength();
    /// @notice Master-key registration payload violates required invariants.
    /// @param _keyData_ The invalid master-key registration payload.
    error KeyManager__InvalidMasterKeyReg(IKey.KeyDataReg _keyData_);

    // =============================================================
    //                            EVENTS
    // =============================================================

    /// @notice Emitted when a key is registered (master or session).
    /// @param keyId       Hash identifier of the key (bytes32).
    /// @param keyControl  Control mode for the key (Self or Custodial).
    /// @param keyType     Cryptographic key type (EOA/P256/WEBAUTHN/...).
    /// @param masterKey   True if the key is the master/admin key.
    /// @param validAfter  Not-before timestamp.
    /// @param validUntil  Inclusive expiry timestamp.
    /// @param limits      Initial transactions quota (0 for master).
    event KeyRegistered(
        bytes32 indexed keyId,
        IKey.KeyControl indexed keyControl,
        IKey.KeyType keyType,
        bool masterKey,
        uint48 validAfter,
        uint48 validUntil,
        uint48 limits
    );

    /// @notice Emitted when a key is revoked and its permissions cleared.
    /// @param keyId Identifier of the key.
    event KeyRevoked(bytes32 indexed keyId);

    /// @notice Emitted when a key is paused (soft-disabled).
    /// @param keyId Identifier of the key.
    event KeyPaused(bytes32 indexed keyId);
    /// @notice Emitted when a paused key is unpaused.
    /// @param keyId Identifier of the key.
    event KeyUnpaused(bytes32 indexed keyId);

    /// @notice Emitted when validity window and/or quota for a key is updated.
    /// @param keyId      Identifier of the key.
    /// @param validUntil New inclusive expiry timestamp.
    /// @param limits     New transactions quota (per-key).
    event KeyUpdated(bytes32 indexed keyId, uint48 validUntil, uint48 limits);

    /// @notice Emitted when a `(target, selector)` permission is granted or revoked for a key.
    /// @param keyId  Identifier of the key.
    /// @param target Target contract/EOA address.
    /// @param funSel Function selector (or special selector for empty calldata).
    /// @param can    True when granted; false when removed.
    event CanCallSet(bytes32 indexed keyId, address indexed target, bytes4 funSel, bool can);

    /// @notice Emitted when all `(target, selector)` permissions are cleared for a key.
    /// @param keyId Identifier of the key.
    event ExecutePermissionsCleared(bytes32 indexed keyId);

    /// @notice Emitted when a token spend rule is set or updated for a key.
    /// @param keyId  Identifier of the key.
    /// @param token  Token address (use the NATIVE pseudo-address for ETH).
    /// @param period Spend period bucket.
    /// @param limit  Per-period limit.
    event TokenSpendSet(
        bytes32 indexed keyId, address indexed token, SpendPeriod period, uint256 limit
    );

    /// @notice Emitted when a token spend rule is removed.
    /// @param keyId Identifier of the key.
    /// @param token Token address that was removed from spend tracking.
    event TokenSpendRemoved(bytes32 indexed keyId, address indexed token);

    /// @notice Emitted when all token spend permissions are cleared for a key.
    /// @param keyId Identifier of the key.
    event SpendPermissionsCleared(bytes32 indexed keyId);

    /**
     * @notice Registers a new session key (non-master) with limits and validity window.
     * @param _keyData Registration payload (key type, validity, limits, encoded key, control mode).
     */
    function registerKey(IKey.KeyDataReg calldata _keyData) external;

    /**
     * @notice Creates a token spend rule for a key.
     * @param _keyId  The key identifier.
     * @param _token  ERC-20 token address (or NATIVE for ETH).
     * @param _limit  Per-period spend limit for `_token`.
     * @param _period Spending period bucket.
     */
    function setTokenSpend(bytes32 _keyId, address _token, uint256 _limit, SpendPeriod _period)
        external;

    /**
     * @notice Grants or revokes permission for a `(target, selector)` tuple for a key.
     * @param _keyId  The key identifier.
     * @param _target Target contract/EOA address.
     * @param _funSel Function selector on `_target` (or special selector for empty calldata).
     * @param can     Whether to permit (`true`) or remove/forbid (`false`) the tuple.
     */
    function setCanCall(bytes32 _keyId, address _target, bytes4 _funSel, bool can) external;

    /**
     * @notice Updates a key’s validity and transactions quota.
     * @param _keyId      The key identifier.
     * @param _validUntil New inclusive expiry timestamp.
     * @param _limits     New transactions quota (must be > 0).
     */
    function updateKeyData(bytes32 _keyId, uint48 _validUntil, uint48 _limits) external;

    /**
     * @notice Updates an existing token spend rule for a key.
     * @param _keyId  The key identifier.
     * @param _token  Token whose rule is updated.
     * @param _limit  New per-period limit.
     * @param _period New spend period.
     */
    function updateTokenSpend(bytes32 _keyId, address _token, uint256 _limit, SpendPeriod _period)
        external;

    /**
     * @notice Revokes a key and clears all its permissions.
     * @param _keyId The key identifier to revoke.
     */
    function revokeKey(bytes32 _keyId) external;

    /**
     * @notice Removes a token spend rule from a key.
     * @param _keyId The key identifier.
     * @param _token Token to remove from spend tracking.
     */
    function removeTokenSpend(bytes32 _keyId, address _token) external;

    /**
     * @notice Returns the total number of keys ever registered (monotonic counter).
     * @return The current value of the counter.
     */
    function keyCount() external view returns (uint256);

    /**
     * @notice Returns the `keyId` and stored `KeyData` at registration index `i`.
     * @param i Index in the registration order.
     * @return keyId The key identifier at index `i`.
     * @return data  The stored `KeyData` for `keyId`.
     */
    function keyAt(uint256 i) external view returns (bytes32 keyId, IKey.KeyData memory data);

    /**
     * @notice Returns the stored `KeyData` for a given key identifier.
     * @param _keyId The key identifier.
     * @return The `KeyData` for `_keyId`.
     */
    function getKey(bytes32 _keyId) external view returns (IKey.KeyData memory);

    /**
     * @notice Whether a key has ever been registered or is currently active.
     * @param _keyId The key identifier.
     * @return True if registered/active; false otherwise.
     */
    function isRegistered(bytes32 _keyId) external view returns (bool);

    /**
     * @notice Whether a key is currently active.
     * @param _keyId The key identifier.
     * @return True if active; false otherwise.
     */
    function isKeyActive(bytes32 _keyId) external view returns (bool);

    /**
     * @notice Returns the packed `(target, selector)` permissions for a key.
     * @param _keyId The key identifier.
     * @return Array of packed entries encoding `(target, selector)`.
     */
    function canExecutePackedInfos(bytes32 _keyId) external view returns (bytes32[] memory);

    /**
     * @notice Number of `(target, selector)` entries a key is allowed to call.
     * @param _keyId The key identifier.
     * @return The size of the permission set.
     */
    function canExecuteLength(bytes32 _keyId) external view returns (uint256);

    /**
     * @notice Returns the `(target, selector)` tuple at index `i` for a key.
     * @param _keyId The key identifier.
     * @param i      Index into the permission set.
     * @return target Target contract address.
     * @return fnSel  Function selector on `target`.
     */
    function canExecuteAt(bytes32 _keyId, uint256 i)
        external
        view
        returns (address target, bytes4 fnSel);

    /**
     * @notice Checks if a `(target, selector)` tuple is permitted for a key.
     * @param _keyId  The key identifier.
     * @param _target Target contract address.
     * @param _funSel Function selector on `_target`.
     * @return True if the tuple is present; false otherwise.
     */
    function hasCanCall(bytes32 _keyId, address _target, bytes4 _funSel)
        external
        view
        returns (bool);

    /**
     * @notice Lists all tokens with configured spend limits for a key.
     * @param _keyId The key identifier.
     * @return Array of token addresses with spend rules.
     */
    function spendTokens(bytes32 _keyId) external view returns (address[] memory);

    /**
     * @notice Whether a token spend rule exists for a key.
     * @param _keyId The key identifier.
     * @param _token Token address.
     * @return True if a rule exists; false otherwise.
     */
    function hasTokenSpend(bytes32 _keyId, address _token) external view returns (bool);

    /**
     * @notice Returns the spend rule for (`_keyId`, `_token`).
     * @param _keyId The key identifier.
     * @param _token Token address.
     * @return period      Spend period enum.
     * @return limit       Per-period spend limit.
     * @return spent       Amount spent in the current period.
     * @return lastUpdated Timestamp of the last counter reset/update.
     */
    function tokenSpend(bytes32 _keyId, address _token)
        external
        view
        returns (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated);

    /**
     * @notice Pauses a key (soft-disable without wiping data/permissions).
     * @param _keyId The key identifier to pause.
     */
    function pauseKey(bytes32 _keyId) external;

    /**
     * @notice Unpauses a previously paused key.
     * @param _keyId The key identifier to unpause.
     */
    function unpauseKey(bytes32 _keyId) external;

    /**
     * @notice Clears all token spend rules for a key.
     * @param _keyId The key identifier whose spend rules are cleared.
     */
    function clearSpendPermissions(bytes32 _keyId) external;

    /**
     * @notice Clears all `(target, selector)` permissions for a key.
     * @param _keyId The key identifier whose execute permissions are cleared.
     */
    function clearExecutePermissions(bytes32 _keyId) external;
}
