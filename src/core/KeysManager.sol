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

pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {BaseOPF7702} from "src/core/BaseOPF7702.sol";
import {IUserOpPolicy} from "src/interfaces/IPolicy.sol";
import {KeysManagerLib} from "src/libs/KeysManagerLib.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {EnumerableSetLib} from "lib/solady/src/utils/EnumerableSetLib.sol";
import {EnumerableMapLib} from "lib/solady/src/utils/EnumerableMapLib.sol";

/// @title KeysManager
/// @author Openfort@0xkoiner
/// @notice Manages registration, revocation, limits, and call permissions for keys (EOA/WebAuthn/P-256).
/// @dev Inherits BaseOPF7702. Uses enumerable maps/sets for can-call and token-spend, with capacities 2048/64.
/// @custom:inspired-by Ithaca Account (Token Spend & Can Call permission model)
abstract contract KeysManager is BaseOPF7702, IKeysManager, IKey {
    using KeysManagerLib for *;
    using EnumerableSetLib for *;
    using EnumerableMapLib for *;

    // =============================================================
    //                          CONSTANTS
    // =============================================================

    /// @notice Wildcard sentinel for “any target” in can-call rules.
    address internal constant ANY_TARGET = 0x3232323232323232323232323232323232323232;
    /// @notice Wildcard sentinel for “any function selector” in can-call rules.
    bytes4 internal constant ANY_FN_SEL = 0x32323232;
    /// @notice Pseudo-selector used to permit calls with empty calldata (e.g., plain ETH transfers).
    bytes4 internal constant EMPTY_CALLDATA_FN_SEL = 0xe0e0e0e0;
    /// @notice Pseudo-address representing native ETH in spend rules.
    address internal constant NATIVE_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    // =============================================================
    //                          STATE VARIABLES
    // =============================================================

    /// @notice Incremental ID for WebAuthn/P256/P256NONKEY keys
    /// @dev Id = 0 always saved for MasterKey (Admin)
    uint256 public id;

    /// @notice Mapping from key ID to Key hash ID
    mapping(uint256 => bytes32) public idKeys;
    /// @notice Mapping from hashed key to Key struct (WebAuthn/P256/P256NONKEY)
    /// @dev Indexed by keyId (bytes32).
    mapping(bytes32 => KeyData) internal keys;

    /// @notice Per-key execute permissions: allowed (target, selector) pairs.
    /// @dev Indexed by keyId (bytes32).
    mapping(bytes32 => ExecutePermissions) internal permissions;
    /// @notice Per-key token spend configuration and accounting.
    /// @dev Indexed by keyId (bytes32); tracks per-token limits, period, and counters.
    mapping(bytes32 => SpendStorage) internal spendStore;

    // =============================================================
    //                 PUBLIC / EXTERNAL FUNCTIONS
    // =============================================================

    ////////////// Setters //////////////

    /**
     * @notice Registers a new session key (non-master) with limits and validity window.
     * @dev
     *      - `_keyData.key` is non-zero (`keyCantBeZero()`). abi.encode(<address> || <bytes32(x), bytes32(y)>);
     *      - `_keyData.limits > 0` (`mustHaveLimits()`), total transactions limit, this path does not register master keys.
     *      - Timestamps are valid (`validateTimestamps(_validUntil, _validAfter)`).
     *        Stores computed `keyId`, marks key active.
     * @param _keyData Registration payload (key type, validity, limits, raw key bytes, control type).
     */
    function registerKey(KeyDataReg calldata _keyData) public {
        _requireForExecute();
        _keyData.keyCantBeZero();
        _keyData.mustHaveLimits();

        // validateTimestamps: (validUntil, validAfter, currentValidUntil, isUpdate)
        KeysManagerLib.validateTimestamps(_keyData.validUntil, _keyData.validAfter, 0, false);

        _addKey(_keyData);
    }

    /**
     * @notice Creates a token spend rule for a key.
     * @dev Requires the key be valid/active, non-masterKey (`validateKeyBefore()`).
     *      Validates `_token` and `_limit`. Inserts `_token` into the per-key set (capacity 64)
     *      and initializes its period/limit.
     * @param _keyId  The key identifier.
     * @param _token  ERC-20 token address (non-zero) or NATIVE_ADDRESS for native token.
     * @param _limit  Amount spend limit for `_token`. Per-period.
     * @param _period Spending period(interval) (Minute/Hour/Day/Week/Month/Year/Forever).
     */
    function setTokenSpend(bytes32 _keyId, address _token, uint256 _limit, SpendPeriod _period)
        public
    {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        sKey.validateKeyBefore();

        _token.checkAddress();
        _limit.checkLimits();

        _setTokenSpend(_keyId, _token, _limit, _period, false);

        emit TokenSpendSet(_keyId, _token, _period, _limit);
    }

    /**
     * @notice Grants or revokes permission for a `(target, selector)` tuple for a key.
     * @dev Requires the key be valid/active. Validates `_target`. address(this) forbidden
     *      Updates an enumerable set (capacity 2048) using a packed `(target, fnSel)` key.
     *      Supports wildcards if your packing uses `ANY_TARGET` / `ANY_FN_SEL`.
     * @param _keyId  The key identifier.
     * @param _target Target contract/eoa address.
     * @param _funSel Function selector on `_target` or `EMPTY_CALLDATA_FN_SEL` for native token.
     * @param can     Whether the tuple is permitted (`true`) or removed/forbidden (`false`).
     */
    function setCanCall(bytes32 _keyId, address _target, bytes4 _funSel, bool can) public {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        sKey.validateKeyBefore();

        _target.checkTargetAddress();

        _setCanCall(_keyId, _target, _funSel, can);

        emit CanCallSet(_keyId, _target, _funSel, can);
    }

    ////////////// Updatters //////////////

    /**
     * @notice Updates a key’s validity and total transactions limit.
     * @dev Requires the key be valid/active.
     *      Validates the new window (`validateTimestamps(_validUntil, sKey.validAfter, sKey.validUntil, true)`).
     *      Overwrites `validUntil` and `limits` only; `validAfter` remains unchanged.
     * @param _keyId       The key identifier.
     * @param _validUntil  New inclusive expiry timestamp.
     * @param _limits      New per-period transaction limit (must be > 0).
     */
    function updateKeyData(bytes32 _keyId, uint48 _validUntil, uint48 _limits) public {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        sKey.validateKeyBefore();

        KeysManagerLib.validateTimestamps(_validUntil, sKey.validAfter, sKey.validUntil, true);

        _limits.checkLimits();

        sKey.validUntil = _validUntil;
        sKey.limits = _limits;

        emit KeyUpdated(_keyId, _validUntil, _limits);
    }

    /**
     * @notice Updates an existing token spend rule for a key.
     * @dev Requires the key be valid/active.
     *      Validates `_token` and `_limit`. Rule must already exist; otherwise reverts.
     *      Resets `spent` and `lastUpdated` counters to zero.
     * @param _keyId  The key identifier.
     * @param _token  Token whose rule is updated.
     * @param _limit  New per-period limit.
     * @param _period New spend period.
     */
    function updateTokenSpend(bytes32 _keyId, address _token, uint256 _limit, SpendPeriod _period)
        public
    {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        sKey.validateKeyBefore();

        _token.checkAddress();
        _limit.checkLimits();

        _setTokenSpend(_keyId, _token, _limit, _period, true);

        emit TokenSpendSet(_keyId, _token, _period, _limit);
    }

    ////////////// Removers //////////////

    /**
     * @notice Revokes a key and clears all its permissions.
     * @notice Not clears idKeys.
     * @dev Requires the key be valid/active.
     *      Marks the key inactive and zeroizes its fields (via `_revoke`),
     *      then clears both execute and spend permissions to avoid residual grants.
     * @param _keyId The key identifier to revoke.
     */
    function revokeKey(bytes32 _keyId) public {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        sKey.validateKeyBefore();

        _revoke(sKey);

        emit KeyRevoked(_keyId);

        clearExecutePermissions(_keyId);
        clearSpendPermissions(_keyId);
    }

    /**
     * @notice Removes a token spend rule from a key.
     * @dev Requires the key be valid/active and the rule exist.
     *      Deletes accounting for `_token` and removes it from the per-key set.
     * @param _keyId The key identifier.
     * @param _token Token to remove from spend tracking.
     */
    function removeTokenSpend(bytes32 _keyId, address _token) public {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        sKey.validateKeyBefore();

        _removeTokenSpend(_keyId, _token);

        emit TokenSpendRemoved(_keyId, _token);
    }

    // =============================================================
    //                 INTERNAL / PRIVATE
    // =============================================================

    /**
     * @notice Internal: persists a newly registered key.
     * @dev Computes `keyId`, rejects duplicates, initializes `KeyData` (type, key bytes, validity, limits),
     *      sets `masterKey = (_keyData.limits == 0)`, and marks active.
     *      If `_keyData.keyControl == KeyControl.Custodial`, enables 3'rd party control and calls
     *      `IUserOpPolicy(GAS_POLICY).initializeGasPolicy(address(this), keyId, _keyData.limits)`.
     *      Indexes `idKeys[id] = keyId`, increments `id`, and emits `KeyRegistered`.
     * @param _keyData Registration payload to store.
     */
    function _addKey(KeyDataReg memory _keyData) internal {
        bytes32 keyId = _keyData.computeKeyId();
        KeyData storage sKey = keys[keyId];

        if (sKey.isActive) revert KeyManager__KeyRegistered();

        sKey.keyType = _keyData.keyType;
        sKey.key = _keyData.key;
        sKey.validUntil = _keyData.validUntil;
        sKey.validAfter = _keyData.validAfter;
        sKey.limits = _keyData.limits;
        sKey.masterKey = (_keyData.limits == 0);
        sKey.isActive = true;
        sKey.isDelegatedControl = false;

        if (_keyData.keyControl == KeyControl.Custodial) {
            sKey.isDelegatedControl = true;
            IUserOpPolicy(GAS_POLICY).initializeGasPolicy(
                address(this), keyId, uint256(_keyData.limits)
            );
        }

        idKeys[id] = keyId;

        unchecked {
            id++;
        }

        emit KeyRegistered(
            keyId,
            _keyData.keyControl,
            _keyData.keyType,
            sKey.masterKey,
            _keyData.validAfter,
            _keyData.validUntil,
            _keyData.limits
        );
    }

    /**
     * @notice Internal: clears and deactivates a key.
     * @dev Clears `isActive`, `isDelegatedControl`, validity, limits, key bytes, and type.
     *      Does not touch permission or spend stores; callers clear them separately.
     * @param _sKey Storage reference to the key being revoked.
     */
    function _revoke(KeyData storage _sKey) internal {
        _sKey.isActive = false;
        _sKey.isDelegatedControl = false;
        _sKey.validUntil = 0;
        _sKey.validAfter = 0;
        _sKey.limits = 0;
        delete _sKey.key;
        delete _sKey.keyType;
    }

    /**
     * @notice Internal: sets or updates a token spend rule, resetting runtime counters.
     * @dev If `update == false`, inserts `_token` into the per-key set (capacity 64); reverts if already set.
     *      If `update == true`, requires the rule exist; reverts if missing.
     *      In both cases, overwrites `period` and `limit`, and resets `spent` and `lastUpdated` to zero.
     * @param _keyId  The key identifier.
     * @param _token  Token being configured.
     * @param _limit  Spending limit for `_token`.
     * @param _period Spend period enum.
     * @param update  `false` to create, `true` to modify an existing rule.
     */
    function _setTokenSpend(
        bytes32 _keyId,
        address _token,
        uint256 _limit,
        SpendPeriod _period,
        bool update
    ) internal {
        SpendStorage storage sSpend = spendStore[_keyId];

        if (!update) {
            bool inSet = sSpend.tokens.add(_token, 64);
            if (!inSet) revert KeyManager__TokenSpendAlreadySet();
        } else if (update) {
            if (!sSpend.tokens.contains(_token)) revert KeyManager__TokenSpendNotSet();
        }

        TokenSpendPeriod storage sTokenSpend = sSpend.tokenData[_token];
        sTokenSpend.period = _period;
        sTokenSpend.limit = _limit;
        sTokenSpend.spent = 0;
        sTokenSpend.lastUpdated = 0;
    }

    /**
     * @notice Internal: deletes a token spend rule and removes it from the set.
     * @dev Reverts if the rule does not exist.
     * @param _keyId The key identifier.
     * @param _token Token to remove.
     */
    function _removeTokenSpend(bytes32 _keyId, address _token) internal {
        SpendStorage storage sSpend = spendStore[_keyId];
        if (!sSpend.tokens.contains(_token)) revert KeyManager__TokenSpendNotSet();
        delete sSpend.tokenData[_token];
        sSpend.tokens.remove(_token);
    }

    /**
     * @notice Internal: grants or revokes a `(target, selector)` permission for a key.
     * @dev Packs and updates the `(target, selector)` entry in an enumerable set (capacity 2048).
     * @param _keyId  The key identifier.
     * @param _target Target contract/eoa address.
     * @param _funSel Function selector on `_target`.
     * @param can     Whether to permit (`true`) or remove/forbid (`false`) the tuple.
     */
    function _setCanCall(bytes32 _keyId, address _target, bytes4 _funSel, bool can) internal {
        ExecutePermissions storage sExecute = permissions[_keyId];
        sExecute.canExecute.update(_target.packCanExecute(_funSel), can, 2048);
    }

    // =============================================================
    //                   PUBLIC / EXTERNAL GETTERS
    // =============================================================

    /**
     * @notice Returns the total number of keys ever registered (monotonic counter).
     * @dev Includes revoked/paused keys; this is not a count of active keys.
     * @return The current value of `id`.
     */
    function keyCount() external view returns (uint256) {
        return id;
    }

    /**
     * @notice Returns the `keyId` and stored `KeyData` at registration index `i`.
     * @dev Indexing follows insertion order: `0..id-1`.
     * @param i Index in `idKeys`.
     * @return keyId The key identifier at index `i`.
     * @return data  The stored `KeyData` for `keyId`.
     */
    function keyAt(uint256 i) public view returns (bytes32 keyId, KeyData memory data) {
        keyId = idKeys[i];
        data = keys[keyId];
    }

    /**
     * @notice Returns the stored `KeyData` for a given key identifier.
     * @param _keyId The key identifier.
     * @return The `KeyData` for `_keyId` (zeroed if never set).
     */
    function getKey(bytes32 _keyId) external view returns (KeyData memory) {
        return keys[_keyId];
    }

    /**
     * @notice Whether a key has ever been registered or is currently active.
     * @dev Returns true if `validUntil != 0` OR `isActive == true`.
     * @param _keyId The key identifier.
     * @return True if registered/active, false otherwise.
     */
    function isRegistered(bytes32 _keyId) external view returns (bool) {
        return keys[_keyId].validUntil != 0 || keys[_keyId].isActive;
    }

    /**
     * @notice Whether a key is currently active.
     * @param _keyId The key identifier.
     * @return True if active; false otherwise.
     */
    function isKeyActive(bytes32 _keyId) external view returns (bool) {
        return keys[_keyId].isActive;
    }

    /**
     * @notice Returns the packed `(target, selector)` permissions for a key.
     * @param _keyId The key identifier.
     * @return Array of packed `bytes32` entries encoding `(target, selector)`.
     */
    function canExecutePackedInfos(bytes32 _keyId) public view returns (bytes32[] memory) {
        return permissions[_keyId].canExecute.values();
    }

    /**
     * @notice Number of `(target, selector)` entries a key is allowed to call.
     * @param _keyId The key identifier.
     * @return The size of the permission set.
     */
    function canExecuteLength(bytes32 _keyId) external view returns (uint256) {
        return permissions[_keyId].canExecute.length();
    }

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
        returns (address target, bytes4 fnSel)
    {
        bytes32 packed = permissions[_keyId].canExecute.at(i);
        return packed.unpackCanExecute();
    }

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
        returns (bool)
    {
        return permissions[_keyId].canExecute.contains(_target.packCanExecute(_funSel));
    }

    /**
     * @notice Lists all tokens with configured spend limits for a key.
     * @param _keyId The key identifier.
     * @return Array of token addresses with spend rules.
     */
    function spendTokens(bytes32 _keyId) external view returns (address[] memory) {
        return spendStore[_keyId].tokens.values();
    }

    /**
     * @notice Whether a token spend rule exists for a key.
     * @param _keyId The key identifier.
     * @param _token Token address.
     * @return True if a rule exists; false otherwise.
     */
    function hasTokenSpend(bytes32 _keyId, address _token) public view returns (bool) {
        return spendStore[_keyId].tokens.contains(_token);
    }

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
        returns (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated)
    {
        TokenSpendPeriod storage s = spendStore[_keyId].tokenData[_token];
        return (s.period, s.limit, s.spent, s.lastUpdated);
    }

    // =============================================================
    //                          ADMIN FUNC.
    // =============================================================

    /**
     * @notice Pauses a key (soft-disable without wiping data/permissions).
     * @dev Reverts if already paused.
     * @param _keyId The key identifier to pause.
     */
    function pauseKey(bytes32 _keyId) public {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        if (!sKey.isActive) revert KeyManager__KeyAlreadyPaused();

        sKey.isActive = false;
        emit KeyPaused(_keyId);
    }

    /**
     * @notice Unpauses a previously paused key.
     * @dev Reverts if already active.
     * @param _keyId The key identifier to unpause.
     */
    function unpauseKey(bytes32 _keyId) public {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        if (sKey.isActive) revert KeyManager__KeyAlreadyActive();

        sKey.isActive = true;
        emit KeyUnpaused(_keyId);
    }

    /**
     * @notice Clears **all** token spend rules for a key.
     * @dev Iterates and deletes each rule; gas scales with rule count.
     * @param _keyId The key identifier whose spend rules are cleared.
     */
    function clearSpendPermissions(bytes32 _keyId) public {
        _requireForExecute();
        SpendStorage storage sSpend = spendStore[_keyId];

        while (sSpend.tokens.length() != 0) {
            address token = sSpend.tokens.at(sSpend.tokens.length() - 1);
            delete sSpend.tokenData[token];
            sSpend.tokens.remove(token);
        }
        emit SpendPermissionsCleared(_keyId);
    }

    /**
     * @notice Clears **all** `(target, selector)` permissions for a key.
     * @dev Iterates and deletes each packed entry; gas scales with entry count.
     * @param _keyId The key identifier whose execute permissions are cleared.
     */
    function clearExecutePermissions(bytes32 _keyId) public {
        _requireForExecute();
        ExecutePermissions storage sExecute = permissions[_keyId];

        while (sExecute.canExecute.length() != 0) {
            bytes32 packed = sExecute.canExecute.at(sExecute.canExecute.length() - 1);
            sExecute.canExecute.remove(packed);
        }

        emit ExecutePermissionsCleared(_keyId);
    }

    /// @dev Master key must have: validUntil = max(uint48), validAfter = 0, limit = 0, whitelisting = false.
    function _masterKeyValidation(KeyDataReg memory _keyData) internal pure {
        _keyData.keyCantBeZero();
        if (
            _keyData.limits != 0 || _keyData.validAfter != 0
                || _keyData.validUntil != type(uint48).max || _keyData.keyControl != KeyControl.Self
                || _keyData.keyType == KeyType.P256 || _keyData.keyType == KeyType.P256NONKEY
        ) revert IKeysManager.KeyManager__InvalidMasterKeyReg(_keyData);
    }
}
