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

abstract contract KeysManager is BaseOPF7702, IKeysManager, IKey {
    using KeysManagerLib for *;
    using EnumerableSetLib for *;
    using EnumerableMapLib for *;

    // =============================================================
    //                          CONSTANTS
    // =============================================================

    address internal constant ANY_TARGET = 0x3232323232323232323232323232323232323232;
    bytes4 internal constant ANY_FN_SEL = 0x32323232;
    bytes4 internal constant EMPTY_CALLDATA_FN_SEL = 0xe0e0e0e0;
    address internal constant NATIVE_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    // =============================================================
    //                          STATE VARIABLES
    // =============================================================

    uint256 public id;
    mapping(uint256 => bytes32) public idKeys;
    mapping(bytes32 => KeyData) internal keys;

    mapping(bytes32 => ExecutePermissions) internal permissions;

    mapping(bytes32 => SpendStorage) internal spendStore;

    // =============================================================
    //                 PUBLIC / EXTERNAL FUNCTIONS
    // =============================================================

    ////////////// Setters //////////////
    function registerKey(KeyDataReg calldata _keyData) public {
        _requireForExecute();
        _keyData.keyCantBeZero();
        _keyData.mustHaveLimits();

        KeysManagerLib.validateTimestamps(_keyData.validUntil, _keyData.validAfter, 0, false);

        _addKey(_keyData);
    }

    function revokeKey(bytes32 _keyId) public {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        sKey.validateKeyBefore();

        _revoke(sKey);
        emit KeyRevoked(_keyId);

        clearExecutePermissions(_keyId);
        clearSpendPermissions(_keyId);
    }

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

    function setCanCall(bytes32 _keyId, address _target, bytes4 _funSel, bool can) public {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        sKey.validateKeyBefore();

        _target.checkTargetAddress();

        _setCanCall(_keyId, _target, _funSel, can);
        emit CanCallSet(_keyId, _target, _funSel, can);
    }

    ////////////// Updatterd //////////////
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

    function _revoke(KeyData storage _sKey) internal {
        _sKey.isActive = false;
        _sKey.isDelegatedControl = false;
        _sKey.validUntil = 0;
        _sKey.validAfter = 0;
        _sKey.limits = 0;
        delete _sKey.key;
        delete _sKey.keyType;
    }

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

    function _removeTokenSpend(bytes32 _keyId, address _token) internal {
        SpendStorage storage sSpend = spendStore[_keyId];
        if (!sSpend.tokens.contains(_token)) revert KeyManager__TokenSpendNotSet();
        delete sSpend.tokenData[_token];
        sSpend.tokens.remove(_token);
    }

    function _setCanCall(bytes32 _keyId, address _target, bytes4 _funSel, bool can) internal {
        ExecutePermissions storage sExecute = permissions[_keyId];
        sExecute.canExecute.update(_target.packCanExecute(_funSel), can, 2048);
    }

    // =============================================================
    //                   PUBLIC / EXTERNAL GETTERS
    // =============================================================

    function keyCount() external view returns (uint256) {
        return id;
    }

    function keyAt(uint256 i) public view returns (bytes32 keyId, KeyData memory data) {
        keyId = idKeys[i];
        data = keys[keyId];
    }

    function getKey(bytes32 _keyId) external view returns (KeyData memory) {
        return keys[_keyId];
    }

    function isRegistered(bytes32 _keyId) external view returns (bool) {
        return keys[_keyId].validUntil != 0 || keys[_keyId].isActive;
    }

    function isKeyActive(bytes32 _keyId) external view returns (bool) {
        return keys[_keyId].isActive;
    }

    function canExecutePackedInfos(bytes32 _keyId) public view returns (bytes32[] memory) {
        return permissions[_keyId].canExecute.values();
    }

    function canExecuteLength(bytes32 _keyId) external view returns (uint256) {
        return permissions[_keyId].canExecute.length();
    }

    function canExecuteAt(bytes32 _keyId, uint256 i)
        external
        view
        returns (address target, bytes4 fnSel)
    {
        bytes32 packed = permissions[_keyId].canExecute.at(i);
        return packed.unpackCanExecute();
    }

    function hasCanCall(bytes32 _keyId, address _target, bytes4 _funSel)
        external
        view
        returns (bool)
    {
        return permissions[_keyId].canExecute.contains(_target.packCanExecute(_funSel));
    }

    function spendTokens(bytes32 _keyId) external view returns (address[] memory) {
        return spendStore[_keyId].tokens.values();
    }

    function hasTokenSpend(bytes32 _keyId, address _token) public view returns (bool) {
        return spendStore[_keyId].tokens.contains(_token);
    }

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

    function pauseKey(bytes32 _keyId) public {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        if (!sKey.isActive) revert KeyManager__KeyAlreadyPaused();

        sKey.isActive = false;
        emit KeyPaused(_keyId);
    }

    function unpauseKey(bytes32 _keyId) public {
        _requireForExecute();
        KeyData storage sKey = keys[_keyId];
        if (sKey.isActive) revert KeyManager__KeyAlreadyActive();

        sKey.isActive = true;
        emit KeyUnpaused(_keyId);
    }

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
        bytes memory pubKey
    ) external pure returns (bytes memory) {
        bytes memory inner = abi.encode(
            requireUserVerification,
            authenticatorData,
            clientDataJSON,
            challengeIndex,
            typeIndex,
            r,
            s,
            pubKey
        );

        return abi.encode(KeyType.WEBAUTHN, inner);
    }

    /**
     * @notice Encodes a P-256 signature payload (KeyType.P256 || KeyType.P256NONKEY).
     * @param r       R component of the P-256 signature (32 bytes).
     * @param s       S component of the P-256 signature (32 bytes).
     * @param pubKey  Public key (x, y) used for signing.3
     * @param _keyType  KeyType of key.
     * @return ABI‐encoded payload as: KeyType.P256, abi.encode(r, s, pubKey).
     */
    function encodeP256Signature(bytes32 r, bytes32 s, bytes memory pubKey, KeyType _keyType)
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
