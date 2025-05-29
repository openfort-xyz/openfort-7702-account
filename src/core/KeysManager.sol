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

abstract contract KeysManager is BaseOPF7702, ISessionkey, SpendLimit {
    uint256 public constant MAX_SELECTORS = 10;
    address public constant DEAD_ADDRESS = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;

    // Todo: id for EOA session Keys
    uint256 public id;
    uint256 public idEOA;

    mapping(uint256 id => Key key) public idSessionKeys;
    mapping(bytes32 sessionKey => SessionKey sessionKeyData) public sessionKeys;
    mapping(bytes32 challenge => bool isUsed) public usedChallenges;

    mapping(uint256 idEOA => Key key) public idSessionKeysEOA;
    mapping(address sessionKeyEOA => SessionKey sessionKeyData) public sessionKeysEOA;

    error SessionKeyManager__InvalidTimestamp();
    error SessionKeyManager__AddressCantBeZero();
    error SessionKeyManager__SessionKeyInactive();
    error SessionKeyManager__SelectorsListTooBig();
    error SessionKeyManager__SessionKeyRegistered();

    event SessionKeyRevoked(bytes32 indexed sessionKey);
    event SessionKeyRegistrated(bytes32 indexed sessionKey);

    /**
     * @notice Registers a new session key with specified permissions
     * @param _key Key information (EOA or WebAuthn)
     * @param _validUntil Timestamp until which the key is valid
     * @param _validAfter Timestamp after which the key becomes valid
     * @param _limit Number of transactions allowed (0 for unlimited/master key)
     * @param _whitelisting Whether contract address whitelisting is enabled
     * @param _contractAddress Initial whitelisted contract address
     * @param _spendTokenInfo Token spending limit information
     * @param _allowedSelectors List of allowed function selectors
     * @param _ethLimit Maximum amount of ETH that can be spent
     * @dev Only callable by accounts with ADMIN_ROLE
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
        if (_validUntil <= block.timestamp) revert SessionKeyManager__InvalidTimestamp();
        if (_validAfter > _validUntil) revert SessionKeyManager__InvalidTimestamp();

        if (
            _key.keyType == KeyType.WEBAUTHN || _key.keyType == KeyType.P256
                || _key.keyType == KeyType.P256NONKEY
        ) {
            bytes32 keyHash = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));

            if (sessionKeys[keyHash].isActive) revert SessionKeyManager__SessionKeyRegistered();

            SessionKey storage sKey = sessionKeys[keyHash];
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

            idSessionKeys[id] = _key;
            id++;

            emit SessionKeyRegistrated(keyHash);
        } else if (_key.keyType == KeyType.EOA) {
            if (_key.eoaAddress == address(0)) revert SessionKeyManager__AddressCantBeZero();
            if (sessionKeysEOA[_key.eoaAddress].isActive) {
                revert SessionKeyManager__SessionKeyRegistered();
            }

            SessionKey storage sKey = sessionKeysEOA[_key.eoaAddress];

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
            idEOA++;

            emit SessionKeyRegistrated(keccak256(abi.encodePacked(_key.eoaAddress)));
        }
    }

    /**
     * @notice Internal function to add a session key with all parameters
     * @param sKey Storage reference to the session key data
     * @param _key Key information
     * @param _validUntil Timestamp until which the key is valid
     * @param _validAfter Timestamp after which the key becomes valid
     * @param _limit Number of transactions allowed
     * @param _whitelisting Whether contract address whitelisting is enabled
     * @param _contractAddress Initial whitelisted contract address
     * @param _spendTokenInfo Token spending limit information
     * @param _allowedSelectors List of allowed function selectors
     * @param _ethLimit Maximum amount of ETH that can be spent
     */
    function _addSessionKey(
        SessionKey storage sKey,
        Key calldata _key,
        uint48 _validUntil,
        uint48 _validAfter,
        uint48 _limit,
        bool _whitelisting,
        address _contractAddress,
        SpendTokenInfo calldata _spendTokenInfo,
        bytes4[] calldata _allowedSelectors,
        uint256 _ethLimit
    ) internal {
        sKey.pubKey = _key.pubKey;
        sKey.isActive = true;
        sKey.validUntil = _validUntil;
        sKey.validAfter = _validAfter;
        sKey.limit = _limit;
        sKey.masterSessionKey = (_limit == 0);
        sKey.whoRegistrated = address(this);

        if (_limit > 0) {
            sKey.whitelisting = _whitelisting;
            sKey.ethLimit = _ethLimit;

            if (_whitelisting) {
                if (_contractAddress == address(0)) revert SessionKeyManager__AddressCantBeZero();
                sKey.whitelist[_contractAddress] = true;
                sKey.whitelist[_spendTokenInfo.token] = true;

                uint256 len = _allowedSelectors.length;
                if (len > MAX_SELECTORS) revert SessionKeyManager__SelectorsListTooBig();

                for (uint256 i = 0; i < len;) {
                    sKey.allowedSelectors.push(_allowedSelectors[i]);
                    unchecked {
                        ++i;
                    }
                }
            }

            if (_spendTokenInfo.token == address(0)) revert SessionKeyManager__AddressCantBeZero();
            sKey.spendTokenInfo.token = _spendTokenInfo.token;
            sKey.spendTokenInfo.limit = _spendTokenInfo.limit;
        }
    }

    /**
     * @notice Revokes a specific session key
     * @param _key Key information of the session key to revoke
     * @dev Only callable by accounts with ADMIN_ROLE
     */
    function revokeSessionKey(Key calldata _key) external {
        _requireForExecute();
        if (
            _key.keyType == KeyType.WEBAUTHN || _key.keyType == KeyType.P256
                || _key.keyType == KeyType.P256NONKEY
        ) {
            bytes32 keyHash = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
            SessionKey storage sKey = sessionKeys[keyHash];
            _revokeSessionKey(sKey);
            emit SessionKeyRevoked(keyHash);
        } else if (_key.keyType == KeyType.EOA) {
            if (_key.eoaAddress == address(0)) revert SessionKeyManager__AddressCantBeZero();
            SessionKey storage sKey = sessionKeysEOA[_key.eoaAddress];
            _revokeSessionKey(sKey);
            emit SessionKeyRevoked(keccak256(abi.encodePacked(_key.eoaAddress)));
        }
    }

    /**
     * @notice Internal function to revoke a session key
     * @param sKey Storage reference to the session key to revoke
     */
    function _revokeSessionKey(SessionKey storage sKey) internal {
        if (!sKey.isActive) revert SessionKeyManager__SessionKeyInactive();

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

    /**
     * @notice Revokes all registered session keys
     * @dev Only callable by accounts with ADMIN_ROLE
     */
    function revokeAllSessionKeys() external {
        _requireForExecute();

        // Revoke WebAuthn/P256 keys
        for (uint256 i = 0; i < id; i++) {
            Key memory _key = getKeyById(i, KeyType.WEBAUTHN); // Default to WEBAUTHN, we'll check the actual type

            if (
                _key.keyType == KeyType.WEBAUTHN || _key.keyType == KeyType.P256
                    || _key.keyType == KeyType.P256NONKEY
            ) {
                bytes32 keyHash = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
                SessionKey storage sKey = sessionKeys[keyHash];
                _revokeSessionKey(sKey);
                emit SessionKeyRevoked(keyHash);
            }
        }

        // Revoke EOA keys
        for (uint256 i = 0; i < idEOA; i++) {
            Key memory _key = getKeyById(i, KeyType.EOA);

            if (_key.keyType == KeyType.EOA && _key.eoaAddress != address(0)) {
                SessionKey storage sKey = sessionKeysEOA[_key.eoaAddress];
                _revokeSessionKey(sKey);
                emit SessionKeyRevoked(keccak256(abi.encodePacked(_key.eoaAddress)));
            }
        }
    }

    /**
     * @notice Retrieves registration information for a key
     * @param _id ID of the key
     * @return keyType Type of the key
     * @return registeredBy Address that registered the key
     * @return isActive Whether the key is active
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
            Key memory key = getKeyById(_id, KeyType.WEBAUTHN);
            bytes32 keyHash = keccak256(abi.encodePacked(key.pubKey.x, key.pubKey.y));
            return (key.keyType, sessionKeys[keyHash].whoRegistrated, sessionKeys[keyHash].isActive);
        } else if (_keyType == KeyType.EOA) {
            Key memory key = getKeyById(_id, KeyType.EOA);
            return (
                key.keyType,
                sessionKeysEOA[key.eoaAddress].whoRegistrated,
                sessionKeysEOA[key.eoaAddress].isActive
            );
        }
    }

    /**
     * @notice Retrieves key information by ID of WebAuthn/P256/EOA
     * @param _id ID of the key to retrieve
     * @return Key information
     */
    function getKeyById(uint256 _id, KeyType _keyType) public view returns (Key memory) {
        if (
            _keyType == KeyType.WEBAUTHN || _keyType == KeyType.P256
                || _keyType == KeyType.P256NONKEY
        ) {
            Key storage _key = idSessionKeys[_id];
            return _key;
        } else {
            Key storage _key = idSessionKeysEOA[_id];
            return _key;
        }
    }

    /**
     * @notice Retrieves session key data for a WebAuthn key
     * @param _keyHash Hash of the WebAuthn public key
     * @return isActive Whether the key is active
     * @return validUntil Timestamp until which the key is valid
     * @return validAfter Timestamp after which the key becomes valid
     * @return limit Number of transactions allowed
     */
    function getSessionKeyData(bytes32 _keyHash)
        external
        view
        returns (bool, uint48, uint48, uint48)
    {
        bool isActive = sessionKeys[_keyHash].isActive;
        uint48 validUntil = sessionKeys[_keyHash].validUntil;
        uint48 validAfter = sessionKeys[_keyHash].validAfter;
        uint48 limit = sessionKeys[_keyHash].limit;

        return (isActive, validUntil, validAfter, limit);
    }

    /**
     * @notice Retrieves session key data for a WebAuthn key
     * @param _key Address of EOA Session Key
     * @return isActive Whether the key is active
     * @return validUntil Timestamp until which the key is valid
     * @return validAfter Timestamp after which the key becomes valid
     * @return limit Number of transactions allowed
     */
    function getSessionKeyData(address _key) external view returns (bool, uint48, uint48, uint48) {
        bool isActive = sessionKeysEOA[_key].isActive;
        uint48 validUntil = sessionKeysEOA[_key].validUntil;
        uint48 validAfter = sessionKeysEOA[_key].validAfter;
        uint48 limit = sessionKeysEOA[_key].limit;

        return (isActive, validUntil, validAfter, limit);
    }

    /**
     * @notice Checks if an EOA session key is active
     * @param eoaKey EOA address to check
     * @return True if the session key is active, false otherwise
     */
    function isSessionKeyActive(address eoaKey) external view returns (bool) {
        return sessionKeysEOA[eoaKey].isActive;
    }

    /**
     * @notice Checks if a WebAuthn session key is active
     * @param keyHash Hash of the WebAuthn public key
     * @return True if the session key is active, false otherwise
     */
    function isSessionKeyActive(bytes32 keyHash) external view returns (bool) {
        return sessionKeys[keyHash].isActive;
    }

    /**
     * @notice Encodes WebAuthn signature data for use in transaction submission
     * @param requireUserVerification Whether user verification is required
     * @param authenticatorData Authenticator data from WebAuthn
     * @param clientDataJSON Client data JSON from WebAuthn
     * @param challengeIndex Index of challenge in client data
     * @param typeIndex Index of type in client data
     * @param r R component of the signature
     * @param s S component of the signature
     * @param pubKey Public key used for signing
     * @return Encoded signature data
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

    function encodeP256Signature(bytes32 r, bytes32 s, PubKey memory pubKey)
        external
        pure
        returns (bytes memory)
    {
        bytes memory inner = abi.encode(r, s, pubKey);
        return abi.encode(KeyType.P256, inner);
    }

    function encodeP256NonKeySignature(bytes32 r, bytes32 s, PubKey memory pubKey)
        external
        pure
        returns (bytes memory)
    {
        bytes memory inner = abi.encode(r, s, pubKey);
        return abi.encode(KeyType.P256NONKEY, inner);
    }

    /**
     * @notice Encodes EOA signature data for use in transaction submission
     * @param _signature Signed digest of UserOp
     * @return Encoded signature data
     */
    function encodeEOASignature(bytes calldata _signature) external pure returns (bytes memory) {
        return abi.encode(KeyType.EOA, _signature);
    }
}
