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

import {Execution} from "src/core/Execution.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCESS,
    _packValidationData
} from "lib/account-abstraction/contracts/core/Helpers.sol";

/**
 * @title Openfort Base Account 7702 with ERC-4337 Support
 * @author Openfort@0xkoiner
 * @notice This contract implements an EIP-7702 compatible account with EIP-712 signatures and ERC-4337 support
 * @dev Implements EIP-7702, EIP-712, ERC-4337, and various token handling capabilities
 */

// address: 0xD24af0109E31F238440E2d6A6d49935d499274b7 14/05/2025
// keccak256("openfort.baseAccount.7702.v1") = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368 == 57943590311362240630886240343495690972153947532773266946162183175043753177960
contract OPF7702 is Execution, Initializable, WebAuthnVerifier layout at 57943590311362240630886240343495690972153947532773266946162183175043753177960 {
    using ECDSA for bytes32;

    /// @notice Address of the implementation contract
    address public immutable _OPENFORT_CONTRACT_ADDRESS;

    /// @notice Emitted when the account is initialized with an masterKey
    event Initialized(Key indexed masterKey);

    /**
     * @notice Sets up the contract with EIP-712 domain and the EntryPoint
     * @param _entryPoint Address of the ERC-4337 EntryPoint contract
     */
    constructor(address _entryPoint) {
        ENTRY_POINT = _entryPoint;
        _OPENFORT_CONTRACT_ADDRESS = address(this);
        _disableInitializers();
    }

    /**
     * @notice Initializes the account
     * @dev Can only be called via EntryPoint or during contract creation
     * @param _validUntil The timestamp until which the initialization is valid
     * @param _hash Hash of the user operation
     * @param _signature Signature to validate ownership
     * @param _nonce Nonce to prevent replay attacks
     */
    function initialize(
        Key calldata _key,
        SpendTokenInfo calldata _spendTokenInfo,
        bytes4[] calldata _allowedSelectors,
        bytes32 _hash,
        bytes memory _signature,
        uint256 _validUntil,
        uint256 _nonce
    ) external initializer {
        _requireForExecute();
        _clearStorage();
        _validateNonce(_nonce);
        _notExpired(_validUntil);

        if (!_checkSignature(_hash, _signature)) {
            revert OpenfortBaseAccount7702V1__InvalidSignature();
        }

        nonce = _nonce;
        // Todo: Ask Jaume if its good to do the MK with endless time
        registerSessionKey(
            _key,
            type(uint48).max,
            uint48(0),
            uint48(0),
            false,
            DEAD_ADDRESS,
            _spendTokenInfo,
            _allowedSelectors,
            0
        );

        emit Initialized(_key);
    }

    /**
     * @notice ERC-4337 signature validation
     * @dev Validates the signature for a user operation
     * @param userOp The user operation to validate
     * @param userOpHash Hash of the user operation
     * @return validationData Packed validation data (success, validUntil, validAfter) or SIG_VALIDATION_SUCCESS | SIG_VALIDATION_FAILED
     */
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        (KeyType sigType, bytes memory sigData) = abi.decode(userOp.signature, (KeyType, bytes));

        if (sigType == KeyType.EOA) {
            bytes memory signature = sigData;

            address signer = ECDSA.recover(userOpHash, signature);

            if (address(this) == signer) return 0;

            SessionKey storage sKey = sessionKeysEOA[signer];

            PubKey memory _pubKey = PubKey({x: sKey.pubKey.x, y: sKey.pubKey.y});
            Key memory _key = Key({pubKey: _pubKey, eoaAddress: signer, keyType: KeyType.EOA});

            if (isValidSessionKey(_key, userOp.callData)) {
                return _packValidationData(false, sKey.validUntil, sKey.validAfter);
            }
        } else if (sigType == KeyType.WEBAUTHN) {
            (
                ,
                bool requireUserVerification,
                bytes memory authenticatorData,
                string memory clientDataJSON,
                uint256 challengeIndex,
                uint256 typeIndex,
                bytes32 r,
                bytes32 s,
                PubKey memory pubKey
            ) = abi.decode(
                userOp.signature,
                (KeyType, bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey)
            );

            if (usedChallenges[userOpHash]) return SIG_VALIDATION_FAILED;

            bool isValid = verifySoladySignature(
                userOpHash,
                requireUserVerification,
                authenticatorData,
                clientDataJSON,
                challengeIndex,
                typeIndex,
                r,
                s,
                pubKey.x,
                pubKey.y
            );

            if (!isValid) return SIG_VALIDATION_FAILED;

            bytes32 keyHash = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
            SessionKey storage sKey = sessionKeys[keyHash];

            Key memory _key = Key({
                pubKey: PubKey({x: sKey.pubKey.x, y: sKey.pubKey.y}),
                eoaAddress: address(0),
                keyType: KeyType.WEBAUTHN
            });

            if (sKey.masterSessionKey) return 0;

            if (isValidSessionKey(_key, userOp.callData)) {
                usedChallenges[userOpHash] = true;
                return _packValidationData(false, sKey.validUntil, sKey.validAfter);
            }
        } else if (sigType == KeyType.P256 || sigType == KeyType.P256NONKEY) {
            (bytes32 r, bytes32 s, PubKey memory pubKey) =
                abi.decode(sigData, (bytes32, bytes32, PubKey));

            if (usedChallenges[userOpHash]) return SIG_VALIDATION_FAILED;

            if (sigType == KeyType.P256NONKEY) {
                userOpHash = EfficientHashLib.sha2(userOpHash);
            }

            bool isValid = verifyP256Signature(userOpHash, r, s, pubKey.x, pubKey.y);

            if (!isValid) return SIG_VALIDATION_FAILED;

            bytes32 keyHash = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
            SessionKey storage sKey = sessionKeys[keyHash];

            Key memory _key = Key({
                pubKey: PubKey({x: sKey.pubKey.x, y: sKey.pubKey.y}),
                eoaAddress: address(0),
                keyType: KeyType.P256
            });

            if (sKey.masterSessionKey) return 0;

            if (isValidSessionKey(_key, userOp.callData)) {
                usedChallenges[userOpHash] = true;
                return _packValidationData(false, sKey.validUntil, sKey.validAfter);
            }
        }

        return SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Validates if a session key is allowed to execute the given call data
     * @param _key Key information
     * @param _callData Call data to be executed
     * @return True if the session key is allowed to execute the call, false otherwise
     */
    function isValidSessionKey(Key memory _key, bytes calldata _callData)
        internal
        virtual
        returns (bool)
    {
        // 1. Get the session key based on key type
        SessionKey storage sessionKey;

        if (_key.keyType == KeyType.WEBAUTHN) {
            bytes32 keyHash = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
            sessionKey = sessionKeys[keyHash];
        } else if (_key.keyType == KeyType.P256 || _key.keyType == KeyType.P256NONKEY) {
            bytes32 keyHash = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
            sessionKey = sessionKeys[keyHash];
        } else if (_key.keyType == KeyType.EOA) {
            if (_key.eoaAddress == address(0)) return false;
            sessionKey = sessionKeysEOA[_key.eoaAddress];
        } else {
            return false;
        }

        // 2. Basic validation for all key types
        if (sessionKey.validUntil == 0 || !sessionKey.isActive) return false;
        if (sessionKey.whoRegistrated != address(this)) return false;
        // 3. Extract function selector from callData
        bytes4 funcSelector = bytes4(_callData[:4]);

        // 4. Handle EXECUTE_SELECTOR
        if (funcSelector == EXECUTE_SELECTOR) {
            return _validateExecuteCall(sessionKey, _callData);
        }
        // 5. Handle EXECUTEBATCH_SELECTOR
        if (funcSelector == EXECUTEBATCH_SELECTOR) {
            return _validateExecuteBatchCall(sessionKey, _callData);
        }

        return false;
    }

    /**
     * @notice Validates a single execute call
     * @param sessionKey Session key data
     * @param _callData Call data to validate
     * @return True if the call is valid, false otherwise
     */
    function _validateExecuteCall(SessionKey storage sessionKey, bytes calldata _callData)
        internal
        returns (bool)
    {
        // Decode the execute call parameters
        address toContract;
        bytes memory innerData;
        uint256 amount;
        (toContract, amount, innerData) = abi.decode(_callData[4:], (address, uint256, bytes));

        // Basic validation
        if (toContract == address(this)) return false;
        if (sessionKey.masterSessionKey) return true;
        if (sessionKey.limit == 0) return false;
        if (sessionKey.ethLimit < amount) return false;

        // Validate selector
        bytes4 innerSelector = bytes4(innerData);

        if (!_isAllowedSelector(sessionKey.allowedSelectors, innerSelector)) {
            return false;
        }

        // Update limits
        unchecked {
            sessionKey.limit--;
        }
        if (amount > 0) sessionKey.ethLimit = sessionKey.ethLimit - amount;

        // Handle token spend limits
        if (sessionKey.spendTokenInfo.token == toContract) {
            bool validSpend = _validateTokenSpend(sessionKey, innerData);
            if (!validSpend) return false;
        }

        // Check whitelisting
        if (!sessionKey.whitelisting || sessionKey.whitelist[toContract]) {
            return true;
        }
        return false;
    }

    /**
     * @notice Validates a batch of execute calls
     * @param sessionKey Session key data
     * @param _callData Call data containing batch execution data
     * @return True if all calls in the batch are valid, false otherwise
     */
    function _validateExecuteBatchCall(SessionKey storage sessionKey, bytes calldata _callData)
        internal
        returns (bool)
    {
        // Decode the batch call parameters
        (address[] memory toContracts, uint256[] memory amounts, bytes[] memory innerDataArray) =
            abi.decode(_callData[4:], (address[], uint256[], bytes[]));

        uint256 numberOfInteractions = toContracts.length;
        if (numberOfInteractions > 9) return false;

        // Check if session key has enough limit for all interactions
        if (!sessionKey.masterSessionKey) {
            if (sessionKey.limit < numberOfInteractions) return false;
            unchecked {
                sessionKey.limit = sessionKey.limit - SafeCast.toUint48(numberOfInteractions);
            }
        }

        // Validate each interaction
        for (uint256 i = 0; i < numberOfInteractions; ++i) {
            if (toContracts[i] == address(this)) return false;

            if (!sessionKey.masterSessionKey) {
                // Validate selector
                bytes4 innerSelector = bytes4(innerDataArray[i]);
                if (!_isAllowedSelector(sessionKey.allowedSelectors, innerSelector)) {
                    return false;
                }

                // Check ETH limit
                if (sessionKey.ethLimit < amounts[i]) return false;
                if (amounts[i] > 0) sessionKey.ethLimit = sessionKey.ethLimit - amounts[i];

                // Handle token spend limits
                if (sessionKey.spendTokenInfo.token == toContracts[i]) {
                    bool validSpend = _validateTokenSpend(sessionKey, innerDataArray[i]);
                    if (!validSpend) return false;
                }

                // Check whitelisting
                if (sessionKey.whitelisting && !sessionKey.whitelist[toContracts[i]]) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @notice Validates token spending against limits
     * @param sessionKey Session key data
     * @param innerData Call data containing token transfer details
     * @return True if the token spend is valid, false otherwise
     */
    function _validateTokenSpend(SessionKey storage sessionKey, bytes memory innerData)
        internal
        override
        returns (bool)
    {
        uint256 startPos = innerData.length - 32;
        bytes32 value;
        assembly {
            value := mload(add(add(innerData, 0x20), startPos))
        }

        if (uint256(value) > sessionKey.spendTokenInfo.limit) return false;

        if (uint256(value) > 0) {
            sessionKey.spendTokenInfo.limit = sessionKey.spendTokenInfo.limit - uint256(value);
        }

        return true;
    }

    /**
     * @notice Checks if a function selector is in the allowed list
     * @param selectors List of allowed selectors
     * @param selector Selector to check
     * @return True if the selector is allowed, false otherwise
     */
    function _isAllowedSelector(bytes4[] storage selectors, bytes4 selector)
        internal
        view
        returns (bool)
    {
        for (uint256 i = 0; i < selectors.length; ++i) {
            if (selectors[i] == selector) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Implements EIP-1271 signature validation
     * @param _hash Hash that was signed
     * @param _signature Signature to verify
     * @return magicValue Magic value indicating whether signature is valid
     */
    function isValidSignature(bytes32 _hash, bytes memory _signature)
        public
        view
        returns (bytes4 magicValue)
    {
        uint256 key;
        assembly {
            key := mload(add(_signature, 32))
        }

        if (key == uint256(KeyType.WEBAUTHN)) {
            return _validateWebAuthnSignature(_signature, _hash);
        } else if (key == uint256(KeyType.P256) || key == uint256(KeyType.P256NONKEY)) {
            return _validateP256Signature(_signature, _hash);
        } else if (_signature.length == 64 || _signature.length == 65) {
            address signer = ECDSA.recover(_hash, _signature);

            if (address(this) == signer) return this.isValidSignature.selector;
            SessionKey storage sessionKey = sessionKeysEOA[signer];

            if (
                sessionKey.validUntil == 0 || sessionKey.validAfter > block.timestamp
                    || sessionKey.validUntil < block.timestamp
                    || (!sessionKey.masterSessionKey && sessionKey.limit < 1)
            ) {
                return bytes4(0xffffffff);
            } else if (sessionKey.whoRegistrated != address(this)) {
                return bytes4(0xffffffff);
            } else {
                return this.isValidSignature.selector;
            }
        }

        return bytes4(0xffffffff);
    }

    /**
     * @notice Internal function to validate WebAuthn signatures
     * @param _signature WebAuthn signature data
     * @return Magic value if the signature is valid, otherwise 0xffffffff
     */
    function _validateWebAuthnSignature(bytes memory _signature, bytes32 _hash)
        internal
        view
        returns (bytes4)
    {
        (
            ,
            bool requireUserVerification,
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeIndex,
            uint256 typeIndex,
            bytes32 r,
            bytes32 s,
            PubKey memory pubKey
        ) = abi.decode(
            _signature, (KeyType, bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey)
        );

        if (usedChallenges[_hash]) return bytes4(0xffffffff);

        bool isValid = verifySoladySignature(
            _hash,
            requireUserVerification,
            authenticatorData,
            clientDataJSON,
            challengeIndex,
            typeIndex,
            r,
            s,
            pubKey.x,
            pubKey.y
        );

        if (!isValid) return bytes4(0xffffffff);

        bytes32 keyHash = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
        SessionKey storage sessionKey = sessionKeys[keyHash];

        if (
            sessionKey.validUntil == 0 || sessionKey.validAfter > block.timestamp
                || sessionKey.validUntil < block.timestamp
                || (!sessionKey.masterSessionKey && sessionKey.limit < 1)
        ) {
            return bytes4(0xffffffff);
        } else if (sessionKey.whoRegistrated != address(this)) {
            return bytes4(0xffffffff);
        } else {
            return this.isValidSignature.selector;
        }
    }

    function _validateP256Signature(bytes memory _signature, bytes32 _hash)
        internal
        view
        returns (bytes4)
    {
        (KeyType key, bytes memory inner) = abi.decode(_signature, (KeyType, bytes));

        (bytes32 r, bytes32 s, PubKey memory pubKey) = abi.decode(inner, (bytes32, bytes32, PubKey));

        if (usedChallenges[_hash]) return bytes4(0xffffffff);

        if (key == KeyType.P256NONKEY) {
            _hash = EfficientHashLib.sha2(_hash);
        }

        bool isValid = verifyP256Signature(_hash, r, s, pubKey.x, pubKey.y);

        if (!isValid) return bytes4(0xffffffff);

        bytes32 keyHash = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
        SessionKey storage sessionKey = sessionKeys[keyHash];

        if (
            sessionKey.validUntil == 0 || sessionKey.validAfter > block.timestamp
                || sessionKey.validUntil < block.timestamp
                || (!sessionKey.masterSessionKey && sessionKey.limit < 1)
        ) {
            return bytes4(0xffffffff);
        } else if (sessionKey.whoRegistrated != address(this)) {
            return bytes4(0xffffffff);
        } else {
            return this.isValidSignature.selector;
        }
    }

    function _checkSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return ECDSA.recover(hash, signature) == address(this);
    }
}
