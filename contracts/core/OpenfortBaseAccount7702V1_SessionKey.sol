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

import {SpendLimit} from "contracts/utils/SpendLimit.sol";
import {Ownable7702} from "contracts/access/Ownable7702.sol";
import {IValidation} from "contracts/interfaces/IValidation.sol";
import {ISessionKey} from "contracts/interfaces/ISessionkey.sol";
import {WebAuthnVerifier} from "contracts/utils/WebAuthnVerifier.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TokenCallbackHandler} from "contracts/core/TokenCallbackHandler.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS, _packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";

/**
 * @title Openfort Base Account 7702 with ERC-4337 Support
 * @author Openfort@0xkoiner
 * @notice This contract implements an EIP-7702 compatible account with EIP-712 signatures and ERC-4337 support
 * @dev Implements EIP-7702, EIP-712, ERC-4337, and various token handling capabilities
 */
 
// keccak256("openfort.baseAccount.7702.v1") = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
contract OpenfortBaseAccount7702V1SessionKey layout at 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368 is
    EIP712,
    IAccount,
    SpendLimit,
    BaseAccount,
    ISessionKey,
    Ownable7702, 
    Initializable, 
    ReentrancyGuard, 
    WebAuthnVerifier,
    TokenCallbackHandler
{
    using ECDSA for bytes32;

    /**
     * @notice Structure for representing a transaction to be executed by the account
     * @dev Contains destination address, ETH value, and calldata
     */
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
    }

    uint256 public constant MAX_SELECTORS = 10;
    bytes4 internal constant EXECUTE_SELECTOR = 0xb61d27f6;
    bytes4 internal constant EXECUTEBATCH_SELECTOR = 0x47e1da2a;
    bytes32 private constant P256_VERIFIER = 0x2562256225622562256225622562256225622562256225622562256225622562;

    /// @notice TypeHash used for EIP-712 signature verification
    // keccak256("PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)")
    bytes32 public constant USEROP_TYPEHASH = 0x58a2b86998ee046a6138be7db7c3eb3dcbdf805b51b06558cd8b18f9091af245;

    /// @notice Address of the implementation contract
    address public immutable _OPENFORT_CONTRACT_ADDRESS;

    /// @notice The EntryPoint singleton contract
    address private immutable ENTRY_POINT;

    /// @notice Current transaction nonce, used to prevent replay attacks
    uint256 public nonce;

    uint256 private id;
    mapping(uint256 id => Key key) public idSessionKeys;
    mapping(bytes32 sessionKey => SessionKey sessionKeyData) public sessionKeys;
    mapping(address sessionKeyEOA => SessionKey sessionKeyData) public sessionKeysEOA;
    mapping(bytes challenge => bool isUsed) public usedChallenges;

    error OpenfortBaseAccount7702V1__InvalidNonce();
    error OpenfortBaseAccount7702V1__InvalidSignature();
    error OpenfortBaseAccount7702V1__ValidationExpired();
    error OpenfortBaseAccount7702V1__InvalidTransactionLength();
    error OpenfortBaseAccount7702V1__InvalidTransactionTarget();
    error OpenfortBaseAccount7702V1__TransactionFailed(bytes returnData);
    error OpenfortBaseAccount7702V1__WithdrawFailed();

    error SessionKeyManager__InvalidTimestamp();
    error SessionKeyManager__AddressCantBeZero();
    error SessionKeyManager__SessionKeyInactive();
    error SessionKeyManager__SelectorsListTooBig();
    error SessionKeyManager__SessionKeyRegistered();

    /// @notice Emitted when the account is initialized with an owner
    event Initialized(address indexed owner);

    /// @notice Emitted when a transaction is executed
    event TransactionExecuted(address indexed target, uint256 value, bytes data);

    /// @notice Emitted when deposit is added for gas fees
    event DepositAdded(address indexed source, uint256 amount);

    /// @notice Emitted when funds are withdrawn
    event FundsWithdrawn(address indexed to, uint256 amount);

    event SessionKeyRevoked(bytes32 indexed sessionKey);
    event SessionKeyRegistrated(bytes32 indexed sessionKey);

    /**
     * @notice Sets up the contract with EIP-712 domain and the EntryPoint
     * @param _entryPoint Address of the ERC-4337 EntryPoint contract
     */
    constructor(address _entryPoint) EIP712("OpenfortBaseAccount7702V1", "1") {
        ENTRY_POINT = _entryPoint;
        _OPENFORT_CONTRACT_ADDRESS = address(this);
        _disableInitializers();
    }

    receive() external payable {
        // This allows the contract to receive ETH
        emit DepositAdded(msg.sender, msg.value);
    }
    
    /**
     * @notice Initializes the account with an owner
     * @dev Can only be called via EntryPoint or during contract creation
     * @param _owner The address to set as owner
     * @param _validUntil The timestamp until which the initialization is valid
     * @param userOpHash Hash of the user operation
     * @param _signature Signature to validate ownership
     * @param _nonce Nonce to prevent replay attacks
     */
    function initialize(address _owner, uint256 _validUntil, bytes32 userOpHash, bytes calldata _signature, uint256 _nonce) external initializer {
        /// Todo: _requireForExecute(); how posible to create here who will send the init?>
        /// Todo: register session key during initilize?
        _requireForExecute();
        _clearStorage();
        _validateNonce(_nonce);
        _notExpired(_validUntil);

        if (!_checkSignature(userOpHash, _signature)) {
            revert OpenfortBaseAccount7702V1__InvalidSignature();
        }

        initializeOwner(_owner);

        nonce++;

        emit Initialized(_owner);
    }

   
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
    ) external {
        _requireForExecute();
        if (_validUntil <= block.timestamp) revert SessionKeyManager__InvalidTimestamp();
        if (_validAfter > _validUntil) revert SessionKeyManager__InvalidTimestamp();

        idSessionKeys[id] = _key;
        id++;

        if (_key.keyType == KeyType.WEBAUTHN) {
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

            emit SessionKeyRegistrated(keyHash);
        } else if (_key.keyType == KeyType.EOA) {
            if (_key.eoaAddress == address(0)) revert SessionKeyManager__AddressCantBeZero();
            if (sessionKeysEOA[_key.eoaAddress].isActive) revert SessionKeyManager__SessionKeyRegistered();

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
        sKey.whoRegistrated = owner();

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
        if (_key.keyType == KeyType.WEBAUTHN) {
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
        for (uint256 i = 0; i < id; i++) {
            Key memory _key = getKeyById(i);

            if (_key.keyType == KeyType.WEBAUTHN) {
                bytes32 keyHash = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
                SessionKey storage sKey = sessionKeys[keyHash];
                _revokeSessionKey(sKey);
                emit SessionKeyRevoked(keyHash);
            } else if (_key.keyType == KeyType.EOA) {
                if (_key.eoaAddress == address(0)) continue;
                SessionKey storage sKey = sessionKeysEOA[_key.eoaAddress];
                _revokeSessionKey(sKey);
                emit SessionKeyRevoked(keccak256(abi.encodePacked(_key.eoaAddress)));
            }
        }
    }

   /**
     * @notice Executes a batch of transactions
     * @dev Can only be called via EntryPoint or by self
     * @param _transactions Array of transactions to execute
     */
    function execute(Transaction[] calldata _transactions) payable external nonReentrant {
        _requireForExecute();
        if (_transactions.length == 0 || _transactions.length > 9) {
            revert OpenfortBaseAccount7702V1__InvalidTransactionLength();
        }

        uint256 transactionsLength = _transactions.length;
        Transaction calldata transactionCall;

        for (uint256 i = 0; i < transactionsLength; i++) {
            transactionCall = _transactions[i];
            address target = transactionCall.to;
            uint256 value = transactionCall.value;
            bytes memory data = transactionCall.data;

            if (target == address(this)) {
                revert OpenfortBaseAccount7702V1__InvalidTransactionTarget();
            }

            (bool success, bytes memory returnData) = target.call{value: value}(data);
            
            if (!success) {
                revert OpenfortBaseAccount7702V1__TransactionFailed(returnData);
            }

            emit TransactionExecuted(target, value, data);      
        }
    }

    /**
     * @notice ERC-4337 signature validation
     * @dev Validates the signature for a user operation
     * @param userOp The user operation to validate
     * @param userOpHash Hash of the user operation
     * @return validationData Packed validation data (success, validUntil, validAfter) or SIG_VALIDATION_SUCCESS | SIG_VALIDATION_FAILED
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData) {
        (KeyType sigType, bytes memory sigData) = abi.decode(userOp.signature, (KeyType, bytes));

        if (sigType == KeyType.EOA) {
            bytes memory signature = sigData;
            bytes32 structHash = keccak256(abi.encode(USEROP_TYPEHASH, userOpHash));
            bytes32 digest = _hashTypedDataV4(structHash);
            address signer = digest.recover(signature);

            if (owner() == signer) return 0;

            SessionKey storage sKey = sessionKeysEOA[signer];
            
            PubKey memory _pubKey = PubKey({x: sKey.pubKey.x, y: sKey.pubKey.y});
            Key memory _key = Key({pubKey: _pubKey, eoaAddress: signer, keyType: KeyType.EOA});

            if (isValidSessionKey(_key, userOp.callData)) {
                return _packValidationData(false, sKey.validUntil, sKey.validAfter);
            }
        } else if (sigType == KeyType.WEBAUTHN) {
            (
                ,
                bytes memory challenge,
                bool requireUserVerification,
                bytes memory authenticatorData,
                string memory clientDataJSON,
                uint256 challengeIndex,
                uint256 typeIndex,
                bytes32 r,
                bytes32 s,
                PubKey memory pubKey
            ) = abi.decode(userOp.signature, (KeyType, bytes, bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey));

            if (usedChallenges[challenge]) return SIG_VALIDATION_FAILED;

            bool isValid = verifySoladySignature(
                challenge,
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

            if (isValidSessionKey(_key, userOp.callData)) {
                usedChallenges[challenge] = true;
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
    function isValidSessionKey(Key memory _key, bytes calldata _callData) internal virtual returns (bool) {
        // 1. Get the session key based on key type
        SessionKey storage sessionKey;
        if (_key.keyType == KeyType.WEBAUTHN) {
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
        if (sessionKey.whoRegistrated != owner()) return false;

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
    function _validateExecuteCall(SessionKey storage sessionKey, bytes calldata _callData) internal returns (bool) {
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
    function _isAllowedSelector(bytes4[] storage selectors, bytes4 selector) internal view returns (bool) {
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
    function isValidSignature(bytes32 _hash, bytes memory _signature) public view returns (bytes4 magicValue) {
        if (_hash == P256_VERIFIER && _signature.length > 65) {
            uint256 key;
            assembly {
                key := mload(add(_signature, 32))
            }

            if (key == uint256(KeyType.WEBAUTHN)) {
                return _validateWebAuthnSignature(_signature);
            }
        } else if (_signature.length == 64 || _signature.length == 65) {
            bytes32 structHash = keccak256(abi.encode(USEROP_TYPEHASH, _hash));
            bytes32 digest = _hashTypedDataV4(structHash);
            address signer = digest.recover(_signature);

            if (owner() == signer) return this.isValidSignature.selector;
            SessionKey storage sessionKey = sessionKeysEOA[signer];

            if (
                sessionKey.validUntil == 0 || sessionKey.validAfter > block.timestamp
                    || sessionKey.validUntil < block.timestamp || (!sessionKey.masterSessionKey && sessionKey.limit < 1)
            ) {
                return bytes4(0xffffffff);
            } else if (sessionKey.whoRegistrated != owner()) {
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
    function _validateWebAuthnSignature(bytes memory _signature) internal view returns (bytes4) {

        (
            KeyType sigType,
            bytes memory challenge,
            bool requireUserVerification,
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeIndex,
            uint256 typeIndex,
            bytes32 r,
            bytes32 s,
            PubKey memory pubKey
        ) = abi.decode(_signature, (KeyType, bytes, bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey));

        if (sigType != KeyType.WEBAUTHN) {
            return bytes4(0xffffffff);
        }

        if (usedChallenges[challenge]) return bytes4(0xffffffff);

        bool isValid = verifySoladySignature(
            challenge,
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
                || sessionKey.validUntil < block.timestamp || (!sessionKey.masterSessionKey && sessionKey.limit < 1)
        ) {
            return bytes4(0xffffffff);
        } else if (sessionKey.whoRegistrated != owner()) {
            return bytes4(0xffffffff);
        } else {
            return this.isValidSignature.selector;
        }
    }

    function _checkSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return ECDSA.recover(hash, signature) == address(this);
    }
    
    /**
     * @notice Verifies that the validation has not expired
     * @dev Compares current timestamp with validUntil timestamp
     * @param _validUntil The timestamp until which the validation is valid
     */
    function _notExpired(uint256 _validUntil) internal view {
        if (block.timestamp > _validUntil) {
            revert OpenfortBaseAccount7702V1__ValidationExpired();
        }
    }

    /**
     * @notice Validates that the provided nonce is not equal to the current nonce
     * @dev Ensures nonce is different to prevent replay attacks
     * @param _nonce The nonce to validate
     */
    function _validateNonce(uint256 _nonce) internal override view {
        if (_nonce == nonce) {
            revert OpenfortBaseAccount7702V1__InvalidNonce();
        }
    }

    /**
    * @notice Calculates the hash of a user operation
    * @param userOp User operation to hash
    * @return Hash of the user operation for signing
    */
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                USEROP_TYPEHASH,
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.accountGasLimits,
                userOp.preVerificationGas,
                userOp.gasFees,
                keccak256(userOp.paymasterAndData)
            )
        );

        return _hashTypedDataV4(structHash);
    }

    /**
    * @notice Calculates the digest to be signed for a hash
    * @param hash Hash to convert to a digest
    * @return EIP-712 typed data digest
    */
    function getDigestToSign(bytes32 hash) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(USEROP_TYPEHASH, hash));
        return _hashTypedDataV4(structHash);
    }

    /**
     * @notice Return the EntryPoint used by this account
     * @return The EntryPoint contract
     */
    function entryPoint() public view override returns (IEntryPoint) {
        return IEntryPoint(ENTRY_POINT);
    }

    /**
     * @notice Check if caller is authorized to execute functions
     * @dev Only self-calls and EntryPoint calls are allowed
     */
    function _requireForExecute() internal view virtual override {
        require(
            msg.sender == address(this) ||
            msg.sender == address(entryPoint()),
            "not from self or EntryPoint"
        );
    }

    /**
     * @notice Add deposit for gas payments
     * @dev Deposits ETH to the EntryPoint to pay for user operations
     */
    function addDeposit() external payable {
        IEntryPoint(ENTRY_POINT).depositTo{value: msg.value}(address(this));
        emit DepositAdded(msg.sender, msg.value);
    }

    /**
     * @notice Get the account's deposit in the EntryPoint
     * @return The deposit amount
     */
    function getDeposit() external view returns (uint256) {
        return IEntryPoint(ENTRY_POINT).balanceOf(address(this));
    }

    /**
     * @notice Withdraw funds from the EntryPoint
     * @param to Address to withdraw to
     * @param amount Amount to withdraw
     */
    function withdrawDepositTo(address payable to, uint256 amount) external onlyOwner {
        // Withdraw funds from EntryPoint
        // This requires implementation in the EntryPoint contract
        // For now, we can manually handle direct withdrawal
        
        (bool success,) = to.call{value: amount}("");
        if (!success) {
            revert OpenfortBaseAccount7702V1__WithdrawFailed();
        }
        
        emit FundsWithdrawn(to, amount);
    }

    /**
     * @notice Clears the contract's storage slots for reinitialization
     * @dev Uses inline assembly to directly clear storage at specific slots
     */
    function _clearStorage() internal {
        bytes32 baseSlot = keccak256("openfort.baseAccount.7702.v1");
        
        for (uint256 i = 2; i < 5; i++) {
            bytes32 slot = bytes32(uint256(baseSlot) + i);
            assembly {
                sstore(slot, 0)
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
    function getKeyRegistrationInfo(uint256 _id)
        external
        view
        returns (KeyType keyType, address registeredBy, bool isActive)
    {
        Key memory key = getKeyById(_id);
        if (key.keyType == KeyType.WEBAUTHN) {
            bytes32 keyHash = keccak256(abi.encodePacked(key.pubKey.x, key.pubKey.y));
            return (key.keyType, sessionKeys[keyHash].whoRegistrated, sessionKeys[keyHash].isActive);
        } else if (key.keyType == KeyType.EOA) {
            return (key.keyType, sessionKeysEOA[key.eoaAddress].whoRegistrated, sessionKeysEOA[key.eoaAddress].isActive);
        }
        return (key.keyType, address(0), false);
    }

    /**
     * @notice Retrieves key information by ID
     * @param _id ID of the key to retrieve
     * @return Key information
     */
    function getKeyById(uint256 _id) public view returns (Key memory) {
        Key storage _key = idSessionKeys[_id];
        return _key;
    }

    /**
     * @notice Retrieves session key data for a WebAuthn key
     * @param _keyHash Hash of the WebAuthn public key
     * @return isActive Whether the key is active
     * @return validUntil Timestamp until which the key is valid
     * @return validAfter Timestamp after which the key becomes valid
     * @return limit Number of transactions allowed
     */
    function getSessionKeyData(bytes32 _keyHash) external view returns (bool, uint48, uint48, uint48) {
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
     * @param challenge Challenge that was signed
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
        bytes memory challenge,
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
            challenge,
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
     * @notice Encodes EOA signature data for use in transaction submission
     * @param _signature Signed digest of UserOp
     * @return Encoded signature data
     */
    function encodeEOASignature(bytes calldata _signature) external pure returns (bytes memory) {
        return abi.encode(KeyType.EOA, _signature);
    }
}