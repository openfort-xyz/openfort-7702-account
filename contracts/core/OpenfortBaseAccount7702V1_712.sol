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

import {Ownable7702} from "contracts/access/Ownable7702.sol";
import {IValidation} from "contracts/interfaces/IValidation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TokenCallbackHandler} from "contracts/core/TokenCallbackHandler.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 * @title Openfort Base Account 7702
 * @author Openfort@0xkoiner
 * @notice This contract implements an EIP-7702 compatible account with EIP-712 signatures
 * @dev Implements EIP-7702 (account abstraction), EIP-712 (typed data hashing and signing), 
 *      and various token callback handlers. Uses a fixed storage layout at a predetermined slot.
 */
 
// keccak256("openfort.baseAccount.7702.v1") = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
contract OpenfortBaseAccount7702V1_712 layout at 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368 is
    EIP712,
    Ownable7702, 
    Initializable, 
    ReentrancyGuard, 
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

    /// @notice TypeHash used for EIP-712 signature verification
    // keccak256("Validation712(uint256 nonce,uint256 validUntil,address openfortContract)")
    bytes32 public constant VALIDATION_TYPEHASH = 0x75cf993678be57bd60fb75e5ecd3d66109483a36f06dafaef84d8b83b48e139a;

    /// @notice Address of the implementation contract
    address public immutable _OPENFORT_CONTRACT_ADDRESS;

    /// @notice Current transaction nonce, used to prevent replay attacks
    uint256 public nonce;

    error OpenfortBaseAccount7702V1__InvalidNonce();
    error OpenfortBaseAccount7702V1__InvalidSignature();
    error OpenfortBaseAccount7702V1__ValidationExpired();
    error OpenfortBaseAccount7702V1__InvalidTransactionLength();
    error OpenfortBaseAccount7702V1__InvalidTransactionTarget();
    error OpenfortBaseAccount7702V1__TransactionFailed(bytes returnData);

    /// @notice Emitted when the account is initialized with an owner
    event Initialized(address indexed owner);

    /// @notice Emitted when a transaction is executed
    event TransactionExecuted(address indexed target, uint256 value, bytes data);

    /**
     * @notice Sets up the contract with EIP-712 domain and disables initializers
     * @dev Sets the OpenfortContract address to this contract's address and disables initializers
     */
    constructor() EIP712("OpenfortBaseAccount7702V1", "1") {
        _OPENFORT_CONTRACT_ADDRESS = address(this);
        _disableInitializers();
    }

    receive() external payable {}

    /**
     * @notice Initializes the account with an owner and validates the signature
     * @dev Clears storage, validates nonce and expiration, verifies signature, sets owner
     * @param _owner The address to set as the owner of this account
     * @param _validation The validation struct containing signature and validation data
     */
    function initialize(address _owner, IValidation.Validation calldata _validation) external initializer {
        _clearStorage();
        _validateNonce(_validation.nonce);
        _notExpired(_validation.validUntil);

        if (!_isValidateSignature(_validation)) {
            revert OpenfortBaseAccount7702V1__InvalidSignature();
        }

        initializeOwner(_owner);

        nonce++;

        emit Initialized(_owner);
    }

    /**
     * @notice Executes a batch of transactions if called by the owner
     * @dev Applies reentrancy guard and owner check, verifies transaction count and targets
     * @param _transactions An array of transactions to execute
     */
    function execute(Transaction[] calldata _transactions) payable external nonReentrant onlyOwner {
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
    function _validateNonce(uint256 _nonce) internal view {
        if (_nonce == nonce) {
            revert OpenfortBaseAccount7702V1__InvalidNonce();
        }
    }

    /**
     * @notice Validates that the signature was signed by this contract
     * @dev Uses EIP-712 and ECDSA to recover the signer from the signature
     * @param _validation The validation struct containing the signature
     * @return bool True if the signature is valid, false otherwise
     */
    function _isValidateSignature(IValidation.Validation calldata _validation) internal view returns (bool) {
        (address recoveredSigner, ,) = ECDSA.tryRecover(getHashMessage(_validation), _validation.v, _validation.r, _validation.s);
        return recoveredSigner == address(this);
    }

    /**
     * @notice Gets the EIP-712 typed data hash for signature verification
     * @dev Combines VALIDATION_TYPEHASH with validation data using EIP-712 encoding
     * @param _validation The validation struct
     * @return bytes32 The hash to be signed
     */
    function getHashMessage(IValidation.Validation calldata _validation) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    VALIDATION_TYPEHASH,
                    _validation.nonce,
                    _validation.validUntil,
                    _OPENFORT_CONTRACT_ADDRESS
                )
            )
        );
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
}