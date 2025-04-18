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
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 * @title Openfort Base Account 7702
 * @author Openfort@0xkoiner
 * @notice This contract implements an EIP-7702 compatible smart contract account
 * @dev Implements EIP-7702 (account abstraction) and various token callback handlers.
 *      Uses a fixed storage layout at a predetermined slot.
 */

// keccak256("openfort.baseAccount.7702.v1") = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
contract OpenfortBaseAccount7702V1 layout at 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368 is 
    Ownable7702, 
    Initializable, 
    ReentrancyGuard, 
    TokenCallbackHandler 
{
    /**
     * @notice Structure for representing a transaction to be executed by the account
     * @dev Contains destination address, ETH value, and calldata
     */
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
    }
    
    /// @notice Address of the implementation contract
    address public immutable _OPENFORT_CONTRACT_ADDRESS;

    /// @notice Current transaction nonce, used to prevent replay attacks
    uint256 public nonce;

    /// @notice Error thrown when an invalid nonce is provided
    error OpenfortBaseAccount7702V1__InvalidNonce();
    /// @notice Error thrown when the signature verification fails
    error OpenfortBaseAccount7702V1__InvalidSignature();
    /// @notice Error thrown when the validation has expired
    error OpenfortBaseAccount7702V1__ValidationExpired();
    /// @notice Error thrown when the transaction list has an invalid length
    error OpenfortBaseAccount7702V1__InvalidTransactionLength();
    /// @notice Error thrown when a transaction targets the account itself
    error OpenfortBaseAccount7702V1__InvalidTransactionTarget();
    /// @notice Error thrown when a transaction execution fails
    error OpenfortBaseAccount7702V1__TransactionFailed(bytes returnData);

    /// @notice Emitted when the account is initialized with an owner
    event Initialized(address indexed owner);
    /// @notice Emitted when a transaction is executed
    event TransactionExecuted(address indexed target, uint256 value, bytes data);

    /**
     * @notice Sets up the contract and disables initializers
     * @dev Sets the OpenfortContract address to this contract's address and disables initializers
     */
    constructor() {
        _OPENFORT_CONTRACT_ADDRESS = address(this);
        _disableInitializers();
    }

    /// @notice Allows the contract to receive ETH
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

        address signer = ECDSA.recover(
            keccak256(abi.encode(_owner, _validation.nonce, _validation.validUntil, keccak256("initialize"), _OPENFORT_CONTRACT_ADDRESS, block.chainid)),
            _validation.v, _validation.r, _validation.s
        );

        if (signer != address(this)) {
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
     * @notice Clears the contract's storage slots for reinitialization
     * @dev Uses inline assembly to directly clear storage at specific slots
     */
    function _clearStorage() internal {
        bytes32 baseSlot = keccak256("openfort.baseAccount.7702.v1");
        
        for (uint256 i = 0; i < 4; i++) {
            bytes32 slot = bytes32(uint256(baseSlot) + i);
            assembly {
                sstore(slot, 0)
            }
        }
    }
}