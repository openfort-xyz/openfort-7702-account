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
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "@account-abstraction/contracts/core/Helpers.sol";

/**
 * @title Openfort Base Account 7702 with ERC-4337 Support
 * @author Openfort@0xkoiner
 * @notice This contract implements an EIP-7702 compatible account with EIP-712 signatures and ERC-4337 support
 * @dev Implements EIP-7702, EIP-712, ERC-4337, and various token handling capabilities
 */
 
// keccak256("openfort.baseAccount.7702.v1") = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
contract OpenfortBaseAccount7702V1_4337 layout at 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368 is
    EIP712,
    IAccount,
    BaseAccount,
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
    // keccak256("PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)")
    bytes32 public constant USEROP_TYPEHASH = 0x58a2b86998ee046a6138be7db7c3eb3dcbdf805b51b06558cd8b18f9091af245;

    /// @notice Address of the implementation contract
    address public immutable _OPENFORT_CONTRACT_ADDRESS;

    /// @notice The EntryPoint singleton contract
    address private immutable ENTRY_POINT;

    /// @notice Current transaction nonce, used to prevent replay attacks
    uint256 public nonce;

    error OpenfortBaseAccount7702V1__InvalidNonce();
    error OpenfortBaseAccount7702V1__InvalidSignature();
    error OpenfortBaseAccount7702V1__ValidationExpired();
    error OpenfortBaseAccount7702V1__InvalidTransactionLength();
    error OpenfortBaseAccount7702V1__InvalidTransactionTarget();
    error OpenfortBaseAccount7702V1__TransactionFailed(bytes returnData);
    error OpenfortBaseAccount7702V1__InsufficientFunds();
    error OpenfortBaseAccount7702V1__WithdrawFailed();

    /// @notice Emitted when the account is initialized with an owner
    event Initialized(address indexed owner);

    /// @notice Emitted when a transaction is executed
    event TransactionExecuted(address indexed target, uint256 value, bytes data);

    /// @notice Emitted when deposit is added for gas fees
    event DepositAdded(address indexed source, uint256 amount);

    /// @notice Emitted when funds are withdrawn
    event FundsWithdrawn(address indexed to, uint256 amount);

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

        _clearStorage();
        _validateNonceDirect(_nonce);
        _notExpired(_validUntil);

        if (!_checkSignature(userOpHash, _signature)) {
            revert OpenfortBaseAccount7702V1__InvalidSignature();
        }

        initializeOwner(_owner);

        nonce++;

        emit Initialized(_owner);
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

        return _checkSignature(userOpHash, userOp.signature) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Implements EIP-1271 signature validation
     * @param hash Hash that was signed
     * @param signature Signature to verify
     * @return magicValue Magic value indicating whether signature is valid
     */
    function isValidSignature(bytes32 hash, bytes memory signature) public view returns (bytes4 magicValue) {
        return _checkSignature(hash, signature) ? this.isValidSignature.selector : bytes4(0xffffffff);
    }

    /**
     * @notice Verifies a signature
     * @param hash Hash that was signed
     * @param signature Signature to verify
     * @return True if signature is valid
     */
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
    function _validateNonceDirect(uint256 _nonce) internal view {
        if (_nonce == nonce) {
            revert OpenfortBaseAccount7702V1__InvalidNonce();
        }
    }

   /**
     * @notice Get userOp hash according to EIP-712
     * @param _userOp The user operation
     * @return The EIP-712 hash of the user operation
     */
    function getUserOpHash(PackedUserOperation calldata _userOp) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    USEROP_TYPEHASH,
                    _userOp.sender,
                    _userOp.nonce,
                    keccak256(_userOp.initCode),
                    keccak256(_userOp.callData),
                    _userOp.accountGasLimits,
                    _userOp.preVerificationGas,
                    _userOp.gasFees,
                    keccak256(_userOp.paymasterAndData)
                )
            )
        );
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

}