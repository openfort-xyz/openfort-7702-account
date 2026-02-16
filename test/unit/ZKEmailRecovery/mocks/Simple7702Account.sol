// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IKey} from "../interfaces/IKey.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "lib/account-abstraction/contracts/core/Helpers.sol";
import "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {IModule} from "erc7579/interfaces/IERC7579Module.sol";

/**
 * Simple7702Account7579.sol
 * An ERC-7579 compatible account to be used with EIP-7702 and ERC-4337
 * Extends Simple7702Account with module support for testing ZK-Email recovery
 *
 * This account includes an integrated validator - the account IS the validator.
 * No external MockModule dependency is needed for owner management.
 */
contract Simple7702Account is BaseAccount, IERC165, ERC1155Holder, ERC721Holder, IKey {
    error NotFromEntryPoint(address msgSender, address entity, address entryPoint);

    // 0xFA498573E46BcF22bb25F636e084AACd8C00B513
    address internal immutable MOCK_VALIDATOR_FOR_KEY_RECOVERY;
    IEntryPoint private immutable _entryPoint;

    // Module type constants
    uint256 public constant TYPE_VALIDATOR = 1;
    uint256 public constant TYPE_EXECUTOR = 2;

    // Installed modules
    mapping(uint256 moduleType => mapping(address module => bool installed)) internal
        _installedModules;

    // Owner validator (for basic validation)
    address public ownerValidator;

    // Owner key storage (integrated validator)
    Key public ownerKey;

    // Integrated validator initialization flag
    bool private _validatorInitialized;

    // Events
    event OwnerKeyChanged(address indexed account, KeyType keyType, address eoaAddress);

    constructor(IEntryPoint anEntryPoint, address _validator) {
        _entryPoint = anEntryPoint;
        MOCK_VALIDATOR_FOR_KEY_RECOVERY = _validator;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     * Make this account callable through ERC-4337 EntryPoint.
     * The UserOperation should be signed by this account's private key.
     */
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        return _checkSignature(userOpHash, userOp.signature)
            ? SIG_VALIDATION_SUCCESS
            : SIG_VALIDATION_FAILED;
    }

    function isValidSignature(bytes32 hash, bytes memory signature)
        public
        view
        virtual
        returns (bytes4 magicValue)
    {
        return _checkSignature(hash, signature) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    function _checkSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        // Decode the signature
        (, bytes memory actualSig) = abi.decode(signature, (uint8, bytes));
        return ECDSA.recover(hash, actualSig) == address(this);
    }

    function _requireForExecute() internal view virtual override {
        require(
            msg.sender == address(this) || msg.sender == address(entryPoint())
                || _installedModules[TYPE_EXECUTOR][msg.sender],
            NotFromEntryPoint(msg.sender, address(this), address(entryPoint()))
        );
    }

    // ============== ERC-7579 Module Management ==============

    /**
     * @notice Install a module on the account
     * @param moduleTypeId The type of module to install (1 = validator, 2 = executor)
     * @param module The module address
     * @param initData Initialization data for the module
     */
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        external
        payable
    {
        require(
            msg.sender == address(this) || msg.sender == address(entryPoint()),
            "Only self or entrypoint"
        );
        require(module != address(0), "Invalid module");
        require(!_installedModules[moduleTypeId][module], "Module already installed");

        _installedModules[moduleTypeId][module] = true;

        // If this is a validator being installed, set it as the owner validator
        if (moduleTypeId == TYPE_VALIDATOR && ownerValidator == address(0)) {
            ownerValidator = module;
        }

        // Call onInstall on the module
        IModule(module).onInstall(initData);
    }

    /**
     * @notice Uninstall a module from the account
     * @param moduleTypeId The type of module to uninstall
     * @param module The module address
     * @param deInitData Deinitialization data for the module
     */
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        external
        payable
    {
        require(
            msg.sender == address(this) || msg.sender == address(entryPoint()),
            "Only self or entrypoint"
        );
        require(_installedModules[moduleTypeId][module], "Module not installed");

        _installedModules[moduleTypeId][module] = false;

        if (moduleTypeId == TYPE_VALIDATOR && ownerValidator == module) {
            ownerValidator = address(0);
        }

        // Call onUninstall on the module
        IModule(module).onUninstall(deInitData);
    }

    /**
     * @notice Check if a module is installed
     * @param moduleTypeId The type of module
     * @param module The module address
     * @return bool True if the module is installed
     */
    function isModuleInstalled(
        uint256 moduleTypeId,
        address module,
        bytes calldata /*additionalContext*/
    )
        external
        view
        returns (bool)
    {
        return _installedModules[moduleTypeId][module];
    }

    // ============== ERC-7579 Execution ==============

    /**
     * @notice Execute a call from the account (ERC-7579 compatible)
     * @param executionCalldata Encoded execution data
     */
    function execute(
        bytes32,
        /*mode*/
        bytes calldata executionCalldata
    )
        external
        payable
    {
        _requireForExecute();

        // Decode based on mode - for simplicity, we handle batch mode
        Call[] memory calls = abi.decode(executionCalldata, (Call[]));

        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory result) =
                calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
        }
    }

    /**
     * @notice Execute a call from an executor module
     * @param mode Execution mode (ERC-7579)
     *        - mode[0] = callType: 0 = single, 1 = batch
     *        - mode[1] = execType: 0 = default, 1 = try
     * @param executionCalldata Encoded execution data
     *        - For single (mode[0]=0): abi.encodePacked(target, value, data) OR abi.encode(target, value, data)
     *        - For batch (mode[0]=1): abi.encode(Call[])
     * @return returnData Array of return data from each call
     */
    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        external
        payable
        returns (bytes[] memory returnData)
    {
        require(_installedModules[TYPE_EXECUTOR][msg.sender], "Not an executor");

        // Extract callType from mode (first byte)
        uint8 callType = uint8(bytes1(mode));

        if (callType == 0) {
            // Single call mode - detect format and parse accordingly
            returnData = new bytes[](1);

            address target;
            uint256 value;
            bytes memory data;

            // Detect if ABI-encoded format (first 12 bytes are zeros for address padding)
            // ABI format: abi.encode(address, uint256, bytes) - address is left-padded to 32 bytes
            // Packed format: abi.encodePacked(address, uint256, bytes) - address is 20 bytes
            bool isAbiEncoded = executionCalldata.length >= 96
                && uint96(bytes12(executionCalldata[0:12])) == 0
                && address(bytes20(executionCalldata[12:32])) != address(0);

            if (isAbiEncoded) {
                // ABI-encoded format: abi.encode(address, uint256, bytes)
                // - bytes [0:32] = padded target address
                // - bytes [32:64] = value
                // - bytes [64:96] = offset to bytes data
                // - bytes [96:128] = length of bytes data
                // - bytes [128:] = actual calldata
                target = address(bytes20(executionCalldata[12:32]));
                value = uint256(bytes32(executionCalldata[32:64]));
                // Decode the bytes parameter (starts at offset 64, which points to length at 96)
                uint256 dataOffset = uint256(bytes32(executionCalldata[64:96]));
                uint256 dataLength =
                    uint256(bytes32(executionCalldata[64 + dataOffset:96 + dataOffset]));
                data = executionCalldata[96 + dataOffset:96 + dataOffset + dataLength];
            } else {
                // Packed format per ERC-7579:
                // - bytes [0:20] = target address (20 bytes)
                // - bytes [20:52] = value (32 bytes)
                // - bytes [52:] = calldata
                require(executionCalldata.length >= 52, "Invalid single execution calldata");
                target = address(bytes20(executionCalldata[0:20]));
                value = uint256(bytes32(executionCalldata[20:52]));
                data = executionCalldata[52:];
            }

            (bool success, bytes memory result) = target.call{value: value}(data);
            if (!success) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
            returnData[0] = result;
        } else {
            // Batch call mode (callType == 1)
            Call[] memory calls = abi.decode(executionCalldata, (Call[]));
            returnData = new bytes[](calls.length);

            for (uint256 i = 0; i < calls.length; i++) {
                (bool success, bytes memory result) =
                    calls[i].target.call{value: calls[i].value}(calls[i].data);
                if (!success) {
                    assembly {
                        revert(add(result, 32), mload(result))
                    }
                }
                returnData[i] = result;
            }
        }
    }

    // ============== Account ID ==============

    function accountId() external pure returns (string memory) {
        return "openfort.simple7702.1.0.0";
    }

    // ============== Module Support Queries ==============

    function supportsExecutionMode(bytes32) external pure returns (bool) {
        return true; // Support all modes for testing
    }

    function supportsModule(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == TYPE_VALIDATOR || moduleTypeId == TYPE_EXECUTOR;
    }

    // ============== ERC-165 ==============

    function supportsInterface(bytes4 id)
        public
        pure
        virtual
        override(ERC1155Holder, IERC165)
        returns (bool)
    {
        return id == type(IERC165).interfaceId || id == type(IAccount).interfaceId
            || id == type(IERC1155Receiver).interfaceId || id == type(IERC721Receiver).interfaceId;
    }

    // Accept incoming calls (with or without value), to mimic an EOA.
    fallback() external payable {}

    receive() external payable {}

    // ============== Integrated Validator Functions ==============

    /**
     * @notice Called when this account is installed as its own validator
     * @param data Optional encoded Key struct for initial owner
     */
    function onInstall(bytes calldata data) external {
        require(!_validatorInitialized, "Validator already initialized");
        _validatorInitialized = true;

        if (data.length > 0) {
            ownerKey = abi.decode(data, (Key));
        } else {
            // Default: set account address as EOA owner
            ownerKey = Key({
                pubKey: PubKey({x: bytes32(0), y: bytes32(0)}),
                eoaAddress: address(this),
                keyType: KeyType.EOA
            });
        }

        emit OwnerKeyChanged(address(this), ownerKey.keyType, ownerKey.eoaAddress);
    }

    /**
     * @notice Called when this validator is uninstalled
     */
    function onUninstall(bytes calldata) external {
        delete ownerKey;
        _validatorInitialized = false;
    }

    /**
     * @notice Recovery function called by ZK-Email recovery module
     * @param _recoveryKey The new owner key
     */
    function startRecovery(Key memory _recoveryKey) external {
        if (msg.sender != MOCK_VALIDATOR_FOR_KEY_RECOVERY) {
            revert("Not from UNIVERSAL_EMAIL_RECOVERY_MODULE");
        }
        ownerKey = _recoveryKey;
        emit OwnerKeyChanged(address(this), _recoveryKey.keyType, _recoveryKey.eoaAddress);
    }

    /**
     * @notice Check if validator is initialized
     * @return True if the validator has been initialized
     */
    function isInitialized(address) external view returns (bool) {
        return _validatorInitialized;
    }

    /**
     * @notice Get the current owner key
     * @return The full Key struct
     */
    function getOwnerKey() external view returns (Key memory) {
        return ownerKey;
    }

    /**
     * @notice EIP-1271 signature validation with sender
     * @dev Always returns valid for testing purposes
     */
    function isValidSignatureWithSender(address, bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return 0x1626ba7e; // Always valid for testing
    }
}
