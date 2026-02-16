// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "../interfaces/IKeyV2.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "lib/account-abstraction/contracts/core/Helpers.sol";
import "lib/account-abstraction/contracts/core/BaseAccount.sol";

/**
 * @title Simple7702AccountIndi
 * @notice Non-ERC7579 account that intercepts executeFromExecutor for ZK-Email recovery
 * @dev Instead of forwarding to an external validator, this account directly decodes
 *      the KeyDataReg from the execution calldata and updates masterKeyData.
 *
 * Flow:
 * 1. Recovery module calls account.executeFromExecutor(mode, executionCalldata)
 * 2. executionCalldata is abi.encodePacked(target, value, abi.encodeWithSelector(selector, keyDataReg))
 *    - bytes [0:20]  = target address (20 bytes)
 *    - bytes [20:52]  = value (32 bytes)
 *    - bytes [52:56]  = function selector (4 bytes)
 *    - bytes [56:]    = abi.encode(KeyDataReg)
 * 3. Account decodes KeyDataReg from offset 56 and updates masterKeyData
 */
contract Simple7702AccountIndi is BaseAccount, IERC165, ERC1155Holder, ERC721Holder, IKeyV2 {
    address internal constant UNIVERSAL_EMAIL_RECOVERY_MODULE =
        0x636632FA22052d2a4Fb6e3Bab84551B620b9C1F9;

    IEntryPoint private immutable _entryPoint;

    KeyData public masterKeyData;

    error NotFromEntryPoint(address msgSender, address entity, address entryPoint);

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

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

    function _checkSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        (, bytes memory actualSig) = abi.decode(signature, (uint8, bytes));
        return ECDSA.recover(hash, actualSig) == address(this);
    }

    function _requireForExecute() internal view virtual override {
        require(
            msg.sender == address(this) || msg.sender == address(entryPoint()),
            NotFromEntryPoint(msg.sender, address(this), address(entryPoint()))
        );
    }

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

    fallback() external payable {}

    receive() external payable {}

    function executeFromExecutor(
        bytes32, /*mode*/
        bytes calldata executionCalldata
    ) external returns (bytes[] memory empty) {
        if (msg.sender != UNIVERSAL_EMAIL_RECOVERY_MODULE) {
            revert("Only Universal Email Recovery Module can call recovery");
        }

        KeyDataReg memory keyDataReg = abi.decode(executionCalldata[56:], (KeyDataReg));

        _recovery(keyDataReg);

        empty = new bytes[](1);
    }

    function _recovery(KeyDataReg memory _keyDataReg) internal {
        KeyData storage sKey = masterKeyData;
        sKey.keyType = _keyDataReg.keyType;
        sKey.isActive = true;
        sKey.masterKey = true;
        sKey.isDelegatedControl = false;
        sKey.validUntil = type(uint48).max;
        sKey.validAfter = 0;
        sKey.limits = 0;
        sKey.key = _keyDataReg.key;
    }

    function isModuleInstalled(uint256, address, bytes calldata) external view returns (bool) {
        if (msg.sender != UNIVERSAL_EMAIL_RECOVERY_MODULE) {
            return false;
        }
        return true;
    }
}
