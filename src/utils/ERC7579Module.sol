/*
░  ░░░░  ░░░      ░░░  ░░░░░░░░        ░░       ░░░░      ░░░        ░░░      ░░░       ░░
▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒
▓▓  ▓▓  ▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓  ▓▓       ▓▓
███    ████        ██  ███████████  █████  ████  ██        █████  █████  ████  ██  ███  ██
████  █████  ████  ██        ██        ██       ███  ████  █████  ██████      ███  ████  █
*/

// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IKey} from "../interfaces/IKey.sol";

interface IOPF7702Account {
    function completeRecovery(IKey.KeyDataReg memory _recoveryKey) external;
}

/**
 * @title ERC7579Module
 * @author 0xKoiner@openfort
 * @notice External validator that forwards startRecovery(Key) to account
 * @dev Allows passing full Key struct during ZK-Email recovery
 *
 * Flow:
 * 1. Recovery module calls account.executeFromExecutor(...)
 * 2. Account calls this.startRecovery(Key) with msg.sender = account
 * 3. This contract forwards to account.startRecovery(Key)
 *
 * Why external validator?
 * The deployed UniversalEmailRecoveryModule has a security restriction:
 * - When validator == account: Only Safe selectors allowed (swapOwner, addOwner, etc.)
 * - When validator != account: Any selector allowed except onInstall/onUninstall/0x00
 *
 * By using an external validator, we can use startRecovery(Key) selector!
 */
contract ERC7579Module {
    uint256 constant MODULE_TYPE_VALIDATOR = 1;
    uint256 constant MODULE_TYPE_EXECUTOR = 2;

    // Track which accounts have installed this validator
    mapping(address account => bool installed) public isInstalled;

    event RecoveryForwarded(
        address indexed account, bytes indexed newOwnerKey, IKey.KeyType keyType
    );

    function onInstall(bytes calldata) external {
        isInstalled[msg.sender] = true;
    }

    function onUninstall(bytes calldata) external {
        isInstalled[msg.sender] = false;
    }

    function isModuleType(uint256 _moduleTypeId) external pure returns (bool) {
        return _moduleTypeId == MODULE_TYPE_VALIDATOR || _moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    /**
     * @notice Called by account via executeFromExecutor during recovery
     * @dev msg.sender is the account. Forwards Key to account's startRecovery
     * @param _newOwnerKey The new owner KeyDataReg struct
     */
    function completeRecovery(IKey.KeyDataReg memory _newOwnerKey) external {
        require(isInstalled[msg.sender], "Validator not installed");

        emit RecoveryForwarded(msg.sender, _newOwnerKey.key, _newOwnerKey.keyType);

        IOPF7702Account(msg.sender).completeRecovery(_newOwnerKey);
    }
}
