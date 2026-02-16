// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";

interface ISimple7702Account {
    function startRecovery(IKey.KeyDataReg memory _recoveryKey) external;
}

/**
 * @title MockValidator
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
contract MockValidator is IKey {
    // Track which accounts have installed this validator
    mapping(address account => bool installed) public isInstalled;

    event RecoveryForwarded(address indexed account, bytes indexed newOwner, KeyType keyType);

    function onInstall(bytes calldata) external {
        isInstalled[msg.sender] = true;
    }

    function onUninstall(bytes calldata) external {
        isInstalled[msg.sender] = false;
    }

    /**
     * @notice Called by account via executeFromExecutor during recovery
     * @dev msg.sender is the account. Forwards Key to account's startRecovery
     * @param _newOwner The new owner Key struct
     */
    function startRecovery(KeyDataReg memory _newOwner) external {
        require(isInstalled[msg.sender], "Validator not installed");

        // Forward to account's startRecovery function
        ISimple7702Account(msg.sender).startRecovery(_newOwner);

        emit RecoveryForwarded(msg.sender, _newOwner.key, _newOwner.keyType);
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
        return 0x1626ba7e; // EIP-1271 magic value
    }
}
