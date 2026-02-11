// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IKey} from "./IKey.sol";

/// @title IValidator
/// @author 0xKoiner@openfort
/// @notice Interface for the external Validator contract used in ZK-Email recovery flows.
interface IValidator {
    event RecoveryForwarded(address indexed account, bytes indexed newOwnerKey, IKey.KeyType keyType);

    function isInstalled(address account) external view returns (bool);

    function onInstall(bytes calldata) external;

    function onUninstall(bytes calldata) external;

    function completeRecovery(IKey.KeyDataReg memory _newOwnerKey) external;
}
