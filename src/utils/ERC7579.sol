// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {BaseOPF7702} from "src/core/BaseOPF7702.sol";
import {EnumerableSetLib} from "lib/solady/src/utils/EnumerableSetLib.sol";

interface IERC7579Module {
    function isModuleType(uint256 _moduleTypeId) external pure returns (bool);
    function onInstall(bytes calldata) external;
    function onUninstall(bytes calldata) external;
}

abstract contract ERC7579 is BaseOPF7702 {
    using EnumerableSetLib for *;

    /// @dev The module type is not supported.
    error ERC7579UnsupportedModuleType(uint256 moduleTypeId);
    /// @dev The provided module doesn't match the provided module type.
    error ERC7579MismatchedModuleTypeId(uint256 moduleTypeId, address module);
    /// @dev The module is already installed.
    error ERC7579AlreadyInstalledModule(uint256 moduleTypeId, address module);
    /// @dev The module is not installed.
    error ERC7579UninstalledModule(uint256 moduleTypeId, address module);

    uint256 constant VALIDATION_SUCCESS = 0;
    uint256 constant VALIDATION_FAILED = 1;
    uint256 constant MODULE_TYPE_VALIDATOR = 1;
    uint256 constant MODULE_TYPE_EXECUTOR = 2;
    uint256 constant MODULE_TYPE_FALLBACK = 3;
    uint256 constant MODULE_TYPE_HOOK = 4;

    EnumerableSetLib.AddressSet internal _validators;
    EnumerableSetLib.AddressSet internal _executors;

    event ModuleInstalled(uint256 moduleTypeId, address module);
    event ModuleUninstalled(uint256 moduleTypeId, address module);

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        public
        virtual
    {
        _requireForExecute();
        _installModule(moduleTypeId, module, initData);
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        public
        virtual
    {
        _requireForExecute();
        _uninstallModule(moduleTypeId, module, deInitData);
    }

    function _installModule(uint256 moduleTypeId, address module, bytes memory initData)
        internal
        virtual
    {
        if (!supportsModule(moduleTypeId)) {
            revert ERC7579UnsupportedModuleType(moduleTypeId);
        }
        if (!IERC7579Module(module).isModuleType(moduleTypeId)) {
            revert ERC7579MismatchedModuleTypeId(moduleTypeId, module);
        }

        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            require(_validators.add(module), ERC7579AlreadyInstalledModule(moduleTypeId, module));
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            require(_executors.add(module), ERC7579AlreadyInstalledModule(moduleTypeId, module));
        }

        emit ModuleInstalled(moduleTypeId, module);

        IERC7579Module(module).onInstall(initData);
    }

    function _uninstallModule(uint256 moduleTypeId, address module, bytes memory deInitData)
        internal
        virtual
    {
        if (!supportsModule(moduleTypeId)) revert ERC7579UnsupportedModuleType(moduleTypeId);

        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            require(_validators.remove(module), ERC7579UninstalledModule(moduleTypeId, module));
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            require(_executors.remove(module), ERC7579UninstalledModule(moduleTypeId, module));
        }

        emit ModuleUninstalled(moduleTypeId, module);

        IERC7579Module(module).onUninstall(deInitData);
    }

    function isModuleInstalled(uint256 moduleTypeId, address module)
        public
        view
        virtual
        returns (bool)
    {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) return _validators.contains(module);
        if (moduleTypeId == MODULE_TYPE_EXECUTOR) return _executors.contains(module);
        return false;
    }

    function supportsModule(uint256 moduleTypeId) public view virtual returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR || moduleTypeId == MODULE_TYPE_EXECUTOR;
    }
}
