// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { Constants } from "./Constants.sol";
import { Contracts } from "./Contracts.t.sol";
import { ERC1967Proxy } from "lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Etch is Contracts {
    function _ethc() internal {
        // Non-proxy contracts: etch runtime bytecodes directly
        vm.etch(Constants.UNIVERSAL_EMAIL_RECOVERY_MODULE, Constants.UNIVERSAL_EMAIL_RECOVERY_MODULE_BYTECODE);
        vm.etch(Constants.EMAIL_AUTH_IMPLEMENTATION, Constants.EMAIL_AUTH_IMPLEMENTATION_BYTECODE);
        vm.etch(Constants.EMAIL_RECOVERY_COMMAND_HANDLER, Constants.EMAIL_RECOVERY_COMMAND_HANDLER_BYTECODE);
        vm.etch(Constants.GROTH16_VERIFIER, Constants.GROTH16_VERIFIER_BYTECODE);

        // Implementation bytecodes
        vm.etch(
            Constants.USER_OVERRIDEABLE_DKIM_REGISTRY_IMPLEMENTATION,
            Constants.USER_OVERRIDEABLE_DKIM_REGISTRY_BYTECODE_IMPLEMENTATION
        );
        vm.etch(Constants.VERIFIER_IMPLEMENTATION, Constants.VERIFIER_BYTECODE_IMPLEMENTATION);
        vm.etch(Constants.COMMAND_UTILS, Constants.COMMAND_UTILS_BYTECODE);
        vm.etch(Constants.STRING_UTILS, Constants.STRING_UTILS_BYTECODE);

        // Proxy contracts: the *_BYTECODE_PROXY constants contain creation code (constructor),
        // not runtime code. vm.etch requires runtime code. We etch the actual ERC1967 proxy
        // runtime bytecode and configure storage slots (implementation + initialized state).
        _setupProxy(Constants.USER_OVERRIDEABLE_DKIM_REGISTRY, Constants.USER_OVERRIDEABLE_DKIM_REGISTRY_IMPLEMENTATION);
        _setupProxy(Constants.VERIFIER, Constants.VERIFIER_IMPLEMENTATION);

        // Verifier proxy storage: slot 0 = groth16Verifier address
        // (OZ v5 OwnableUpgradeable uses ERC-7201 namespaced storage, so slot 0 is free for the contract's own state)
        vm.store(Constants.VERIFIER, bytes32(uint256(0)), bytes32(uint256(uint160(Constants.GROTH16_VERIFIER))));

        // UniversalEmailRecoveryModule inherits EmailAccountRecovery which has 3 storage variables
        // set in the constructor. vm.etch doesn't run constructors, so we set them manually:
        //   slot 0: verifierAddr
        //   slot 1: dkimAddr
        //   slot 2: emailAuthImplementationAddr
        vm.store(
            Constants.UNIVERSAL_EMAIL_RECOVERY_MODULE,
            bytes32(uint256(0)),
            bytes32(uint256(uint160(Constants.VERIFIER)))
        );
        vm.store(
            Constants.UNIVERSAL_EMAIL_RECOVERY_MODULE,
            bytes32(uint256(1)),
            bytes32(uint256(uint160(Constants.USER_OVERRIDEABLE_DKIM_REGISTRY)))
        );
        vm.store(
            Constants.UNIVERSAL_EMAIL_RECOVERY_MODULE,
            bytes32(uint256(2)),
            bytes32(uint256(uint160(Constants.EMAIL_AUTH_IMPLEMENTATION)))
        );
    }

    function _setupProxy(address proxy, address implementation) internal {
        // Etch ERC1967 proxy runtime bytecode (not creation code)
        vm.etch(proxy, type(ERC1967Proxy).runtimeCode);

        // Set ERC1967 implementation storage slot
        bytes32 implSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        vm.store(proxy, implSlot, bytes32(uint256(uint160(implementation))));

        // Mark as initialized (OZ v5 Initializable storage slot)
        // This prevents InvalidInitialization() errors and satisfies initializer-only checks
        bytes32 initSlot = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;
        vm.store(proxy, initSlot, bytes32(uint256(1)));
    }
}
