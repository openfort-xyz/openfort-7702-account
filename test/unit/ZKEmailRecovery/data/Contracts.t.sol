//SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Constants} from "./Constants.sol";
import {Test} from "lib/forge-std/src/Test.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {EmailAuth} from "node_modules/@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import {IUserOverrideableDKIMRegistry} from "../interfaces/IUserOverrideableDKIMRegistry.sol";
import {ERC1967Proxy} from "lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {
    EmailRecoveryUniversalFactory
} from "zk-email-recovery-contracts/email-recovery/src/factories/EmailRecoveryUniversalFactory.sol";
import {
    EmailRecoveryCommandHandler
} from "zk-email-recovery-contracts/email-recovery/src/handlers/EmailRecoveryCommandHandler.sol";
import {
    UniversalEmailRecoveryModule
} from "zk-email-recovery-contracts/email-recovery/src/modules/UniversalEmailRecoveryModule.sol";

abstract contract Contracts is Test {
    EntryPoint internal entryPoint;
    WebAuthnVerifierV2 public webAuthn;

    EmailRecoveryUniversalFactory internal emailRecoveryUniversalFactory;
    UniversalEmailRecoveryModule internal universalEmailRecoveryModule;
    ERC1967Proxy internal userOverrideableDKIMRegistry;
    IUserOverrideableDKIMRegistry internal dkimRegistry;
    ERC1967Proxy internal verifier;
    EmailAuth internal emailAuthMsg;
    EmailRecoveryCommandHandler internal emailRecoveryCommandHandler;

    function _initExistContracts() internal {
        entryPoint = EntryPoint(payable(Constants.ENTRY_POINT_9));
        webAuthn = WebAuthnVerifierV2(payable(Constants.WEBAUTHN_VERIFIER));
        emailRecoveryUniversalFactory =
            EmailRecoveryUniversalFactory(payable(Constants.EMAIL_RECOVERY_UNIVERSAL_FACTORY));
        universalEmailRecoveryModule =
            UniversalEmailRecoveryModule(payable(Constants.UNIVERSAL_EMAIL_RECOVERY_MODULE));
        userOverrideableDKIMRegistry =
            ERC1967Proxy(payable(Constants.USER_OVERRIDEABLE_DKIM_REGISTRY));
        dkimRegistry = IUserOverrideableDKIMRegistry(Constants.USER_OVERRIDEABLE_DKIM_REGISTRY);
        verifier = ERC1967Proxy(payable(Constants.VERIFIER));
        emailAuthMsg = EmailAuth(payable(Constants.EMAIL_AUTH_IMPLEMENTATION));
        emailRecoveryCommandHandler =
            EmailRecoveryCommandHandler(payable(Constants.EMAIL_RECOVERY_COMMAND_HANDLER));
    }

    function _labelContracts() internal {
        vm.label(Constants.ENTRY_POINT_9, "EntryPoint-V9");
        vm.label(Constants.EMAIL_RECOVERY_UNIVERSAL_FACTORY, "Email-Recovery-Universal-Factory");
        vm.label(Constants.UNIVERSAL_EMAIL_RECOVERY_MODULE, "Universal-Email-Recovery-Module");
        vm.label(Constants.USER_OVERRIDEABLE_DKIM_REGISTRY, "User-Overrideable-DKIM-Registry");
        vm.label(Constants.VERIFIER, "Verifier");
        vm.label(Constants.EMAIL_AUTH_IMPLEMENTATION, "Email-Auth");
        vm.label(Constants.EMAIL_RECOVERY_COMMAND_HANDLER, "Email-Recovery-Command-Handler");
    }
}
