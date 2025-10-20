// SPDX-Lincese-Identifier: MIT
pragma solidity 0.8.29;

import {BaseData} from "./../BaseData.t.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";
import {LibEIP7702} from "lib/solady/src/accounts/LibEIP7702.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract Upgrade7702 is BaseData {
    address proxy;

    function setUp() public {
        (owner, ownerPK) = makeAddrAndKey("owner");
        (sender, senderPK) = makeAddrAndKey("sender");

        entryPoint = IEntryPoint(payable(ENTRYPOINT_V8));
        webAuthn = WebAuthnVerifierV2(payable(WEBAUTHN_VERIFIER));
        gasPolicy = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        recoveryManager = new SocialRecoveryManager(
            RECOVERY_PERIOD, LOCK_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW
        );

        implementation = new OPF7702(
            address(entryPoint), WEBAUTHN_VERIFIER, address(gasPolicy), address(recoveryManager)
        );

        proxy = LibEIP7702.deployProxy(address(implementation), address(0));

        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), proxy));
        account = OPF7702(payable(owner));
    }

    function test_Attched7702() external view {
        bytes memory code = owner.code;
        bytes memory designator = abi.encodePacked(bytes3(0xef0100), proxy);
        assertEq(code, designator);
    }

    function test_AfterDeploy7702Proxy() external view {
        assertEq(address(entryPoint), address(implementation.entryPoint()));
        assertEq(WEBAUTHN_VERIFIER, implementation.webAuthnVerifier());
        assertEq(address(gasPolicy), implementation.gasPolicy());
        assertEq(address(implementation), implementation._OPENFORT_CONTRACT_ADDRESS());
    }

    function test_upgradeProxyDelegation() external {
        address newImpl = address(
            new OPF7702(
                address(entryPoint), WEBAUTHN_VERIFIER, address(gasPolicy), address(recoveryManager)
            )
        );
        address oldImpl = account._OPENFORT_CONTRACT_ADDRESS();

        vm.prank(owner);
        account.upgradeProxyDelegation(newImpl);

        address afterUpg = account._OPENFORT_CONTRACT_ADDRESS();
        assert(afterUpg != oldImpl);
    }
}
