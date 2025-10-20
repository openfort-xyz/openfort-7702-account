// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {IOPF7702Recoverable} from "src/interfaces/IOPF7702Recoverable.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

contract OPF7702RecoverableTest is Deploy {
    error GasPolicy__InitializationIncorrect();
    error OpenfortBaseAccount7702V1__InvalidSignature();
    error OPF7702Recoverable__AddressCantBeZero();

    PubKey internal pK;

    function test_RevretOPF7702Recoverable_InsecurePeriodAndGasPolicy__InitializationIncorrect()
        external
    {
        vm.startPrank(sender);

        entryPoint = IEntryPoint(payable(ENTRYPOINT_V8));
        webAuthn = WebAuthnVerifierV2(payable(WEBAUTHN_VERIFIER));
        vm.expectRevert(GasPolicy__InitializationIncorrect.selector);
        gasPolicy = new GasPolicy(0, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        recoveryManager = new SocialRecoveryManager(
            RECOVERY_PERIOD, LOCK_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW
        );

        implementation = new OPF7702(
            address(entryPoint), WEBAUTHN_VERIFIER, address(gasPolicy), address(recoveryManager)
        );

        vm.stopPrank();
    }

    function test_RevertOpenfortBaseAccount7702V1__InvalidSignature() external {
        vm.startPrank(sender);

        entryPoint = IEntryPoint(payable(ENTRYPOINT_V8));
        webAuthn = WebAuthnVerifierV2(payable(WEBAUTHN_VERIFIER));
        gasPolicy = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        recoveryManager = new SocialRecoveryManager(
            RECOVERY_PERIOD, LOCK_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW
        );

        _createInitialGuradian();

        implementation = new OPF7702(
            address(entryPoint), WEBAUTHN_VERIFIER, address(gasPolicy), address(recoveryManager)
        );

        erc20 = new MockERC20();

        _etch();

        vm.stopPrank();

        _createQuickFreshKey(true);
        _createQuickFreshKey(false);

        bytes memory mkDataEnc = abi.encode(
            mkReg.keyType,
            mkReg.validUntil,
            mkReg.validAfter,
            mkReg.limits,
            mkReg.key,
            mkReg.keyControl
        );

        bytes memory skDataEnc = abi.encode(
            skReg.keyType,
            skReg.validUntil,
            skReg.validAfter,
            skReg.limits,
            skReg.key,
            skReg.keyControl
        );

        bytes32 structHash =
            keccak256(abi.encode(INIT_TYPEHASH, mkDataEnc, skDataEnc, _initialGuardian));

        string memory name = "OPF7702Recoverable";
        string memory version = "0";

        bytes32 domainSeparator = keccak256(
            abi.encode(
                TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1__InvalidSignature.selector);
        vm.prank(owner);
        account.initialize(mkReg, skReg, sig, _initialGuardian);
    }

    function test_RevertOPF7702Recoverable__AddressCantBeZero() external {
        vm.startPrank(sender);

        entryPoint = IEntryPoint(payable(ENTRYPOINT_V8));
        webAuthn = WebAuthnVerifierV2(payable(WEBAUTHN_VERIFIER));
        gasPolicy = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        recoveryManager = new SocialRecoveryManager(
            RECOVERY_PERIOD, LOCK_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW
        );

        _createInitialGuradian();

        implementation = new OPF7702(
            address(entryPoint), WEBAUTHN_VERIFIER, address(gasPolicy), address(recoveryManager)
        );

        erc20 = new MockERC20();

        _etch();

        vm.stopPrank();

        _createInitialGuradian();

        _populateWebAuthn("eth.json", ".eth");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );
        _createQuickFreshKey(false);

        bytes memory mkDataEnc = abi.encode(
            mkReg.keyType,
            mkReg.validUntil,
            mkReg.validAfter,
            mkReg.limits,
            mkReg.key,
            mkReg.keyControl
        );

        bytes memory skDataEnc = abi.encode(
            skReg.keyType,
            skReg.validUntil,
            skReg.validAfter,
            skReg.limits,
            skReg.key,
            skReg.keyControl
        );

        bytes32 structHash = keccak256(abi.encode(INIT_TYPEHASH, mkDataEnc, skDataEnc, bytes32(0)));

        string memory name = "OPF7702Recoverable";
        string memory version = "1";

        bytes32 domainSeparator = keccak256(
            abi.encode(
                TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        _etch();
        vm.expectRevert(OPF7702Recoverable__AddressCantBeZero.selector);
        vm.prank(owner);
        account.initialize(mkReg, skReg, sig, bytes32(0));
    }
}
