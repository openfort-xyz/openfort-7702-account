// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {BaseData} from "././BaseData.t.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

contract Deploy is BaseData {
    string internal RPC_URL = vm.envString("SEPOLIA_RPC_URL");
    uint256 internal forkId;

    function setUp() public virtual {
        (owner, ownerPK) = makeAddrAndKey("owner");
        (sender, senderPK) = makeAddrAndKey("sender");
        (sessionKey, sessionKeyPK) = makeAddrAndKey("sessionKey");
        (guardian, guardianPK) = makeAddrAndKey("GUARDIAN_EOA_ADDRESS");
        _deal();

        forkId = vm.createFork(RPC_URL);
        vm.selectFork(forkId);

        vm.startPrank(sender);

        entryPoint = IEntryPoint(payable(ENTRYPOINT_V8));
        webAuthn = WebAuthnVerifierV2(payable(WEBAUTHN_VERIFIER));
        gasPolicy = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);

        _createInitialGuradian();

        implementation = new OPF7702(
            address(entryPoint),
            WEBAUTHN_VERIFIER,
            RECOVERY_PERIOD,
            LOCK_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            address(gasPolicy)
        );

        erc20 = new MockERC20();

        _etch();

        vm.stopPrank();
    }

    function _etch() internal {
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(implementation)));
        account = OPF7702(payable(owner));
    }

    function test_AfterDeploy7702() external view {
        assertEq(address(entryPoint), address(implementation.entryPoint()));
        assertEq(WEBAUTHN_VERIFIER, implementation.webAuthnVerifier());
        assertEq(address(gasPolicy), implementation.gasPolicy());
        assertEq(address(implementation), implementation._OPENFORT_CONTRACT_ADDRESS());
    }

    function test_Attched7702() external view {
        bytes memory code = owner.code;
        bytes memory designator = abi.encodePacked(bytes3(0xef0100), address(implementation));

        assertEq(code, designator);
    }

    function _quickInitializeAccount() internal {
        _createQuickFreshKey(true);
        _createQuickFreshKey(false);
    }

    function _initializeAccount() internal {
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
        string memory version = "1";

        bytes32 domainSeparator = keccak256(
            abi.encode(
                TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(owner);
        account.initialize(mkReg, skReg, sig, _initialGuardian);
    }
}
