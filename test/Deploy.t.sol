// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {BaseData} from "././BaseData.t.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract Deploy is BaseData {
    string internal RPC_URL = vm.envString("SEPOLIA_RPC_URL");
    uint256 internal forkId;

    function setUp() public virtual {
        (owner, ownerPK) = makeAddrAndKey("owner");
        (sender, senderPK) = makeAddrAndKey("sender");
        (sessionKey, sessionKeyPK) = makeAddrAndKey("sessionKey");
        (guardian, guardianPK) = makeAddrAndKey("GUARDIAN_EOA_ADDRESS");

        forkId = vm.createFork(RPC_URL);
        vm.selectFork(forkId);

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

        _deal();

        vm.prank(sender);
        entryPoint.depositTo{value: 1e18}(owner);
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

    function _getNonce() internal view returns (uint256) {
        return entryPoint.getNonce(owner, 1);
    }

    function _populateUserOp(
        PackedUserOperation memory _userOp,
        bytes memory _callData,
        bytes32 _accountGasLimits,
        uint256 _preVerificationGas,
        bytes32 _gasFees,
        bytes memory _paymasterAndData
    ) internal view returns (PackedUserOperation memory) {
        _userOp.nonce = entryPoint.getNonce(owner, 1);
        _userOp.callData = _callData;
        _userOp.accountGasLimits = _accountGasLimits;
        _userOp.preVerificationGas = _preVerificationGas;
        _userOp.gasFees = _gasFees;
        _userOp.paymasterAndData = _paymasterAndData;

        return _userOp;
    }

    function _getUserOpHash(PackedUserOperation memory _userOp)
        internal
        view
        returns (bytes32 hash)
    {
        hash = entryPoint.getUserOpHash(_userOp);
    }

    function _signUserOp(PackedUserOperation memory _userOp)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 userOpHash = _getUserOpHash(_userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, userOpHash);
        signature = abi.encodePacked(r, s, v);
    }

    function _signUserOp(PackedUserOperation memory _userOp, uint256 _pK)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 userOpHash = _getUserOpHash(_userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pK, userOpHash);
        signature = abi.encodePacked(r, s, v);
    }

    function _signUserOpWithSK(PackedUserOperation memory _userOp)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 userOpHash = _getUserOpHash(_userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPK, userOpHash);
        signature = abi.encodePacked(r, s, v);
    }

    function _encodeEOASignature(bytes memory _signature) internal pure returns (bytes memory) {
        return abi.encode(KeyType.EOA, _signature);
    }

    function _encodeWebAuthnSignature(
        bool requireUserVerification,
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint256 challengeIndex,
        uint256 typeIndex,
        bytes32 r,
        bytes32 s,
        PubKey memory pubKey
    ) internal pure returns (bytes memory) {
        bytes memory inner = abi.encode(
            requireUserVerification,
            authenticatorData,
            clientDataJSON,
            challengeIndex,
            typeIndex,
            r,
            s,
            pubKey
        );

        return abi.encode(KeyType.WEBAUTHN, inner);
    }

    function _encodeP256Signature(bytes32 r, bytes32 s, PubKey memory pubKey, KeyType _keyType)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory inner = abi.encode(r, s, pubKey);
        return abi.encode(_keyType, inner);
    }

    function _getSignedUserOpByWebAuthn(WebAuthn memory _wA, PubKey memory _pK_)
        internal
        pure
        returns (bytes memory signature)
    {
        signature = _encodeWebAuthnSignature(
            _wA.UVR,
            _wA.AUTHENTICATOR_DATA,
            _wA.CLIENT_DATA_JSON,
            _wA.CHALLENGE_INDEX,
            _wA.TYPE_INDEX,
            _wA.R,
            _wA.S,
            _pK_
        );
    }

    function _callRecoveryManager(bytes memory data) internal {
        Call[] memory calls = new Call[](1);
        calls[0] = _createCall(address(recoveryManager), 0, data);

        _etch();
        vm.prank(owner);
        account.execute(mode_1, abi.encode(calls));
    }

    function _proposeGuardian(bytes32 guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            SocialRecoveryManager.proposeGuardian.selector, address(account), guardian
        );
        _callRecoveryManager(data);
    }

    function _confirmGuardian(bytes32 guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            SocialRecoveryManager.confirmGuardianProposal.selector, address(account), guardian
        );
        _callRecoveryManager(data);
    }

    function _cancelGuardianProposal(bytes32 guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            SocialRecoveryManager.cancelGuardianProposal.selector, address(account), guardian
        );
        _callRecoveryManager(data);
    }

    function _revokeGuardian(bytes32 guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            SocialRecoveryManager.revokeGuardian.selector, address(account), guardian
        );
        _callRecoveryManager(data);
    }

    function _confirmGuardianRevocation(bytes32 guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            SocialRecoveryManager.confirmGuardianRevocation.selector, address(account), guardian
        );
        _callRecoveryManager(data);
    }

    function _cancelGuardianRevocation(bytes32 guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            SocialRecoveryManager.cancelGuardianRevocation.selector, address(account), guardian
        );
        _callRecoveryManager(data);
    }

    function _cancelRecovery() internal {
        bytes memory data =
            abi.encodeWithSelector(SocialRecoveryManager.cancelRecovery.selector, address(account));
        _callRecoveryManager(data);
    }
}
