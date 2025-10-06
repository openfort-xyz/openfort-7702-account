// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract BaseOPF7702Test is Deploy {
    PubKey internal pK;
    PubKey internal pK_SK;

    function setUp() public virtual override {
        super.setUp();
        _populateWebAuthn("execution.json", ".batch");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );
        _createQuickFreshKey(false);

        _initializeAccount();
    }

    function test_RevertKeyManager__InvalidSignatureLengthEOA() external {
        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        Call[] memory calls = _getCalls(1, address(erc20), 0, data);
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = abi.encodePacked(_encodeEOASignature(signature), keccak256("more-bytes"));

        bytes32 userOpHash = _getUserOpHash(userOp);

        vm.expectRevert(KeyManager__InvalidSignatureLength.selector);
        _sendUserOp(userOp, userOpHash);
    }

    function test_RevertKeyManager__InvalidSignatureLengthP256() external {
        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        Call[] memory calls = _getCalls(1, address(erc20), 0, data);
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        userOp.signature = abi.encodePacked(
            _encodeP256Signature(DEF_P256.R, DEF_P256.S, pK_SK, KeyType.P256),
            keccak256("more-bytes")
        );

        bytes32 userOpHash = _getUserOpHash(userOp);

        vm.expectRevert(KeyManager__InvalidSignatureLength.selector);
        _sendUserOp(userOp, userOpHash);
    }

    function test_FullisValidSignatureEOA() external view {
        Call[] memory calls = _getCalls(1, address(123456), 0.1 ether, hex"");

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);
        bytes32 userOpHash = _getUserOpHash(userOp);

        bytes4 res = account.isValidSignature(userOpHash, signature);

        assertEq(res, this.isValidSignature.selector);

        signature = hex"aa";
        res = account.isValidSignature(userOpHash, signature);
        assertEq(res, bytes4(0xffffffff));

        signature = _signUserOp(userOp);
        res = account.isValidSignature((keccak256("a")), signature);
        assertEq(res, bytes4(0xffffffff));

        signature = abi.encode(
            DEF_WEBAUTHN.UVR,
            DEF_WEBAUTHN.AUTHENTICATOR_DATA,
            DEF_WEBAUTHN.CLIENT_DATA_JSON,
            DEF_WEBAUTHN.CHALLENGE_INDEX,
            DEF_WEBAUTHN.TYPE_INDEX,
            DEF_WEBAUTHN.R,
            DEF_WEBAUTHN.S,
            pK
        );

        userOpHash = 0x61d7d1b953d3350007a9cca8c4bba96fb75e181067523c598a3c6d893f1d09ae;

        res = account.isValidSignature(userOpHash, signature);
        assertEq(res, this.isValidSignature.selector);

        res = account.isValidSignature(userOpHash, abi.encode(KeyType.EOA, signature));
        assertEq(res, bytes4(0xffffffff));

        res = account.isValidSignature((keccak256("a")), signature);
        assertEq(res, bytes4(0xffffffff));
    }

    function _sendUserOp(PackedUserOperation memory _userOp, bytes32 _userOpHash) internal {
        _etch();
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(_userOp, _userOpHash, 0);
    }

    function _relayUserOp(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }

    function isValidSignature(bytes32 _hash, bytes memory _signature)
        external
        view
        returns (bytes4)
    {}
}
