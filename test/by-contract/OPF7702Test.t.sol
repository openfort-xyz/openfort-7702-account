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

        userOpHash = 0xb3dc75bdf6e0365104000f50a3e9c7c6cb96a8729b2ef110f284e8dc9084f6a7;

        res = account.isValidSignature(userOpHash, signature);
        assertEq(res, this.isValidSignature.selector);

        res = account.isValidSignature(userOpHash, abi.encode(KeyType.EOA, signature));
        assertEq(res, bytes4(0xffffffff));

        res = account.isValidSignature((keccak256("a")), signature);
        assertEq(res, bytes4(0xffffffff));

        signature = abi.encode(
            DEF_WEBAUTHN.UVR,
            DEF_WEBAUTHN.AUTHENTICATOR_DATA,
            DEF_WEBAUTHN.CLIENT_DATA_JSON,
            DEF_WEBAUTHN.CHALLENGE_INDEX,
            DEF_WEBAUTHN.TYPE_INDEX,
            keccak256("R"),
            DEF_WEBAUTHN.S,
            pK
        );

        res = account.isValidSignature(userOpHash, signature);
        assertEq(res, bytes4(0xffffffff));

        signature = abi.encode(
            true,
            hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
            "{\"type\":\"webauthn.get\",\"challenge\":\"3lqq6PdMJiHsocGXGhfGdrpFz9mM7bbh7oA4SN7zyfM\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}",
            23,
            1,
            hex"587932e2148151a1ec7629aaba061dc3f385bdda0dec658ebb37c23440d5cad1",
            hex"467ce186dab65a09882b67533d06a48924542bd38559574060015afba4b16d68",
            PubKey({
                x: 0x654f68e6d3f5d3e048e4e0b0b49153ce184a5d4c60523595269f5f7c84c97450,
                y: 0x19e487175223fb66f60d8283b34a3b5c7d600c30dd34e5e9d441acbcab03751f
            })
        );

        userOpHash = 0xde5aaae8f74c2621eca1c1971a17c676ba45cfd98cedb6e1ee803848def3c9f3;

        res = account.isValidSignature(userOpHash, signature);
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
