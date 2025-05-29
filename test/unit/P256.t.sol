// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {Base} from "test/Base.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {OPF7702 as OPF7702} from "src/core/OPF7702.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {ISessionkey} from "src/interfaces/ISessionkey.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract P256Test is Base {
    /* ───────────────────────────────────────────────────────────── contracts ── */
    IEntryPoint public entryPoint;
    WebAuthnVerifier public webAuthn;
    OPF7702 public implementation;
    OPF7702 public account;

    /* ──────────────────────────────────────────────────────── key structures ── */
    Key internal keyMK;
    PubKey internal pubKeyMK;
    Key internal keySK;
    PubKey internal pubKeySK;

    /* ─────────────────────────────────────────────────────────────── setup ──── */
    function setUp() public {
        vm.startPrank(sender);

        entryPoint = IEntryPoint(payable(SEPOLIA_ENTRYPOINT));
        webAuthn = WebAuthnVerifier(payable(SEPOLIA_WEBAUTHN));

        implementation = new OPF7702(address(entryPoint));
        vm.etch(owner, address(implementation).code);
        account = OPF7702(payable(owner));

        vm.stopPrank();

        _initializeAccount();
        _register_SessionKeyP256();

        vm.prank(sender);
        entryPoint.depositTo{value: 0.11 ether}(owner);
    }

    function test_ExecuteBatchSKP256() public {
        console.log("/* ------------- test_ExecuteBatchSKP256 ------------- */");

        bytes memory callData1 = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory callData2 =
            abi.encodeWithSelector(IERC20(TOKEN).transfer.selector, sender, 5e18);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        for (uint256 i = 0; i < 2; i++) {
            targets[i] = TOKEN;
            values[i] = 0;
        }

        datas[0] = callData1;
        datas[1] = callData2;

        bytes memory callData = abi.encodeWithSelector(0x47e1da2a, targets, values, datas);
        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(400000, 300000),
            preVerificationGas: 800000,
            gasFees: _packGasFees(80 gwei, 15 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        console.log("userOpHash:");
        console.logBytes32(userOpHash);

        ISessionkey.PubKey memory pubKey =
            ISessionkey.PubKey({x: P256_PUBLIC_KEY_X, y: P256_PUBLIC_KEY_Y});

        bytes memory _signature =
            account.encodeP256Signature(P256_SIGNATURE_R, P256_SIGNATURE_S, pubKey);
        console.log("isValidSignature:");
        console.logBytes4(account.isValidSignature(userOpHash, _signature));

        userOp.signature = _signature;

        uint256 balanceBefore = IERC20(TOKEN).balanceOf(sender);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceAfter = IERC20(TOKEN).balanceOf(sender);
        console.log("balanceAfter:", balanceAfter);

        assertEq(balanceAfter, balanceBefore + 5e18);

        console.log("/* ------------- test_ExecuteBatchSKP256 ------------- */");
    }

    function _register_SessionKeyP256() internal {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 limit = 3;

        pubKeySK = PubKey({x: P256_PUBLIC_KEY_X, y: P256_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerSessionKey(
            keySK, validUntil, 0, limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
        );
    }

    function _initializeAccount() internal {
        pubKeyMK = PubKey({x: VALID_PUBLIC_KEY_X, y: VALID_PUBLIC_KEY_Y});

        keyMK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 0});

        bytes32 msgHash = keccak256(abi.encode("Hello OPF7702"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, msgHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 validUntil = block.timestamp + 1 days;

        vm.prank(address(entryPoint));
        account.initialize(keyMK, spendInfo, _allowedSelectors(), msgHash, sig, validUntil, 1);
    }
}
