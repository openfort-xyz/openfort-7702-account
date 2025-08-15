// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {Base} from "test/Base.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

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

    KeyReg internal keyData;
    /* ─────────────────────────────────────────────────────────────── setup ──── */

    function setUp() public {
        vm.startPrank(sender);
        (owner, ownerPk) = makeAddrAndKey("owner");
        (sender, senderPk) = makeAddrAndKey("sender");
        (sessionKey, sessionKeyPk) = makeAddrAndKey("sessionKey");
        (GUARDIAN_EOA_ADDRESS, GUARDIAN_EOA_PRIVATE_KEY) = makeAddrAndKey("GUARDIAN_EOA_ADDRESS");
        entryPoint = IEntryPoint(payable(SEPOLIA_ENTRYPOINT));
        webAuthn = WebAuthnVerifier(payable(SEPOLIA_WEBAUTHN));

        _createInitialGuradian();
        implementation = new OPF7702(
            address(entryPoint),
            WEBAUTHN_VERIFIER,
            RECOVERY_PERIOD,
            LOCK_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW
        );
        vm.etch(owner, address(implementation).code);
        account = OPF7702(payable(owner));

        vm.stopPrank();

        _initializeAccount();
        _register_KeyP256();
        _deal();

        vm.prank(sender);
        entryPoint.depositTo{value: 0.09e18}(owner);
    }

    function test_ExecuteBatchSKP256() public {
        console.log("/* ------------- test_ExecuteBatchSKP256 ------------- */");

        // Create the Call array with multiple transactions
        Call[] memory calls = new Call[](2);

        bytes memory dataHex = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory dataHex2 =
            abi.encodeWithSelector(IERC20(TOKEN).transfer.selector, sender, 5e18);

        calls[0] = Call({target: TOKEN, value: 0, data: dataHex});
        calls[1] = Call({target: TOKEN, value: 0, data: dataHex2});

        // ERC-7821 mode for batch execution (still mode ID = 1)
        bytes32 mode = bytes32(uint256(0x01000000000000000000) << (22 * 8));

        // Encode the execution data as Call[] array
        bytes memory executionData = abi.encode(calls);

        // Create the callData for the ERC-7821 execute function
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), mode, executionData);

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(600000, 400000),
            preVerificationGas: 800000,
            gasFees: _packGasFees(80 gwei, 15 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        console.log("userOpHash:");
        console.logBytes32(userOpHash);

        IKey.PubKey memory pubKey =
            IKey.PubKey({x: MINT_P256_PUBLIC_KEY_X, y: MINT_P256_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            MINT_P256_SIGNATURE_R, MINT_P256_SIGNATURE_S, pubKey, KeyType.P256
        );
        // console.log("isValidSignature:");
        // console.logBytes4(account.isValidSignature(userOpHash, _signature));

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

    function _register_KeyP256() internal {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 limit = 3;

        pubKeySK = PubKey({x: MINT_P256_PUBLIC_KEY_X, y: MINT_P256_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

        keyData = KeyReg({
            validUntil: validUntil,
            validAfter: 0,
            limit: limit,
            whitelisting: true,
            contractAddress: ETH_RECIVE,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 0
        });

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(keySK, keyData);
    }

    function _initializeAccount() internal {
        pubKeyMK = PubKey({x: VALID_PUBLIC_KEY_X, y: VALID_PUBLIC_KEY_Y});

        keyMK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 0});

        keyData = KeyReg({
            validUntil: type(uint48).max,
            validAfter: 0,
            limit: 0,
            whitelisting: false,
            contractAddress: address(0),
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 0
        });

        pubKeyMK = PubKey({x: bytes32(0), y: bytes32(0)});
        keySK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        bytes32 structHash = keccak256(
            abi.encode(
                RECOVER_TYPEHASH,
                keyMK.pubKey.x,
                keyMK.pubKey.y,
                keyMK.eoaAddress,
                keyMK.keyType,
                initialGuardian
            )
        );

        string memory name = "OPF7702Recoverable";
        string memory version = "1";

        bytes32 domainSeparator = keccak256(
            abi.encode(
                TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        account.initialize(keyMK, keyData, keySK, keyData, sig, initialGuardian);
    }
}
