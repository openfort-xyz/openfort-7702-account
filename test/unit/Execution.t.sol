// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Base} from "test/Base.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {OPF7702Recoverable as OPF7702} from "src/core/OPF7702Recoverable.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract Execution is Base {
    /* ───────────────────────────────────────────────────────────── contracts ── */
    IEntryPoint public entryPoint;
    WebAuthnVerifier public webAuthn;
    OPF7702 public implementation;
    OPF7702 public account; // clone deployed at `owner`

    /* ──────────────────────────────────────────────────────── key structures ── */
    Key internal keyMK;
    PubKey internal pubKeyMK;
    Key internal keyMK_Mint;
    PubKey internal pubKeyMK_Mint;
    Key internal keyMK_BATCH;
    PubKey internal pubKeyMK_BATCH;
    Key internal keySK;
    PubKey internal pubKeySK;

    /* ─────────────────────────────────────────────────────────────── setup ──── */
    function setUp() public {
        vm.startPrank(sender);

        // forkId = vm.createFork(SEPOLIA_RPC_URL);
        // vm.selectFork(forkId);

        /* live contracts on fork */
        entryPoint = IEntryPoint(payable(SEPOLIA_ENTRYPOINT));
        webAuthn = WebAuthnVerifier(payable(SEPOLIA_WEBAUTHN));

        _createInitialGuradian();
        /* deploy implementation & bake it into `owner` address */
        implementation = new OPF7702(
            address(entryPoint), RECOVERY_PERIOD, LOCK_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW
        );
        vm.etch(owner, address(implementation).code);
        account = OPF7702(payable(owner));

        vm.stopPrank();

        _initializeAccount();
        _register_MKMint();
        _register_MKBatch();
        _register_KeyEOA();
        _register_KeyP256();
        _register_KeyP256NonKey();

        vm.prank(sender);
        entryPoint.depositTo{value: 0.11e18}(owner);
    }

    /* ─────────────────────────────────────────────────────────────── tests ──── */
    function test_getKeyById_zero() external view {
        Key memory k = account.getKeyById(0, KeyType.WEBAUTHN);
        console.log("/* --------------------------------- test_getKeyById_zero -------- */");

        console.logBytes32(k.pubKey.x);
        console.logBytes32(k.pubKey.y);

        Key memory kSk = account.getKeyById(1, KeyType.P256);
        console.logBytes32(kSk.pubKey.x);
        console.logBytes32(kSk.pubKey.y);

        Key memory kSkNonKey = account.getKeyById(1, KeyType.P256NONKEY);
        console.logBytes32(kSkNonKey.pubKey.x);
        console.logBytes32(kSkNonKey.pubKey.y);
        console.log("/* --------------------------------- test_getKeyById_zero -------- */");
    }

    function test_ExecuteOwnerCall() public {
        console.log("/* -------------------------------- test_ExecuteOwnerCall -------- */");

        Call[] memory txs = new Call[](1);

        bytes memory dataHex = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);

        txs[0] = Call({target: TOKEN, value: 0, data: dataHex});

        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute((address,uint256,bytes)[])")), txs);

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

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory _signature = account.encodeEOASignature(signature);

        bytes4 magicValue = account.isValidSignature(userOpHash, signature);
        console.logBytes4(magicValue);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(owner);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        console.log("balanceOfBefore", balanceOfBefore);
        console.log("balanceOfAfter", balanceOfAfter);
        assertEq(balanceOfBefore + 10e18, balanceOfAfter);
        console.log("/* -------------------------------- test_ExecuteOwnerCall -------- */");
    }

    function test_ExecuteBatchOwnerCall() public {
        console.log("/* -------------------------------- test_ExecuteBatchOwnerCall -------- */");

        Call[] memory txs = new Call[](2);

        bytes memory dataHex = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);

        bytes memory dataHex2 =
            abi.encodeWithSelector(IERC20(TOKEN).transfer.selector, sender, 5e18);

        txs[0] = Call({target: TOKEN, value: 0, data: dataHex});

        txs[1] = Call({target: TOKEN, value: 0, data: dataHex2});

        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute((address,uint256,bytes)[])")), txs);

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

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory _signature = account.encodeEOASignature(signature);

        bytes4 magicValue = account.isValidSignature(userOpHash, signature);
        console.logBytes4(magicValue);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(owner);
        uint256 balanceOfBeforeSender = IERC20(TOKEN).balanceOf(sender);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        uint256 balanceOfAfterSender = IERC20(TOKEN).balanceOf(sender);
        console.log("balanceOfBefore", balanceOfBefore);
        console.log("balanceOfAfter", balanceOfAfter);
        assertEq(balanceOfBefore, balanceOfAfter - 5e18);
        assertEq(balanceOfBeforeSender + 5e18, balanceOfAfterSender);
        console.log("/* -------------------------------- test_ExecuteBatchOwnerCall -------- */");
    }

    function test_ExecuteOwner() public {
        console.log("/* -------------------------------- test_ExecuteOwner -------- */");

        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);

        bytes memory callData = abi.encodeWithSelector(0xb61d27f6, TOKEN, 0, data);

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

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory _signature = account.encodeEOASignature(signature);

        bytes4 magicValue = account.isValidSignature(userOpHash, signature);
        console.logBytes4(magicValue);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(owner);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        console.log("balanceOfBefore", balanceOfBefore);
        console.log("balanceOf", balanceOfAfter);
        assertEq(balanceOfBefore + 10e18, balanceOfAfter);
        console.log("/* -------------------------------- test_ExecuteOwner -------- */");
    }

    function test_ExecuteBatchOwner() public {
        console.log("/* -------------------------------- test_ExecuteBatchOwner -------- */");

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

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory _signature = account.encodeEOASignature(signature);

        bytes4 magicValue = account.isValidSignature(userOpHash, signature);
        console.logBytes4(magicValue);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(sender);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(sender);
        console.log("balanceOfBefore", balanceOfBefore);
        console.log("balanceOf", balanceOfAfter);
        assertEq(balanceOfBefore + 5e18, balanceOfAfter);
        console.log("/* -------------------------------- test_ExecuteBatchOwner -------- */");
    }

    function test_ExecuteMasterKey() public {
        console.log("/* ---------------------------------- test_ExecuteMasterKey -------- */");

        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);

        bytes memory callData = abi.encodeWithSelector(0xb61d27f6, TOKEN, 0, data);

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
        console.logBytes32(userOpHash);

        IKey.PubKey memory pubKeyExecuteBatch =
            IKey.PubKey({x: MINT_VALID_PUBLIC_KEY_X, y: MINT_VALID_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            MINT_AUTHENTICATOR_DATA,
            MINT_CLIENT_DATA_JSON,
            MINT_CHALLENGE_INDEX,
            MINT_TYPE_INDEX,
            MINT_VALID_SIGNATURE_R,
            MINT_VALID_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bool isValid = webAuthn.verifySoladySignature(
            userOpHash,
            true,
            MINT_AUTHENTICATOR_DATA,
            MINT_CLIENT_DATA_JSON,
            MINT_CHALLENGE_INDEX,
            MINT_TYPE_INDEX,
            MINT_VALID_SIGNATURE_R,
            MINT_VALID_SIGNATURE_S,
            MINT_VALID_PUBLIC_KEY_X,
            MINT_VALID_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(owner);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        console.log("balanceOf", balanceOfAfter);
        assertEq(balanceOfBefore + 10e18, balanceOfAfter);
        console.log("/* ---------------------------------- test_ExecuteMasterKey -------- */");
    }

    function test_ExecuteBatchMasterKey() public {
        console.log("/* ---------------------------------- test_ExecuteBatchMasterKey -------- */");

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
        console.logBytes32(userOpHash);

        IKey.PubKey memory pubKeyExecuteBatch =
            IKey.PubKey({x: BATCH_VALID_PUBLIC_KEY_X, y: BATCH_VALID_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            BATCH_AUTHENTICATOR_DATA,
            BATCH_CLIENT_DATA_JSON,
            BATCH_CHALLENGE_INDEX,
            BATCH_TYPE_INDEX,
            BATCH_VALID_SIGNATURE_R,
            BATCH_VALID_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bool isValid = webAuthn.verifySoladySignature(
            userOpHash,
            true,
            BATCH_AUTHENTICATOR_DATA,
            BATCH_CLIENT_DATA_JSON,
            BATCH_CHALLENGE_INDEX,
            BATCH_TYPE_INDEX,
            BATCH_VALID_SIGNATURE_R,
            BATCH_VALID_SIGNATURE_S,
            BATCH_VALID_PUBLIC_KEY_X,
            BATCH_VALID_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(sender);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(sender);
        console.log("balanceOf", balanceOfAfter);
        assertEq(balanceOfBefore + 5e18, balanceOfAfter);
        console.log("/* ---------------------------------- test_ExecuteBatchMasterKey -------- */");
    }

    function test_ExecuteSKEOA() public {
        console.log("/* -------------------------------- test_ExecuteSKEOA -------- */");

        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);

        bytes memory callData = abi.encodeWithSelector(0xb61d27f6, TOKEN, 0, data);

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

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory _signature = account.encodeEOASignature(signature);

        bytes4 magicValue = account.isValidSignature(userOpHash, signature);
        console.logBytes4(magicValue);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(owner);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        console.log("balanceOf", balanceOfAfter);
        assertEq(balanceOfBefore + 10e18, balanceOfAfter);
        console.log("/* -------------------------------- test_ExecuteSKEOA -------- */");
    }

    function test_ExecuteBatchSKEOA() public {
        console.log("/* -------------------------------- test_ExecuteBatchSKEOA -------- */");

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

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory _signature = account.encodeEOASignature(signature);

        bytes4 magicValue = account.isValidSignature(userOpHash, signature);
        console.logBytes4(magicValue);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(sender);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(sender);
        console.log("balanceOf", balanceOfAfter);
        assertEq(balanceOfBefore + 5e18, balanceOfAfter);
        console.log("/* -------------------------------- test_ExecuteBatchSKEOA -------- */");
    }

    function test_ExecuteSKP256() public {
        console.log("/* ---------------------------------- test_ExecuteSKP256 -------- */");

        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);

        bytes memory callData = abi.encodeWithSelector(0xb61d27f6, TOKEN, 0, data);

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
        console.logBytes32(userOpHash);

        IKey.PubKey memory pubKeyExecuteBatch =
            IKey.PubKey({x: MINT_P256_PUBLIC_KEY_X, y: MINT_P256_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            MINT_P256_SIGNATURE_R, MINT_P256_SIGNATURE_S, pubKeyExecuteBatch
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bool isValid = webAuthn.verifyP256Signature(
            userOpHash,
            MINT_P256_SIGNATURE_R,
            MINT_P256_SIGNATURE_S,
            MINT_P256_PUBLIC_KEY_X,
            MINT_P256_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(owner);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        console.log("balanceOf", balanceOfAfter);
        assertEq(balanceOfBefore + 10e18, balanceOfAfter);
        console.log("/* ---------------------------------- test_ExecuteSKP256 -------- */");
    }

    function test_ExecuteBatchSKP256() public {
        console.log("/* ---------------------------------- test_ExecuteBatchSKP256 -------- */");

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
        console.logBytes32(userOpHash);

        IKey.PubKey memory pubKeyExecuteBatch =
            IKey.PubKey({x: P256_PUBLIC_KEY_X, y: P256_PUBLIC_KEY_Y});

        bytes memory _signature =
            account.encodeP256Signature(P256_SIGNATURE_R, P256_SIGNATURE_S, pubKeyExecuteBatch);

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bool isValid = webAuthn.verifyP256Signature(
            userOpHash, P256_SIGNATURE_R, P256_SIGNATURE_S, P256_PUBLIC_KEY_X, P256_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(sender);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(sender);
        console.log("balanceOf", balanceOfAfter);
        assertEq(balanceOfBefore + 5e18, balanceOfAfter);
        console.log("/* ---------------------------------- test_ExecuteBatchSKP256 -------- */");
    }

    function test_ExecuteSKP256NonKey() public {
        console.log("/* ---------------------------------- test_ExecuteSKP256NonKey -------- */");

        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);

        bytes memory callData = abi.encodeWithSelector(0xb61d27f6, TOKEN, 0, data);

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
        console.logBytes32(userOpHash);

        IKey.PubKey memory pubKeyExecuteBatch =
            IKey.PubKey({x: MINT_P256NOKEY_PUBLIC_KEY_X, y: MINT_P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256NonKeySignature(
            MINT_P256NOKEY_SIGNATURE_R, MINT_P256NOKEY_SIGNATURE_S, pubKeyExecuteBatch
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bytes32 _hash = EfficientHashLib.sha2(userOpHash);
        console.logBytes32(_hash);
        bool isValid = webAuthn.verifyP256Signature(
            _hash,
            MINT_P256NOKEY_SIGNATURE_R,
            MINT_P256NOKEY_SIGNATURE_S,
            MINT_P256NOKEY_PUBLIC_KEY_X,
            MINT_P256NOKEY_PUBLIC_KEY_Y
        );
        console.log("isValid Test", isValid);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(owner);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        console.log("balanceOf", balanceOfAfter);
        assertEq(balanceOfBefore + 10e18, balanceOfAfter);
        console.log("/* ---------------------------------- test_ExecuteSKP256NonKey -------- */");
    }

    function test_ExecuteBatchSKP256NonKey() public {
        console.log(
            "/* ---------------------------------- test_ExecuteBatchSKP256NonKey -------- */"
        );

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
        console.logBytes32(userOpHash);

        IKey.PubKey memory pubKeyExecuteBatch =
            IKey.PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256NonKeySignature(
            P256NOKEY_SIGNATURE_R, P256NOKEY_SIGNATURE_S, pubKeyExecuteBatch
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bytes32 _hash = EfficientHashLib.sha2(userOpHash);
        console.logBytes32(_hash);
        bool isValid = webAuthn.verifyP256Signature(
            _hash,
            P256NOKEY_SIGNATURE_R,
            P256NOKEY_SIGNATURE_S,
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y
        );
        console.log("isValid Test", isValid);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(sender);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(sender);
        console.log("balanceOf", balanceOfAfter);
        assertEq(balanceOfBefore + 5e18, balanceOfAfter);
        console.log(
            "/* ---------------------------------- test_ExecuteBatchSKP256NonKey -------- */"
        );
    }

    function _register_KeyEOA() internal {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 limit = uint48(3);
        pubKeySK = PubKey({
            x: 0x0000000000000000000000000000000000000000000000000000000000000000,
            y: 0x0000000000000000000000000000000000000000000000000000000000000000
        });

        keySK = Key({pubKey: pubKeySK, eoaAddress: sessionKey, keyType: KeyType.EOA});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(
            keySK, validUntil, uint48(0), limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
        );
    }

    function _register_KeyP256() internal {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 limit = uint48(3);
        pubKeySK = PubKey({x: P256_PUBLIC_KEY_X, y: P256_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(
            keySK, validUntil, uint48(0), limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
        );

        pubKeySK = PubKey({x: MINT_P256_PUBLIC_KEY_X, y: MINT_P256_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256});

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(
            keySK, validUntil, uint48(0), limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
        );
    }

    function _register_KeyP256NonKey() internal {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 limit = uint48(3);
        pubKeySK = PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256NONKEY});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(
            keySK, validUntil, uint48(0), limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
        );

        pubKeySK = PubKey({x: MINT_P256NOKEY_PUBLIC_KEY_X, y: MINT_P256NOKEY_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256});

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(
            keySK, validUntil, uint48(0), limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
        );
    }

    function _register_MKMint() internal {
        uint48 validUntil = type(uint48).max;
        uint48 limit = uint48(50);

        /* sample WebAuthn public key – replace with a real one if needed */
        pubKeyMK_Mint = PubKey({x: MINT_VALID_PUBLIC_KEY_X, y: MINT_VALID_PUBLIC_KEY_Y});

        keyMK_Mint = Key({pubKey: pubKeyMK_Mint, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        SpendLimit.SpendTokenInfo memory spendInfo_Mint =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 10000e18});

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(
            keyMK_Mint,
            validUntil,
            uint48(0),
            limit,
            true,
            TOKEN,
            spendInfo_Mint,
            _allowedSelectors(),
            0
        );
    }

    function _register_MKBatch() internal {
        uint48 validUntil = type(uint48).max;
        uint48 limit = uint48(50);

        /* sample WebAuthn public key – replace with a real one if needed */
        pubKeyMK_BATCH = PubKey({x: BATCH_VALID_PUBLIC_KEY_X, y: BATCH_VALID_PUBLIC_KEY_Y});

        keyMK_BATCH =
            Key({pubKey: pubKeyMK_BATCH, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        SpendLimit.SpendTokenInfo memory spendInfo_BATCH =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 10000e18});

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(
            keyMK_BATCH,
            validUntil,
            uint48(0),
            limit,
            true,
            TOKEN,
            spendInfo_BATCH,
            _allowedSelectors(),
            0
        );
    }

    /* ─────────────────────────────────────────────────────────── helpers ──── */
    function _initializeAccount() internal {
        /* sample WebAuthn public key – replace with a real one if needed */
        pubKeyMK = PubKey({x: VALID_PUBLIC_KEY_X, y: VALID_PUBLIC_KEY_Y});

        keyMK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 0});

        /* sign arbitrary message so initialise() passes sig check */
        bytes32 msgHash = keccak256(abi.encode("Hello OPF7702"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, msgHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 validUntil = block.timestamp + 1 days;

        vm.prank(address(entryPoint));
        account.initialize(
            keyMK, spendInfo, _allowedSelectors(), msgHash, sig, validUntil, 1, initialGuardian
        );
    }
}
