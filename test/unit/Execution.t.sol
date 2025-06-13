// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Base} from "test/Base.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {IKey} from "src/interfaces/IKey.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract Execution7821 is Base {
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
    Key internal keyMK_BATCHS;
    PubKey internal pubKeyMK_BATCHS;
    Key internal keySK;
    PubKey internal pubKeySK;
    Key internal keySK_B;
    PubKey internal pubKeySK_B;
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

        _deal();
        _initializeAccount();
        _register_MKMint();
        _register_MKBatch();
        _register_MKBatchs();
        _register_SessionKeyEOA();
        _register_SessionKeyP256();
        _register_SessionKeyP256NonKey();

        vm.prank(sender);
        entryPoint.depositTo{value: 0.11e18}(owner);
    }

    /* ─────────────────────────────────────────────────────────────── tests ──── */
    function test_getKeyById_zero() external view {
        Key memory k = account.getKeyById(0);
        console.log("/* --------------------------------- test_getKeyById_zero -------- */");

        console.logBytes32(k.pubKey.x);
        console.logBytes32(k.pubKey.y);

        Key memory kSk = account.getKeyById(1);
        console.logBytes32(kSk.pubKey.x);
        console.logBytes32(kSk.pubKey.y);

        Key memory kSkNonKey = account.getKeyById(1);
        console.logBytes32(kSkNonKey.pubKey.x);
        console.logBytes32(kSkNonKey.pubKey.y);
        console.log("/* --------------------------------- test_getKeyById_zero -------- */");
    }

    function test_ExecuteOwnerCall7821() public {
        console.log("/* -------------------------------- test_ExecuteOwnerCall -------- */");

        Call[] memory calls = new Call[](1);

        bytes memory dataHex = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);

        calls[0] = Call({target: TOKEN, value: 0, data: dataHex});

        // ERC-7821 mode for single execution (mode ID = 1)
        // The mode value should have the pattern at position 22*8 bits
        bytes32 mode = bytes32(uint256(0x01000000000000000000) << (22 * 8));

        // Encode the execution data as Call[] array
        bytes memory executionData = abi.encode(calls);

        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), mode, executionData);

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

    function test_ExecuteBatchOwnerCall7821() public {
        console.log("/* -------------------------------- test_ExecuteBatchOwnerCall -------- */");

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

    function test_ExecuteBatchOfBatches7821() public {
        console.log("/* -------------------------------- test_ExecuteBatchOfBatches -------- */");

        // Create first batch - minting operations
        Call[] memory mintBatch = new Call[](2);
        mintBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18)
        });
        mintBatch[1] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(MockERC20.mint.selector, sender, 5e18)
        });

        // Create second batch - transfer operations (FROM OWNER)
        Call[] memory transferBatch = new Call[](2);
        transferBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, sender, 3e18)
        });
        transferBatch[1] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, address(0x123), 2e18)
        });

        // Create third batch - approval operations
        Call[] memory approveBatch = new Call[](1);
        approveBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.approve.selector, address(0x456), 1e18)
        });

        // Encode each batch separately
        bytes memory batch1Data = abi.encode(mintBatch);
        bytes memory batch2Data = abi.encode(transferBatch);
        bytes memory batch3Data = abi.encode(approveBatch);

        // Create array of batch data
        bytes[] memory batches = new bytes[](3);
        batches[0] = batch1Data;
        batches[1] = batch2Data;
        batches[2] = batch3Data;

        // Mode for batch of batches (ID = 3)
        bytes32 mode = bytes32(uint256(0x01000000000078210002) << (22 * 8));

        // Encode the execution data as bytes[] array
        bytes memory executionData = abi.encode(batches);

        // Create the callData for the ERC-7821 execute function
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), mode, executionData);

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
        uint256 balanceOfBefore0x123 = IERC20(TOKEN).balanceOf(address(0x123));

        console.log("BEFORE EXECUTION:");
        console.log("Owner balance:", balanceOfBefore);
        console.log("Sender balance:", balanceOfBeforeSender);
        console.log("0x123 balance:", balanceOfBefore0x123);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        uint256 balanceOfAfterSender = IERC20(TOKEN).balanceOf(sender);
        uint256 balanceOfAfter0x123 = IERC20(TOKEN).balanceOf(address(0x123));

        console.log("AFTER EXECUTION:");
        console.log("Owner balance:", balanceOfAfter);
        console.log("Sender balance:", balanceOfAfterSender);
        console.log("0x123 balance:", balanceOfAfter0x123);

        // CORRECTED ASSERTIONS - Check balance CHANGES, not absolute values:

        // Owner should gain: +10e18 (minted) -3e18 (to sender) -2e18 (to 0x123) = +5e18
        assertEq(balanceOfAfter, balanceOfBefore + 5e18, "Owner should gain 5e18");

        // Sender should gain: +5e18 (minted) +3e18 (from owner) = +8e18
        assertEq(balanceOfAfterSender, balanceOfBeforeSender + 8e18, "Sender should gain 8e18");

        // 0x123 should gain: +2e18 (from owner) = +2e18
        assertEq(balanceOfAfter0x123, balanceOfBefore0x123 + 2e18, "0x123 should gain 2e18");

        // Verify approval was set
        uint256 allowance = IERC20(TOKEN).allowance(owner, address(0x456));
        assertEq(allowance, 1e18, "Approval should be 1e18");

        console.log("/* -------------------------------- test_ExecuteBatchOfBatches -------- */");
    }

    function test_ExecuteSKEOA7821() public {
        console.log("/* -------------------------------- test_ExecuteBatchSKEOA7821 -------- */");

        Call[] memory calls = new Call[](1);

        bytes memory dataHex = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);

        calls[0] = Call({target: TOKEN, value: 0, data: dataHex});

        // ERC-7821 mode for single execution (mode ID = 1)
        // The mode value should have the pattern at position 22*8 bits
        bytes32 mode = bytes32(uint256(0x01000000000000000000) << (22 * 8));

        // Encode the execution data as Call[] array
        bytes memory executionData = abi.encode(calls);

        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), mode, executionData);

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
        console.log("balanceOfBefore", balanceOfBefore);
        console.log("balanceOfAfter", balanceOfAfter);
        assertEq(balanceOfBefore + 10e18, balanceOfAfter);
        console.log("/* -------------------------------- test_ExecuteBatchSKEOA7821 -------- */");
    }

    function test_ExecuteBatchSKEOA7821() public {
        console.log("/* -------------------------------- test_ExecuteBatchSKEOA7821 -------- */");

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
        console.log("/* -------------------------------- test_ExecuteBatchSKEOA7821 -------- */");
    }

    function test_ExecuteBatchSKEOA7821ApproveSendETH() public {
        console.log("/* -------------------------------- test_ExecuteBatchSKEOA7821 -------- */");

        // Create the Call array with multiple transactions
        Call[] memory calls = new Call[](3);

        bytes memory dataHex = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory dataHex2 =
            abi.encodeWithSelector(IERC20(TOKEN).transfer.selector, sender, 5e18);

        calls[0] = Call({target: TOKEN, value: 0, data: dataHex});
        calls[1] = Call({target: ETH_RECIVE, value: 0.1e18, data: hex""});
        calls[2] = Call({target: TOKEN, value: 0, data: dataHex2});

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
            accountGasLimits: _packAccountGasLimits(400000, 300000),
            preVerificationGas: 800000,
            gasFees: _packGasFees(80 gwei, 15 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardianB_PK, userOpHash);
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
        console.log("/* -------------------------------- test_ExecuteBatchSKEOA7821 -------- */");
    }

    function test_ExecuteBatchOfBatchesSKEOA7821() public {
        // Create first batch - minting operations
        Call[] memory mintBatch = new Call[](2);
        mintBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18)
        });
        mintBatch[1] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(MockERC20.mint.selector, sender, 1e18)
        });

        // Create second batch - transfer operations (FROM OWNER)
        Call[] memory transferBatch = new Call[](2);
        transferBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, sender, 1e18)
        });
        transferBatch[1] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, address(0x123), 1e18)
        });

        // Create third batch - approval operations
        Call[] memory approveBatch = new Call[](1);
        approveBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, address(0x456), 1e18)
        });

        // Encode each batch separately
        bytes memory batch1Data = abi.encode(mintBatch);
        bytes memory batch2Data = abi.encode(transferBatch);
        bytes memory batch3Data = abi.encode(approveBatch);

        // Create array of batch data
        bytes[] memory batches = new bytes[](3);
        batches[0] = batch1Data;
        batches[1] = batch2Data;
        batches[2] = batch3Data;

        // Mode for batch of batches (ID = 3)
        bytes32 mode = bytes32(uint256(0x01000000000078210002) << (22 * 8));

        // Encode the execution data as bytes[] array
        bytes memory executionData = abi.encode(batches);

        // Create the callData for the ERC-7821 execute function
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), mode, executionData);

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
        uint256 balanceOfBeforeSender = IERC20(TOKEN).balanceOf(sender);
        uint256 balanceOfBefore0x123 = IERC20(TOKEN).balanceOf(address(0x123));

        console.log("BEFORE EXECUTION:");
        console.log("Owner balance:", balanceOfBefore);
        console.log("Sender balance:", balanceOfBeforeSender);
        console.log("0x123 balance:", balanceOfBefore0x123);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        uint256 balanceOfAfterSender = IERC20(TOKEN).balanceOf(sender);
        uint256 balanceOfAfter0x123 = IERC20(TOKEN).balanceOf(address(0x123));

        console.log("AFTER EXECUTION:");
        console.log("Owner balance:", balanceOfAfter);
        console.log("Sender balance:", balanceOfAfterSender);
        console.log("0x123 balance:", balanceOfAfter0x123);

        // CORRECTED ASSERTIONS based on your actual test transactions:

        // Owner should: +10e18 (mint) -1e18 (to sender) -1e18 (to 0x123) -1e18 (to 0x456) = +7e18
        assertEq(balanceOfAfter, balanceOfBefore + 7e18, "Owner should gain 7e18");

        // Sender should: +1e18 (mint) +1e18 (from owner) = +2e18
        assertEq(balanceOfAfterSender, balanceOfBeforeSender + 2e18, "Sender should gain 2e18");

        // 0x123 should: +1e18 (from owner) = +1e18
        assertEq(balanceOfAfter0x123, balanceOfBefore0x123 + 1e18, "0x123 should gain 1e18");

        // Remove or comment out the approval check since third batch is doing transfer, not approve
        // uint256 allowance = IERC20(TOKEN).allowance(owner, address(0x456));
        // assertEq(allowance, 1e18, "Approval should be 1e18");
        console.log(
            "/* -------------------------------- test_ExecuteBatchOfBatchesSKEOA7821 -------- */"
        );
    }

    function test_ExecuteBatchMasterKey7821() public {
        console.log(
            "/* ---------------------------------- test_ExecuteBatchMasterKey7821 -------- */"
        );

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

    function test_ExecuteBatchOfBatchesMasterKey7821() public {
        // Create first batch - minting operations
        Call[] memory mintBatch = new Call[](2);
        mintBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18)
        });
        mintBatch[1] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(MockERC20.mint.selector, sender, 1e18)
        });

        // Create second batch - transfer operations (FROM OWNER)
        Call[] memory transferBatch = new Call[](2);
        transferBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, sender, 1e18)
        });
        transferBatch[1] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, address(0x123), 1e18)
        });

        // Create third batch - approval operations
        Call[] memory approveBatch = new Call[](1);
        approveBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, address(0x456), 1e18)
        });

        // Encode each batch separately
        bytes memory batch1Data = abi.encode(mintBatch);
        bytes memory batch2Data = abi.encode(transferBatch);
        bytes memory batch3Data = abi.encode(approveBatch);

        // Create array of batch data
        bytes[] memory batches = new bytes[](3);
        batches[0] = batch1Data;
        batches[1] = batch2Data;
        batches[2] = batch3Data;

        // Mode for batch of batches (ID = 3)
        bytes32 mode = bytes32(uint256(0x01000000000078210002) << (22 * 8));

        // Encode the execution data as bytes[] array
        bytes memory executionData = abi.encode(batches);

        // Create the callData for the ERC-7821 execute function
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), mode, executionData);

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
            IKey.PubKey({x: BATCHS_VALID_PUBLIC_KEY_X, y: BATCHS_VALID_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            BATCHS_AUTHENTICATOR_DATA,
            BATCHS_CLIENT_DATA_JSON,
            BATCHS_CHALLENGE_INDEX,
            BATCHS_TYPE_INDEX,
            BATCHS_VALID_SIGNATURE_R,
            BATCHS_VALID_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bool isValid = webAuthn.verifySoladySignature(
            userOpHash,
            true,
            BATCHS_AUTHENTICATOR_DATA,
            BATCHS_CLIENT_DATA_JSON,
            BATCHS_CHALLENGE_INDEX,
            BATCHS_TYPE_INDEX,
            BATCHS_VALID_SIGNATURE_R,
            BATCHS_VALID_SIGNATURE_S,
            BATCHS_VALID_PUBLIC_KEY_X,
            BATCHS_VALID_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(owner);
        uint256 balanceOfBeforeSender = IERC20(TOKEN).balanceOf(sender);
        uint256 balanceOfBefore0x123 = IERC20(TOKEN).balanceOf(address(0x123));

        console.log("BEFORE EXECUTION:");
        console.log("Owner balance:", balanceOfBefore);
        console.log("Sender balance:", balanceOfBeforeSender);
        console.log("0x123 balance:", balanceOfBefore0x123);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        uint256 balanceOfAfterSender = IERC20(TOKEN).balanceOf(sender);
        uint256 balanceOfAfter0x123 = IERC20(TOKEN).balanceOf(address(0x123));

        console.log("AFTER EXECUTION:");
        console.log("Owner balance:", balanceOfAfter);
        console.log("Sender balance:", balanceOfAfterSender);
        console.log("0x123 balance:", balanceOfAfter0x123);

        // CORRECTED ASSERTIONS based on your actual test transactions:

        // Owner should: +10e18 (mint) -1e18 (to sender) -1e18 (to 0x123) -1e18 (to 0x456) = +7e18
        assertEq(balanceOfAfter, balanceOfBefore + 7e18, "Owner should gain 7e18");

        // Sender should: +1e18 (mint) +1e18 (from owner) = +2e18
        assertEq(balanceOfAfterSender, balanceOfBeforeSender + 2e18, "Sender should gain 2e18");

        // 0x123 should: +1e18 (from owner) = +1e18
        assertEq(balanceOfAfter0x123, balanceOfBefore0x123 + 1e18, "0x123 should gain 1e18");

        // Remove or comment out the approval check since third batch is doing transfer, not approve
        // uint256 allowance = IERC20(TOKEN).allowance(owner, address(0x456));
        // assertEq(allowance, 1e18, "Approval should be 1e18");
        console.log(
            "/* -------------------------------- test_ExecuteBatchOfBatchesSKEOA7821 -------- */"
        );
    }

    function test_ExecuteBatchP2567821() public {
        console.log("/* ---------------------------------- test_ExecuteBatchP2567821 -------- */");

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
        console.log("/* ---------------------------------- test_ExecuteBatchP2567821 -------- */");
    }

    function test_ExecuteBatchOfBatchesP2567821() public {
        // Create first batch - minting operations
        Call[] memory mintBatch = new Call[](2);
        mintBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18)
        });
        mintBatch[1] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(MockERC20.mint.selector, sender, 1e18)
        });

        // Create second batch - transfer operations (FROM OWNER)
        Call[] memory transferBatch = new Call[](2);
        transferBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, sender, 1e18)
        });
        transferBatch[1] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, address(0x123), 1e18)
        });

        // Create third batch - approval operations
        Call[] memory approveBatch = new Call[](1);
        approveBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, address(0x456), 1e18)
        });

        // Encode each batch separately
        bytes memory batch1Data = abi.encode(mintBatch);
        bytes memory batch2Data = abi.encode(transferBatch);
        bytes memory batch3Data = abi.encode(approveBatch);

        // Create array of batch data
        bytes[] memory batches = new bytes[](3);
        batches[0] = batch1Data;
        batches[1] = batch2Data;
        batches[2] = batch3Data;

        // Mode for batch of batches (ID = 3)
        bytes32 mode = bytes32(uint256(0x01000000000078210002) << (22 * 8));

        // Encode the execution data as bytes[] array
        bytes memory executionData = abi.encode(batches);

        // Create the callData for the ERC-7821 execute function
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), mode, executionData);

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

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(owner);
        uint256 balanceOfBeforeSender = IERC20(TOKEN).balanceOf(sender);
        uint256 balanceOfBefore0x123 = IERC20(TOKEN).balanceOf(address(0x123));

        console.log("BEFORE EXECUTION:");
        console.log("Owner balance:", balanceOfBefore);
        console.log("Sender balance:", balanceOfBeforeSender);
        console.log("0x123 balance:", balanceOfBefore0x123);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        uint256 balanceOfAfterSender = IERC20(TOKEN).balanceOf(sender);
        uint256 balanceOfAfter0x123 = IERC20(TOKEN).balanceOf(address(0x123));

        console.log("AFTER EXECUTION:");
        console.log("Owner balance:", balanceOfAfter);
        console.log("Sender balance:", balanceOfAfterSender);
        console.log("0x123 balance:", balanceOfAfter0x123);

        // CORRECTED ASSERTIONS based on your actual test transactions:

        // Owner should: +10e18 (mint) -1e18 (to sender) -1e18 (to 0x123) -1e18 (to 0x456) = +7e18
        assertEq(balanceOfAfter, balanceOfBefore + 7e18, "Owner should gain 7e18");

        // Sender should: +1e18 (mint) +1e18 (from owner) = +2e18
        assertEq(balanceOfAfterSender, balanceOfBeforeSender + 2e18, "Sender should gain 2e18");

        // 0x123 should: +1e18 (from owner) = +1e18
        assertEq(balanceOfAfter0x123, balanceOfBefore0x123 + 1e18, "0x123 should gain 1e18");

        // Remove or comment out the approval check since third batch is doing transfer, not approve
        // uint256 allowance = IERC20(TOKEN).allowance(owner, address(0x456));
        // assertEq(allowance, 1e18, "Approval should be 1e18");
        console.log(
            "/* -------------------------------- test_ExecuteBatchOfBatchesSKEOA7821 -------- */"
        );
    }

    function test_ExecuteBatchP256NonKey7821() public {
        console.log("/* ---------------------------------- test_ExecuteBatchP2567821 -------- */");

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
        console.log("/* ---------------------------------- test_ExecuteBatchP2567821 -------- */");
    }

    function test_ExecuteBatchOfBatchesP256NonKey7821() public {
        // Create first batch - minting operations
        Call[] memory mintBatch = new Call[](2);
        mintBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18)
        });
        mintBatch[1] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(MockERC20.mint.selector, sender, 1e18)
        });

        // Create second batch - transfer operations (FROM OWNER)
        Call[] memory transferBatch = new Call[](2);
        transferBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, sender, 1e18)
        });
        transferBatch[1] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, address(0x123), 1e18)
        });

        // Create third batch - approval operations
        Call[] memory approveBatch = new Call[](1);
        approveBatch[0] = Call({
            target: TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.transfer.selector, address(0x456), 1e18)
        });

        // Encode each batch separately
        bytes memory batch1Data = abi.encode(mintBatch);
        bytes memory batch2Data = abi.encode(transferBatch);
        bytes memory batch3Data = abi.encode(approveBatch);

        // Create array of batch data
        bytes[] memory batches = new bytes[](3);
        batches[0] = batch1Data;
        batches[1] = batch2Data;
        batches[2] = batch3Data;

        // Mode for batch of batches (ID = 3)
        bytes32 mode = bytes32(uint256(0x01000000000078210002) << (22 * 8));

        // Encode the execution data as bytes[] array
        bytes memory executionData = abi.encode(batches);

        // Create the callData for the ERC-7821 execute function
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), mode, executionData);

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

        uint256 balanceOfBefore = IERC20(TOKEN).balanceOf(owner);
        uint256 balanceOfBeforeSender = IERC20(TOKEN).balanceOf(sender);
        uint256 balanceOfBefore0x123 = IERC20(TOKEN).balanceOf(address(0x123));

        console.log("BEFORE EXECUTION:");
        console.log("Owner balance:", balanceOfBefore);
        console.log("Sender balance:", balanceOfBeforeSender);
        console.log("0x123 balance:", balanceOfBefore0x123);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = IERC20(TOKEN).balanceOf(owner);
        uint256 balanceOfAfterSender = IERC20(TOKEN).balanceOf(sender);
        uint256 balanceOfAfter0x123 = IERC20(TOKEN).balanceOf(address(0x123));

        console.log("AFTER EXECUTION:");
        console.log("Owner balance:", balanceOfAfter);
        console.log("Sender balance:", balanceOfAfterSender);
        console.log("0x123 balance:", balanceOfAfter0x123);

        // CORRECTED ASSERTIONS based on your actual test transactions:

        // Owner should: +10e18 (mint) -1e18 (to sender) -1e18 (to 0x123) -1e18 (to 0x456) = +7e18
        assertEq(balanceOfAfter, balanceOfBefore + 7e18, "Owner should gain 7e18");

        // Sender should: +1e18 (mint) +1e18 (from owner) = +2e18
        assertEq(balanceOfAfterSender, balanceOfBeforeSender + 2e18, "Sender should gain 2e18");

        // 0x123 should: +1e18 (from owner) = +1e18
        assertEq(balanceOfAfter0x123, balanceOfBefore0x123 + 1e18, "0x123 should gain 1e18");

        // Remove or comment out the approval check since third batch is doing transfer, not approve
        // uint256 allowance = IERC20(TOKEN).allowance(owner, address(0x456));
        // assertEq(allowance, 1e18, "Approval should be 1e18");
        console.log(
            "/* -------------------------------- test_ExecuteBatchOfBatchesSKEOA7821 -------- */"
        );
    }

    function _register_SessionKeyEOA() internal {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 limit = uint48(10);
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

        keySK_B = Key({pubKey: pubKeySK, eoaAddress: guardianB, keyType: KeyType.EOA});

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(
            keySK_B,
            validUntil,
            uint48(0),
            limit,
            true,
            ETH_RECIVE,
            spendInfo,
            _allowedSelectors(),
            ETH_LIMIT
        );
    }

    function _register_SessionKeyP256() internal {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 limit = uint48(10);
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

    function _register_SessionKeyP256NonKey() internal {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 limit = uint48(10);
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
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 100000e18});

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

    function _register_MKBatchs() internal {
        uint48 validUntil = type(uint48).max;
        uint48 limit = uint48(100);

        /* sample WebAuthn public key – replace with a real one if needed */
        pubKeyMK_BATCHS = PubKey({x: BATCHS_VALID_PUBLIC_KEY_X, y: BATCHS_VALID_PUBLIC_KEY_Y});

        keyMK_BATCHS =
            Key({pubKey: pubKeyMK_BATCHS, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        SpendLimit.SpendTokenInfo memory spendInfo_BATCH =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000000000e18});

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(
            keyMK_BATCHS,
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
        pubKeyMK = PubKey({x: REG_PUBLIC_KEY_X, y: REG_PUBLIC_KEY_Y});

        keyMK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 0});

        /* sign arbitrary message so initialise() passes sig check */
        bytes32 msgHash = account.getDigestToSign();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, msgHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        account.initialize(keyMK, spendInfo, _allowedSelectors(), sig, initialGuardian);
    }
}
