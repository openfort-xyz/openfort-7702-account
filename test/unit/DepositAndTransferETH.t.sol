// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Base} from "test/Base.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract DepositAndTransferETH is Base {
    /* ───────────────────────────────────────────────────────────── contracts ── */
    IEntryPoint public entryPoint;
    WebAuthnVerifier public webAuthn;
    OPF7702 public implementation;
    OPF7702 public account; // clone deployed at `owner`

    /* ──────────────────────────────────────────────────────── key structures ── */
    Key internal keyMK;
    PubKey internal pubKeyMK;
    Key internal keySK;
    PubKey internal pubKeySK;

    KeyReg internal keyData;
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
        _register_KeyEOA();
        _register_KeyP256();
        _register_KeyP256NonKey();

        vm.prank(sender);
        entryPoint.depositTo{value: 0.09e18}(owner);
    }

    function test_ExecuteOwnerCall() public {
        console.log("/* -------------------------------- test_ExecuteOwnerCall -------- */");

        Call[] memory calls = new Call[](1);

        bytes memory dataHex = hex"";

        calls[0] = Call({target: sessionKey, value: 2e18, data: dataHex});

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
            accountGasLimits: _packAccountGasLimits(600000, 400000),
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

        uint256 balanceOwnerBefore = owner.balance;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOwnerAfter = owner.balance;

        assertEq(balanceOwnerBefore - 2e18, balanceOwnerAfter);
        console.log("/* -------------------------------- test_ExecuteOwnerCall -------- */");
    }

    function test_ExecuteBatchOwnerCall() public {
        console.log("/* -------------------------------- test_ExecuteBatchOwnerCall -------- */");

        // Create the Call array with multiple transactions
        Call[] memory calls = new Call[](2);

        bytes memory dataHex = hex"";
        bytes memory dataHex2 = hex"";

        calls[0] = Call({target: sessionKey, value: 2e18, data: dataHex});
        calls[1] = Call({target: sessionKey, value: 2e18, data: dataHex2});

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

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory _signature = account.encodeEOASignature(signature);

        bytes4 magicValue = account.isValidSignature(userOpHash, signature);
        console.logBytes4(magicValue);

        userOp.signature = _signature;

        uint256 balanceOwnerBefore = owner.balance;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOwnerAfter = owner.balance;

        assertEq(balanceOwnerBefore - 4e18, balanceOwnerAfter);
        console.log("/* -------------------------------- test_ExecuteBatchOwnerCall -------- */");
    }

    function test_DepositEthFromEOA() public {
        uint256 balanceBefore = sender.balance;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);
        uint256 balanceOwnerBefore = owner.balance;

        vm.prank(sender);
        (bool s,) = owner.call{value: 2e18}("");

        uint256 balanceAfter = sender.balance;
        uint256 balanceOwnerAfter = owner.balance;

        assertTrue(s);
        assertEq(balanceBefore - 2e18, balanceAfter);
        assertEq(balanceOwnerBefore + 2e18, balanceOwnerAfter);
    }

    function test_TransferFromAccount() public {
        uint256 balanceBefore = sender.balance;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        uint256 balanceOwnerBefore = owner.balance;

        vm.prank(owner);
        (bool s,) = sender.call{value: 2e18}("");

        uint256 balanceAfter = sender.balance;
        uint256 balanceOwnerAfter = owner.balance;

        assertTrue(s);
        assertEq(balanceBefore + 2e18, balanceAfter);
        assertEq(balanceOwnerBefore - 2e18, balanceOwnerAfter);
    }

    function test_ExecuteMasterKey() public {
        console.log("/* -------------------------------- test_ExecuteMasterKey -------- */");
        uint256 value = 1e18;
        Call[] memory calls = new Call[](1);

        bytes memory dataHex = hex"";

        calls[0] = Call({target: sessionKey, value: value, data: dataHex});

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
            accountGasLimits: _packAccountGasLimits(600000, 400000),
            preVerificationGas: 800000,
            gasFees: _packGasFees(80 gwei, 15 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        console.logBytes32(userOpHash);

        IKey.PubKey memory pubKeyExecuteBatch =
            IKey.PubKey({x: ETH_PUBLIC_KEY_X, y: ETH_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            ETH_AUTHENTICATOR_DATA,
            ETH_CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            ETH_SIGNATURE_R,
            ETH_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            AUTHENTICATOR_DATA,
            ETH_CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            ETH_SIGNATURE_R,
            ETH_SIGNATURE_S,
            ETH_PUBLIC_KEY_X,
            ETH_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        uint256 balanceOfBefore = owner.balance;
        uint256 balanceSenderBefore = sender.balance;

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = owner.balance;
        uint256 balanceSenderAfter = sender.balance;

        console.log("balanceOfBefore", balanceOfBefore);
        console.log("balanceOfAfter", balanceOfAfter);
        console.log("balanceSenderBefore", balanceSenderBefore);
        console.log("balanceSenderAfter", balanceSenderAfter);
        assertEq(balanceOfBefore - value, balanceOfAfter);

        console.log("/* -------------------------------- test_ExecuteMasterKey -------- */");
    }

    function test_ExecuteBatchSKEOA() public {
        console.log("/* -------------------------------- test_ExecuteBatchSKEOA -------- */");
        // Create the Call array with multiple transactions
        Call[] memory calls = new Call[](2);

        bytes memory dataHex = hex"";
        bytes memory dataHex2 = hex"";

        uint256 value = 0.1e18;

        calls[0] = Call({target: ETH_RECIVE, value: value, data: dataHex});
        calls[1] = Call({target: ETH_RECIVE, value: value, data: dataHex2});

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

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory _signature = account.encodeEOASignature(signature);

        bytes4 magicValue = account.isValidSignature(userOpHash, signature);
        console.logBytes4(magicValue);

        userOp.signature = _signature;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        uint256 balanceOfBefore = owner.balance;
        uint256 balanceSenderBefore = ETH_RECIVE.balance;

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = owner.balance;
        uint256 balanceSenderAfter = ETH_RECIVE.balance;

        console.log("balanceOfBefore", balanceOfBefore);
        console.log("balanceOfAfter", balanceOfAfter);
        console.log("balanceSenderBefore", balanceSenderBefore);
        console.log("balanceSenderAfter", balanceSenderAfter);
        assertEq(balanceOfBefore - (value * 2), balanceOfAfter);

        console.log("/* -------------------------------- test_ExecuteBatchSKEOA -------- */");
    }

    function test_ExecuteBatchSKP256() public {
        console.log("/* ---------------------------------- test_ExecuteBatchSKP256 -------- */");

        // Create the Call array with multiple transactions
        Call[] memory calls = new Call[](2);

        bytes memory dataHex = hex"";
        bytes memory dataHex2 = hex"";
        uint256 value = 0.1e18;
        calls[0] = Call({target: ETH_RECIVE, value: value, data: dataHex});
        calls[1] = Call({target: ETH_RECIVE, value: value, data: dataHex2});

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
        console.logBytes32(userOpHash);

        IKey.PubKey memory pubKeyExecuteBatch =
            IKey.PubKey({x: ETH_P256_PUBLIC_KEY_X, y: ETH_P256_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            ETH_P256_SIGNATURE_R, ETH_P256_SIGNATURE_S, pubKeyExecuteBatch, KeyType.P256
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bool isValid = webAuthn.verifyP256Signature(
            userOpHash,
            ETH_P256_SIGNATURE_R,
            ETH_P256_SIGNATURE_S,
            P256_PUBLIC_KEY_X,
            P256_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        uint256 balanceOfBefore = owner.balance;
        uint256 balanceSenderBefore = ETH_RECIVE.balance;

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = owner.balance;
        uint256 balanceSenderAfter = ETH_RECIVE.balance;

        console.log("balanceOfBefore", balanceOfBefore);
        console.log("balanceOfAfter", balanceOfAfter);
        console.log("balanceSenderBefore", balanceSenderBefore);
        console.log("balanceSenderAfter", balanceSenderAfter);
        assertEq(balanceOfBefore - (value * 2), balanceOfAfter);
        console.log("/* ---------------------------------- test_ExecuteBatchSKP256 -------- */");
    }

    function test_ExecuteBatchSKP256NonKey() public {
        console.log(
            "/* ---------------------------------- test_ExecuteBatchSKP256NonKey -------- */"
        );

        // Create the Call array with multiple transactions
        Call[] memory calls = new Call[](2);

        bytes memory dataHex = hex"";
        bytes memory dataHex2 = hex"";
        uint256 value = 0.1e18;

        calls[0] = Call({target: ETH_RECIVE, value: value, data: dataHex});
        calls[1] = Call({target: ETH_RECIVE, value: value, data: dataHex2});

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
        console.logBytes32(userOpHash);

        IKey.PubKey memory pubKeyExecuteBatch =
            IKey.PubKey({x: ETH_P256NOKEY_PUBLIC_KEY_X, y: ETH_P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            ETH_P256NOKEY_SIGNATURE_R,
            ETH_P256NOKEY_SIGNATURE_S,
            pubKeyExecuteBatch,
            KeyType.P256NONKEY
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bytes32 _hash = EfficientHashLib.sha2(userOpHash);
        console.logBytes32(_hash);

        bool isValid = webAuthn.verifyP256Signature(
            _hash,
            ETH_P256NOKEY_SIGNATURE_R,
            ETH_P256NOKEY_SIGNATURE_S,
            ETH_P256NOKEY_PUBLIC_KEY_X,
            ETH_P256NOKEY_PUBLIC_KEY_Y
        );
        console.log("isValid Test", isValid);

        userOp.signature = _signature;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        uint256 balanceOfBefore = owner.balance;
        uint256 balanceSenderBefore = ETH_RECIVE.balance;

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        uint256 balanceOfAfter = owner.balance;
        uint256 balanceSenderAfter = ETH_RECIVE.balance;

        console.log("balanceOfBefore", balanceOfBefore);
        console.log("balanceOfAfter", balanceOfAfter);
        console.log("balanceSenderBefore", balanceSenderBefore);
        console.log("balanceSenderAfter", balanceSenderAfter);
        assertEq(balanceOfBefore - (value * 2), balanceOfAfter);
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

        keyData = KeyReg({
            validUntil: validUntil,
            validAfter: 0,
            limit: limit,
            whitelisting: true,
            contractAddress: ETH_RECIVE,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: ETH_LIMIT
        });

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(keySK, keyData);
    }

    function _register_KeyP256() internal {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 limit = uint48(3);
        pubKeySK = PubKey({x: ETH_P256_PUBLIC_KEY_X, y: ETH_P256_PUBLIC_KEY_Y});

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
            ethLimit: ETH_LIMIT
        });

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(keySK, keyData);
    }

    function _register_KeyP256NonKey() internal {
        uint48 validUntil = uint48(block.timestamp + 1 days);
        uint48 limit = uint48(3);
        pubKeySK = PubKey({x: ETH_P256NOKEY_PUBLIC_KEY_X, y: ETH_P256NOKEY_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256NONKEY});

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
            ethLimit: ETH_LIMIT
        });

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(keySK, keyData);
    }

    /* ─────────────────────────────────────────────────────────── helpers ──── */
    function _initializeAccount() internal {
        /* sample WebAuthn public key – replace with a real one if needed */
        pubKeyMK = PubKey({x: ETH_PUBLIC_KEY_X, y: ETH_PUBLIC_KEY_Y});

        keyMK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 0});

        keyData = KeyReg({
            validUntil: type(uint48).max,
            validAfter: 0,
            limit: 0,
            whitelisting: false,
            contractAddress: 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 0
        });
        /* sign arbitrary message so initialise() passes sig check */
        bytes32 msgHash = account.getDigestToInit(keyMK, initialGuardian);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, msgHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        account.initialize(keyMK, keyData, sig, initialGuardian);
    }
}
