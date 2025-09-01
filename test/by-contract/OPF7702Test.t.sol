// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {BaseContract} from "test/by-contract/BaseContract.t.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {ISpendLimit} from "src/interfaces/ISpendLimit.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {console2 as console} from "lib/forge-std/src/Test.sol";
import {_packValidationData} from "lib/account-abstraction/contracts/core/Helpers.sol";

contract OPF7702Test is BaseContract {
    bytes32 mode_1 = bytes32(uint256(0x01000000000000000000) << (22 * 8));
    bytes32 mode_3 = bytes32(uint256(0x01000000000078210002) << (22 * 8));
    bytes32 mode_bad = bytes32(uint256(0x01000000000000000bad) << (22 * 8));

    function test_validateSignatureRevertInvalidKeyType() public {
        PackedUserOperation memory op = _getUserOpFresh();

        bytes32 hash = keccak256("Hash");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, hash);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes memory signature = abi.encode(uint8(5), sig);

        op.signature = signature;

        _etch();

        vm.expectRevert();
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(op, hash, 0);
    }

    function test_validateSignatureRevertInvalidSignatureLengthEOA() public {
        PackedUserOperation memory op = _getUserOpFresh();

        bytes32 hash = keccak256("Hash");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, hash);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes memory signature = abi.encode(KeyType.EOA, sig, sig);

        op.signature = signature;

        _etch();

        vm.expectRevert(KeyManager__InvalidSignatureLength.selector);
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(op, hash, 0);
    }

    function test_validateSignatureRevertInvalidSignatureLengthP256() public {
        PackedUserOperation memory op = _getUserOpFresh();
        bytes32 hash = keccak256("Hash");

        bytes memory signature = account.encodeP256Signature(
            P256NOKEY_SIGNATURE_R, P256NOKEY_SIGNATURE_S, pubKeySK, KeyType.P256NONKEY
        );

        bytes memory largeSignature = abi.encodePacked(signature, signature);
        op.signature = largeSignature;

        _etch();

        vm.expectRevert(KeyManager__InvalidSignatureLength.selector);
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(op, hash, 0);
    }

    function test_validateKeyTypeEOA_SIG_VALIDATION_FAILED() public {
        PubKey memory pubKeySK2 = PubKey({x: bytes32(0), y: bytes32(0)});
        Key memory keySK2 = Key({pubKey: pubKeySK2, eoaAddress: sender, keyType: KeyType.EOA});
        ISpendLimit.SpendTokenInfo memory spendInfo =
            ISpendLimit.SpendTokenInfo({token: TOKEN, limit: 100e18});

        KeyReg memory keyDataSKEOA = KeyReg({
            validUntil: uint48(block.timestamp + 1 days),
            validAfter: 0,
            limit: 10,
            whitelisting: true,
            contractAddress: ETH_RECIVE,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 1e18
        });

        _etch();

        vm.prank(owner);
        account.registerKey(keySK2, keyDataSKEOA);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 20e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(senderPK, userOpHash);
        bytes memory signature = abi.encodePacked(r2, s2, v2);

        bytes memory _signature = account.encodeEOASignature(signature);
        userOp.signature = _signature;

        _etch();

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(res, 1);
    }

    function test_validateKeyTypeWEBAUTHNRevertUsedChallenge() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 20e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        PubKey memory pubKeyExecuteBatch = PubKey({x: PUBLIC_KEY_X, y: PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            SIGNATURE_R,
            SIGNATURE_S,
            pubKeyExecuteBatch
        );

        userOp.signature = _signature;

        bytes32 userOpHash = CHALLENGE;
        _etch();

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            SIGNATURE_R,
            SIGNATURE_S,
            PUBLIC_KEY_X,
            PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(userOp, userOpHash, 0);

        vm.expectRevert(KeyManager__UsedChallenge.selector);
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(userOp, userOpHash, 0);
    }

    function test_validateKeyTypeWEBAUTHNBadSignature() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 20e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        PubKey memory pubKeyExecuteBatch = PubKey({x: PUBLIC_KEY_X, y: PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            40,
            SIGNATURE_R,
            SIGNATURE_S,
            pubKeyExecuteBatch
        );

        userOp.signature = _signature;

        bytes32 userOpHash = CHALLENGE;
        _etch();

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            40,
            SIGNATURE_R,
            SIGNATURE_S,
            PUBLIC_KEY_X,
            PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(res, 1);
    }

    function test_WebAuthnSKRevertRevertGasPolicy() public {
        _createSKWebAuthnData();

        vm.prank(owner);
        account.registerKey(keySK, keyDataSKP256NonKey);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 20e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(5 gwei, 80 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        PubKey memory pubKeyExecuteBatch = PubKey({x: SK_PUBLIC_KEY_X, y: SK_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        userOp.signature = _signature;

        bytes32 userOpHash = SK_CHALLENGE;
        _etch();

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            SK_PUBLIC_KEY_X,
            SK_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        vm.expectRevert(KeyManager__RevertGasPolicy.selector);
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(userOp, userOpHash, 0);
    }

    function test_WebAuthnSKBadSinature() public {
        _createSKWebAuthnData();

        vm.prank(owner);
        account.registerKey(keySK, keyDataSKP256NonKey);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 20e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        PubKey memory pubKeyExecuteBatch = PubKey({x: SK_PUBLIC_KEY_X, y: SK_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        userOp.signature = _signature;

        bytes32 userOpHash = SK_CHALLENGE;
        _etch();

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            SK_PUBLIC_KEY_X,
            SK_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(res, 1);
    }

    function test_WebAuthnSKGoodSinature() public {
        _createSKWebAuthnData();

        vm.prank(owner);
        account.registerKey(keySK, keyDataSKP256NonKey);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 0e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        PubKey memory pubKeyExecuteBatch = PubKey({x: SK_PUBLIC_KEY_X, y: SK_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        userOp.signature = _signature;

        bytes32 userOpHash = SK_CHALLENGE;
        _etch();

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            SK_PUBLIC_KEY_X,
            SK_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);

        uint256 pack = _packValidationData(
            false, keyDataSKP256NonKey.validUntil, keyDataSKP256NonKey.validAfter
        );
        assertEq(res, pack);
    }

    function test_WebAuthnSKGoodNotAllowedSelector() public {
        _createSKWebAuthnData();

        vm.prank(owner);
        account.registerKey(keySK, keyDataSKP256NonKey);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 0e18, data: hex"deadbeef"});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        PubKey memory pubKeyExecuteBatch = PubKey({x: SK_PUBLIC_KEY_X, y: SK_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        userOp.signature = _signature;

        bytes32 userOpHash = SK_CHALLENGE;
        _etch();

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            SK_PUBLIC_KEY_X,
            SK_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(res, 1);
    }

    function test_WebAuthnSKMode3False() public {
        _createSKWebAuthnData();

        vm.prank(owner);
        account.registerKey(keySK, keyDataSKP256NonKey);

        Call[] memory calls_1 = new Call[](2);
        calls_1[0] = Call({target: ETH_RECIVE, value: 20e18, data: hex""});
        calls_1[1] = Call({target: ETH_RECIVE, value: 0e18, data: hex""});

        Call[] memory calls_2 = new Call[](2);
        calls_2[0] = Call({target: ETH_RECIVE, value: 0e18, data: hex""});
        calls_2[1] = Call({target: ETH_RECIVE, value: 0e18, data: hex""});

        bytes memory batch1Data = abi.encode(calls_1);
        bytes memory batch2Data = abi.encode(calls_2);

        bytes[] memory batches = new bytes[](2);
        batches[0] = batch1Data;
        batches[1] = batch2Data;

        bytes memory executionData = abi.encode(batches);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_3, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        PubKey memory pubKeyExecuteBatch = PubKey({x: SK_PUBLIC_KEY_X, y: SK_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        userOp.signature = _signature;

        bytes32 userOpHash = SK_CHALLENGE;
        _etch();

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            SK_PUBLIC_KEY_X,
            SK_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(res, 1);
    }

    function test_IncorrectIsValidKeySelector() public {
        _createSKWebAuthnData();

        vm.prank(owner);
        account.registerKey(keySK, keyDataSKP256NonKey);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 20e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute2(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        PubKey memory pubKeyExecuteBatch = PubKey({x: SK_PUBLIC_KEY_X, y: SK_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        userOp.signature = _signature;

        bytes32 userOpHash = SK_CHALLENGE;
        _etch();

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            SK_PUBLIC_KEY_X,
            SK_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(res, 1);
    }

    function test_ValidateKeyTypeP256RevertUsedChallenge() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 0e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        console.logBytes32(userOpHash);

        bytes32 hashToValidate = EfficientHashLib.sha2(userOpHash);

        PubKey memory pubKeyExecuteBatch =
            PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            P256NOKEY_SIGNATURE_R, P256NOKEY_SIGNATURE_S, pubKeyExecuteBatch, KeyType.P256NONKEY
        );

        bool isValid = webAuthn.verifyP256Signature(
            hashToValidate,
            P256NOKEY_SIGNATURE_R,
            P256NOKEY_SIGNATURE_S,
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y
        );
        
        console.log("isValid", isValid);
        userOp.signature = _signature;

        _etch();
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(userOp, userOpHash, 0);
        
        _etch();
        vm.expectRevert(KeyManager__UsedChallenge.selector);
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(userOp, userOpHash, 0);
    }

    function test_ValidateKeyTypeP256BadSignature() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 20e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = P256NOKEY_CHALLENGE;

        PubKey memory pubKeyExecuteBatch =
            PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            0x83be515c1c0786a236c625e381d45c0591a25a3c398670c381e16c71d7ceb0ff,
            P256NOKEY_SIGNATURE_S,
            pubKeyExecuteBatch,
            KeyType.P256NONKEY
        );

        bool isValid = webAuthn.verifyP256Signature(
            EfficientHashLib.sha2(userOpHash),
            0x83be515c1c0786a236c625e381d45c0591a25a3c398670c381e16c71d7ceb0ff,
            P256NOKEY_SIGNATURE_S,
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(res, 1);
    }

    function test_ValidateKeyTypeP256BadValidation() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 20e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = P256NOKEY_CHALLENGE;

        PubKey memory pubKeyExecuteBatch =
            PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            P256NOKEY_SIGNATURE_R, P256NOKEY_SIGNATURE_S, pubKeyExecuteBatch, KeyType.P256NONKEY
        );

        bool isValid = webAuthn.verifyP256Signature(
            EfficientHashLib.sha2(userOpHash),
            P256NOKEY_SIGNATURE_R,
            P256NOKEY_SIGNATURE_S,
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(res, 1);
    }

    function test_ValidateKeyTypeP256keyValidationFalse() public {
        vm.prank(owner);
        account.revokeKey(keySK);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 0e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = P256NOKEY_CHALLENGE;

        PubKey memory pubKeyExecuteBatch =
            PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            P256NOKEY_SIGNATURE_R, P256NOKEY_SIGNATURE_S, pubKeyExecuteBatch, KeyType.P256NONKEY
        );

        bool isValid = webAuthn.verifyP256Signature(
            EfficientHashLib.sha2(userOpHash),
            P256NOKEY_SIGNATURE_R,
            P256NOKEY_SIGNATURE_S,
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(res, 1);
    }

    function test_ValidateKeyTypeP256IncorrectMode() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 0e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_bad, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = P256NOKEY_CHALLENGE;

        PubKey memory pubKeyExecuteBatch =
            PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            P256NOKEY_SIGNATURE_R, P256NOKEY_SIGNATURE_S, pubKeyExecuteBatch, KeyType.P256NONKEY
        );

        bool isValid = webAuthn.verifyP256Signature(
            EfficientHashLib.sha2(userOpHash),
            P256NOKEY_SIGNATURE_R,
            P256NOKEY_SIGNATURE_S,
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(res, 1);
    }

    function test_ValidateKeyTypeP256IncorrectSelector() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 0e18, data: hex"deadbeef"});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = P256NOKEY_CHALLENGE;

        PubKey memory pubKeyExecuteBatch =
            PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            P256NOKEY_SIGNATURE_R, P256NOKEY_SIGNATURE_S, pubKeyExecuteBatch, KeyType.P256NONKEY
        );

        bool isValid = webAuthn.verifyP256Signature(
            EfficientHashLib.sha2(userOpHash),
            P256NOKEY_SIGNATURE_R,
            P256NOKEY_SIGNATURE_S,
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(res, 1);
    }

    function test_ValidateKeyTypeP256NoWhitelisted() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(123456), value: 0e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = P256NOKEY_CHALLENGE;

        PubKey memory pubKeyExecuteBatch =
            PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            P256NOKEY_SIGNATURE_R, P256NOKEY_SIGNATURE_S, pubKeyExecuteBatch, KeyType.P256NONKEY
        );

        bool isValid = webAuthn.verifyP256Signature(
            EfficientHashLib.sha2(userOpHash),
            P256NOKEY_SIGNATURE_R,
            P256NOKEY_SIGNATURE_S,
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(res, 1);
    }

    function test_ValidateKeyTypeP256SpendLimitBig() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: TOKEN,
            value: 0e18,
            data: abi.encodeWithSelector(IERC20.transfer.selector, sender, 300e18)
        });
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = P256NOKEY_CHALLENGE;

        PubKey memory pubKeyExecuteBatch =
            PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeP256Signature(
            P256NOKEY_SIGNATURE_R, P256NOKEY_SIGNATURE_S, pubKeyExecuteBatch, KeyType.P256NONKEY
        );

        bool isValid = webAuthn.verifyP256Signature(
            EfficientHashLib.sha2(userOpHash),
            P256NOKEY_SIGNATURE_R,
            P256NOKEY_SIGNATURE_S,
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        userOp.signature = _signature;

        vm.prank(ENTRYPOINT_V8);
        uint256 res = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(res, 1);
    }

    function test_IsValidSignatureBadLength() public view {
        bytes32 hash = keccak256("Hash");

        bytes memory signature = hex"deadbeef";

        bytes4 res = account.isValidSignature(hash, signature);

        assertEq(res, bytes4(0xffffffff));
    }

    function test_validateKeyTypeWEBAUTHNRevertUsedChallengeIsValidSignature() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: ETH_RECIVE, value: 20e18, data: hex""});
        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        uint256 nonce = entryPoint.getNonce(owner, 1);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: owner,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(360_000, 240_000),
            preVerificationGas: 110_000,
            gasFees: _packGasFees(2 gwei, 5 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        PubKey memory pubKeyExecuteBatch = PubKey({x: PUBLIC_KEY_X, y: PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            SIGNATURE_R,
            SIGNATURE_S,
            pubKeyExecuteBatch
        );

        userOp.signature = _signature;

        bytes32 userOpHash = CHALLENGE;
        _etch();

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            SIGNATURE_R,
            SIGNATURE_S,
            PUBLIC_KEY_X,
            PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(userOp, userOpHash, 0);

        bytes memory _signatureD = abi.encode(
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            SIGNATURE_R,
            SIGNATURE_S,
            pubKeyExecuteBatch
        );

        bytes4 res = account.isValidSignature(userOpHash, _signatureD);

        assertEq(res, bytes4(0xffffffff));
    }

    function test_validateKeyTypeWEBAUTHNNoMKIsValidSignature() public view {
        PubKey memory pubKeyExecuteBatch = PubKey({x: SK_PUBLIC_KEY_X, y: SK_PUBLIC_KEY_Y});

        bytes memory _signature = abi.encode(
            true,
            SK_AUTHENTICATOR_DATA,
            SK_CLIENT_DATA_JSON,
            SK_CHALLENGE_INDEX,
            SK_TYPE_INDEX,
            SK_SIGNATURE_R,
            SK_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        bytes32 userOpHash = SK_CHALLENGE;

        bytes4 res = account.isValidSignature(userOpHash, _signature);

        assertEq(res, bytes4(0xffffffff));
    }
}
