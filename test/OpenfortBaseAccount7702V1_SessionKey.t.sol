// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {BaseSK} from "test/BaseSK.t.sol";
import {SpendLimit} from "contracts/utils/SpendLimit.sol";
import {Test, console2 as console} from "forge-std/Test.sol";
import {ISessionKey} from "contracts/interfaces/ISessionkey.sol";
import {OpenfortBaseAccount7702V1SessionKey} from "contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {ValidationData, _parseValidationData} from "@account-abstraction/contracts/core/Helpers.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IStakeManager} from "@account-abstraction/contracts/interfaces/IStakeManager.sol";

contract OpenfortBaseAccount7702V1SessionKeyTest is Test, BaseSK, SpendLimit, ISessionKey {

    EntryPoint public ENTRY_POINT;
    OpenfortBaseAccount7702V1SessionKey public implementation;
    OpenfortBaseAccount7702V1SessionKey public openfortBaseAccount;

    uint256 ANVIL_PRIVATE_KEY = vm.envUint("ANVIL_PRIVATE_KEY_OPENFORT_USER");
    address public OPENFORT_USER = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
    address public OPENFORT_DEPLOER = address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
    address public BURN_ADDRESS = address(0);
    bytes32 public constant USEROP_TYPEHASH = 0x58a2b86998ee046a6138be7db7c3eb3dcbdf805b51b06558cd8b18f9091af245;

    Key public _key;
    Key public _keyEOA;
    PubKey public pubKey;
    bytes32 public keyHash;
    PubKey public _pubKeyEmpty;

    PackedUserOperation public OP_EMPTY;
    PackedUserOperation public OP_EPOINT;

    function setUp() public {
        vm.startPrank(OPENFORT_DEPLOER);
        forkId = vm.createFork(MAINNET_RPC_URL);
        vm.selectFork(forkId);

        ENTRY_POINT = new EntryPoint();
        implementation = new OpenfortBaseAccount7702V1SessionKey(address(ENTRY_POINT));
        bytes memory code = address(implementation).code;
        vm.etch(OPENFORT_USER, code);
        openfortBaseAccount = OpenfortBaseAccount7702V1SessionKey(payable(OPENFORT_USER));

        vm.stopPrank();

        (SESSION_KEY, SESSION_KEY_PRIVATE_KEY) = makeAddrAndKey("SESSION_KEY");
        (RANDOM, RANDOM_PRIVATE_KEY) = makeAddrAndKey("RANDOM");
        
        _deal();
        _op_empty();
        _initialize(1, block.timestamp + 1 days);
        _registerWebAuthn();
        _registerEOA();

        vm.prank(RANDOM);
        ENTRY_POINT.depositTo{value: 1e18}(OPENFORT_USER);
    }

    function test_PreDeploy() public view {
        assertEq(openfortBaseAccount._OPENFORT_CONTRACT_ADDRESS(), implementation._OPENFORT_CONTRACT_ADDRESS());
    }

    function test_CheckOwner() public view {
        assertEq(openfortBaseAccount.owner(), OPENFORT_USER);
    }

    function test_CheckNonce() public view {
        assertEq(openfortBaseAccount.nonce(), 1);
    }

    function test_Registration() public view {
        (KeyType _keyType, address _registeredBy, bool _isActive) = openfortBaseAccount.getKeyRegistrationInfo(0);
        assertEq(_registeredBy, OPENFORT_USER);
        assertEq(_isActive, true);
        assertEq(uint256(_keyType), uint256(KeyType.WEBAUTHN));

        (KeyType _keyTypeEOA, address _registeredByEOA, bool _isActivEOA) = openfortBaseAccount.getKeyRegistrationInfo(1);
        assertEq(_registeredByEOA, OPENFORT_USER);
        assertEq(_isActivEOA, true);
        assertEq(uint256(_keyTypeEOA), uint256(KeyType.EOA));
    }

    function test_Revoke() public {
        vm.prank(OPENFORT_USER);
        openfortBaseAccount.revokeSessionKey(_key);
        (bool _isActive, uint256 _validUntil, uint256 _validAfter, uint256 _limit) =
            openfortBaseAccount.getSessionKeyData(keyHash);

        assertEq(_isActive, false);
        assertEq(_validUntil, 0);
        assertEq(_validAfter, 0);
        assertEq(_limit, 0);
    }

    function test_RevokeAll() public {
        vm.prank(OPENFORT_USER);
        openfortBaseAccount.revokeAllSessionKeys();
        (bool _isActive, uint256 _validUntil, uint256 _validAfter, uint256 _limit) =
            openfortBaseAccount.getSessionKeyData(keyHash);

        assertEq(_isActive, false);
        assertEq(_validUntil, 0);
        assertEq(_validAfter, 0);
        assertEq(_limit, 0);

        bool isActiveEOA = openfortBaseAccount.isSessionKeyActive(SESSION_KEY);
        assertFalse(isActiveEOA);

        (bool _isActiveEOA, uint256 _validUntilEOA, uint256 _validAfterEOA, uint256 _limitEOA) =
        openfortBaseAccount.getSessionKeyData(SESSION_KEY);

        assertEq(_isActiveEOA, false);
        assertEq(_validUntilEOA, 0);
        assertEq(_validAfterEOA, 0);
        assertEq(_limitEOA, 0);
    }

    function test_IsValidSignature() public view {
        bool isActive = openfortBaseAccount.isSessionKeyActive(keyHash);
        assertTrue(isActive, "The Session Keys Is Inactive | Failed Register");

        bytes memory webAuthnSignatureData = openfortBaseAccount.encodeWebAuthnSignature(
            CHALLENGE,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            VALID_SIGNATURE_R,
            VALID_SIGNATURE_S,
            pubKey
        );

        bytes4 isValid = openfortBaseAccount.isValidSignature(P256_VERIFIER, webAuthnSignatureData);

        console.logBytes4(isValid);
        assertEq(isValid, MAGICVALUE, "WebAuthn signature verification should succeed with valid signature");


        (bytes32 userOpHash, bytes memory signature) = _getHashAndSignature(ANVIL_PRIVATE_KEY, OPENFORT_USER);

        bytes4 isValidOwner = openfortBaseAccount.isValidSignature(userOpHash, signature);
        console.logBytes4(isValidOwner);
        assertEq(isValidOwner, MAGICVALUE, "WebAuthn signature verification should succeed with valid signature");

        bool isActiveEOA = openfortBaseAccount.isSessionKeyActive(SESSION_KEY);
        assertTrue(isActiveEOA, "The Session Keys Is Inactive | Failed Register");

        (bytes32 userOpHashEOA, bytes memory signatureEOA) = _getHashAndSignature(SESSION_KEY_PRIVATE_KEY, SESSION_KEY);
        bytes4 isValidEOA = openfortBaseAccount.isValidSignature(userOpHashEOA, signatureEOA);

        console.logBytes4(isValidEOA);
        assertEq(isValidEOA, MAGICVALUE, "WebAuthn signature verification should succeed with valid signature");
    }

    function test_IsValidSignatureFailed() public view {
        bool isActive = openfortBaseAccount.isSessionKeyActive(keyHash);
        assertTrue(isActive, "The Session Keys Is Inactive | Failed Register");

        bytes32 modifiedR = bytes32(uint256(VALID_SIGNATURE_R) + 1);

        bytes memory webAuthnSignatureData = openfortBaseAccount.encodeWebAuthnSignature(
            CHALLENGE,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            modifiedR,
            VALID_SIGNATURE_S,
            pubKey
        );

        bytes4 isValid = openfortBaseAccount.isValidSignature(P256_VERIFIER, webAuthnSignatureData);

        console.logBytes4(isValid);
        assertEq(isValid, FAILED_VALUE, "WebAuthn signature verification should succeed with valid signature");

        bool isActiveEOA = openfortBaseAccount.isSessionKeyActive(SESSION_KEY);
        assertTrue(isActiveEOA, "The Session Keys Is Inactive | Failed Register");

        (bytes32 userOpHashEOA, bytes memory signatureEOA) = _getHashAndSignature(RANDOM_PRIVATE_KEY, RANDOM);
        bytes4 isValidEOA = openfortBaseAccount.isValidSignature(userOpHashEOA, signatureEOA);

        console.logBytes4(isValidEOA);
        assertEq(isValidEOA, FAILED_VALUE, "WebAuthn signature verification should succeed with valid signature");
    }

    function test_ExecutionBatch() public {
        bool isActive = openfortBaseAccount.isSessionKeyActive(keyHash);
        assertTrue(isActive, "The Session Keys Is Inactive | Failed Register");

        uint256 count = 3;
        
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        for (uint256 i = 0; i < count; i++) {
            targets[i] = CONTRACT;
            values[i] = 0.3e18;
            callData[i] = hex"12345678";
        }

        bytes memory callDataExecuteBatch = abi.encodeWithSelector(0x47e1da2a, targets, values, callData);

        bytes memory webAuthnSignatureData = openfortBaseAccount.encodeWebAuthnSignature(
            CHALLENGE,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            VALID_SIGNATURE_R,
            VALID_SIGNATURE_S,
            pubKey
        );

        _op(webAuthnSignatureData, callDataExecuteBatch);
        
        vm.prank(address(ENTRY_POINT));
        uint256 validationData = openfortBaseAccount.validateUserOp(OP_EPOINT, P256_VERIFIER, 0);

        ValidationData memory data = _parseValidationData(validationData);

        assertEq(uint48(block.timestamp + 1000), data.validUntil);

        bytes32 userOpHash = openfortBaseAccount.getUserOpHash(OP_EPOINT);
        bytes32 digest = openfortBaseAccount.getDigestToSign(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SESSION_KEY_PRIVATE_KEY, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory fullSignature = openfortBaseAccount.encodeEOASignature(signature);
        OP_EPOINT.signature = fullSignature;

        vm.prank(address(ENTRY_POINT));
        uint256 validationDataEOA = openfortBaseAccount.validateUserOp(OP_EPOINT, userOpHash, 0);

        ValidationData memory dataEOA = _parseValidationData(validationDataEOA);

        assertEq(uint48(block.timestamp + 1000), dataEOA.validUntil);

        bytes32 userOpHashOwner = openfortBaseAccount.getUserOpHash(OP_EPOINT);
        bytes32 digestOwner = openfortBaseAccount.getDigestToSign(userOpHashOwner);
        (uint8 vOwner, bytes32 rOwner, bytes32 sOwner) = vm.sign(ANVIL_PRIVATE_KEY, digestOwner);
        bytes memory signatureOwner = abi.encodePacked(rOwner, sOwner, vOwner);
        bytes memory fullSignatureOwner = openfortBaseAccount.encodeEOASignature(signatureOwner);
        OP_EPOINT.signature = fullSignatureOwner;

        vm.prank(address(ENTRY_POINT));
        uint256 validationDataOwner = openfortBaseAccount.validateUserOp(OP_EPOINT, userOpHashOwner, 0);

        assertEq(validationDataOwner, 0);
    }

    function test_Execution() public {
        bool isActive = openfortBaseAccount.isSessionKeyActive(keyHash);
        assertTrue(isActive, "The Session Keys Is Inactive | Failed Register");

        bytes memory callDataExecute = abi.encodeWithSelector(0xb61d27f6, CONTRACT, 0.4e18, hex"12345678");

        bytes memory webAuthnSignatureData = openfortBaseAccount.encodeWebAuthnSignature(
            CHALLENGE,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            VALID_SIGNATURE_R,
            VALID_SIGNATURE_S,
            pubKey
        );

        _op(webAuthnSignatureData, callDataExecute);
        
        vm.prank(address(ENTRY_POINT));
        uint256 validationData = openfortBaseAccount.validateUserOp(OP_EPOINT, P256_VERIFIER, 0);

        ValidationData memory data = _parseValidationData(validationData);
        assertEq(uint48(block.timestamp + 1000), data.validUntil);

        bytes32 userOpHash = openfortBaseAccount.getUserOpHash(OP_EPOINT);
        bytes32 digest = openfortBaseAccount.getDigestToSign(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SESSION_KEY_PRIVATE_KEY, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory fullSignature = openfortBaseAccount.encodeEOASignature(signature);
        OP_EPOINT.signature = fullSignature;

        vm.prank(address(ENTRY_POINT));
        uint256 validationDataEOA = openfortBaseAccount.validateUserOp(OP_EPOINT, userOpHash, 0);

        ValidationData memory dataEOA = _parseValidationData(validationDataEOA);

        assertEq(uint48(block.timestamp + 1000), dataEOA.validUntil);

        bytes32 userOpHashOwner = openfortBaseAccount.getUserOpHash(OP_EPOINT);
        bytes32 digestOwner = openfortBaseAccount.getDigestToSign(userOpHashOwner);
        (uint8 vOwner, bytes32 rOwner, bytes32 sOwner) = vm.sign(ANVIL_PRIVATE_KEY, digestOwner);
        bytes memory signatureOwner = abi.encodePacked(rOwner, sOwner, vOwner);
        bytes memory fullSignatureOwner = openfortBaseAccount.encodeEOASignature(signatureOwner);
        OP_EPOINT.signature = fullSignatureOwner;

        vm.prank(address(ENTRY_POINT));
        uint256 validationDataOwner = openfortBaseAccount.validateUserOp(OP_EPOINT, userOpHashOwner, 0);

        assertEq(validationDataOwner, 0);
    }

    function test_MasterKeyCanAll() public {
        _pubKeyEmpty = PubKey({x: hex"", y: hex""});

        Key memory _keyEOAMaster = Key({
            pubKey: _pubKeyEmpty,
            eoaAddress: RANDOM,
            keyType: KeyType.EOA
        });

        SpendTokenInfo memory spendTokenInfo = SpendTokenInfo({
            token: TOKEN_ADDRESS,
            limit: SPEND_LIMIT
        });

        vm.startPrank(OPENFORT_USER);
        openfortBaseAccount.registerSessionKey(
            _keyEOAMaster,
            uint48(block.timestamp + 1000),
            uint48(0),
            0,
            true,
            CONTRACT,
            spendTokenInfo,
            _allowedSelectors,
            ETH_LIMIT
        );
        vm.stopPrank();

        (,,, uint48 limit) = openfortBaseAccount.getSessionKeyData(RANDOM);

        assertEq(limit, 0);

        uint256 count = 3;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        for (uint256 i = 0; i < count; i += 1) {
            targets[i] = address(TOKEN_ADDRESS);
            values[i] = 30e18;
            callData[i] =
                hex"095ea7b3000000000000000000000000933597a323eb81cae705c5bc29985172fd5a39730000000000000000000000000000000000000000000000000000000006281d56";
        }

        bytes memory callDataExecuteBatch = abi.encodeWithSelector(0x47e1da2a, targets, values, callData);

        OP_EPOINT.callData = callDataExecuteBatch;
        bytes32 userOpHash = openfortBaseAccount.getUserOpHash(OP_EPOINT);
        bytes32 digest = openfortBaseAccount.getDigestToSign(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(RANDOM_PRIVATE_KEY, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory fullSignature = openfortBaseAccount.encodeEOASignature(signature);
        OP_EPOINT.signature = fullSignature;


        bytes4 isValid = openfortBaseAccount.isValidSignature(userOpHash, signature);

        assertEq(isValid, MAGICVALUE, "WebAuthn signature verification should succeed with valid signature");

        vm.prank(address(ENTRY_POINT));
        uint256 validationDataEOA = openfortBaseAccount.validateUserOp(OP_EPOINT, userOpHash, 0);

        ValidationData memory dataEOA = _parseValidationData(validationDataEOA);

        assertEq(uint48(block.timestamp + 1000), dataEOA.validUntil);
    }

    function test_GetAndSendETH() public {
        vm.deal(RANDOM, 10e18);

        uint256 OPENFORT_USER_BALANCE_BEFORE = OPENFORT_USER.balance;

        vm.prank(RANDOM);
        (bool ok,) = payable(address(OPENFORT_USER)).call{value: 1e18}("");
        assertTrue(ok);

        uint256 OPENFORT_USER_BALANCE_AFTER = OPENFORT_USER.balance;

        assertEq(OPENFORT_USER_BALANCE_BEFORE + 1e18, OPENFORT_USER_BALANCE_AFTER);

        uint256 RANDOM_USER_BALANCE_BEFORE = RANDOM.balance;

        OpenfortBaseAccount7702V1SessionKey.Transaction[] memory transactions = new OpenfortBaseAccount7702V1SessionKey.Transaction[](1);
        transactions[0] = OpenfortBaseAccount7702V1SessionKey.Transaction({
            to: RANDOM, 
            value: 2e18, 
            data: hex""
        });
        
        vm.prank(address(ENTRY_POINT));
        openfortBaseAccount.execute(transactions);

        uint256 RANDOM_USER_BALANCE_AFTER = RANDOM.balance;

        assertEq(RANDOM_USER_BALANCE_BEFORE + 2e18, RANDOM_USER_BALANCE_AFTER);
    }
    
    function test_ExecuteHandleOpWebAuthn() public {

        bytes memory callDataExecute = abi.encodeWithSelector(0xb61d27f6, CONTRACT, 0.4e18, hex"12345678");

        bytes memory webAuthnSignatureData = openfortBaseAccount.encodeWebAuthnSignature(
            CHALLENGE,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            VALID_SIGNATURE_R,
            VALID_SIGNATURE_S,
            pubKey
        );

        _opHandleOps(webAuthnSignatureData, callDataExecute);
        PackedUserOperation[] memory opArr = new PackedUserOperation[](1);
        opArr[0] = OP_EPOINT;

        bytes memory code = abi.encodePacked(
        bytes3(0xef0100),
        address(implementation) // or your logic contract
        );
        vm.etch(OPENFORT_USER, code);

        vm.prank(RANDOM);
        ENTRY_POINT.handleOps(opArr, payable(OPENFORT_USER));
    }

    function test_ExecuteHandleOpEOASessionKey() public {
        bytes memory callDataExecute = abi.encodeWithSelector(0xb61d27f6, CONTRACT, 0.4e18, hex"12345678");

        uint256 nonce = ENTRY_POINT.getNonce(OPENFORT_USER, 1);
        uint256 callGasLimit = 200_000; 
        uint256 verificationGasLimit = 150_000; 
        uint256 preVerificationGas = 80_000; 
        uint256 maxFeePerGas = 50 gwei;
        uint256 maxPriorityFeePerGas = 2 gwei;

        OP_EPOINT = PackedUserOperation({
        sender: OPENFORT_USER,
        nonce: nonce,
        initCode: hex"7702",
        callData: callDataExecute,
        accountGasLimits: _packAccountGasLimits(callGasLimit, verificationGasLimit),
        preVerificationGas: preVerificationGas,
        gasFees: _packGasFees(maxFeePerGas, maxPriorityFeePerGas),
        paymasterAndData: hex"",
        signature: hex""
        });

        bytes memory code2 = abi.encodePacked(
        bytes3(0xef0100),
        address(implementation) // or your logic contract
        );
        vm.etch(OPENFORT_USER, code2);

        bytes32 userOpHash = ENTRY_POINT.getUserOpHash(OP_EPOINT);

        bytes32 digest = openfortBaseAccount.getDigestToSign(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SESSION_KEY_PRIVATE_KEY, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory fullSignature = openfortBaseAccount.encodeEOASignature(signature);
        OP_EPOINT.signature = fullSignature;
        console.log("SESSION_KEY", SESSION_KEY);
        
        PackedUserOperation[] memory opArr = new PackedUserOperation[](1);
        opArr[0] = OP_EPOINT;

        bytes memory code = abi.encodePacked(
        bytes3(0xef0100),
        address(implementation) // or your logic contract
        );
        vm.etch(OPENFORT_USER, code);

        vm.prank(RANDOM);
        ENTRY_POINT.handleOps(opArr, payable(OPENFORT_USER));
    }
    
    function test_ExecuteHandleOpOwner() public {
        bytes memory callDataExecute = abi.encodeWithSelector(0xb61d27f6, CONTRACT, 0.4e18, hex"12345678");

        uint256 nonce = ENTRY_POINT.getNonce(OPENFORT_USER, 1);
        uint256 callGasLimit = 200_000; 
        uint256 verificationGasLimit = 150_000; 
        uint256 preVerificationGas = 80_000; 
        uint256 maxFeePerGas = 50 gwei;
        uint256 maxPriorityFeePerGas = 2 gwei;

        OP_EPOINT = PackedUserOperation({
        sender: OPENFORT_USER,
        nonce: nonce,
        initCode: hex"7702",
        callData: callDataExecute,
        accountGasLimits: _packAccountGasLimits(callGasLimit, verificationGasLimit),
        preVerificationGas: preVerificationGas,
        gasFees: _packGasFees(maxFeePerGas, maxPriorityFeePerGas),
        paymasterAndData: hex"",
        signature: hex""
        });

        bytes memory code2 = abi.encodePacked(
        bytes3(0xef0100),
        address(implementation) // or your logic contract
        );
        vm.etch(OPENFORT_USER, code2);

        bytes32 userOpHash = ENTRY_POINT.getUserOpHash(OP_EPOINT);

        bytes32 digest = openfortBaseAccount.getDigestToSign(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ANVIL_PRIVATE_KEY, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory fullSignature = openfortBaseAccount.encodeEOASignature(signature);
        OP_EPOINT.signature = fullSignature;
                
        PackedUserOperation[] memory opArr = new PackedUserOperation[](1);
        opArr[0] = OP_EPOINT;

        bytes memory code = abi.encodePacked(
        bytes3(0xef0100),
        address(implementation) // or your logic contract
        );
        vm.etch(OPENFORT_USER, code);

        vm.prank(RANDOM);
        ENTRY_POINT.handleOps(opArr, payable(OPENFORT_USER));
    }

    function _registerWebAuthn() internal {
        pubKey = PubKey({
            x: VALID_PUBLIC_KEY_X,
            y: VALID_PUBLIC_KEY_Y
        });
        keyHash = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
        _key = Key({
            pubKey: pubKey,
            eoaAddress: BURN_ADDRESS,
            keyType: KeyType.WEBAUTHN
        });
        SpendTokenInfo memory spendTokenInfo = SpendTokenInfo({
            token: TOKEN_ADDRESS,
            limit: SPEND_LIMIT
        });
        for (uint256 i; i < 5; i++) {
            _allowedSelectors.push(0x12345678);
        }
        vm.startPrank(OPENFORT_USER);
        openfortBaseAccount.registerSessionKey(_key, uint48(block.timestamp + 1000), uint48(0), LIMIT, true, CONTRACT, spendTokenInfo, _allowedSelectors, ETH_LIMIT);
        vm.stopPrank();
    }

    function _registerEOA() internal {
        _pubKeyEmpty = PubKey({x: hex"", y: hex""});

        _keyEOA = Key({
            pubKey: _pubKeyEmpty,
            eoaAddress: SESSION_KEY,
            keyType: KeyType.EOA
        });
        SpendTokenInfo memory spendTokenInfo = SpendTokenInfo({
            token: TOKEN_ADDRESS,
            limit: SPEND_LIMIT
        });
        for (uint256 i; i < 5; i++) {
            _allowedSelectors.push(0x12345678);
        }
        vm.startPrank(OPENFORT_USER);
        openfortBaseAccount.registerSessionKey(_keyEOA, uint48(block.timestamp + 1000), uint48(0), LIMIT, true, CONTRACT, spendTokenInfo, _allowedSelectors, ETH_LIMIT);
        vm.stopPrank();
    }

    function _initialize(uint256 _nonce, uint256 _validUntil) internal {
        bytes32 hashMessage = ENTRY_POINT.getUserOpHash(OP_EMPTY);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ANVIL_PRIVATE_KEY, hashMessage);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(address(ENTRY_POINT));
        openfortBaseAccount.initialize(OPENFORT_USER, _validUntil, hashMessage, signature, _nonce);
    }

    function _deal() internal {
        vm.deal(OPENFORT_USER, 10 ether);
        vm.deal(RANDOM, 10 ether);
        vm.deal(address(ENTRY_POINT), 1 ether);
    }

    function _op_empty() internal {
            OP_EMPTY = PackedUserOperation({
            sender: OPENFORT_USER,
            nonce: 1,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: 0x0000000000000000000000000000000000000000000000000000000000000000,
            preVerificationGas: 0,
            gasFees: 0x0000000000000000000000000000000000000000000000000000000000000000,
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _op(bytes memory _signature, bytes memory _callData) internal {
            OP_EPOINT = PackedUserOperation({
            sender: OPENFORT_USER,
            nonce: 2,
            initCode: hex"",
            callData: _callData,
            accountGasLimits: 0x0000000000000000000000000000000000000000000000000000000000000000,
            preVerificationGas: 0,
            gasFees: 0x0000000000000000000000000000000000000000000000000000000000000000,
            paymasterAndData: hex"",
            signature: _signature
        });
    }

    function _opHandleOps(bytes memory _signature, bytes memory _callData) internal {
        uint256 nonce = ENTRY_POINT.getNonce(OPENFORT_USER, 1);
        uint256 callGasLimit = 200_000; 
        uint256 verificationGasLimit = 150_000; 
        uint256 preVerificationGas = 80_000; 
        uint256 maxFeePerGas = 50 gwei;
        uint256 maxPriorityFeePerGas = 2 gwei;

        OP_EPOINT = PackedUserOperation({
        sender: OPENFORT_USER,
        nonce: nonce,
        initCode: hex"7702",
        callData: _callData,
        accountGasLimits: _packAccountGasLimits(callGasLimit, verificationGasLimit),
        preVerificationGas: preVerificationGas,
        gasFees: _packGasFees(maxFeePerGas, maxPriorityFeePerGas),
        paymasterAndData: hex"",
        signature: _signature
        });
    }

    function _packAccountGasLimits(uint256 callGasLimit, uint256 verificationGasLimit) internal pure returns (bytes32) {
        return bytes32((callGasLimit << 128) | verificationGasLimit);
    }

    function _packGasFees(uint256 maxFeePerGas, uint256 maxPriorityFeePerGas) internal pure returns (bytes32) {
        return bytes32((maxFeePerGas << 128) | maxPriorityFeePerGas);
    }

    function _getHashAndSignature(uint256 _privateKey, address _sender) internal view returns (bytes32, bytes memory) {
        PackedUserOperation memory OP = PackedUserOperation({
            sender: _sender,
            nonce: 1,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: 0x0000000000000000000000000000000000000000000000000000000000000000,
            preVerificationGas: 0,
            gasFees: 0x0000000000000000000000000000000000000000000000000000000000000000,
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = openfortBaseAccount.getUserOpHash(OP);

        bytes32 digestToSign = openfortBaseAccount.getDigestToSign(userOpHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, digestToSign);
        bytes memory signature = abi.encodePacked(r, s, v);

        return (userOpHash, signature);
    }
}

/**
 * @dev Simple mock of an ENTRY_POINT - NOT implementing any interface to avoid compilation issues
 */
contract SimpleMockENTRY_POINT {
    mapping(address => uint256) private balances;
    
    function depositTo(address account) external payable {
        balances[account] += msg.value;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }

    function getUserOpHash(PackedUserOperation calldata userOp) external pure returns (bytes32) {
        return keccak256(abi.encode(
            userOp.sender,
            userOp.nonce,
            keccak256(userOp.initCode),
            keccak256(userOp.callData),
            userOp.accountGasLimits,
            userOp.preVerificationGas,
            userOp.gasFees,
            keccak256(userOp.paymasterAndData)
        ));
    }

    function withdrawTo(address payable withdrawAddress, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool success,) = withdrawAddress.call{value: amount}("");
        require(success, "failed to withdraw");
    }
}