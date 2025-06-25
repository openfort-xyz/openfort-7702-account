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
import {KeysManager} from "src/core/KeysManager.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract RegistartionTest is Base {
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

        _initializeAccount();
        _register_KeyEOA();
        _register_KeyP256();
        _register_KeyP256NonKey();

        vm.prank(sender);
        entryPoint.depositTo{value: 0.09e18}(owner);
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

    function test_RegisterKeyEOAWithMK() public {
        console.log("/* ------------------------- test_RegisterKeyWithMK -------- */");
        uint48 validUntil = uint48(1795096759);
        uint48 limit = uint48(3);
        pubKeySK = PubKey({
            x: 0x0000000000000000000000000000000000000000000000000000000000000000,
            y: 0x0000000000000000000000000000000000000000000000000000000000000000
        });

        address skAddress = makeAddr("skAddress");
        keySK = Key({pubKey: pubKeySK, eoaAddress: skAddress, keyType: KeyType.WEBAUTHN});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

        bytes memory callData = abi.encodeWithSelector(
            KeysManager.registerKey.selector,
            validUntil,
            uint48(0),
            limit,
            true,
            TOKEN,
            spendInfo,
            _allowedSelectors(),
            0
        );

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
            IKey.PubKey({x: REG_PUBLIC_KEY_X, y: REG_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            REG_AUTHENTICATOR_DATA,
            REG_CLIENT_DATA_JSON,
            REG_CHALLENGE_INDEX,
            REG_TYPE_INDEX,
            REG_SIGNATURE_R,
            REG_SIGNATURE_S,
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
            REG_CLIENT_DATA_JSON,
            REG_CHALLENGE_INDEX,
            REG_TYPE_INDEX,
            REG_SIGNATURE_R,
            REG_SIGNATURE_S,
            REG_PUBLIC_KEY_X,
            REG_PUBLIC_KEY_Y
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

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        Key memory k = account.getKeyById(0);
        console.logBytes32(k.pubKey.x);
        console.logBytes32(k.pubKey.y);
    }

    function test_RegisterKeyP256WithMK() public {
        console.log("/* ----------------------- test_RegisterKeyP256WithMK -------- */");
        uint48 validUntil = uint48(1795096759);
        uint48 limit = uint48(3);
        pubKeySK = PubKey({x: P256_PUBLIC_KEY_X, y: P256_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

        bytes memory callData = abi.encodeWithSelector(
            KeysManager.registerKey.selector,
            validUntil,
            uint48(0),
            limit,
            true,
            TOKEN,
            spendInfo,
            _allowedSelectors(),
            0
        );

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
            IKey.PubKey({x: REG_PUBLIC_KEY_X, y: REG_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            AUTHENTICATOR_DATA,
            REG_CLIENT_DATA_JSON,
            REG_CHALLENGE_INDEX,
            REG_TYPE_INDEX,
            REG_SIGNATURE_R,
            REG_SIGNATURE_S,
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
            REG_CLIENT_DATA_JSON,
            REG_CHALLENGE_INDEX,
            REG_TYPE_INDEX,
            REG_SIGNATURE_R,
            REG_SIGNATURE_S,
            REG_PUBLIC_KEY_X,
            REG_PUBLIC_KEY_Y
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

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        Key memory k = account.getKeyById(0);
        console.logBytes32(k.pubKey.x);
        console.logBytes32(k.pubKey.y);
        console.log("/* ----------------------- test_RegisterKeyP256WithMK -------- */");
    }

    function test_RegisterKeyP256NonKeyWithMK() public {
        console.log("/* ----------------------- test_RegisterKeyP256NonKeyWithMK -------- */");
        uint48 validUntil = uint48(1795096759);
        uint48 limit = uint48(3);
        pubKeySK = PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256NONKEY});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

        bytes memory callData = abi.encodeWithSelector(
            KeysManager.registerKey.selector,
            validUntil,
            uint48(0),
            limit,
            true,
            TOKEN,
            spendInfo,
            _allowedSelectors(),
            0
        );

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
            IKey.PubKey({x: REG_PUBLIC_KEY_X, y: REG_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            AUTHENTICATOR_DATA,
            REG_CLIENT_DATA_JSON,
            REG_CHALLENGE_INDEX,
            REG_TYPE_INDEX,
            REG_SIGNATURE_R,
            REG_SIGNATURE_S,
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
            REG_CLIENT_DATA_JSON,
            REG_CHALLENGE_INDEX,
            REG_TYPE_INDEX,
            REG_SIGNATURE_R,
            REG_SIGNATURE_S,
            REG_PUBLIC_KEY_X,
            REG_PUBLIC_KEY_Y
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

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        Key memory k = account.getKeyById(0);
        console.logBytes32(k.pubKey.x);
        console.logBytes32(k.pubKey.y);
        console.log("/* ----------------------- test_RegisterKeyP256NonKeyWithMK -------- */");
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
            contractAddress: TOKEN,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 0
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
        pubKeySK = PubKey({x: P256_PUBLIC_KEY_X, y: P256_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

        keyData = KeyReg({
            validUntil: validUntil,
            validAfter: 0,
            limit: limit,
            whitelisting: true,
            contractAddress: TOKEN,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 0
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
        pubKeySK = PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});

        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256NONKEY});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

        keyData = KeyReg({
            validUntil: validUntil,
            validAfter: 0,
            limit: limit,
            whitelisting: true,
            contractAddress: TOKEN,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 0
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
        pubKeyMK = PubKey({x: REG_PUBLIC_KEY_X, y: REG_PUBLIC_KEY_Y});

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
