// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Base} from "test/Base.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {BaseOPF7702} from "src/core/BaseOPF7702.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract DepositAndTransferETH is Base {
    error NotFromEntryPoint();

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

    function test_Addresses() external view {
        console.log("/* --------------------------------- test_Addresses -------- */");
        address ePoint = address(account.entryPoint());
        address webAuthnVerifier = account.webAuthnVerifier();

        console.log("entryPoint", ePoint);
        console.log("webAuthnVerifier", webAuthnVerifier);

        assertEq(ePoint, address(entryPoint));
        assertEq(webAuthnVerifier, address(SEPOLIA_WEBAUTHN));
        console.log("/* --------------------------------- test_Addresses -------- */");
    }

    function test_UpgradeEntryPointWithRootKey() public {
        console.log(
            "/* -------------------------------- test_UpgradeEntryPointWithRootKey -------- */"
        );
        bytes memory callData =
            abi.encodeWithSelector(BaseOPF7702.setEntryPoint.selector, address(789012));

        uint256 nonce = entryPoint.getNonce(owner, 1);

        address ePoint_Before = address(account.entryPoint());

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

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        address ePoint_After = address(account.entryPoint());
        assertEq(ePoint_Before, address(entryPoint));
        assertEq(ePoint_After, address(789012));
        assertNotEq(ePoint_After, ePoint_Before);
        console.log(
            "/* -------------------------------- test_UpgradeEntryPointWithRootKey -------- */"
        );
    }

    function test_UpgradeWebAuthnVerifiertWithRootKey() public {
        console.log(
            "/* -------------------------------- test_UpgradeWebAuthnVerifiertWithRootKey -------- */"
        );
        bytes memory callData =
            abi.encodeWithSelector(BaseOPF7702.setWebAuthnVerifier.selector, address(123456));

        uint256 nonce = entryPoint.getNonce(owner, 1);

        address webAuthnVerifier_Before = account.webAuthnVerifier();

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

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        address webAuthnVerifier_After = account.webAuthnVerifier();
        assertEq(webAuthnVerifier_Before, WEBAUTHN_VERIFIER);
        assertEq(webAuthnVerifier_After, address(123456));
        assertNotEq(webAuthnVerifier_After, webAuthnVerifier_Before);
        console.log(
            "/* -------------------------------- test_UpgradeWebAuthnVerifiertWithRootKey -------- */"
        );
    }

    function test_UpgradeEntryPointWithMasterKey() public {
        console.log(
            "/* -------------------------------- test_test_UpgradeEntryPointWithMasterKey -------- */"
        );
        bytes memory callData =
            abi.encodeWithSelector(BaseOPF7702.setEntryPoint.selector, address(789012));

        uint256 nonce = entryPoint.getNonce(owner, 1);

        address ePoint_Before = address(account.entryPoint());

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
            IKey.PubKey({x: CHANGE_PUBLIC_KEY_X, y: CHANGE_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            CHANGE_AUTHENTICATOR_DATA,
            CHANGE_CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            CHANGE_SIGNATURE_R,
            CHANGE_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            CHANGE_AUTHENTICATOR_DATA,
            CHANGE_CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            CHANGE_SIGNATURE_R,
            CHANGE_SIGNATURE_S,
            CHANGE_PUBLIC_KEY_X,
            CHANGE_PUBLIC_KEY_Y
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

        address ePoint_After = address(account.entryPoint());
        assertEq(ePoint_Before, address(entryPoint));
        assertEq(ePoint_After, address(789012));
        assertNotEq(ePoint_After, ePoint_Before);

        console.log(
            "/* -------------------------------- test_test_UpgradeEntryPointWithMasterKey -------- */"
        );
    }

    function test_UpgradeEntryPointAndSendTXWithMasterKey() public {
        console.log(
            "/* -------------------------------- test_UpgradeEntryPointAndSendTXWithMasterKey -------- */"
        );
        address ePoint_Before = address(account.entryPoint());

        _upgradeEPoint();

        address ePoint_After = address(account.entryPoint());
        assertEq(ePoint_Before, address(entryPoint));
        assertEq(ePoint_After, address(789012));
        assertNotEq(ePoint_After, ePoint_Before);

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

        vm.expectRevert();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));

        console.log(
            "/* -------------------------------- test_UpgradeEntryPointAndSendTXWithMasterKey -------- */"
        );
    }

    function _upgradeEPoint() internal {
        bytes memory callData =
            abi.encodeWithSelector(BaseOPF7702.setEntryPoint.selector, address(789012));

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
            IKey.PubKey({x: CHANGE_PUBLIC_KEY_X, y: CHANGE_PUBLIC_KEY_Y});

        bytes memory _signature = account.encodeWebAuthnSignature(
            true,
            CHANGE_AUTHENTICATOR_DATA,
            CHANGE_CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            CHANGE_SIGNATURE_R,
            CHANGE_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        bool usedChallenge = account.usedChallenges(userOpHash);
        console.log("usedChallenge", usedChallenge);
        console.logBytes4(magicValue);

        bool isValid = webAuthn.verifySignature(
            userOpHash,
            true,
            CHANGE_AUTHENTICATOR_DATA,
            CHANGE_CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            CHANGE_SIGNATURE_R,
            CHANGE_SIGNATURE_S,
            CHANGE_PUBLIC_KEY_X,
            CHANGE_PUBLIC_KEY_Y
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
        pubKeyMK = PubKey({x: CHANGE_PUBLIC_KEY_X, y: CHANGE_PUBLIC_KEY_Y});

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

        pubKeyMK = PubKey({x: bytes32(0), y: bytes32(0)});
        keySK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        /* sign arbitrary message so initialise() passes sig check */
        bytes32 msgHash = account.getDigestToInit(keyMK, initialGuardian);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, msgHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        account.initialize(keyMK, keyData, keySK, keyData, sig, initialGuardian);
    }
}
