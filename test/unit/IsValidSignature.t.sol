// SPDX-license-Identifier: MIT

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
import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

contract IsValidSignature is Base {
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
    KeyReg internal keyDataSK;

    /* ─────────────────────────────────────────────────────────────── setup ──── */
    function setUp() public {
        vm.startPrank(sender);
        (owner, ownerPk) = makeAddrAndKey("owner");
        (sender, senderPk) = makeAddrAndKey("sender");
        (sessionKey, sessionKeyPk) = makeAddrAndKey("sessionKey");
        (GUARDIAN_EOA_ADDRESS, GUARDIAN_EOA_PRIVATE_KEY) = makeAddrAndKey("GUARDIAN_EOA_ADDRESS");
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
        _deal();

        vm.prank(sender);
        entryPoint.depositTo{value: 0.09e18}(owner);
    }

    function test_IsValidSignatureRootKey() public view {
        bytes32 hash = keccak256("Hello OPF7702!");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 magicValue = account.isValidSignature(hash, signature);
        console.logBytes4(magicValue);

        bool isOK = magicValue == 0x1626ba7e;
        assertTrue(isOK, "Returns 0xffffffff");
    }

    function test_IsValidSignatureWebAuthnMK() public {
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
            initCode: hex"",
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
            IKey.PubKey({x: ERC1271_PUBLIC_KEY_X, y: ERC1271_PUBLIC_KEY_Y});

        bytes memory _signature = abi.encode(
            true,
            AUTHENTICATOR_DATA,
            ERC1271_CLIENT_DATA_JSON,
            REG_CHALLENGE_INDEX,
            REG_TYPE_INDEX,
            ERC1271_SIGNATURE_R,
            ERC1271_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        bytes4 magicValue = account.isValidSignature(userOpHash, _signature);
        console.logBytes4(magicValue);

        bool isOK = magicValue == 0x1626ba7e;
        assertTrue(isOK, "Returns 0xffffffff");
    }

    /* ─────────────────────────────────────────────────────────── helpers ──── */
    function _initializeAccount() internal {
        /* sample WebAuthn public key – replace with a real one if needed */
        pubKeyMK = PubKey({x: ERC1271_PUBLIC_KEY_X, y: ERC1271_PUBLIC_KEY_Y});

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

        pubKeySK = PubKey({x: MINT_P256_PUBLIC_KEY_X, y: MINT_P256_PUBLIC_KEY_Y});
        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256});
        uint48 validUntil = uint48(1795096759);
        uint48 limit = uint48(20);

        keyDataSK = KeyReg({
            validUntil: validUntil,
            validAfter: 0,
            limit: limit,
            whitelisting: true,
            contractAddress: TOKEN,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 1e18
        });

        /* sign arbitrary message so initialise() passes sig check */
        bytes32 initialGuardian = keccak256(abi.encodePacked(sender));

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
        account.initialize(keyMK, keyData, keySK, keyDataSK, sig, initialGuardian);
    }
}
