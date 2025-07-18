// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Base} from "test/Base.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
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

contract KeysTest is Base {
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
        entryPoint.depositTo{value: 0.08e18}(owner);
    }

    function test_RevokeByID() public {
        uint256 idLength = account.id();

        console.log("idLength", idLength);

        uint256 id = 5;

        Key memory k1 = account.getKeyById(id);
        Key memory k2 = account.getKeyById(id + 20);
        Key memory mk = account.getKeyById(0);

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.startPrank(owner);

        account.revokeKey(k1);
        account.revokeKey(k2);
        account.revokeKey(mk);

        vm.stopPrank();
        (bool _isActivek1, uint256 _validUntilk1,, uint256 _limitk1) =
            account.getKeyData(keccak256(abi.encodePacked(k1.eoaAddress)));

        (bool _isActivek2, uint256 _validUntilk2,, uint256 _limitk2) =
            account.getKeyData(keccak256(abi.encodePacked(k2.pubKey.x, k2.pubKey.y)));

        (bool _isActivemk, uint256 _validUntilmk,, uint256 _limitmk) =
            account.getKeyData(keccak256(abi.encodePacked(mk.pubKey.x, mk.pubKey.y)));

        assertFalse(_isActivek1);
        assertFalse(_isActivek2);
        assertFalse(_isActivemk);

        assertEq(_validUntilk1, 0);
        assertEq(_validUntilk2, 0);
        assertEq(_validUntilmk, 0);

        assertEq(_limitk1, 0);
        assertEq(_limitk2, 0);
        assertEq(_limitmk, 0);
    }

    function test_RevokeALL() public {
        vm.prank(owner);

        account.revokeAllKeys();

        uint256 idLength = account.id();

        for (uint256 i = 1; i < idLength; i++) {
            Key memory k = account.getKeyById(i);

            // Declare variables outside the if/else blocks
            bool _isActive;
            uint256 _validUntil;
            uint256 _limit;

            if (k.keyType == KeyType.WEBAUTHN) {
                (_isActive, _validUntil,, _limit) =
                    account.getKeyData(keccak256(abi.encodePacked(k.pubKey.x, k.pubKey.y)));
            } else {
                (_isActive, _validUntil,, _limit) =
                    account.getKeyData(keccak256(abi.encodePacked(k.eoaAddress)));
            }

            // Now the variables are accessible here
            assertFalse(_isActive);
            assertEq(_validUntil, 0);
            assertEq(_limit, 0);
        }
    }

    /* ─────────────────────────────────────────────────────────────── tests ──── */
    function _register_KeyEOA() internal {
        uint256 count = 15;

        for (uint256 i; i < count; i++) {
            uint48 validUntil = uint48(block.timestamp + 1 days);
            uint48 limit = uint48(3);
            pubKeySK = PubKey({
                x: 0x0000000000000000000000000000000000000000000000000000000000000000,
                y: 0x0000000000000000000000000000000000000000000000000000000000000000
            });

            string memory iString = vm.toString(i);
            address sessionKeyAddr = makeAddr(iString);

            keySK = Key({pubKey: pubKeySK, eoaAddress: sessionKeyAddr, keyType: KeyType.EOA});

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

            bytes memory code = abi.encodePacked(
                bytes3(0xef0100),
                address(implementation) // or your logic contract
            );
            vm.etch(owner, code);

            vm.prank(address(entryPoint));
            account.registerKey(keySK, keyData);
        }
    }

    function _register_KeyP256() internal {
        uint256 count = 15;

        for (uint256 i; i < count; i++) {
            uint48 validUntil = uint48(block.timestamp + 1 days);
            uint48 limit = uint48(3);

            bytes32 RANDOM_P256_PUBLIC_KEY_X =
                keccak256(abi.encodePacked("X_KEY", i, block.timestamp));
            bytes32 RANDOM_P256_PUBLIC_KEY_Y =
                keccak256(abi.encodePacked("Y_KEY", i, block.timestamp, msg.sender));

            pubKeySK = PubKey({x: RANDOM_P256_PUBLIC_KEY_X, y: RANDOM_P256_PUBLIC_KEY_Y});

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

            bytes memory code = abi.encodePacked(
                bytes3(0xef0100),
                address(implementation) // or your logic contract
            );
            vm.etch(owner, code);

            vm.prank(address(entryPoint));
            account.registerKey(keySK, keyData);
        }
    }

    function _register_KeyP256NonKey() internal {
        uint256 count = 10;

        for (uint256 i; i < count; i++) {
            uint48 validUntil = uint48(block.timestamp + 1 days);
            uint48 limit = uint48(3);

            bytes32 RANDOM_P256_PUBLIC_KEY_X =
                keccak256(abi.encodePacked("X_KEY", i, block.timestamp + 1000));
            bytes32 RANDOM_P256_PUBLIC_KEY_Y =
                keccak256(abi.encodePacked("Y_KEY", i, block.timestamp + 1000, msg.sender));

            pubKeySK = PubKey({x: RANDOM_P256_PUBLIC_KEY_X, y: RANDOM_P256_PUBLIC_KEY_Y});

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
    }

    /* ─────────────────────────────────────────────────────────── helpers ──── */
    function _initializeAccount() internal {
        /* sample WebAuthn public key – replace with a real one if needed */
        pubKeyMK = PubKey({x: VALID_PUBLIC_KEY_X, y: VALID_PUBLIC_KEY_Y});

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
