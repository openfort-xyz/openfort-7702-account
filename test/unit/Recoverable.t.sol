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
import {KeysManager} from "src/core/KeysManager.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {ISessionkey} from "src/interfaces/ISessionkey.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract Recoverable is Base {
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

    Key internal propose_KeyGuardianEOA;
    PubKey internal propose_PubKeyGuardianEOA;
    Key internal propose_keyGuardianWebAuthn;
    PubKey internal propose_pubKeyGuardianWebAuthn;

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
        _register_SessionKeyEOA();
        _register_SessionKeyP256();
        _register_SessionKeyP256NonKey();
        _poroposeGuardian();

        vm.prank(sender);
        entryPoint.depositTo{value: 0.11e18}(owner);
    }

    /* ─────────────────────────────────────────────────────────────── tests ──── */
    function test_AfterConstructor() external view {
        console.log("/* --------------------------------- test_AfterConstructor -------- */");

        bytes32[] memory guardians;
        guardians = account.getGuardians();
        console.log("l", guardians.length);
        uint256 i;
        for (i; i < guardians.length;) {
            console.logBytes32(guardians[i]);

            unchecked {
                ++i;
            }
        }
        bool isActive = account.isGuardian(keyGuardianEOA);
        console.log("isActive", isActive);

        assertTrue(isActive);

        assertEq(guardians[0], keccak256(abi.encodePacked(GUARDIAN_EOA_ADDRESS)));

        console.log("/* --------------------------------- test_AfterConstructor -------- */");
    }

    function test_AfterProposal() external view {
        console.log("/* --------------------------------- test_AfterProposal -------- */");

        bool isActiveEOA = account.isGuardian(propose_KeyGuardianEOA);
        console.log("isActiveEOA", isActiveEOA);

        bool isActiveWebAuthn = account.isGuardian(propose_keyGuardianWebAuthn);
        console.log("isActiveWebAuthn", isActiveWebAuthn);

        assertFalse(isActiveEOA);
        assertFalse(isActiveWebAuthn);
        console.log("/* --------------------------------- test_AfterProposal -------- */");
    }

    function _poroposeGuardian() internal {
        propose_PubKeyGuardianEOA = PubKey({
            x: 0x0000000000000000000000000000000000000000000000000000000000000000,
            y: 0x0000000000000000000000000000000000000000000000000000000000000000
        });
        propose_KeyGuardianEOA =
            Key({pubKey: propose_PubKeyGuardianEOA, eoaAddress: sessionKey, keyType: KeyType.EOA});

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.proposeGuardian(propose_KeyGuardianEOA);

        propose_pubKeyGuardianWebAuthn =
            PubKey({x: MINT_VALID_PUBLIC_KEY_X, y: MINT_VALID_PUBLIC_KEY_Y});
        propose_keyGuardianWebAuthn = Key({
            pubKey: propose_pubKeyGuardianWebAuthn,
            eoaAddress: address(0),
            keyType: KeyType.WEBAUTHN
        });

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.proposeGuardian(propose_keyGuardianWebAuthn);
    }

    function _register_SessionKeyEOA() internal {
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
        account.registerSessionKey(
            keySK, validUntil, uint48(0), limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
        );
    }

    function _register_SessionKeyP256() internal {
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
        account.registerSessionKey(
            keySK, validUntil, uint48(0), limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
        );
    }

    function _register_SessionKeyP256NonKey() internal {
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
        account.registerSessionKey(
            keySK, validUntil, uint48(0), limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
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
            keyMK, spendInfo, _allowedSelectors(), msgHash, sig, validUntil, 1, keyGuardianEOA
        );
    }
}
