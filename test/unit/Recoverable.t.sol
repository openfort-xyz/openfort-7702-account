// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Base} from "test/Base.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {Math} from "lib/openzeppelin-contracts/contracts/utils/math/Math.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";
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
    Key internal recovery_keyEOA;
    PubKey internal recovery_pubKeyEOA;

    uint256 internal proposalTimestamp;

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

        uint256 pendingEOA = account.getPendingStatusGuardians(propose_KeyGuardianEOA);
        uint256 pendingWebAuthn = account.getPendingStatusGuardians(propose_keyGuardianWebAuthn);
        console.log("pendingEOA", pendingEOA);
        console.log("pendingWebAuthn", pendingWebAuthn);

        assertEq(pendingEOA, proposalTimestamp + SECURITY_PERIOD);
        assertEq(pendingWebAuthn, proposalTimestamp + SECURITY_PERIOD);
        console.log("/* --------------------------------- test_AfterProposal -------- */");
    }

    function test_AfterCancellation() external {
        console.log("/* --------------------------------- test_AfterCancellation -------- */");

        bool isActiveEOA = account.isGuardian(propose_KeyGuardianEOA);
        console.log("isActiveEOA", isActiveEOA);

        bool isActiveWebAuthn = account.isGuardian(propose_keyGuardianWebAuthn);
        console.log("isActiveWebAuthn", isActiveWebAuthn);

        assertFalse(isActiveEOA);
        assertFalse(isActiveWebAuthn);

        uint256 pendingEOA = account.getPendingStatusGuardians(propose_KeyGuardianEOA);
        uint256 pendingWebAuthn = account.getPendingStatusGuardians(propose_keyGuardianWebAuthn);
        console.log("pendingEOA", pendingEOA);
        console.log("pendingWebAuthn", pendingWebAuthn);

        assertEq(pendingEOA, proposalTimestamp + SECURITY_PERIOD);
        assertEq(pendingWebAuthn, proposalTimestamp + SECURITY_PERIOD);

        _cancelGuardian();

        uint256 pendingEOA_After = account.getPendingStatusGuardians(propose_KeyGuardianEOA);
        uint256 pendingWebAuthn_After =
            account.getPendingStatusGuardians(propose_keyGuardianWebAuthn);
        console.log("pendingEOA_After", pendingEOA_After);
        console.log("pendingWebAuthn_After", pendingWebAuthn_After);

        assertEq(pendingEOA_After, 0);
        assertEq(pendingWebAuthn_After, 0);
        console.log("/* --------------------------------- test_AfterCancellation -------- */");
    }

    function test_AfterConfirmation() external {
        console.log("/* --------------------------------- test_AfterConfirmation -------- */");
        _confirmGuardian();
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
        bool isActiveEOA = account.isGuardian(propose_KeyGuardianEOA);
        console.log("isActiveEOA", isActiveEOA);
        bool isActiveWebAuthn = account.isGuardian(propose_keyGuardianWebAuthn);
        console.log("isActiveWebAuthn", isActiveWebAuthn);

        assertTrue(isActive);
        assertTrue(isActiveEOA);
        assertTrue(isActiveWebAuthn);

        assertEq(guardians[0], keccak256(abi.encodePacked(GUARDIAN_EOA_ADDRESS)));
        assertEq(guardians[1], keccak256(abi.encodePacked(sessionKey)));
        assertEq(
            guardians[2],
            keccak256(
                abi.encodePacked(propose_pubKeyGuardianWebAuthn.x, propose_pubKeyGuardianWebAuthn.y)
            )
        );

        console.log("/* --------------------------------- test_AfterConfirmation -------- */");
    }

    function test_RevokeGuardian() external {
        console.log("/* --------------------------------- test_RevokeGuardian -------- */");
        _confirmGuardian();
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
        bool isActiveEOA = account.isGuardian(propose_KeyGuardianEOA);
        console.log("isActiveEOA", isActiveEOA);
        bool isActiveWebAuthn = account.isGuardian(propose_keyGuardianWebAuthn);
        console.log("isActiveWebAuthn", isActiveWebAuthn);

        assertTrue(isActive);
        assertTrue(isActiveEOA);
        assertTrue(isActiveWebAuthn);

        assertEq(guardians[0], keccak256(abi.encodePacked(GUARDIAN_EOA_ADDRESS)));
        assertEq(guardians[1], keccak256(abi.encodePacked(sessionKey)));
        assertEq(
            guardians[2],
            keccak256(
                abi.encodePacked(propose_pubKeyGuardianWebAuthn.x, propose_pubKeyGuardianWebAuthn.y)
            )
        );
        _revokeGuardian();

        uint256 pendingEOA = account.getPendingStatusGuardians(propose_KeyGuardianEOA);
        uint256 pendingWebAuthn = account.getPendingStatusGuardians(propose_keyGuardianWebAuthn);

        console.log("pendingEOA", pendingEOA);
        console.log("pendingWebAuthn", pendingWebAuthn);
        console.log("block.timestamp + SECURITY_PERIOD", block.timestamp + SECURITY_PERIOD);

        assertEq(pendingEOA, block.timestamp + SECURITY_PERIOD);
        assertEq(pendingWebAuthn, block.timestamp + SECURITY_PERIOD);
        console.log("/* --------------------------------- test_RevokeGuardian -------- */");
    }

    function test_CancelGuardianRevocation() external {
        console.log("/* --------------------------------- test_RevokeGuardian -------- */");
        _confirmGuardian();
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
        bool isActiveEOA = account.isGuardian(propose_KeyGuardianEOA);
        console.log("isActiveEOA", isActiveEOA);
        bool isActiveWebAuthn = account.isGuardian(propose_keyGuardianWebAuthn);
        console.log("isActiveWebAuthn", isActiveWebAuthn);

        assertTrue(isActive);
        assertTrue(isActiveEOA);
        assertTrue(isActiveWebAuthn);

        assertEq(guardians[0], keccak256(abi.encodePacked(GUARDIAN_EOA_ADDRESS)));
        assertEq(guardians[1], keccak256(abi.encodePacked(sessionKey)));
        assertEq(
            guardians[2],
            keccak256(
                abi.encodePacked(propose_pubKeyGuardianWebAuthn.x, propose_pubKeyGuardianWebAuthn.y)
            )
        );
        _revokeGuardian();

        uint256 pendingEOA = account.getPendingStatusGuardians(propose_KeyGuardianEOA);
        uint256 pendingWebAuthn = account.getPendingStatusGuardians(propose_keyGuardianWebAuthn);

        console.log("pendingEOA", pendingEOA);
        console.log("pendingWebAuthn", pendingWebAuthn);
        console.log("block.timestamp + SECURITY_PERIOD", block.timestamp + SECURITY_PERIOD);

        assertEq(pendingEOA, block.timestamp + SECURITY_PERIOD);
        assertEq(pendingWebAuthn, block.timestamp + SECURITY_PERIOD);

        _cancelGuardianRevocation();

        uint256 pendingEOA_After = account.getPendingStatusGuardians(propose_KeyGuardianEOA);
        uint256 pendingWebAuthn_After =
            account.getPendingStatusGuardians(propose_keyGuardianWebAuthn);

        assertEq(pendingEOA_After, 0);
        assertEq(pendingWebAuthn_After, 0);
        console.log("/* --------------------------------- test_RevokeGuardian -------- */");
    }

    function test_AfterRevokeConfirmation() external {
        console.log("/* --------------------------------- test_RevokeGuardian -------- */");
        _confirmGuardian();
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
        bool isActiveEOA = account.isGuardian(propose_KeyGuardianEOA);
        console.log("isActiveEOA", isActiveEOA);
        bool isActiveWebAuthn = account.isGuardian(propose_keyGuardianWebAuthn);
        console.log("isActiveWebAuthn", isActiveWebAuthn);

        assertTrue(isActive);
        assertTrue(isActiveEOA);
        assertTrue(isActiveWebAuthn);

        assertEq(guardians[0], keccak256(abi.encodePacked(GUARDIAN_EOA_ADDRESS)));
        assertEq(guardians[1], keccak256(abi.encodePacked(sessionKey)));
        assertEq(
            guardians[2],
            keccak256(
                abi.encodePacked(propose_pubKeyGuardianWebAuthn.x, propose_pubKeyGuardianWebAuthn.y)
            )
        );

        _revokeGuardian();
        uint256 pendingEOA = account.getPendingStatusGuardians(propose_KeyGuardianEOA);
        uint256 pendingWebAuthn = account.getPendingStatusGuardians(propose_keyGuardianWebAuthn);

        console.log("pendingEOA", pendingEOA);
        console.log("pendingWebAuthn", pendingWebAuthn);
        console.log("block.timestamp + SECURITY_PERIOD", block.timestamp + SECURITY_PERIOD);

        assertEq(pendingEOA, block.timestamp + SECURITY_PERIOD);
        assertEq(pendingWebAuthn, block.timestamp + SECURITY_PERIOD);

        _confirmGuardianRevocationEOA();

        guardians = account.getGuardians();
        console.log("l", guardians.length);
        i = 0;
        for (i; i < guardians.length;) {
            console.logBytes32(guardians[i]);

            unchecked {
                ++i;
            }
        }

        bool isActiveEOA_After = account.isGuardian(propose_KeyGuardianEOA);
        console.log("isActiveEOA_After", isActiveEOA_After);
        assertTrue(!isActiveEOA_After);

        assertEq(guardians[0], keccak256(abi.encodePacked(GUARDIAN_EOA_ADDRESS)));
        assertEq(
            guardians[1],
            keccak256(
                abi.encodePacked(propose_pubKeyGuardianWebAuthn.x, propose_pubKeyGuardianWebAuthn.y)
            )
        );

        _confirmGuardianRevocationWebAuthn();

        guardians = account.getGuardians();
        console.log("l", guardians.length);
        i = 0;
        for (i; i < guardians.length;) {
            console.logBytes32(guardians[i]);

            unchecked {
                ++i;
            }
        }

        bool isActiveWebAuthn_After = account.isGuardian(propose_keyGuardianWebAuthn);
        console.log("isActiveWebAuthn_After", isActiveWebAuthn_After);
        assertTrue(!isActiveWebAuthn_After);
        assertEq(guardians[0], keccak256(abi.encodePacked(GUARDIAN_EOA_ADDRESS)));

        console.log("/* --------------------------------- test_RevokeGuardian -------- */");
    }

    function test_StartRecovery() external {
        _confirmGuardian();
        _startRecovery();

        (Key memory k, uint64 executeAfter, uint32 guardiansRequired) = account.recoveryData();
        console.log("r.key.eoaAddress", k.eoaAddress);
        console.log("executeAfter", executeAfter);
        console.log("guardiansRequired", guardiansRequired);

        assertEq(k.eoaAddress, sender);
        assertEq(SafeCast.toUint64(block.timestamp + RECOVERY_PERIOD), executeAfter);
        assertEq(SafeCast.toUint32(Math.ceilDiv(account.guardianCount(), 2)), guardiansRequired);
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

        proposalTimestamp = block.timestamp;

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

    function _confirmGuardian() internal {
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

        proposalTimestamp = block.timestamp;

        vm.warp(proposalTimestamp + SECURITY_PERIOD + 1);

        vm.prank(address(entryPoint));
        account.confirmGuardianProposal(propose_KeyGuardianEOA);

        propose_pubKeyGuardianWebAuthn =
            PubKey({x: MINT_VALID_PUBLIC_KEY_X, y: MINT_VALID_PUBLIC_KEY_Y});
        propose_keyGuardianWebAuthn = Key({
            pubKey: propose_pubKeyGuardianWebAuthn,
            eoaAddress: address(0),
            keyType: KeyType.WEBAUTHN
        });

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.confirmGuardianProposal(propose_keyGuardianWebAuthn);
    }

    function _revokeGuardian() internal {
        propose_PubKeyGuardianEOA = PubKey({
            x: 0x0000000000000000000000000000000000000000000000000000000000000000,
            y: 0x0000000000000000000000000000000000000000000000000000000000000000
        });
        propose_KeyGuardianEOA =
            Key({pubKey: propose_PubKeyGuardianEOA, eoaAddress: sessionKey, keyType: KeyType.EOA});

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.revokeGuardian(propose_KeyGuardianEOA);

        propose_pubKeyGuardianWebAuthn =
            PubKey({x: MINT_VALID_PUBLIC_KEY_X, y: MINT_VALID_PUBLIC_KEY_Y});
        propose_keyGuardianWebAuthn = Key({
            pubKey: propose_pubKeyGuardianWebAuthn,
            eoaAddress: address(0),
            keyType: KeyType.WEBAUTHN
        });

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.revokeGuardian(propose_keyGuardianWebAuthn);
    }

    function _cancelGuardianRevocation() internal {
        propose_PubKeyGuardianEOA = PubKey({
            x: 0x0000000000000000000000000000000000000000000000000000000000000000,
            y: 0x0000000000000000000000000000000000000000000000000000000000000000
        });
        propose_KeyGuardianEOA =
            Key({pubKey: propose_PubKeyGuardianEOA, eoaAddress: sessionKey, keyType: KeyType.EOA});

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        proposalTimestamp = block.timestamp;

        vm.warp(proposalTimestamp + SECURITY_PERIOD + 1);

        vm.prank(address(entryPoint));
        account.cancelGuardianRevocation(propose_KeyGuardianEOA);

        propose_pubKeyGuardianWebAuthn =
            PubKey({x: MINT_VALID_PUBLIC_KEY_X, y: MINT_VALID_PUBLIC_KEY_Y});
        propose_keyGuardianWebAuthn = Key({
            pubKey: propose_pubKeyGuardianWebAuthn,
            eoaAddress: address(0),
            keyType: KeyType.WEBAUTHN
        });

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.cancelGuardianRevocation(propose_keyGuardianWebAuthn);
    }

    function _confirmGuardianRevocationEOA() internal {
        propose_PubKeyGuardianEOA = PubKey({
            x: 0x0000000000000000000000000000000000000000000000000000000000000000,
            y: 0x0000000000000000000000000000000000000000000000000000000000000000
        });
        propose_KeyGuardianEOA =
            Key({pubKey: propose_PubKeyGuardianEOA, eoaAddress: sessionKey, keyType: KeyType.EOA});

        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);
        proposalTimestamp = block.timestamp;

        vm.warp(proposalTimestamp + SECURITY_PERIOD + 1);
        vm.prank(address(entryPoint));
        account.confirmGuardianRevocation(propose_KeyGuardianEOA);
    }

    function _confirmGuardianRevocationWebAuthn() internal {
        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));

        propose_pubKeyGuardianWebAuthn =
            PubKey({x: MINT_VALID_PUBLIC_KEY_X, y: MINT_VALID_PUBLIC_KEY_Y});
        propose_keyGuardianWebAuthn = Key({
            pubKey: propose_pubKeyGuardianWebAuthn,
            eoaAddress: address(0),
            keyType: KeyType.WEBAUTHN
        });
        proposalTimestamp = block.timestamp;

        vm.warp(proposalTimestamp + SECURITY_PERIOD + 1);
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.confirmGuardianRevocation(propose_keyGuardianWebAuthn);
    }

    function _cancelGuardian() internal {
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

        proposalTimestamp = block.timestamp;

        vm.warp(proposalTimestamp + SECURITY_PERIOD + 1);

        vm.prank(address(entryPoint));
        account.cancelGuardianProposal(propose_KeyGuardianEOA);

        propose_pubKeyGuardianWebAuthn =
            PubKey({x: MINT_VALID_PUBLIC_KEY_X, y: MINT_VALID_PUBLIC_KEY_Y});
        propose_keyGuardianWebAuthn = Key({
            pubKey: propose_pubKeyGuardianWebAuthn,
            eoaAddress: address(0),
            keyType: KeyType.WEBAUTHN
        });

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.cancelGuardianProposal(propose_keyGuardianWebAuthn);
    }

    function _startRecovery() internal {
        recovery_pubKeyEOA = PubKey({
            x: 0x0000000000000000000000000000000000000000000000000000000000000000,
            y: 0x0000000000000000000000000000000000000000000000000000000000000000
        });
        recovery_keyEOA =
            Key({pubKey: propose_PubKeyGuardianEOA, eoaAddress: sender, keyType: KeyType.EOA});

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.startRecovery(recovery_keyEOA, propose_keyGuardianWebAuthn);
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
