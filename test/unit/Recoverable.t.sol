// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Base} from "test/Base.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {Math} from "lib/openzeppelin-contracts/contracts/utils/math/Math.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {OPF7702Recoverable as OPF7702} from "src/core/OPF7702Recoverable.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {KeysManager} from "src/core/KeysManager.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {IKey} from "src/interfaces/IKey.sol";
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

    Key internal recovery_keyEOA;
    PubKey internal recovery_pubKeyEOA;
    Key internal recovery_keyWebAuthn;
    PubKey internal recovery_pubKeyWebAuthn;

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
        bool isActive = account.isGuardian(initialGuardian);
        console.log("isActive", isActive);

        assertTrue(isActive);

        assertEq(guardians[0], keccak256(abi.encodePacked(initialGuardian)));

        console.log("/* --------------------------------- test_AfterConstructor -------- */");
    }

    function test_AfterProposal() external view {
        console.log("/* --------------------------------- test_AfterProposal -------- */");

        bool isActiveEOA = account.isGuardian(sessionKey);
        console.log("isActiveEOA", isActiveEOA);

        bool isActiveB = account.isGuardian(guardianB);
        console.log("isActiveB", isActiveB);

        assertFalse(isActiveEOA);
        assertFalse(isActiveB);

        uint256 pendingEOA = account.getPendingStatusGuardians(sessionKey);
        uint256 pendingEOAB = account.getPendingStatusGuardians(guardianB);
        console.log("pendingEOA", pendingEOA);
        console.log("pendingEOAB", pendingEOAB);

        assertEq(pendingEOA, proposalTimestamp + SECURITY_PERIOD);
        assertEq(pendingEOAB, proposalTimestamp + SECURITY_PERIOD);
        console.log("/* --------------------------------- test_AfterProposal -------- */");
    }

    function test_AfterCancellation() external {
        console.log("/* --------------------------------- test_AfterCancellation -------- */");

        bool isActiveEOA = account.isGuardian(sessionKey);
        console.log("isActiveEOA", isActiveEOA);

        bool isActiveB = account.isGuardian(guardianB);
        console.log("isActiveB", isActiveB);

        assertFalse(isActiveEOA);
        assertFalse(isActiveB);

        uint256 pendingEOA = account.getPendingStatusGuardians(sessionKey);
        uint256 pendingEOAB = account.getPendingStatusGuardians(guardianB);
        console.log("pendingEOA", pendingEOA);
        console.log("pendingEOAB", pendingEOAB);

        assertEq(pendingEOA, proposalTimestamp + SECURITY_PERIOD);
        assertEq(pendingEOAB, proposalTimestamp + SECURITY_PERIOD);

        _cancelGuardian();

        uint256 pendingEOA_After = account.getPendingStatusGuardians(sessionKey);
        uint256 pendingEOAB_After = account.getPendingStatusGuardians(guardianB);
        console.log("pendingEOA_After", pendingEOA_After);
        console.log("pendingEOAB_After", pendingEOAB_After);

        assertEq(pendingEOA_After, 0);
        assertEq(pendingEOAB_After, 0);
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
        bool isActive = account.isGuardian(initialGuardian);
        console.log("isActive", isActive);
        bool isActiveEOA = account.isGuardian(sessionKey);
        console.log("isActiveEOA", isActiveEOA);
        bool isActiveB = account.isGuardian(guardianB);
        console.log("isActiveB", isActiveB);

        assertTrue(isActive);
        assertTrue(isActiveEOA);
        assertTrue(isActiveB);

        assertEq(guardians[0], keccak256(abi.encodePacked(initialGuardian)));
        assertEq(guardians[1], keccak256(abi.encodePacked(sessionKey)));
        assertEq(guardians[2], keccak256(abi.encodePacked(guardianB)));

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
        bool isActive = account.isGuardian(initialGuardian);
        console.log("isActive", isActive);
        bool isActiveEOA = account.isGuardian(sessionKey);
        console.log("isActiveEOA", isActiveEOA);
        bool isActiveB = account.isGuardian(guardianB);
        console.log("isActiveB", isActiveB);

        assertTrue(isActive);
        assertTrue(isActiveEOA);
        assertTrue(isActiveB);

        assertEq(guardians[0], keccak256(abi.encodePacked(initialGuardian)));
        assertEq(guardians[1], keccak256(abi.encodePacked(sessionKey)));
        assertEq(guardians[2], keccak256(abi.encodePacked(guardianB)));
        _revokeGuardian();

        uint256 pendingEOA = account.getPendingStatusGuardians(sessionKey);
        uint256 pendingEOAB = account.getPendingStatusGuardians(guardianB);

        console.log("pendingEOA", pendingEOA);
        console.log("pendingEOAB", pendingEOAB);
        console.log("block.timestamp + SECURITY_PERIOD", block.timestamp + SECURITY_PERIOD);

        assertEq(pendingEOA, block.timestamp + SECURITY_PERIOD);
        assertEq(pendingEOAB, block.timestamp + SECURITY_PERIOD);
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
        bool isActive = account.isGuardian(initialGuardian);
        console.log("isActive", isActive);
        bool isActiveEOA = account.isGuardian(sessionKey);
        console.log("isActiveEOA", isActiveEOA);
        bool isActiveB = account.isGuardian(guardianB);
        console.log("isActiveB", isActiveB);

        assertTrue(isActive);
        assertTrue(isActiveEOA);
        assertTrue(isActiveB);

        assertEq(guardians[0], keccak256(abi.encodePacked(initialGuardian)));
        assertEq(guardians[1], keccak256(abi.encodePacked(sessionKey)));
        assertEq(guardians[2], keccak256(abi.encodePacked(guardianB)));
        _revokeGuardian();

        uint256 pendingEOA = account.getPendingStatusGuardians(sessionKey);
        uint256 pendingEOAB = account.getPendingStatusGuardians(guardianB);

        console.log("pendingEOA", pendingEOA);
        console.log("pendingEOAB", pendingEOAB);
        console.log("block.timestamp + SECURITY_PERIOD", block.timestamp + SECURITY_PERIOD);

        assertEq(pendingEOA, block.timestamp + SECURITY_PERIOD);
        assertEq(pendingEOAB, block.timestamp + SECURITY_PERIOD);

        _cancelGuardianRevocation();

        uint256 pendingEOA_After = account.getPendingStatusGuardians(sessionKey);
        uint256 pendingEOAB_After = account.getPendingStatusGuardians(guardianB);

        assertEq(pendingEOA_After, 0);
        assertEq(pendingEOAB_After, 0);
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
        bool isActive = account.isGuardian(initialGuardian);
        console.log("isActive", isActive);
        bool isActiveEOA = account.isGuardian(sessionKey);
        console.log("isActiveEOA", isActiveEOA);
        bool isActiveB = account.isGuardian(guardianB);
        console.log("isActiveB", isActiveB);

        assertTrue(isActive);
        assertTrue(isActiveEOA);
        assertTrue(isActiveB);

        assertEq(guardians[0], keccak256(abi.encodePacked(initialGuardian)));
        assertEq(guardians[1], keccak256(abi.encodePacked(sessionKey)));
        assertEq(guardians[2], keccak256(abi.encodePacked(guardianB)));

        _revokeGuardian();
        uint256 pendingEOA = account.getPendingStatusGuardians(sessionKey);
        uint256 pendingEOAB = account.getPendingStatusGuardians(guardianB);

        console.log("pendingEOA", pendingEOA);
        console.log("pendingEOAB", pendingEOAB);
        console.log("block.timestamp + SECURITY_PERIOD", block.timestamp + SECURITY_PERIOD);

        assertEq(pendingEOA, block.timestamp + SECURITY_PERIOD);
        assertEq(pendingEOAB, block.timestamp + SECURITY_PERIOD);

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

        bool isActiveEOA_After = account.isGuardian(sessionKey);
        console.log("isActiveEOA_After", isActiveEOA_After);
        assertTrue(!isActiveEOA_After);

        assertEq(guardians[0], keccak256(abi.encodePacked(initialGuardian)));
        assertEq(guardians[1], keccak256(abi.encodePacked(guardianB)));

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

        bool isActiveB_After = account.isGuardian(guardianB);
        console.log("isActiveB_After", isActiveB_After);
        assertTrue(!isActiveB_After);
        assertEq(guardians[0], keccak256(abi.encodePacked(initialGuardian)));

        console.log("/* --------------------------------- test_RevokeGuardian -------- */");
    }

    function test_StartRecovery() external {
        console.log("/* --------------------------------- test_StartRecovery -------- */");

        _confirmGuardian();
        _startRecovery();

        (Key memory k, uint64 executeAfter, uint32 guardiansRequired) = account.recoveryData();
        console.log("r.key.eoaAddress", k.eoaAddress);
        console.log("executeAfter", executeAfter);
        console.log("guardiansRequired", guardiansRequired);

        assertEq(k.eoaAddress, sender);
        assertEq(SafeCast.toUint64(block.timestamp + RECOVERY_PERIOD), executeAfter);
        assertEq(SafeCast.toUint32(Math.ceilDiv(account.guardianCount(), 2)), guardiansRequired);
        console.log("/* --------------------------------- test_StartRecovery -------- */");
    }

    function test_CancelRecovery() external {
        console.log("/* --------------------------------- test_CancelRecovery -------- */");

        _confirmGuardian();
        _startRecovery();

        (Key memory k, uint64 executeAfter, uint32 guardiansRequired) = account.recoveryData();
        console.log("r.key.eoaAddress", k.eoaAddress);
        console.log("executeAfter", executeAfter);
        console.log("guardiansRequired", guardiansRequired);

        assertEq(k.eoaAddress, sender);
        assertEq(SafeCast.toUint64(block.timestamp + RECOVERY_PERIOD), executeAfter);
        assertEq(SafeCast.toUint32(Math.ceilDiv(account.guardianCount(), 2)), guardiansRequired);

        vm.prank(address(entryPoint));
        account.cancelRecovery();

        (Key memory k_After, uint64 executeAfter_After, uint32 guardiansRequired_After) =
            account.recoveryData();
        console.log("r_After.key.eoaAddress", k_After.eoaAddress);
        console.log("executeAfter_After", executeAfter_After);
        console.log("guardiansRequired_After", guardiansRequired_After);

        assertEq(k_After.eoaAddress, address(0));
        assertEq(0, executeAfter_After);
        assertEq(0, guardiansRequired_After);
        console.log("/* --------------------------------- test_CancelRecovery -------- */");
    }

    function test_CompleteRecoveryToEOA() external {
        console.log("/* --------------------------------- test_CompleteRecoveryToEOA -------- */");

        _confirmGuardian();
        _startRecovery();

        (Key memory k, uint64 executeAfter, uint32 guardiansRequired) = account.recoveryData();
        console.log("r.key.eoaAddress", k.eoaAddress);
        console.log("executeAfter", executeAfter);
        console.log("guardiansRequired", guardiansRequired);

        assertEq(k.eoaAddress, sender);
        assertEq(SafeCast.toUint64(block.timestamp + RECOVERY_PERIOD), executeAfter);
        assertEq(SafeCast.toUint32(Math.ceilDiv(account.guardianCount(), 2)), guardiansRequired);

        bytes[] memory sigs = new bytes[](2);

        bytes32 digest = account.getDigestToSign();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, digest);

        bytes memory sig = abi.encodePacked(r, s, v);

        sigs[0] = sig;

        (uint8 v_B, bytes32 r_B, bytes32 s_B) = vm.sign(guardianB_PK, digest);

        bytes memory sig_B = abi.encodePacked(r_B, s_B, v_B);

        sigs[1] = sig_B;

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);

        Key memory old_k = account.getKeyById(0);
        (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit) =
            account.getKeyData(keccak256(abi.encodePacked(old_k.pubKey.x, old_k.pubKey.y)));
        assertTrue(isActive);
        assertEq(validUntil, type(uint48).max);
        assertEq(validAfter, 0);
        assertEq(limit, 0);

        console.log("isActive", isActive);
        console.log("validUntil", validUntil);

        vm.prank(address(entryPoint));
        account.completeRecovery(sigs);

        (bool isActive_After, uint48 validUntil_After, uint48 validAfter_After, uint48 limit_After)
        = account.getKeyData(keccak256(abi.encodePacked(old_k.pubKey.x, old_k.pubKey.y)));
        assertFalse(isActive_After);
        assertEq(validUntil_After, 0);
        assertEq(validAfter_After, 0);
        assertEq(limit_After, 0);
        console.log("isActive_After", isActive_After);
        console.log("validUntil_After", validUntil_After);

        Key memory old_k_After = account.getKeyById(0);
        assertEq(old_k_After.pubKey.x, bytes32(0));
        assertEq(old_k_After.pubKey.y, bytes32(0));
        assertEq(uint256(old_k_After.keyType), uint256(0));

        Key memory new_k = account.getKeyById(0);
        (bool isActive_New, uint48 validUntil_New, uint48 validAfter_New, uint48 limit_New) =
            account.getKeyData(keccak256(abi.encodePacked(new_k.eoaAddress)));
        assertEq(new_k.eoaAddress, k.eoaAddress);
        assertTrue(isActive_New);
        assertEq(validUntil_New, type(uint48).max);
        assertEq(validAfter_New, 0);
        assertEq(limit_New, 0);

        console.log("isActive_New", isActive_New);
        console.log("validUntil_New", validUntil_New);
        console.log("/* --------------------------------- test_CompleteRecoveryToEOA -------- */");
    }

    function test_CompleteRecoveryToWebAuthn() external {
        console.log(
            "/* --------------------------------- test_CompleteRecoveryToWebAuthn -------- */"
        );

        _confirmGuardian();
        _startRecoveryToWebAuthn();

        (Key memory k, uint64 executeAfter, uint32 guardiansRequired) = account.recoveryData();
        console.log("r.key.eoaAddress", k.eoaAddress);
        console.logBytes32(k.pubKey.x);
        console.logBytes32(k.pubKey.y);
        console.log("executeAfter", executeAfter);
        console.log("guardiansRequired", guardiansRequired);

        assertEq(BATCH_VALID_PUBLIC_KEY_X, k.pubKey.x);
        assertEq(BATCH_VALID_PUBLIC_KEY_Y, k.pubKey.y);
        assertEq(k.eoaAddress, address(0));
        assertEq(SafeCast.toUint64(block.timestamp + RECOVERY_PERIOD), executeAfter);
        assertEq(SafeCast.toUint32(Math.ceilDiv(account.guardianCount(), 2)), guardiansRequired);

        bytes[] memory sigs = new bytes[](2);

        bytes32 digest = account.getDigestToSign();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, digest);

        bytes memory sig = abi.encodePacked(r, s, v);

        sigs[0] = sig;

        (uint8 v_B, bytes32 r_B, bytes32 s_B) = vm.sign(guardianB_PK, digest);

        bytes memory sig_B = abi.encodePacked(r_B, s_B, v_B);

        sigs[1] = sig_B;

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);

        Key memory old_k = account.getKeyById(0);
        (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit) =
            account.getKeyData(keccak256(abi.encodePacked(old_k.pubKey.x, old_k.pubKey.y)));
        assertTrue(isActive);
        assertEq(validUntil, type(uint48).max);
        assertEq(validAfter, 0);
        assertEq(limit, 0);

        console.log("isActive", isActive);
        console.log("validUntil", validUntil);

        vm.prank(address(entryPoint));
        account.completeRecovery(sigs);

        (bool isActive_After, uint48 validUntil_After, uint48 validAfter_After, uint48 limit_After)
        = account.getKeyData(keccak256(abi.encodePacked(old_k.pubKey.x, old_k.pubKey.y)));
        assertFalse(isActive_After);
        assertEq(validUntil_After, 0);
        assertEq(validAfter_After, 0);
        assertEq(limit_After, 0);
        console.log("isActive_After", isActive_After);
        console.log("validUntil_After", validUntil_After);

        Key memory new_k = account.getKeyById(0);

        assertNotEq(old_k.pubKey.x, new_k.pubKey.x);
        assertNotEq(old_k.pubKey.y, new_k.pubKey.y);

        (bool isActive_New, uint48 validUntil_New, uint48 validAfter_New, uint48 limit_New) =
            account.getKeyData(keccak256(abi.encodePacked(new_k.pubKey.x, new_k.pubKey.y)));
        assertEq(new_k.eoaAddress, address(0));
        assertEq(new_k.pubKey.x, k.pubKey.x);
        assertEq(new_k.pubKey.y, k.pubKey.y);
        assertTrue(isActive_New);
        assertEq(validUntil_New, type(uint48).max);
        assertEq(validAfter_New, 0);
        assertEq(limit_New, 0);

        console.log("isActive_New", isActive_New);
        console.log("validUntil_New", validUntil_New);
        console.log(
            "/* --------------------------------- test_CompleteRecoveryToWebAuthn -------- */"
        );
    }

    function _poroposeGuardian() internal {
        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        proposalTimestamp = block.timestamp;

        vm.prank(address(entryPoint));
        account.proposeGuardian(sessionKey);

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.proposeGuardian(guardianB);
    }

    function _confirmGuardian() internal {
        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        proposalTimestamp = block.timestamp;

        vm.warp(proposalTimestamp + SECURITY_PERIOD + 1);

        vm.prank(address(entryPoint));
        account.confirmGuardianProposal(sessionKey);

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.confirmGuardianProposal(guardianB);
    }

    function _revokeGuardian() internal {
        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.revokeGuardian(sessionKey);

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.revokeGuardian(guardianB);
    }

    function _cancelGuardianRevocation() internal {
        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);

        proposalTimestamp = block.timestamp;

        vm.warp(proposalTimestamp + SECURITY_PERIOD + 1);

        vm.prank(address(entryPoint));
        account.cancelGuardianRevocation(sessionKey);

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.cancelGuardianRevocation(guardianB);
    }

    function _confirmGuardianRevocationEOA() internal {
        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, code);
        proposalTimestamp = block.timestamp;

        vm.warp(proposalTimestamp + SECURITY_PERIOD + SECURITY_WINDOW);
        vm.prank(address(entryPoint));
        account.confirmGuardianRevocation(sessionKey);
    }

    function _confirmGuardianRevocationWebAuthn() internal {
        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(implementation));

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.confirmGuardianRevocation(guardianB);
    }

    function _cancelGuardian() internal {
        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        proposalTimestamp = block.timestamp;

        vm.warp(proposalTimestamp + SECURITY_PERIOD + 1);

        vm.prank(address(entryPoint));
        account.cancelGuardianProposal(sessionKey);

        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.cancelGuardianProposal(guardianB);
    }

    function _startRecovery() internal {
        recovery_pubKeyEOA = PubKey({
            x: 0x0000000000000000000000000000000000000000000000000000000000000000,
            y: 0x0000000000000000000000000000000000000000000000000000000000000000
        });
        recovery_keyEOA =
            Key({pubKey: recovery_pubKeyEOA, eoaAddress: sender, keyType: KeyType.EOA});

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );

        vm.etch(owner, code);

        vm.prank(sessionKey);
        account.startRecovery(recovery_keyEOA);
    }

    function _startRecoveryToWebAuthn() internal {
        recovery_pubKeyWebAuthn = PubKey({x: BATCH_VALID_PUBLIC_KEY_X, y: BATCH_VALID_PUBLIC_KEY_Y});
        recovery_keyWebAuthn = Key({
            pubKey: recovery_pubKeyWebAuthn,
            eoaAddress: address(0),
            keyType: KeyType.WEBAUTHN
        });

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );

        vm.etch(owner, code);

        vm.prank(sessionKey);
        account.startRecovery(recovery_keyWebAuthn /*, guardianB*/ );
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

        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(implementation) // or your logic contract
        );
        vm.etch(owner, code);

        vm.prank(address(entryPoint));
        account.registerKey(
            keySK, validUntil, uint48(0), limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
        );
    }

    function _register_KeyP256() internal {
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
        account.registerKey(
            keySK, validUntil, uint48(0), limit, true, TOKEN, spendInfo, _allowedSelectors(), 0
        );
    }

    function _register_KeyP256NonKey() internal {
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
        account.registerKey(
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
            keyMK, spendInfo, _allowedSelectors(), msgHash, sig, validUntil, initialGuardian
        );
    }
}
