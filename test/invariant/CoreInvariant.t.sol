// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {StdInvariant} from "lib/forge-std/src/StdInvariant.sol";
import {Test} from "lib/forge-std/src/Test.sol";
import {OPFMain} from "src/core/OPFMain.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {KeysManagerLib} from "src/libs/KeysManagerLib.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {Math} from "lib/openzeppelin-contracts/contracts/utils/math/Math.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {BaseData} from "../BaseData.t.sol";

contract DeployInvariantHelper is BaseData {
    function runSetup() external {
        (owner, ownerPK) = makeAddrAndKey("owner");
        (sender, senderPK) = makeAddrAndKey("sender");
        (sessionKey, sessionKeyPK) = makeAddrAndKey("sessionKey");
        (guardian, guardianPK) = makeAddrAndKey("GUARDIAN_EOA_ADDRESS");

        EntryPoint entryPointImpl = new EntryPoint();
        entryPoint = IEntryPoint(payable(address(entryPointImpl)));

        webAuthn = new WebAuthnVerifierV2();
        gasPolicy = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        recoveryManager = new SocialRecoveryManager(
            RECOVERY_PERIOD, LOCK_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW
        );

        _createInitialGuradian();

        implementation = new OPF7702(
            address(entryPoint), address(webAuthn), address(gasPolicy), address(recoveryManager)
        );

        erc20 = new MockERC20();

        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(implementation)));
        account = OPF7702(payable(owner));

        _deal();

        _createCustomFreshKey(
            true, KeyType.EOA, type(uint48).max, 0, 0, _getKeyEOA(owner), KeyControl.Self
        );

        _createCustomFreshKey(
            false,
            KeyType.EOA,
            uint48(block.timestamp + 30 days),
            0,
            10,
            _getKeyEOA(sessionKey),
            KeyControl.Self
        );

        _initializeAccountInvariant();
    }

    function state()
        external
        view
        returns (
            OPFMain implementation_,
            OPFMain account_,
            SocialRecoveryManager recoveryManager_,
            address owner_,
            address sender_,
            address guardian_,
            bytes32 initialGuardianHash_,
            uint256 guardianPk_,
            IEntryPoint entryPoint_,
            address webAuthnVerifier_,
            address gasPolicy_
        )
    {
        implementation_ = OPFMain(payable(address(implementation)));
        account_ = OPFMain(payable(address(account)));
        recoveryManager_ = recoveryManager;
        owner_ = owner;
        sender_ = sender;
        guardian_ = guardian;
        initialGuardianHash_ = _initialGuardian;
        guardianPk_ = guardianPK;
        entryPoint_ = entryPoint;
        webAuthnVerifier_ = address(webAuthn);
        gasPolicy_ = address(gasPolicy);
    }

    function _initializeAccountInvariant() internal {
        bytes memory mkDataEnc = abi.encode(
            mkReg.keyType,
            mkReg.validUntil,
            mkReg.validAfter,
            mkReg.limits,
            mkReg.key,
            mkReg.keyControl
        );

        bytes memory skDataEnc = abi.encode(
            skReg.keyType,
            skReg.validUntil,
            skReg.validAfter,
            skReg.limits,
            skReg.key,
            skReg.keyControl
        );

        bytes32 structHash =
            keccak256(abi.encode(INIT_TYPEHASH, mkDataEnc, skDataEnc, _initialGuardian));

        string memory name = "OPF7702Recoverable";
        string memory version = "1";

        bytes32 domainSeparator = keccak256(
            abi.encode(
                TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(owner);
        account.initialize(mkReg, skReg, sig, _initialGuardian);
    }
}

error InvariantGuardianQuorumMismatch(
    uint32 stored, uint256 expected, uint256 guardianCount, bool locked
);

contract InvariantHandler is Test {
    using KeysManagerLib for IKey.KeyDataReg;

    OPFMain public immutable implementation;
    OPFMain public immutable account;
    SocialRecoveryManager public immutable recoveryManager;

    address public immutable owner;
    address public immutable sender;

    bytes32 public immutable initialGuardianHash;

    address[] internal guardianPool;
    uint256[] internal guardianPoolPK;

    address[] internal keyPool;

    mapping(bytes32 guardianHash => address guardianAddr) internal guardianAddress;
    mapping(bytes32 guardianHash => uint256 guardianPk) internal guardianPrivateKey;

    constructor(
        OPFMain _implementation,
        OPFMain _account,
        SocialRecoveryManager _recoveryManager,
        address _owner,
        address _sender,
        address _initialGuardian,
        uint256 _initialGuardianPk,
        bytes32 _initialGuardianEncodedHash,
        uint256[] memory _guardianCandidatePks,
        uint256[] memory _keyCandidatePks
    ) {
        implementation = _implementation;
        account = _account;
        recoveryManager = _recoveryManager;
        owner = _owner;
        sender = _sender;

        guardianPoolPK = _guardianCandidatePks;
        guardianPool = new address[](_guardianCandidatePks.length);
        for (uint256 i; i < _guardianCandidatePks.length; ++i) {
            if (_guardianCandidatePks[i] == 0) continue;
            guardianPool[i] = vm.addr(_guardianCandidatePks[i]);
        }

        keyPool = new address[](_keyCandidatePks.length);
        for (uint256 i; i < _keyCandidatePks.length; ++i) {
            if (_keyCandidatePks[i] == 0) continue;
            keyPool[i] = vm.addr(_keyCandidatePks[i]);
        }

        // Map the initial guardian (both hash derivations just in case).
        bytes32 packedHash = keccak256(abi.encodePacked(_initialGuardian));
        guardianAddress[packedHash] = _initialGuardian;
        guardianPrivateKey[packedHash] = _initialGuardianPk;

        guardianAddress[_initialGuardianEncodedHash] = _initialGuardian;
        guardianPrivateKey[_initialGuardianEncodedHash] = _initialGuardianPk;

        initialGuardianHash = _initialGuardianEncodedHash;

        bytes32[] memory existingGuardians = _recoveryManager.getGuardians(address(_account));
        for (uint256 i; i < existingGuardians.length; ++i) {
            if (guardianAddress[existingGuardians[i]] == address(0)) {
                guardianAddress[existingGuardians[i]] = _initialGuardian;
            }
            if (guardianPrivateKey[existingGuardians[i]] == 0) {
                guardianPrivateKey[existingGuardians[i]] = _initialGuardianPk;
            }
        }
    }

    // ──────────────────────────────────────── Handled actions ────────────────────────

    function addGuardian(uint256 seed) external {
        if (_recoveryActive()) return;

        if (guardianPool.length == 0) return;
        uint256 idx = seed % guardianPool.length;
        address newGuardian = guardianPool[idx];
        if (newGuardian == address(0)) return;

        bytes32 guardianHash = keccak256(abi.encodePacked(newGuardian));
        if (recoveryManager.isGuardian(address(account), guardianHash)) return;
        if (recoveryManager.getPendingStatusGuardians(address(account), guardianHash) != 0) return;

        vm.prank(address(account));
        recoveryManager.proposeGuardian(address(account), guardianHash);

        uint256 pending = recoveryManager.getPendingStatusGuardians(address(account), guardianHash);
        if (pending == 0) return;

        vm.warp(pending + 1);
        vm.prank(address(account));
        recoveryManager.confirmGuardianProposal(address(account), guardianHash);

        guardianAddress[guardianHash] = newGuardian;
        guardianPrivateKey[guardianHash] = guardianPoolPK[idx];

        bytes32 altHash = keccak256(abi.encode(newGuardian));
        guardianAddress[altHash] = newGuardian;
        guardianPrivateKey[altHash] = guardianPoolPK[idx];
    }

    function revokeGuardian(uint256 seed) external {
        bytes32[] memory guardians = recoveryManager.getGuardians(address(account));
        if (guardians.length <= 1) return;

        uint256 idx = seed % guardians.length;
        bytes32 guardianHash = guardians[idx];
        if (guardianHash == initialGuardianHash) return;

        vm.prank(address(account));
        recoveryManager.revokeGuardian(address(account), guardianHash);

        uint256 pending = recoveryManager.getPendingStatusGuardians(address(account), guardianHash);
        if (pending == 0) return;

        vm.warp(pending + 1);
        vm.prank(address(account));
        recoveryManager.confirmGuardianRevocation(address(account), guardianHash);

        address removedGuardian = guardianAddress[guardianHash];
        delete guardianAddress[guardianHash];
        delete guardianPrivateKey[guardianHash];

        if (removedGuardian != address(0)) {
            bytes32 altHash = keccak256(abi.encode(removedGuardian));
            delete guardianAddress[altHash];
            delete guardianPrivateKey[altHash];
        }
    }

    function startRecovery(uint256 seed) external {
        if (_recoveryActive()) return;

        bytes32[] memory guardians = recoveryManager.getGuardians(address(account));
        if (guardians.length == 0) return;

        uint256 guardianIdx = seed % guardians.length;
        bytes32 guardianHash = guardians[guardianIdx];
        uint256 pk = guardianPrivateKey[guardianHash];
        address guardianAddr = guardianAddress[guardianHash];
        if (pk == 0 || guardianAddr == address(0)) return;

        if (keyPool.length == 0) return;
        address newOwner = keyPool[seed % keyPool.length];
        if (newOwner == address(0) || newOwner == owner || newOwner == address(account)) return;
        bytes memory encoded = abi.encode(newOwner);

        bytes32 packedHash = keccak256(abi.encodePacked(newOwner));
        bytes32 encodedHash = keccak256(abi.encode(newOwner));
        if (recoveryManager.isGuardian(address(account), packedHash)) return;
        if (recoveryManager.isGuardian(address(account), encodedHash)) return;

        IKey.KeyDataReg memory recoveryKey = IKey.KeyDataReg({
            keyType: IKey.KeyType.EOA,
            validUntil: type(uint48).max,
            validAfter: 0,
            limits: 0,
            key: encoded,
            keyControl: IKey.KeyControl.Self
        });

        if (account.isKeyActive(recoveryKey.computeKeyId())) return;

        vm.prank(guardianAddr);
        recoveryManager.startRecovery(address(account), recoveryKey);
    }

    function cancelRecovery() external {
        if (!_recoveryActive()) return;

        vm.prank(address(account));
        recoveryManager.cancelRecovery(address(account));
    }

    function completeRecovery(uint256) external {
        (IKey.KeyDataReg memory data, uint64 executeAfter, uint32 guardiansRequired) =
            recoveryManager.recoveryData(address(account));

        if (guardiansRequired == 0) return;

        uint256 targetTime = uint256(executeAfter) + 1;
        if (targetTime > block.timestamp) {
            vm.warp(targetTime);
        }

        bytes[] memory signatures = _collectSignatures(guardiansRequired);
        if (signatures.length != guardiansRequired) return;

        _ensureAccountCode();
        vm.prank(sender);
        account.completeRecovery(signatures);

        // Ensure we can sign with the new master key in future scenarios.
        bytes32 newMasterId = data.computeKeyId();
        delete guardianAddress[newMasterId];
        delete guardianPrivateKey[newMasterId];
    }

    function registerKey(uint256 seed) external {
        if (keyPool.length == 0) return;

        address keyOwner = keyPool[seed % keyPool.length];
        if (keyOwner == address(0)) return;

        bytes memory encoded = abi.encode(keyOwner);
        IKey.KeyDataReg memory keyData = IKey.KeyDataReg({
            keyType: IKey.KeyType.EOA,
            validUntil: uint48(
                bound(
                    block.timestamp + 1 days + (seed % 30 days),
                    block.timestamp + 1,
                    type(uint48).max - 1
                )
            ),
            validAfter: 0,
            limits: uint48(bound(seed + 1, 1, type(uint48).max - 1)),
            key: encoded,
            keyControl: IKey.KeyControl.Self
        });

        bytes32 keyId = keyData.computeKeyId();
        if (account.isKeyActive(keyId)) return;

        _ensureAccountCode();
        vm.prank(owner);
        account.registerKey(keyData);
    }

    function revokeKey(uint256 seed) external {
        bytes32[] memory keyIds = _activeNonMasterKeys();
        if (keyIds.length == 0) return;

        bytes32 keyId = keyIds[seed % keyIds.length];
        _ensureAccountCode();
        vm.prank(owner);
        account.revokeKey(keyId);
    }

    function updateKey(uint256 seed, uint48 extendSeed, uint48 limitSeed) external {
        bytes32[] memory keyIds = _activeNonMasterKeys();
        if (keyIds.length == 0) return;

        bytes32 keyId = keyIds[seed % keyIds.length];
        IKey.KeyData memory data = account.getKey(keyId);
        uint48 extendBy = uint48(bound(uint256(extendSeed), 1, 30 days));

        uint256 candidateValidUntil = uint256(data.validUntil) + uint256(extendBy);
        if (candidateValidUntil >= type(uint48).max) {
            candidateValidUntil = type(uint48).max - 1;
        }
        if (candidateValidUntil <= block.timestamp) {
            candidateValidUntil = uint256(block.timestamp) + 1;
        }
        if (candidateValidUntil <= data.validUntil) {
            candidateValidUntil = uint256(data.validUntil) + 1;
        }

        uint48 newValidUntil = uint48(candidateValidUntil);
        uint48 newLimit = uint48(bound(uint256(limitSeed), 1, type(uint48).max - 1));

        _ensureAccountCode();
        vm.prank(owner);
        account.updateKeyData(keyId, newValidUntil, newLimit);
    }

    function warp(uint256 secondsDelta) external {
        uint256 delta = bound(secondsDelta, 1, 7 days);
        vm.warp(block.timestamp + delta);
    }

    // ──────────────────────────────────────── Internal helpers ──────────────────────

    function _ensureAccountCode() internal {
        bytes memory designator = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, designator);
    }

    function _recoveryActive() internal view returns (bool) {
        (, uint64 executeAfter,) = recoveryManager.recoveryData(address(account));
        return executeAfter != 0;
    }

    function _activeNonMasterKeys() internal view returns (bytes32[] memory) {
        uint256 total = account.keyCount();
        bytes32[] memory temp = new bytes32[](total);
        uint256 count;

        for (uint256 i; i < total; ++i) {
            (bytes32 keyId, IKey.KeyData memory data) = account.keyAt(i);
            if (data.isActive && !data.masterKey) {
                temp[count++] = keyId;
            }
        }

        bytes32[] memory results = new bytes32[](count);
        for (uint256 i; i < count; ++i) {
            results[i] = temp[i];
        }
        return results;
    }

    function _collectSignatures(uint32 required) internal view returns (bytes[] memory sigs) {
        bytes32[] memory guardians = recoveryManager.getGuardians(address(account));
        if (guardians.length < required) return new bytes[](0);

        _sort(guardians);

        bytes32 digest = recoveryManager.getDigestToSign(address(account));

        sigs = new bytes[](required);
        bytes32[] memory used = new bytes32[](required);
        uint256 collected;

        for (uint256 i; i < guardians.length && collected < required; ++i) {
            uint256 pk = guardianPrivateKey[guardians[i]];
            address guardianAddr = guardianAddress[guardians[i]];
            if (pk == 0 || guardianAddr == address(0)) continue;

            bytes32 signerHash = keccak256(abi.encodePacked(guardianAddr));
            bool alreadyUsed;
            for (uint256 j; j < collected; ++j) {
                if (used[j] == signerHash) {
                    alreadyUsed = true;
                    break;
                }
            }
            if (alreadyUsed) continue;

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
            sigs[collected] = abi.encodePacked(r, s, v);
            used[collected] = signerHash;
            collected++;
        }

        if (collected != required) {
            return new bytes[](0);
        }
    }

    function _sort(bytes32[] memory data) internal pure {
        uint256 len = data.length;
        for (uint256 i; i < len; ++i) {
            for (uint256 j = i + 1; j < len; ++j) {
                if (data[j] < data[i]) {
                    (data[i], data[j]) = (data[j], data[i]);
                }
            }
        }
    }
}

contract CoreInvariantTest is StdInvariant {
    InvariantHandler internal handler;

    OPFMain internal implementation;
    OPFMain internal account;
    SocialRecoveryManager internal recoveryManager;
    address internal owner;
    address internal sender;
    address internal guardian;
    uint256 internal guardianPK;
    bytes32 internal initialGuardianHash;
    IEntryPoint internal configuredEntryPoint;
    address internal configuredWebAuthn;
    address internal configuredGasPolicy;

    function setUp() public {
        DeployInvariantHelper helper = new DeployInvariantHelper();
        helper.runSetup();

        (
            OPFMain impl,
            OPFMain acct,
            SocialRecoveryManager recovery,
            address ownerAddr,
            address senderAddr,
            address guardianAddr,
            bytes32 initialGuardian,
            uint256 guardianPk,
            IEntryPoint entryPointAddr,
            address webAuthnAddr,
            address gasPolicyAddr
        ) = helper.state();

        implementation = impl;
        account = acct;
        recoveryManager = recovery;
        owner = ownerAddr;
        sender = senderAddr;
        guardian = guardianAddr;
        guardianPK = guardianPk;
        initialGuardianHash = initialGuardian;
        configuredEntryPoint = entryPointAddr;
        configuredWebAuthn = webAuthnAddr;
        configuredGasPolicy = gasPolicyAddr;

        uint256 poolSize = 5;
        uint256[] memory guardianPKs = new uint256[](poolSize);
        for (uint256 i; i < poolSize; ++i) {
            guardianPKs[i] = uint256(keccak256(abi.encodePacked("guardian-candidate", i))) | 1;
        }

        uint256[] memory keyPKs = new uint256[](poolSize);
        for (uint256 i; i < poolSize; ++i) {
            keyPKs[i] = uint256(keccak256(abi.encodePacked("key-candidate", i))) | 1;
        }

        handler = new InvariantHandler(
            implementation,
            account,
            recoveryManager,
            owner,
            sender,
            guardian,
            guardianPK,
            initialGuardianHash,
            guardianPKs,
            keyPKs
        );

        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](9);
        selectors[0] = handler.addGuardian.selector;
        selectors[1] = handler.revokeGuardian.selector;
        selectors[2] = handler.startRecovery.selector;
        selectors[3] = handler.cancelRecovery.selector;
        selectors[4] = handler.completeRecovery.selector;
        selectors[5] = handler.registerKey.selector;
        selectors[6] = handler.revokeKey.selector;
        selectors[7] = handler.updateKey.selector;
        selectors[8] = handler.warp.selector;

        FuzzSelector memory selectorData =
            FuzzSelector({addr: address(handler), selectors: selectors});
        targetSelector(selectorData);
    }

    // ───────────────────────────────────────── Invariants ───────────────────────────

    function invariant_MasterKeyProperties() public view {
        (, IKey.KeyData memory master) = account.keyAt(0);

        require(master.isActive, "master key inactive");
        require(master.masterKey, "master key flag missing");
        require(master.limits == 0, "master key limits must be zero");
        require(master.validAfter == 0, "master key validAfter must be zero");
        require(master.validUntil == type(uint48).max, "master key validUntil must be max");
        require(!master.isDelegatedControl, "master key cannot be delegated");
    }

    function invariant_GuardianCountMatches() public view {
        bytes32[] memory guardiansList = recoveryManager.getGuardians(address(account));
        uint256 count = recoveryManager.guardianCount(address(account));
        require(guardiansList.length == count, "guardian count mismatch");

        for (uint256 i; i < guardiansList.length; ++i) {
            require(
                recoveryManager.isGuardian(address(account), guardiansList[i]),
                "guardian array contains inactive hash"
            );
            uint256 pending =
                recoveryManager.getPendingStatusGuardians(address(account), guardiansList[i]);
            require(pending == 0, "active guardian has pending timestamp");
        }
    }

    function invariant_GuardianUniqueness() public view {
        bytes32[] memory guardiansList = recoveryManager.getGuardians(address(account));

        for (uint256 i; i < guardiansList.length; ++i) {
            for (uint256 j = i + 1; j < guardiansList.length; ++j) {
                require(guardiansList[i] != guardiansList[j], "duplicate guardian hash");
            }
        }
    }

    function invariant_SingleActiveMasterKey() public view {
        (bytes32 masterId,) = account.keyAt(0);
        require(masterId != bytes32(0), "master key id zero");

        uint256 total = account.keyCount();
        for (uint256 i = 1; i < total; ++i) {
            (bytes32 keyId, IKey.KeyData memory data) = account.keyAt(i);
            if (!data.masterKey) continue;
            require(keyId == masterId, "distinct master key detected");
        }
    }

    function invariant_KeyActivitySynchronized() public view {
        uint256 total = account.keyCount();
        for (uint256 i; i < total; ++i) {
            (bytes32 keyId, IKey.KeyData memory data) = account.keyAt(i);
            if (keyId == bytes32(0)) continue;
            bool active = account.isKeyActive(keyId);
            require(active == data.isActive, "active flag mismatch");
            if (data.isActive) {
                require(data.key.length != 0, "active key without material");
            }
        }
    }

    function invariant_ConfigurationAddressesImmutable() public view {
        require(
            address(account.entryPoint()) == address(configuredEntryPoint),
            "account entrypoint mutated"
        );
        require(
            address(implementation.entryPoint()) == address(configuredEntryPoint),
            "implementation entrypoint mismatch"
        );
        require(account.webAuthnVerifier() == configuredWebAuthn, "account webauthn mutated");
        require(
            implementation.webAuthnVerifier() == configuredWebAuthn,
            "implementation webauthn mismatch"
        );
        require(account.gasPolicy() == configuredGasPolicy, "account gas policy mutated");
        require(
            implementation.gasPolicy() == configuredGasPolicy, "implementation gas policy mismatch"
        );
    }

    function invariant_GuardianQuorumMatchesCountExact() public view {
        (,, uint32 guardiansRequired) = recoveryManager.recoveryData(address(account));
        if (guardiansRequired == 0) return;

        if (!recoveryManager.isLocked(address(account))) {
            return;
        }

        uint256 guardianCount = recoveryManager.guardianCount(address(account));
        require(guardianCount > 0, "quorum set but no guardians");
        // uint256 expected = Math.ceilDiv(guardianCount, 2);
        uint32 expected = SafeCast.toUint32(Math.ceilDiv(guardianCount, 2));
        if (guardiansRequired != expected) {
            bool locked = recoveryManager.isLocked(address(account));
            revert InvariantGuardianQuorumMismatch(
                guardiansRequired, expected, guardianCount, locked
            );
        }
    }

    function invariant_GuardianQuorumMaintained() public view {
        (,, uint32 guardiansRequired) = recoveryManager.recoveryData(address(account));
        if (guardiansRequired == 0) return;

        uint256 guardianCount = recoveryManager.guardianCount(address(account));
        require(guardianCount > 0, "recovery with no guardians");
    }

    function invariant_LockClearsWithNoRecovery() public view {
        (, uint64 executeAfter,) = recoveryManager.recoveryData(address(account));
        if (executeAfter == 0) {
            require(!recoveryManager.isLocked(address(account)), "lock persists without recovery");
        }
    }

    function invariant_NonMasterKeysCarryLimits() public view {
        uint256 total = account.keyCount();
        for (uint256 i; i < total; ++i) {
            (, IKey.KeyData memory data) = account.keyAt(i);
            if (data.isActive && !data.masterKey) {
                require(data.limits > 0, "active non-master key without limits");
            }
        }
    }
}
