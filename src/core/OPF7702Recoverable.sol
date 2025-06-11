/*
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░     ░░░░░░        ░░░         ░    ░░░░░   ░        ░░░░░░     ░░░░░░        ░░░░░           ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
▒▒▒   ▒▒▒▒   ▒▒▒   ▒▒▒▒   ▒   ▒▒▒▒▒▒▒  ▒   ▒▒▒   ▒   ▒▒▒▒▒▒▒▒▒   ▒▒▒▒   ▒▒▒   ▒▒▒▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒      ▒   ▒      ▒   ▒▒▒▒▒   ▒▒▒▒▒▒▒   ▒  ▒▒▒
▒   ▒▒▒▒▒▒▒▒   ▒   ▒▒▒▒   ▒   ▒▒▒▒▒▒▒   ▒   ▒▒   ▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒   ▒   ▒▒▒▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒   ▒▒▒▒   ▒▒   ▒▒▒  ▒▒▒▒▒   
▓   ▓▓▓▓▓▓▓▓   ▓        ▓▓▓       ▓▓▓   ▓▓   ▓   ▓       ▓▓▓   ▓▓▓▓▓▓▓▓   ▓  ▓   ▓▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓   ▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓
▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓  ▓   ▓   ▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓   ▓▓▓▓▓▓   ▓▓▓▓   ▓▓▓▓
▓▓▓   ▓▓▓▓▓   ▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓▓  ▓  ▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓   ▓▓   ▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓   ▓▓▓▓   ▓▓▓   ▓▓▓▓▓▓
█████     ██████   ████████         █   ██████   █   ███████████     ██████   ██████   █████   █████████   ████████   ████████    █████         █
█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
 */

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {OPF7702} from "src/core/OPF7702.sol";
import {Math} from "lib/openzeppelin-contracts/contracts/utils/math/Math.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

/**
 * @title   Openfort Base Account 7702 with ERC-4337 Support
 * @author  Openfort — https://openfort.xyz
 * @notice  Smart contract wallet implementing EIP-7702 + ERC-4337 with guardian-based recovery and multi-format keys.
 * @dev
 *  • EIP-4337 integration via EntryPoint
 *  • EIP-7702 support (e.g., setCode)
 *  • Multi-scheme keys: EOA (ECDSA), WebAuthn, P256/P256NONKEY
 *  • ETH/token spending limits + selector whitelists
 *  • ERC-1271 on-chain signature support
 *  • Reentrancy protection & explicit nonce replay prevention
 *
 * Layout storage slot (keccak256):
 *  "openfort.baseAccount.7702.v1" =
 *    0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
 *    == 57943590311362240630886240343495690972153947532773266946162183175043753177960
 */
contract OPF7702Recoverable is OPF7702, EIP712 layout at 57943590311362240630886240343495690972153947532773266946162183175043753177960 {
    using ECDSA for bytes32;

    // ──────────────────────────────────────────────────────────────────────────────
    //                                 Errors
    // ──────────────────────────────────────────────────────────────────────────────

    /// @dev Thrown when the account is in a temporary locked state.
    error OPF7702Recoverable__AccountLocked();
    /// @dev Thrown when a guardian revocation is unknown for the given guardian.
    error OPF7702Recoverable__UnknownRevoke();
    /// @dev Thrown when the caller must be an active guardian but is not.
    error OPF7702Recoverable__MustBeGuardian();
    /// @dev Thrown when a guardian addition proposal is unknown.
    error OPF7702Recoverable__UnknownProposal();
    /// @dev Thrown when another recovery flow is already in progress.
    error OPF7702Recoverable__OngoingRecovery();
    /// @dev Thrown when trying to revoke a guardian twice in the same security window.
    error OPF7702Recoverable__DuplicatedRevoke();
    /// @dev Thrown when no recovery is currently active but one is required.
    error OPF7702Recoverable__NoOngoingRecovery();
    /// @dev Thrown when both address in a guardian are zero values.
    error OPF7702Recoverable__AddressCantBeZero();
    /// @dev Thrown when a duplicate guardian proposal is submitted in the security window.
    error OPF7702Recoverable__DuplicatedProposal();
    /// @dev Thrown when attempting to add a guardian that is already active.
    error OPF7702Recoverable__DuplicatedGuardian();
    /// @dev Thrown when a key type different from EOA or WebAuthn is supplied where unsupported.
    error OPF7702Recoverable__UnsupportedKeyType();
    /// @dev Thrown when the revoke window has not elapsed yet.
    error OPF7702Recoverable__PendingRevokeNotOver();
    /// @dev Thrown when the revoke confirmation window has expired.
    error OPF7702Recoverable__PendingRevokeExpired();
    /// @dev Thrown when the recovery address is already a guardian.
    error OPF7702Recoverable__GuardianCannotBeOwner();
    /// @dev Thrown when no guardians are configured on the wallet.
    error OPF7702Recoverable__NoGuardiansSetOnWallet();
    /// @dev Thrown when the proposal confirmation window has expired.
    error OPF7702Recoverable__PendingProposalExpired();
    /// @dev Thrown when the amount of guardian signatures provided is incorrect.
    error OPF7702Recoverable__InvalidSignatureAmount();
    /// @dev Thrown when attempting to confirm a proposal before the timelock elapses.
    error OPF7702Recoverable__PendingProposalNotOver();
    /// @dev Thrown when guardian-supplied signatures are invalid.
    error OPF7702Recoverable__InvalidRecoverySignatures();
    /// @dev Thrown when guardian address equals the wallet itself.
    error OPF7702Recoverable__GuardianCannotBeAddressThis();
    /// @dev Thrown when guardian equals the current master key.
    error OPF7702Recoverable__GuardianCannotBeCurrentMasterKey();

    // ──────────────────────────────────────────────────────────────────────────────
    //                                 Structs
    // ──────────────────────────────────────────────────────────────────────────────

    /// @notice Metadata kept for each guardian.
    /// @param isActive    Whether the guardian is currently active.
    /// @param index       Index of the guardian hash inside `guardians` array (for O(1) removal).
    /// @param pending     Timestamp after which a proposal/revoke can be executed (0 = none).
    struct GuardianIdentity {
        bool isActive;
        uint256 index;
        uint256 pending;
    }

    /// @notice Encapsulates guardian related state.
    /// @param guardians  Array of guardian identifiers (hashes) in insertion order.
    /// @param data       Mapping from guardian hash to metadata.
    /// @param lock       Global lock timestamp – wallet is locked until this moment.
    struct GuardiansData {
        bytes32[] guardians;
        mapping(bytes32 hashAddress => GuardianIdentity guardianIdentity) data;
        uint256 lock;
    }

    /// @notice Recovery flow state variables.
    /// @param key                The new master key proposed by guardians.
    /// @param executeAfter       Timestamp after which recovery can be executed.
    /// @param guardiansRequired  Number of guardian signatures required to complete recovery.
    struct RecoveryData {
        Key key;
        uint64 executeAfter;
        uint32 guardiansRequired;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Constants
    // ──────────────────────────────────────────────────────────────────────────────

    /// @dev EIP‑712 type hash for the Recovery struct.
    bytes32 private constant RECOVER_TYPEHASH =
        0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;

    // ──────────────────────────────────────────────────────────────────────────────
    //                              Immutable vars
    // ──────────────────────────────────────────────────────────────────────────────

    /// @notice Seconds a recovery proposal must wait before it can be executed.
    uint256 internal immutable recoveryPeriod;
    /// @notice Seconds the wallet remains locked after a recovery proposal is submitted.
    uint256 internal immutable lockPeriod;
    /// @notice Seconds that a guardian proposal/revoke must wait before it can be confirmed.
    uint256 internal immutable securityPeriod;
    /// @notice Seconds after `securityPeriod` during which the proposal/revoke can be confirmed.
    uint256 internal immutable securityWindow;

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Storage vars
    // ──────────────────────────────────────────────────────────────────────────────

    GuardiansData internal guardiansData;
    RecoveryData public recoveryData;

    // ──────────────────────────────────────────────────────────────────────────────
    //                                 Events
    // ──────────────────────────────────────────────────────────────────────────────

    /// @notice Emitted when a new guardian proposal is created.
    event GuardianProposed(bytes32 indexed guardianHash, uint256 executeAfter);
    /// @notice Emitted when a guardian proposal is confirmed and guardian becomes active.
    event GuardianAdded(bytes32 indexed guardianHash);
    /// @notice Emitted when a guardian proposal is cancelled.
    event GuardianProposalCancelled(bytes32 indexed guardianHash);
    /// @notice Emitted when a guardian revocation is scheduled.
    event GuardianRevocationScheduled(bytes32 indexed guardianHash, uint256 executeAfter);
    /// @notice Emitted when guardian revocation is confirmed and guardian removed.
    event GuardianRemoved(bytes32 indexed guardianHash);
    /// @notice Emitted when a scheduled revocation is cancelled.
    event GuardianRevocationCancelled(bytes32 indexed guardianHash);
    /// @notice Emitted when guardians start the recovery process.
    event RecoveryStarted(uint64 executeAfter, uint32 guardiansRequired);
    /// @notice Emitted when recovery completes and a new master key is set.
    event RecoveryCompleted();
    /// @notice Emitted when an ongoing recovery is cancelled.
    event RecoveryCancelled();
    /// @notice Emitted when the wallet is locked.
    event WalletLocked(bool isLocked);

    // ──────────────────────────────────────────────────────────────────────────────
    //                              Constructor
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @param _entryPoint      ERC‑4337 EntryPoint address.
     * @param _recoveryPeriod  Delay (seconds) before guardians can execute recovery.
     * @param _lockPeriod      Period (seconds) that the wallet stays locked after recovery starts.
     * @param _securityPeriod  Timelock (seconds) for guardian add/remove actions.
     * @param _securityWindow  Window (seconds) after the timelock where the action must be executed.
     */
    constructor(
        address _entryPoint,
        uint256 _recoveryPeriod,
        uint256 _lockPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow
    ) OPF7702(_entryPoint) EIP712("OPF7702Recoverable", "1") {
        recoveryPeriod = _recoveryPeriod;
        lockPeriod = _lockPeriod;
        securityPeriod = _securityPeriod;
        securityWindow = _securityWindow;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                          Public / External methods
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @notice Initializes the account with a “master” key (no spending or whitelist restrictions).
     * @dev
     *  • Callable only via EntryPoint or a self-call.
     *  • Clears previous storage, checks nonce & expiration, verifies signature.
     *  • Registers the provided `_key` as a master key:
     *     - validUntil = max (never expires)
     *     - validAfter  = 0
     *     - limit       = 0  (master)
     *     - whitelisting = false
     *     - DEAD_ADDRESS placeholder in whitelistedContracts
     *  • Emits `Initialized(_key)`.
     *
     * @param _key              The Key struct (master key).
     * @param _spendTokenInfo   Token limit info (ignored for master).
     * @param _allowedSelectors Unused selectors (ignored for master).
     * @param _hash             Hash to sign (EIP-712 or UserOp hash).
     * @param _signature        Signature over `_hash` by this contract.
     * @param _validUntil       Expiration timestamp for this initialization.
     */
    function initialize(
        Key calldata _key,
        SpendTokenInfo calldata _spendTokenInfo,
        bytes4[] calldata _allowedSelectors,
        bytes32 _hash,
        bytes memory _signature,
        uint256 _validUntil,
        address _initialGuardian
    ) external initializer {
        _requireForExecute();
        _clearStorage();
        _notExpired(_validUntil);

        if (!_checkSignature(_hash, _signature)) {
            revert OpenfortBaseAccount7702V1__InvalidSignature();
        }

        bytes32 keyId = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
        KeyData storage sKey = keys[keyId];
        idKeys[0] = _key;

        // register masterKey: never expires, no spending/whitelist restrictions
        _addKey(
            sKey,
            _key,
            type(uint48).max, // validUntil = max
            0, // validAfter = 0
            0, // limit = 0 (master)
            false, // no whitelisting
            DEAD_ADDRESS, // dummy contract address
            _spendTokenInfo, // token info (ignored)
            _allowedSelectors, // selectors (ignored)
            0 // ethLimit = 0
        );

        unchecked {
            ++id;
        }

        initializeGuardians(_initialGuardian);

        emit Initialized(_key);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                        Guardian management (internal)
    // ──────────────────────────────────────────────────────────────────────────────

    /// @dev Helper to configure the first guardian during `initialize`.
    /// @param _initialGuardian Guardian address to register.
    function initializeGuardians(address _initialGuardian) private {
        if (_initialGuardian == address(0)) revert OPF7702Recoverable__AddressCantBeZero();
        bytes32 gHash = _guardianHash(_initialGuardian);

        guardiansData.guardians.push(gHash);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        emit GuardianAdded(gHash);

        gi.isActive = true;
        gi.index = 0;
        gi.pending = 0;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                     Guardian add / revoke public interface
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @notice Proposes adding a new guardian. Must be confirmed after the security period.
     * @param _guardian Guardian address to add.
     */
    function proposeGuardian(address _guardian) external {
        _requireForExecute();
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        if (_guardian == address(0)) revert OPF7702Recoverable__AddressCantBeZero();
        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        if (address(this) == _guardian) {
            revert OPF7702Recoverable__GuardianCannotBeAddressThis();
        }

        Key memory mk = getKeyById(0);
        if (mk.eoaAddress == _guardian) {
            revert OPF7702Recoverable__GuardianCannotBeCurrentMasterKey();
        }

        if (gi.isActive) revert OPF7702Recoverable__DuplicatedGuardian();

        if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
            revert OPF7702Recoverable__DuplicatedProposal();
        }

        gi.pending = block.timestamp + securityPeriod;

        emit GuardianProposed(gHash, gi.pending);
    }

    /**
     * @notice Finalizes a previously proposed guardian after the timelock.
     * @param _guardian Guardian address to activate.
     */
    function confirmGuardianProposal(address _guardian) external {
        _requireForExecute();
        _requireRecovery(false);
        if (_guardian == address(0)) revert OPF7702Recoverable__AddressCantBeZero();
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        if (gi.pending == 0) revert OPF7702Recoverable__UnknownProposal();
        if (block.timestamp < gi.pending) revert OPF7702Recoverable__PendingProposalNotOver();
        if (block.timestamp > gi.pending + securityWindow) {
            revert OPF7702Recoverable__PendingProposalExpired();
        }

        if (gi.isActive) revert OPF7702Recoverable__DuplicatedGuardian();

        emit GuardianAdded(gHash);

        gi.isActive = true;
        gi.pending = 0;
        gi.index = guardiansData.guardians.length;
        guardiansData.guardians.push(gHash);
    }

    /**
     * @notice Cancels a guardian addition proposal before it is confirmed.
     * @param _guardian Guardian address whose proposal should be cancelled.
     */
    function cancelGuardianProposal(address _guardian) external {
        _requireForExecute();
        _requireRecovery(false);
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        if (gi.pending == 0) revert OPF7702Recoverable__UnknownProposal();
        if (gi.isActive) revert OPF7702Recoverable__DuplicatedGuardian();

        emit GuardianProposalCancelled(gHash);

        gi.pending = 0;
    }

    /**
     * @notice Initiates guardian removal. Must be confirmed after the security period.
     * @param _guardian Guardian address to revoke.
     */
    function revokeGuardian(address _guardian) external {
        _requireForExecute();
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        if (!gi.isActive) revert OPF7702Recoverable__MustBeGuardian();

        if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
            revert OPF7702Recoverable__DuplicatedRevoke();
        }

        gi.pending = block.timestamp + securityPeriod;

        emit GuardianRevocationScheduled(gHash, gi.pending);
    }

    /**
     * @notice Confirms guardian removal after the timelock.
     * @param _guardian Guardian address to remove permanently.
     */
    function confirmGuardianRevocation(address _guardian) external {
        _requireForExecute();
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        if (gi.pending == 0) revert OPF7702Recoverable__UnknownRevoke();
        if (block.timestamp < gi.pending) revert OPF7702Recoverable__PendingRevokeNotOver();
        if (block.timestamp > gi.pending + securityWindow) {
            revert OPF7702Recoverable__PendingRevokeExpired();
        }
        if (!gi.isActive) revert OPF7702Recoverable__MustBeGuardian();

        uint256 lastIndex = guardiansData.guardians.length - 1;
        bytes32 lastHash = guardiansData.guardians[lastIndex];
        uint256 targetIndex = gi.index;

        if (gHash != lastHash) {
            guardiansData.guardians[targetIndex] = lastHash;
            guardiansData.data[lastHash].index = targetIndex;
        }

        emit GuardianRemoved(gHash);

        guardiansData.guardians.pop();

        delete guardiansData.data[gHash];
    }

    /**
     * @notice Cancels a pending guardian removal.
     * @param _guardian Guardian address whose removal should be cancelled.
     */
    function cancelGuardianRevocation(address _guardian) external {
        _requireForExecute();
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        if (!gi.isActive) revert OPF7702Recoverable__MustBeGuardian();
        if (gi.pending == 0) revert OPF7702Recoverable__UnknownRevoke();

        emit GuardianRevocationCancelled(gHash);

        guardiansData.data[gHash].pending = 0;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                           Recovery flow (guardians)
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @notice Guardians initiate account recovery by proposing a new master key.
     * @dev The caller must be an active guardian. Wallet enters locked state immediately.
     * @param _recoveryKey New master key to set once recovery succeeds.
     */
    function startRecovery(Key memory _recoveryKey) external virtual {
        if (!isGuardian(msg.sender)) {
            revert OPF7702Recoverable__MustBeGuardian();
        }

        _requireRecovery(false);
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        bool hasAddress = _recoveryKey.eoaAddress != address(0);
        bool hasPubKey = _recoveryKey.pubKey.x != bytes32(0) || _recoveryKey.pubKey.y != bytes32(0);
        if (!hasAddress && !hasPubKey) revert OPF7702Recoverable__AddressCantBeZero();

        if (isGuardian(_recoveryKey.eoaAddress)) revert OPF7702Recoverable__GuardianCannotBeOwner();

        uint64 executeAfter = SafeCast.toUint64(block.timestamp + recoveryPeriod);
        uint32 quorum = SafeCast.toUint32(Math.ceilDiv(guardianCount(), 2));

        emit RecoveryStarted(executeAfter, quorum);

        recoveryData =
            RecoveryData({key: _recoveryKey, executeAfter: executeAfter, guardiansRequired: quorum});

        _setLock(block.timestamp + lockPeriod);
    }

    /**
     * @notice Completes recovery after the timelock by providing the required guardian signatures.
     * @param _signatures Encoded guardian signatures approving the recovery.
     */
    function completeRecovery(bytes[] calldata _signatures) external virtual {
        _requireRecovery(true);

        RecoveryData memory r = recoveryData;

        if (r.executeAfter > block.timestamp) {
            revert OPF7702Recoverable__OngoingRecovery();
        }

        require(r.guardiansRequired > 0, OPF7702Recoverable__NoGuardiansSetOnWallet());
        if (r.guardiansRequired != _signatures.length) {
            revert OPF7702Recoverable__InvalidSignatureAmount();
        }
        if (!_validateSignatures(_signatures)) {
            revert OPF7702Recoverable__InvalidRecoverySignatures();
        }

        Key memory recoveryOwner = r.key;
        delete recoveryData;

        _deleteOldKeys();
        _setNewMasterKey(recoveryOwner);
        _setLock(0);
    }

    /// @dev Deletes the old master key data structures (both WebAuthn and EOA variants).
    function _deleteOldKeys() private {
        // Todo: Change the Admin key of index 0 in the keys for new Master Key
        // _transferOwnership(recoveryOwner);

        // Todo: Need to Identify Master Key by Id or Any othewr flag
        // MK WebAuthn will be always id = 0 because of Initalization func enforce to be `0`
        Key storage oldMK = idKeys[0];
        bytes32 oldHash;

        if (oldMK.eoaAddress == address(0) || oldMK.eoaAddress == DEAD_ADDRESS) {
            oldHash = keccak256(abi.encodePacked(oldMK.pubKey.x, oldMK.pubKey.y));
        } else if (oldMK.eoaAddress != address(0)) {
            oldHash = keccak256(abi.encodePacked(oldMK.eoaAddress));
        }

        /// @dev Only the nested mapping in stract will not be cleared mapping(address => bool) whitelist
        /// @notice not providing security risk
        delete keys[oldHash];
        delete idKeys[0];
    }

    /// @dev Registers the new master key after successful recovery.
    /// @param recoveryOwner Key that becomes the new master key.
    function _setNewMasterKey(Key memory recoveryOwner) private {
        KeyData storage sKey;
        bytes32 newHash;

        if (recoveryOwner.keyType == KeyType.WEBAUTHN) {
            newHash = keccak256(abi.encodePacked(recoveryOwner.pubKey.x, recoveryOwner.pubKey.y));
        } else if (recoveryOwner.keyType == KeyType.EOA) {
            newHash = keccak256(abi.encodePacked(recoveryOwner.eoaAddress));
        } else {
            revert OPF7702Recoverable__UnsupportedKeyType();
        }

        idKeys[0] = recoveryOwner;

        sKey = keys[newHash];

        if (sKey.isActive) {
            revert KeyManager__KeyRegistered();
        }

        SpendTokenInfo memory _spendTokenInfo = SpendTokenInfo({token: DEAD_ADDRESS, limit: 0});
        bytes4[] memory _allowedSelectors = new bytes4[](3);

        emit RecoveryCompleted();

        _addKey(
            sKey,
            recoveryOwner,
            type(uint48).max, // validUntil = max
            0, // validAfter = 0
            0, // limit = 0 (master)
            false, // no whitelisting
            DEAD_ADDRESS, // dummy contract address
            _spendTokenInfo, // token info (ignored)
            _allowedSelectors, // selectors (ignored)
            0 // ethLimit = 0
        );
    }

    /// @dev Validates guardian signatures for recovery completion.
    /// @param _signatures Encoded signatures supplied by guardians.
    /// @return True if all signatures are valid and unique.
    function _validateSignatures(bytes[] calldata _signatures) internal view returns (bool) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECOVER_TYPEHASH,
                    recoveryData.key,
                    recoveryData.executeAfter,
                    recoveryData.guardiansRequired
                )
            )
        );

        bytes32 lastGuardianHash;

        unchecked {
            for (uint256 i; i < _signatures.length; ++i) {
                bytes32 guardianHash;

                address signer = digest.recover(_signatures[i]);
                guardianHash = keccak256(abi.encodePacked(signer));

                if (!guardiansData.data[guardianHash].isActive) return false;

                if (guardianHash <= lastGuardianHash) return false;
                lastGuardianHash = guardianHash;
            }
        }

        return true;
    }

    /**
     * @notice Cancels an ongoing recovery and unlocks the wallet.
     */
    function cancelRecovery() external {
        _requireForExecute();
        _requireRecovery(true);
        emit RecoveryCancelled();
        delete recoveryData;
        _setLock(0);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                             Internal helpers
    // ──────────────────────────────────────────────────────────────────────────────

    /// @dev Ensures recovery state matches the expectation.
    /// @param _isRecovery True if function requires an ongoing recovery.
    function _requireRecovery(bool _isRecovery) internal view {
        if (_isRecovery && recoveryData.executeAfter == 0) {
            revert OPF7702Recoverable__NoOngoingRecovery();
        }
        if (!_isRecovery && recoveryData.executeAfter > 0) {
            revert OPF7702Recoverable__OngoingRecovery();
        }
    }

    /// @dev Sets the global lock timestamp.
    /// @param _releaseAfter Timestamp when the lock should be lifted (0 = unlock).
    function _setLock(uint256 _releaseAfter) internal {
        emit WalletLocked(_releaseAfter != 0);
        guardiansData.lock = _releaseAfter;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                               View helpers
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @notice Computes the storage hash for a guardian address.
     * @dev Only EOA (address) are supported.
     * @param _guardian Guardian address to hash.
     * @return Guardian identifier hash.
     */
    function _guardianHash(address _guardian) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_guardian));
    }

    /**
     * @notice Returns all guardian hashes currently active.
     * @return Array of guardian hashes.
     */
    function getGuardians() external view virtual returns (bytes32[] memory) {
        bytes32[] memory guardians = new bytes32[](guardiansData.guardians.length);
        uint256 i;
        for (i; i < guardiansData.guardians.length;) {
            guardians[i] = guardiansData.guardians[i];
            unchecked {
                ++i; // gas optimization
            }
        }

        return guardians;
    }

    /**
     * @notice Returns the pending timestamp (if any) for guardian proposal/revoke.
     * @param _guardian Guardian address to query.
     * @return Timestamp until which the action is pending (0 if none).
     */
    function getPendingStatusGuardians(address _guardian) external view returns (uint256) {
        bytes32 gHash = _guardianHash(_guardian);
        return guardiansData.data[gHash].pending;
    }

    /**
     * @notice Checks whether the wallet is currently locked due to recovery flow.
     * @return True if locked, false otherwise.
     */
    function isLocked() public view virtual returns (bool) {
        return guardiansData.lock > block.timestamp;
    }

    /**
     * @notice Checks if a address is an active guardian.
     * @param _guardian Guardian address to query.
     * @return True if active guardian.
     */
    function isGuardian(address _guardian) public view returns (bool) {
        bytes32 guradianHash;
        guradianHash = keccak256(abi.encodePacked(_guardian));

        return guardiansData.data[guradianHash].isActive;
    }

    /**
     * @notice Returns the number of active guardians.
     */
    function guardianCount() public view virtual returns (uint256) {
        return guardiansData.guardians.length;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                           Utility view functions
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @notice Returns the EIP‑712 digest guardians must sign to approve recovery.
     */
    function getDigestToSign() external view returns (bytes32 digest) {
        bytes32 structHash = keccak256(
            abi.encode(
                RECOVER_TYPEHASH,
                recoveryData.key,
                recoveryData.executeAfter,
                recoveryData.guardiansRequired
            )
        );

        digest = _hashTypedDataV4(structHash);
    }
}
