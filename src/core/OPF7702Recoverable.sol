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
pragma solidity 0.8.29;

import {OPF7702} from "src/core/OPF7702.sol";
import {ERC7201} from "src/utils/ERC7201.sol";
import {KeyHashLib} from "src/libs/KeyHashLib.sol";
import {IOPF7702} from "src/interfaces/IOPF7702.sol";
import {IBaseOPF7702} from "src/interfaces/IBaseOPF7702.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {KeyDataValidationLib} from "src/libs/KeyDataValidationLib.sol";
import {IOPF7702Recoverable} from "src/interfaces/IOPF7702Recoverable.sol";
import {Math} from "lib/openzeppelin-contracts/contracts/utils/math/Math.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EIP712Upgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";
/**
 * @title   Openfort Base Account 7702 with ERC-4337 Support
 * @author  Openfort@0xkoiner
 * @notice  Smart contract wallet implementing EIP-7702 + ERC-4337 with guardian-based recovery and multi-format keys.
 * @dev
 *  • EIP-4337 integration via EntryPoint
 *  • EIP-7702 support (e.g., setCode)
 *  • Multi-scheme keys: EOA (ECDSA), WebAuthn, P256/P256NONKEY
 *  • ETH/token spending limits + selector whitelists
 *  • ERC-1271 on-chain signature support
 *  • Reentrancy protection & explicit nonce replay prevention
 */

contract OPF7702Recoverable is OPF7702, EIP712Upgradeable, ERC7201 {
    using ECDSA for bytes32;
    using KeyHashLib for Key;
    using KeyHashLib for address;
    using KeyDataValidationLib for Key;

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

    /// @notice Recovery flow state variables.
    IOPF7702Recoverable.RecoveryData public recoveryData;
    /// @notice Encapsulates guardian related state.
    IOPF7702Recoverable.GuardiansData internal guardiansData;

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
        address _webAuthnVerifier,
        uint256 _recoveryPeriod,
        uint256 _lockPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow
    ) OPF7702(_entryPoint, _webAuthnVerifier) {
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
     * @param _keyData          KeyReg data structure containing permissions and limits
     * @param _sessionKey       The Key struct (session key).
     * @param _sessionKeyData   KeyReg data structure containing permissions and limits
     * @param _signature        Signature over `_hash` by this contract.
     * @param _initialGuardian  Initialize Guardian. Must be at least one guardian!
     */
    function initialize(
        Key calldata _key,
        KeyReg calldata _keyData,
        Key calldata _sessionKey,
        KeyReg calldata _sessionKeyData,
        bytes memory _signature,
        bytes32 _initialGuardian
    ) external initializer {
        __EIP712_init("OPF7702Recoverable", "1");
        __ReentrancyGuard_init();
        _requireForExecute();
        _clearStorage();

        bytes32 digest = getDigestToInit(_key, _initialGuardian);

        if (!_checkSignature(digest, _signature)) {
            revert IBaseOPF7702.OpenfortBaseAccount7702V1__InvalidSignature();
        }

        KeyData storage sKey = keys[_key.computeKeyId()];
        idKeys[0] = _key;

        // register masterKey: never expires, no spending/whitelist restrictions
        _addKey(sKey, _key, _keyData);

        unchecked {
            ++id;
        }

        if (!_sessionKey.checkKey()) {
            registerKey(_sessionKey, _sessionKeyData);
        }
        initializeGuardians(_initialGuardian);

        emit IOPF7702.Initialized(_key);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                        Guardian management (internal)
    // ──────────────────────────────────────────────────────────────────────────────

    /// @dev Helper to configure the first guardian during `initialize`.
    /// @param _initialGuardian Guardian address to register.
    function initializeGuardians(bytes32 _initialGuardian) private {
        if (_initialGuardian == bytes32(0)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }

        guardiansData.guardians.push(_initialGuardian);
        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData.data[_initialGuardian];

        emit IOPF7702Recoverable.GuardianAdded(_initialGuardian);

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
    function proposeGuardian(bytes32 _guardian) external {
        _requireForExecute();
        if (isLocked()) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        if (_guardian == bytes32(0)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData.data[_guardian];

        if (address(this).computeKeyId() == _guardian) {
            revert IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeAddressThis();
        }

        Key memory mk = getKeyById(0);
        if (mk.eoaAddress.computeKeyId() == _guardian) {
            revert IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeCurrentMasterKey();
        }

        if (gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian();

        if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedProposal();
        }

        gi.pending = block.timestamp + securityPeriod;

        emit IOPF7702Recoverable.GuardianProposed(_guardian, gi.pending);
    }

    /**
     * @notice Finalizes a previously proposed guardian after the timelock.
     * @param _guardian Guardian address to activate.
     */
    function confirmGuardianProposal(bytes32 _guardian) external {
        _requireForExecute();
        _requireRecovery(false);
        if (_guardian == bytes32(0)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }
        if (isLocked()) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData.data[_guardian];

        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownProposal();
        if (block.timestamp < gi.pending) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingProposalNotOver();
        }
        if (block.timestamp > gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingProposalExpired();
        }

        if (gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian();

        emit IOPF7702Recoverable.GuardianAdded(_guardian);

        gi.isActive = true;
        gi.pending = 0;
        gi.index = guardiansData.guardians.length;
        guardiansData.guardians.push(_guardian);
    }

    /**
     * @notice Cancels a guardian addition proposal before it is confirmed.
     * @param _guardian Guardian address whose proposal should be cancelled.
     */
    function cancelGuardianProposal(bytes32 _guardian) external {
        _requireForExecute();
        _requireRecovery(false);
        if (isLocked()) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData.data[_guardian];

        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownProposal();
        if (gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian();

        emit IOPF7702Recoverable.GuardianProposalCancelled(_guardian);

        gi.pending = 0;
    }

    /**
     * @notice Initiates guardian removal. Must be confirmed after the security period.
     * @param _guardian Guardian address to revoke.
     */
    function revokeGuardian(bytes32 _guardian) external {
        _requireForExecute();
        if (isLocked()) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData.data[_guardian];

        if (!gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();

        if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedRevoke();
        }

        gi.pending = block.timestamp + securityPeriod;

        emit IOPF7702Recoverable.GuardianRevocationScheduled(_guardian, gi.pending);
    }

    /**
     * @notice Confirms guardian removal after the timelock.
     * @param _guardian Guardian address to remove permanently.
     */
    function confirmGuardianRevocation(bytes32 _guardian) external {
        _requireForExecute();
        if (isLocked()) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData.data[_guardian];

        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownRevoke();
        if (block.timestamp < gi.pending) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingRevokeNotOver();
        }
        if (block.timestamp > gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingRevokeExpired();
        }
        if (!gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();

        uint256 lastIndex = guardiansData.guardians.length - 1;
        bytes32 lastHash = guardiansData.guardians[lastIndex];
        uint256 targetIndex = gi.index;

        if (_guardian != lastHash) {
            guardiansData.guardians[targetIndex] = lastHash;
            guardiansData.data[lastHash].index = targetIndex;
        }

        emit IOPF7702Recoverable.GuardianRemoved(_guardian);

        guardiansData.guardians.pop();

        delete guardiansData.data[_guardian];
    }

    /**
     * @notice Cancels a pending guardian removal.
     * @param _guardian Guardian address whose removal should be cancelled.
     */
    function cancelGuardianRevocation(bytes32 _guardian) external {
        _requireForExecute();
        if (isLocked()) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData.data[_guardian];

        if (!gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();
        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownRevoke();

        emit IOPF7702Recoverable.GuardianRevocationCancelled(_guardian);

        guardiansData.data[_guardian].pending = 0;
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
        if (!isGuardian(msg.sender.computeKeyId())) {
            revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();
        }
        if (_recoveryKey.keyType == KeyType.P256 || _recoveryKey.keyType == KeyType.P256NONKEY) {
            revert IOPF7702Recoverable.OPF7702Recoverable__UnsupportedKeyType();
        }

        _requireRecovery(false);
        if (isLocked()) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        // bool hasAddress = _recoveryKey.eoaAddress != address(0);
        // bool hasPubKey = _recoveryKey.pubKey.x != bytes32(0) || _recoveryKey.pubKey.y != bytes32(0);
        if (_recoveryKey.checkKey()) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }

        if (keys[_recoveryKey.computeKeyId()].isActive) {
            revert IOPF7702Recoverable.OPF7702Recoverable__RecoverCannotBeActiveKey();
        }

        if (isGuardian(_recoveryKey.eoaAddress.computeKeyId())) {
            revert IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeOwner();
        }

        uint64 executeAfter = SafeCast.toUint64(block.timestamp + recoveryPeriod);
        uint32 quorum = SafeCast.toUint32(Math.ceilDiv(guardianCount(), 2));

        emit IOPF7702Recoverable.RecoveryStarted(executeAfter, quorum);

        recoveryData = IOPF7702Recoverable.RecoveryData({
            key: _recoveryKey,
            executeAfter: executeAfter,
            guardiansRequired: quorum
        });

        _setLock(block.timestamp + lockPeriod);
    }

    /**
     * @notice Completes recovery after the timelock by providing the required guardian signatures.
     * @param _signatures Encoded guardian signatures approving the recovery.
     */
    function completeRecovery(bytes[] calldata _signatures) external virtual {
        _requireRecovery(true);

        IOPF7702Recoverable.RecoveryData memory r = recoveryData;

        if (r.executeAfter > block.timestamp) {
            revert IOPF7702Recoverable.OPF7702Recoverable__OngoingRecovery();
        }

        require(
            r.guardiansRequired > 0,
            IOPF7702Recoverable.OPF7702Recoverable__NoGuardiansSetOnWallet()
        );
        if (r.guardiansRequired != _signatures.length) {
            revert IOPF7702Recoverable.OPF7702Recoverable__InvalidSignatureAmount();
        }
        if (!_validateSignatures(_signatures)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__InvalidRecoverySignatures();
        }

        Key memory recoveryOwner = r.key;
        delete recoveryData;

        _deleteOldKeys();
        _setNewMasterKey(recoveryOwner);
        _setLock(0);
    }

    /// @dev Deletes the old master key data structures (both WebAuthn and EOA variants).
    function _deleteOldKeys() private {
        // MK WebAuthn will be always id = 0 because of Initalization func enforce to be `0`
        Key storage oldMK = idKeys[0];

        /// @dev Only the nested mapping in stract will not be cleared mapping(address => bool) whitelist
        /// @notice not providing security risk
        delete keys[oldMK.computeKeyId()];
        delete idKeys[0];
    }

    /// @dev Registers the new master key after successful recovery.
    /// @param recoveryOwner Key that becomes the new master key.
    function _setNewMasterKey(Key memory recoveryOwner) private {
        KeyData storage sKey;

        idKeys[0] = recoveryOwner;

        sKey = keys[recoveryOwner.computeKeyId()];

        if (sKey.isActive) {
            revert IKeysManager.KeyManager__KeyRegistered();
        }

        SpendTokenInfo memory _spendTokenInfo = SpendTokenInfo({token: DEAD_ADDRESS, limit: 0});
        bytes4[] memory _allowedSelectors = new bytes4[](3);

        emit IOPF7702Recoverable.RecoveryCompleted();

        KeyReg memory keyData = KeyReg({
            validUntil: type(uint48).max,
            validAfter: 0,
            limit: 0,
            whitelisting: false,
            contractAddress: DEAD_ADDRESS,
            spendTokenInfo: _spendTokenInfo,
            allowedSelectors: _allowedSelectors,
            ethLimit: 0
        });

        _addKey(sKey, recoveryOwner, keyData);
    }

    /// @dev Validates guardian signatures for recovery completion.
    /// @param _signatures Encoded signatures supplied by guardians.
    /// @return True if all signatures are valid and unique.
    function _validateSignatures(bytes[] calldata _signatures) internal view returns (bool) {
        bytes32 digest = getDigestToSign();
        bytes32 lastGuardianHash;

        unchecked {
            for (uint256 i; i < _signatures.length; ++i) {
                bytes32 guardianHash;

                address signer = digest.recover(_signatures[i]);
                guardianHash = signer.computeKeyId();

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
        emit IOPF7702Recoverable.RecoveryCancelled();
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
            revert IOPF7702Recoverable.OPF7702Recoverable__NoOngoingRecovery();
        }
        if (!_isRecovery && recoveryData.executeAfter > 0) {
            revert IOPF7702Recoverable.OPF7702Recoverable__OngoingRecovery();
        }
    }

    /// @dev Sets the global lock timestamp.
    /// @param _releaseAfter Timestamp when the lock should be lifted (0 = unlock).
    function _setLock(uint256 _releaseAfter) internal {
        emit IOPF7702Recoverable.WalletLocked(_releaseAfter != 0);
        guardiansData.lock = _releaseAfter;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                               View helpers
    // ──────────────────────────────────────────────────────────────────────────────

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
    function getPendingStatusGuardians(bytes32 _guardian) external view returns (uint256) {
        return guardiansData.data[_guardian].pending;
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
    function isGuardian(bytes32 _guardian) public view returns (bool) {
        return guardiansData.data[_guardian].isActive;
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
    function getDigestToSign() public view returns (bytes32 digest) {
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

    function getDigestToInit(Key calldata _key, bytes32 _initialGuardian)
        public
        view
        returns (bytes32 digest)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                RECOVER_TYPEHASH,
                _key.pubKey.x,
                _key.pubKey.y,
                _key.eoaAddress,
                _key.keyType,
                _initialGuardian
            )
        );

        digest = _hashTypedDataV4(structHash);
    }
}
