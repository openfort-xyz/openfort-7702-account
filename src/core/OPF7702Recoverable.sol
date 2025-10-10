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

import {IKey} from "src/interfaces/IKey.sol";
import {OPF7702} from "src/core/OPF7702.sol";
import {ERC7201} from "src/utils/ERC7201.sol";
import {IOPF7702} from "src/interfaces/IOPF7702.sol";
import {KeysManagerLib} from "src/libs/KeysManagerLib.sol";
import {IBaseOPF7702} from "src/interfaces/IBaseOPF7702.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {IOPF7702Recoverable} from "src/interfaces/IOPF7702Recoverable.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

interface ISocialRecoveryManager {
    function initializeGuardians(address _account, bytes32 _initialGuardian) external;
    function completeRecovery(address _account, bytes[] calldata _signatures)
        external
        returns (IKey.KeyDataReg memory recoveryOwner);
}

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
contract OPF7702Recoverable is OPF7702, EIP712, ERC7201 {
    using ECDSA for bytes32;
    using KeysManagerLib for *;

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Constants
    // ──────────────────────────────────────────────────────────────────────────────
    /// @dev EIP‑712 type hash for the Initialize struct.
    bytes32 private constant INIT_TYPEHASH =
        0x82dc6262fca76342c646d126714aa4005dfcd866448478747905b2e7b9837183;

    // ──────────────────────────────────────────────────────────────────────────────
    //                              Constructor
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @param _entryPoint       ERC-4337 EntryPoint address.
     * @param _webAuthnVerifier WebAuthn verifier contract for P-256/WebAuthn signature checks.
     * @param _gasPolicy        Gas/UserOp policy contract (used for custodial key policy init).
     * @param _recoveryManager  Social Recovery Manager contract that manages guardians & recovery flow.
     */
    constructor(
        address _entryPoint,
        address _webAuthnVerifier,
        address _gasPolicy,
        address _recoveryManager
    ) OPF7702(_entryPoint, _webAuthnVerifier, _gasPolicy) EIP712("OPF7702Recoverable", "1") {
        RECOVERY_MANAGER = _recoveryManager;
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
     *     - address(0) placeholder in whitelistedContracts
     *  • Emits `Initialized(_key)`.
     *
     * @param _keyData          KeyReg data structure containing permissions and limits
     * @param _sessionKeyData   KeyReg data structure containing permissions and limits
     * @param _signature        Signature over `_hash` by this contract.
     * @param _initialGuardian  Initialize Guardian. Must be at least one guardian!
     */
    function initialize(
        KeyDataReg calldata _keyData,
        KeyDataReg calldata _sessionKeyData,
        bytes memory _signature,
        bytes32 _initialGuardian
    ) external initializer {
        _requireForExecute();
        _clearStorage();

        _masterKeyValidation(_keyData);

        bytes32 digest = getDigestToInit(_keyData, _sessionKeyData, _initialGuardian);

        if (!_checkSignature(digest, _signature)) {
            revert IBaseOPF7702.OpenfortBaseAccount7702V1__InvalidSignature();
        }

        // register masterKey: never expires, no spending/whitelist restrictions
        _addKey(_keyData);

        if (_sessionKeyData.key.checkKey()) {
            registerKey(_sessionKeyData);
        }

        ISocialRecoveryManager(RECOVERY_MANAGER).initializeGuardians(
            address(this), _initialGuardian
        );

        emit IOPF7702.Initialized(_keyData);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                     Guardian add / revoke public interface
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @notice Completes recovery after the timelock by providing the required guardian signatures.
     * @param _signatures Encoded guardian signatures approving the recovery.
     */
    function completeRecovery(bytes[] calldata _signatures) external virtual {
        KeyDataReg memory recoveryOwner =
            ISocialRecoveryManager(RECOVERY_MANAGER).completeRecovery(address(this), _signatures);

        _deleteOldKeys();
        _setNewMasterKey(recoveryOwner);
    }

    /// @dev Deletes the old master key data structures (both WebAuthn and EOA variants).
    function _deleteOldKeys() private {
        // MK WebAuthn will be always id = 0 because of Initalization func enforce to be `0`
        (bytes32 keyId,) = keyAt(0);

        /// @dev Only the nested mapping in stract will not be cleared mapping(address => bool) whitelist
        /// @notice not providing security risk
        delete keys[keyId];
        delete idKeys[0];
    }

    /// @dev Registers the new master key after successful recovery.
    /// @param recoveryOwner Key that becomes the new master key.
    function _setNewMasterKey(KeyDataReg memory recoveryOwner) private {
        _masterKeyValidation(recoveryOwner);
        emit IOPF7702Recoverable.RecoveryCompleted();

        bytes32 keyId = recoveryOwner.computeKeyId();

        emit KeyRegistered(
            keyId, recoveryOwner.keyControl, recoveryOwner.keyType, true, 0, type(uint48).max, 0
        );

        KeyData storage sKey = keys[keyId];
        if (sKey.isActive) revert KeyManager__KeyRegistered();

        // master-key enforce id=0
        idKeys[0] = keyId;
        _addMasterKey(sKey, recoveryOwner);
    }

    /// @dev writes master-key fields into storage.
    function _addMasterKey(KeyData storage _sKey, KeyDataReg memory _recoveryOwner) private {
        _sKey.keyType = _recoveryOwner.keyType;
        _sKey.key = _recoveryOwner.key;
        _sKey.validUntil = type(uint48).max;
        _sKey.validAfter = 0;
        _sKey.limits = 0;
        _sKey.masterKey = true;
        _sKey.isActive = true;
        _sKey.isDelegatedControl = false;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                           Utility view functions
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * @notice EIP-712 digest for `initialize(...)`.
     * @dev Computes:
     *      structHash = keccak256(abi.encode(
     *          INIT_TYPEHASH,
     *          abi.encode(_key.pubKey.x, _key.pubKey.y, _key.eoaAddress, _key.keyType),
     *          abi.encode(
     *              _keyData.validUntil, _keyData.validAfter, _keyData.limit,
     *              _keyData.whitelisting, _keyData.contractAddress,
     *              _keyData.spendTokenInfo.token, _keyData.spendTokenInfo.limit,
     *              _keyData.allowedSelectors, _keyData.ethLimit
     *          ),
     *          abi.encode(_sessionKey.pubKey.x, _sessionKey.pubKey.y, _sessionKey.eoaAddress, _sessionKey.keyType),
     *          abi.encode(
     *              _sessionKeyData.validUntil, _sessionKeyData.validAfter, _sessionKeyData.limit,
     *              _sessionKeyData.whitelisting, _sessionKeyData.contractAddress,
     *              _sessionKeyData.spendTokenInfo.token, _sessionKeyData.spendTokenInfo.limit,
     *              _sessionKeyData.allowedSelectors
     *          ),
     *          _initialGuardian
     *      ));
     *
     * NOTE: We intentionally pass dynamic `bytes` (the inner `abi.encode(...)`) into the
     *       outer `abi.encode(...)` to preserve the existing signing schema. Do not
     *       change encoding/order without migrating off-chain signers.
     *
     * @param _keyData          Master key registration payload.
     * @param _sessionKeyData   Session key registration payload.
     * @param _initialGuardian  Guardian identifier used to seed the recovery set.
     * @return digest           EIP-712 typed data hash to be signed off-chain.
     */
    function getDigestToInit(
        KeyDataReg calldata _keyData,
        KeyDataReg calldata _sessionKeyData,
        bytes32 _initialGuardian
    ) public view returns (bytes32 digest) {
        bytes memory keyDataEnc = abi.encode(
            _keyData.keyType,
            _keyData.validUntil,
            _keyData.validAfter,
            _keyData.limits,
            _keyData.key,
            _keyData.keyControl
        );

        // NOTE: Matches your current schema (no `ethLimit` for sessionKeyData here).
        bytes memory skDataEnc = abi.encode(
            _sessionKeyData.keyType,
            _sessionKeyData.validUntil,
            _sessionKeyData.validAfter,
            _sessionKeyData.limits,
            _sessionKeyData.key,
            _sessionKeyData.keyControl
        );

        bytes32 structHash =
            keccak256(abi.encode(INIT_TYPEHASH, keyDataEnc, skDataEnc, _initialGuardian));

        return _hashTypedDataV4(structHash);
    }
}
