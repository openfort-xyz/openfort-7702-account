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
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";

/**
 * @title   Openfort Base Account 7702 with ERC-4337 Support
 * @author  Openfort — https://openfort.xyz
 * @notice  Smart contract wallet implementing EIP-7702 + ERC-4337 + multi-format session keys.
 * @dev
 *  • EIP-4337 integration via EntryPoint
 *  • EIP-7702 support (e.g., setCode)
 *  • Multi-scheme session keys: EOA (ECDSA), WebAuthn, P256/P256NONKEY
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

    error OPF7702Recoverable__AccountLocked();
    error OPF7702Recoverable__UnknownRevoke();
    error OPF7702Recoverable__MustBeGuardian();
    error OPF7702Recoverable__UnknownProposal();
    error OPF7702Recoverable__OngoingRecovery();
    error OPF7702Recoverable__DuplicatedRevoke();
    error OPF7702Recoverable__NoOngoingRecovery();
    error OPF7702Recoverable__DuplicatedProposal();
    error OPF7702Recoverable__DuplicatedGuardian();
    error OPF7702Recoverable__PendingRevokeNotOver();
    error OPF7702Recoverable__PendingRevokeExpired();
    error OPF7702Recoverable__GuardianCannotBeOwner();
    error OPF7702Recoverable__NoGuardiansSetOnWallet();
    error OPF7702Recoverable__PendingProposalExpired();
    error OPF7702Recoverable__InvalidSignatureAmount();
    error OPF7702Recoverable__PendingProposalNotOver();
    error OPF7702Recoverable__InvalidRecoverySignatures();
    error OPF7702Recoverable__AddressOrPubKeyCantBeZero();
    error OPF7702Recoverable__GuardianCannotBeAddressThis();
    error OPF7702Recoverable__GuardianCannotBeCurrentMasterKey();
    error OPF7702Recoverable__NewGuardianCanBeOnlyEOAOrWebAuthn();

    struct GuardianIdentity {
        bool isActive;
        uint256 index;
        uint256 pending;
        KeyType keyType;
    }

    struct GuardiansData {
        bytes32[] guardians;
        mapping(bytes32 hashKey => GuardianIdentity guardianIdentity) data;
        uint256 lock;
    }

    struct RecoveryData {
        Key key;
        uint64 executeAfter;
        uint32 guardiansRequired;
    }

    bytes32 private constant RECOVER_TYPEHASH =
        0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;

    uint256 internal immutable recoveryPeriod;
    uint256 internal immutable lockPeriod;
    uint256 internal immutable securityPeriod;
    uint256 internal immutable securityWindow;

    GuardiansData internal guardiansData;
    RecoveryData public recoveryData;

    constructor(
        address _entryPoint,
        uint256 _recoveryPeriod,
        uint256 _lockPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow
    ) OPF7702(_entryPoint) EIP712("OPF7702Recoverable", "1") {
        recoveryPeriod = _recoveryPeriod;
        lockPeriod = _lockPeriod;
        securityWindow = _securityWindow;
        securityPeriod = _securityPeriod;
    }

    /**
     * @notice Initializes the account with a “master” session key (no spending or whitelist restrictions).
     * @dev
     *  • Callable only via EntryPoint or a self-call.
     *  • Clears previous storage, checks nonce & expiration, verifies signature.
     *  • Registers the provided `_key` as a master session key:
     *     - validUntil = max (never expires)
     *     - validAfter  = 0
     *     - limit       = 0  (master)
     *     - whitelisting = false
     *     - DEAD_ADDRESS placeholder in whitelistedContracts
     *  • Emits `Initialized(_key)`.
     *
     * @param _key              The Key struct (master session key).
     * @param _spendTokenInfo   Token limit info (ignored for master).
     * @param _allowedSelectors Unused selectors (ignored for master).
     * @param _hash             Hash to sign (EIP-712 or UserOp hash).
     * @param _signature        Signature over `_hash` by this contract.
     * @param _validUntil       Expiration timestamp for this initialization.
     * @param _nonce            Nonce to prevent replay.
     */
    function initialize(
        Key calldata _key,
        SpendTokenInfo calldata _spendTokenInfo,
        bytes4[] calldata _allowedSelectors,
        bytes32 _hash,
        bytes memory _signature,
        uint256 _validUntil,
        uint256 _nonce,
        Key memory _initialGuardian
    ) external initializer {
        _requireForExecute();
        _clearStorage();
        _validateNonce(_nonce);
        _notExpired(_validUntil);

        if (!_checkSignature(_hash, _signature)) {
            revert OpenfortBaseAccount7702V1__InvalidSignature();
        }

        // record new nonce
        nonce = _nonce;

        // register masterKey: never expires, no spending/whitelist restrictions
        registerSessionKey(
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

        initializeGuardians(_initialGuardian);

        emit Initialized(_key);
    }

    function initializeGuardians(Key memory _initialGuardian) private {
        _requireNonEmptyGuardian(_initialGuardian);
        bytes32 gHash = _guardianHash(_initialGuardian);

        guardiansData.guardians.push(gHash);
        GuardianIdentity storage gi = guardiansData.data[gHash];
        gi.isActive = true;
        gi.index = 0;
        gi.pending = 0;
        gi.keyType = _initialGuardian.keyType;
    }

    function _guardianHash(Key memory _guardian) internal pure returns (bytes32) {
        if (_guardian.keyType == KeyType.EOA) {
            return keccak256(abi.encodePacked(_guardian.eoaAddress));
        } else if (_guardian.keyType == KeyType.WEBAUTHN) {
            return keccak256(abi.encodePacked(_guardian.pubKey.x, _guardian.pubKey.y));
        }
        revert OPF7702Recoverable__NewGuardianCanBeOnlyEOAOrWebAuthn();
    }

    function _requireNonEmptyGuardian(Key memory _guardian) internal pure {
        bool hasAddress = _guardian.eoaAddress != address(0);
        bool hasPubKey = _guardian.pubKey.x != bytes32(0) || _guardian.pubKey.y != bytes32(0);
        if (!hasAddress && !hasPubKey) revert OPF7702Recoverable__AddressOrPubKeyCantBeZero();
    }

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

    function getPendingStatusGuardians(Key memory _guardian) external view returns (uint256) {
        bytes32 gHash = _guardianHash(_guardian);
        return guardiansData.data[gHash].pending;
    }

    function isLocked() public view virtual returns (bool) {
        return guardiansData.lock > block.timestamp;
    }

    function isGuardian(Key memory _guardian) public view returns (bool) {
        bytes32 guradianHash;
        if (_guardian.keyType == KeyType.EOA) {
            guradianHash = keccak256(abi.encodePacked(_guardian.eoaAddress));
        } else if (_guardian.keyType == KeyType.WEBAUTHN) {
            guradianHash = keccak256(abi.encodePacked(_guardian.pubKey.x, _guardian.pubKey.y));
        }
        return guardiansData.data[guradianHash].isActive;
    }

    function guardianCount() public view virtual returns (uint256) {
        return guardiansData.guardians.length;
    }

    function _requireRecovery(bool _isRecovery) internal view {
        if (_isRecovery && recoveryData.executeAfter == 0) {
            revert OPF7702Recoverable__NoOngoingRecovery();
        }
        if (!_isRecovery && recoveryData.executeAfter > 0) {
            revert OPF7702Recoverable__OngoingRecovery();
        }
    }

    function _setLock(uint256 _releaseAfter) internal {
        guardiansData.lock = _releaseAfter;
    }

    function proposeGuardian(Key memory _guardian) external {
        _requireForExecute();
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        _requireNonEmptyGuardian(_guardian);
        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        // 1. Self‑guardian check
        if (address(this) == _guardian.eoaAddress) {
            revert OPF7702Recoverable__GuardianCannotBeAddressThis();
        }

        // 2. Not current master key
        Key memory mk = getKeyById(0, KeyType.P256);
        if (_guardian.pubKey.x == mk.pubKey.x && _guardian.pubKey.y == mk.pubKey.y) {
            revert OPF7702Recoverable__GuardianCannotBeCurrentMasterKey();
        }

        // 3. Only EOA/WebAuthn
        if (_guardian.keyType != KeyType.EOA && _guardian.keyType != KeyType.WEBAUTHN) {
            revert OPF7702Recoverable__NewGuardianCanBeOnlyEOAOrWebAuthn();
        }

        // 4. Already active?
        if (gi.isActive) revert OPF7702Recoverable__DuplicatedGuardian();

        // 5. Already pending?
        if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
            revert OPF7702Recoverable__DuplicatedProposal();
        }

        gi.pending = block.timestamp + securityPeriod;
    }

    function confirmGuardianProposal(Key memory _guardian) external {
        _requireForExecute();
        _requireRecovery(false);
        _requireNonEmptyGuardian(_guardian);
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        if (gi.pending == 0) revert OPF7702Recoverable__UnknownProposal();
        if (block.timestamp < gi.pending) revert OPF7702Recoverable__PendingProposalNotOver();
        if (block.timestamp > gi.pending + securityWindow) {
            revert OPF7702Recoverable__PendingProposalExpired();
        }

        if (gi.isActive) revert OPF7702Recoverable__DuplicatedGuardian();

        gi.isActive = true;
        gi.pending = 0;
        gi.index = guardiansData.guardians.length;
        guardiansData.guardians.push(gHash);
    }

    function cancelGuardianProposal(Key memory _guardian) external {
        _requireForExecute();
        _requireRecovery(false);
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        _requireNonEmptyGuardian(_guardian);
        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        if (gi.pending == 0) revert OPF7702Recoverable__UnknownProposal();
        if (gi.isActive) revert OPF7702Recoverable__DuplicatedGuardian();

        gi.pending = 0;
    }

    function revokeGuardian(Key memory _guardian) external {
        _requireForExecute();
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        if (!gi.isActive) revert OPF7702Recoverable__MustBeGuardian();

        if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
            revert OPF7702Recoverable__DuplicatedRevoke();
        }

        gi.pending = block.timestamp + securityPeriod;
    }

    function confirmGuardianRevocation(Key memory _guardian) external {
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
        guardiansData.guardians.pop();

        delete guardiansData.data[gHash];
    }

    function cancelGuardianRevocation(Key memory _guardian) external {
        _requireForExecute();
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        bytes32 gHash = _guardianHash(_guardian);
        GuardianIdentity storage gi = guardiansData.data[gHash];

        if (!gi.isActive) revert OPF7702Recoverable__MustBeGuardian();
        if (gi.pending == 0) revert OPF7702Recoverable__UnknownRevoke();

        guardiansData.data[gHash].pending = 0;
    }

    function startRecovery(Key memory _recoveryKey, Key memory _guardian) external virtual {
        // Todo: Must _requireForExecute(); ?? or  _requireForExecuteOrGuardian();
        // Many Options to run startRecovery() :
        // ---------------->    EOA Guardian                      ----> Yes ----> Epoint/Relay  ----> msg.sender  ----> _requireForExecute();
        //                                      ----> If Sponsored
        // ----------------> WebAuthn Guardian                    ----> No  ----> Direct Engn.  ----> ?msg.sender? : A. msg.sender == EOA Guardian || B. WebAuthn Guardian???
        _requireRecovery(false);
        if (isLocked()) revert OPF7702Recoverable__AccountLocked();

        if (!isGuardian(_guardian)) revert OPF7702Recoverable__MustBeGuardian();

        _requireNonEmptyGuardian(_recoveryKey);
        if (isGuardian(_recoveryKey)) revert OPF7702Recoverable__GuardianCannotBeOwner();

        uint64 executeAfter = SafeCast.toUint64(block.timestamp + recoveryPeriod);
        uint32 quorum = SafeCast.toUint32(Math.ceilDiv(guardianCount(), 2));

        recoveryData =
            RecoveryData({key: _recoveryKey, executeAfter: executeAfter, guardiansRequired: quorum});

        _setLock(block.timestamp + lockPeriod);
    }

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

        Key memory recoveryOwner = recoveryData.key;
        delete recoveryData;

        // Todo: Change the Admin key of index 0 in the sessionKeys or sessionKeysEOA for new Master Key
        // _transferOwnership(recoveryOwner);

        // Todo: Need to Identify Master Key by Id or Any othewr flag
        // MK WebAuthn will be always id = 0 because of Initalization func enforce to be `0`
        SessionKey storage mk;
        Key memory kWebAuthn = idSessionKeys[0];
        Key memory kEOA = idSessionKeysEOA[0];

        if (kWebAuthn.keyType == KeyType.WEBAUTHN) {
            mk = sessionKeys[keccak256(abi.encodePacked(kWebAuthn.pubKey.x, kWebAuthn.pubKey.y))];
        } else if (kEOA.keyType == KeyType.EOA) {
            mk = sessionKeysEOA[kEOA.eoaAddress];
        }
        _setLock(0);
    }

    function _validateSignatures(bytes[] calldata _signatures) internal returns (bool) {
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
                (KeyType sigType, bytes memory sigData) =
                    abi.decode(_signatures[i], (KeyType, bytes));

                bytes32 guardianHash;

                if (sigType == KeyType.EOA) {
                    address signer = digest.recover(sigData);
                    guardianHash = keccak256(abi.encodePacked(signer));
                } else if (sigType == KeyType.WEBAUTHN) {
                    (
                        bytes32 challenge,
                        bool requireUV,
                        bytes memory authenticatorData,
                        string memory clientDataJSON,
                        uint256 challengeIndex,
                        uint256 typeIndex,
                        bytes32 r,
                        bytes32 s,
                        PubKey memory pubKey
                    ) = abi.decode(
                        sigData,
                        (bytes32, bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey)
                    );

                    if (
                        !verifySoladySignature(
                            challenge,
                            requireUV,
                            authenticatorData,
                            clientDataJSON,
                            challengeIndex,
                            typeIndex,
                            r,
                            s,
                            pubKey.x,
                            pubKey.y
                        )
                    ) return false;

                    if (usedChallenges[challenge]) {
                        return false;
                    }

                    usedChallenges[challenge] = true;

                    guardianHash = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
                } else {
                    return false;
                }

                if (!guardiansData.data[guardianHash].isActive) return false;

                if (guardianHash <= lastGuardianHash) return false;
                lastGuardianHash = guardianHash;
            }
        }

        return true;
    }

    /**
     * @notice Encodes WebAuthn signature data for use in transaction submission
     * @param challenge Challenge that was signed
     * @param requireUserVerification Whether user verification is required
     * @param authenticatorData Authenticator data from WebAuthn
     * @param clientDataJSON Client data JSON from WebAuthn
     * @param challengeIndex Index of challenge in client data
     * @param typeIndex Index of type in client data
     * @param r R component of the signature
     * @param s S component of the signature
     * @param pubKey Public key used for signing
     * @return Encoded signature data
     */
    function encodeWebAuthnSignatureGuardian(
        bytes32 challenge,
        bool requireUserVerification,
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint256 challengeIndex,
        uint256 typeIndex,
        bytes32 r,
        bytes32 s,
        PubKey memory pubKey
    ) external pure returns (bytes memory) {
        bytes memory payload = abi.encode(
            challenge,
            requireUserVerification,
            authenticatorData,
            clientDataJSON,
            challengeIndex,
            typeIndex,
            r,
            s,
            pubKey
        );

        return abi.encode(KeyType.WEBAUTHN, payload);
    }

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
