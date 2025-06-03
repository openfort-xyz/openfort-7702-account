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
    error OPF7702Recoverable__AccountLocked();
    error OPF7702Recoverable__DuplicatedProposal();
    error OPF7702Recoverable__DuplicatedGuardian();
    error OPF7702Recoverable__AddressOrPubKeyCantBeZero();
    error OPF7702Recoverable__GuardianCannotBeAddressThis();
    error OPF7702Recoverable__GuardianCanBeOnlyEOAOrWebAuthn();
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

    GuardiansData internal guardiansData;
    RecoveryData public recoveryData;

    uint256 internal recoveryPeriod;
    uint256 internal lockPeriod;
    uint256 internal securityPeriod;
    uint256 internal securityWindow;

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
}
