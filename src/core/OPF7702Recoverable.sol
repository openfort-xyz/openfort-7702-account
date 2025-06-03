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
    error OPF7702Recoverable__AddressOrPubKeyCantBeZero();

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
        if (
            _initialGuardian.eoaAddress == address(0)
                && (_initialGuardian.pubKey.x == bytes32(0) && _initialGuardian.pubKey.y == bytes32(0))
        ) revert OPF7702Recoverable__AddressOrPubKeyCantBeZero();

        bytes32 guradianHash;
        if (_initialGuardian.keyType == KeyType.EOA) {
            guradianHash = keccak256(abi.encodePacked(_initialGuardian.eoaAddress));
        } else if (_initialGuardian.keyType == KeyType.WEBAUTHN) {
            guradianHash =
                keccak256(abi.encodePacked(_initialGuardian.pubKey.x, _initialGuardian.pubKey.y));
        }

        guardiansData.guardians.push(guradianHash);
        console.logBytes32(guradianHash);
        guardiansData.data[guradianHash].isActive = true;
        guardiansData.data[guradianHash].index = 0;
        guardiansData.data[guradianHash].pending = 0;
        guardiansData.data[guradianHash].keyType = _initialGuardian.keyType;
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
        console.log("inside", guardiansData.guardians.length);

        return guardians;
    }
}
