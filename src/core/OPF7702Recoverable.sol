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
    error  OPF7702Recoverable__AddressOrPubKeyCantBeZero();
    struct GuardianIdentity {
        bool isActive;
        uint256 index;
        uint256 pending;
        KeyType keyType;
    }

    struct GuardiansData {
        bytes32[] guradians;
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
        uint256 _securityWindow,
        Key memory _initialGuardian
    ) OPF7702(_entryPoint) EIP712("OPF7702Recoverable", "1") {
        recoveryPeriod = _recoveryPeriod;
        lockPeriod = _lockPeriod;
        securityWindow = _securityWindow;
        securityPeriod = _securityPeriod;

        if (
            _initialGuardian.eoaAddress == address(0) && (_initialGuardian.pubKey.x == bytes32(0)
                && _initialGuardian.pubKey.y == bytes32(0))
        ) revert OPF7702Recoverable__AddressOrPubKeyCantBeZero();

        bytes32 guradianHash;
        if (_initialGuardian.keyType == KeyType.EOA){
            guradianHash = keccak256(abi.encodePacked(_initialGuardian.eoaAddress));
        } else if (_initialGuardian.keyType == KeyType.WEBAUTHN) {
            guradianHash = keccak256(abi.encodePacked(_initialGuardian.pubKey.x, _initialGuardian.pubKey.y));
        }

        guardiansData.guradians.push(guradianHash);
        guardiansData.data[guradianHash].isActive = true;
        guardiansData.data[guradianHash].index = 0;
        guardiansData.data[guradianHash].pending = 0;
        guardiansData.data[guradianHash].keyType = _initialGuardian.keyType;
    }
}
