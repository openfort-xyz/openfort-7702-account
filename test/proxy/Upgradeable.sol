// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EIP712Upgradeable} from "lib/openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";
import {ReentrancyGuardUpgradeable} from "lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";

contract Upgradable is EIP712Upgradeable, ReentrancyGuardUpgradeable, IKey {
    using ECDSA for bytes32;

    bytes32 private constant RECOVER_TYPEHASH =
        0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;

    uint256 public id;

    function initialize(
        Key calldata _key,
        bytes memory _signature,
        bytes32 _initialGuardian
    ) external initializer nonReentrant {
        __EIP712_init("OPF7702Recoverable", "1");
        __ReentrancyGuard_init();

        bytes32 digest = getDigestToInit(_key, _initialGuardian);

        if (!_checkSignature(digest, _signature)) {
            revert("Invalid Signature");
        }

        unchecked {
            ++id;
        }
    }

    function _checkSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return ECDSA.recover(hash, signature) == address(this);
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