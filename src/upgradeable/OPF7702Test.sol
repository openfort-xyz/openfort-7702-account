// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {LibEIP7702} from "lib/solady/src/accounts/LibEIP7702.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {Initializable} from "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";

/**
 * @title   Openfort Base Account 7702 with ERC-4337 Support
 * @author  Openfort@0xkoiner
 * @notice  Smart contract wallet implementing EIP-7702 + ERC-4337 with guardian-based recovery and multi-format keys.
 */
contract OPF7702Test is Initializable, IKey, EIP712 {
    using ECDSA for bytes32;

    error OpenfortBaseAccount7702V1__InvalidSignature();

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Constants
    // ──────────────────────────────────────────────────────────────────────────────

    /// @dev EIP‑712 type hash for the Recovery struct.
    bytes32 private constant RECOVER_TYPEHASH =
        0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;

    /// @notice The EntryPoint singleton contract used to dispatch user operations.
    address public immutable ENTRY_POINT;

    /// @notice The WebAuthn Verifier singleton contract used to verify WebAuthn and P256 signatures.
    address public immutable WEBAUTHN_VERIFIER;

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Storage vars (standard layout)
    // ──────────────────────────────────────────────────────────────────────────────
    uint256 public id;
    bytes32 public keyHash;
    bytes32 public initialGuardian;

    // ──────────────────────────────────────────────────────────────────────────────
    //                              Constructor
    // ──────────────────────────────────────────────────────────────────────────────

    constructor(address _ep, address _waV) EIP712("OPF7702Recoverable", "1") {
        ENTRY_POINT = _ep;
        WEBAUTHN_VERIFIER = _waV;
    }

    /// @notice Fallback function to receive ETH without data.
    fallback() external payable {}

    /// @notice Receive function to handle plain ETH transfers.
    receive() external payable {}

    // ──────────────────────────────────────────────────────────────────────────────
    //                          Debug Functions
    // ──────────────────────────────────────────────────────────────────────────────

    /// @notice Check storage at specific slot (for debugging)
    function getStorageAt(uint256 slot) external view returns (bytes32) {
        bytes32 value;
        assembly {
            value := sload(slot)
        }
        return value;
    }

    /// @notice Get the delegation address for this EOA
    function delegationOf(address account) external view returns (address) {
        return LibEIP7702.delegationOf(account);
    }

    /// @notice Get both delegation and implementation for this EOA
    function delegationAndImplementationOf(address account)
        external
        view
        returns (address delegation, address impl)
    {
        return LibEIP7702.delegationAndImplementationOf(account);
    }

    /// @notice Get the implementation address
    function implementationOf(address target) external view returns (address) {
        return LibEIP7702.implementationOf(target);
    }

    /// @notice Check if target is a valid EIP7702Proxy
    function isEIP7702Proxy(address target) external view returns (bool) {
        return LibEIP7702.isEIP7702Proxy(target);
    }

    /// @notice Standard proxy implementation getter
    function implementation() external view returns (address) {
        // Read from ERC1967 implementation slot
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        address impl;
        assembly {
            impl := sload(slot)
        }
        return impl;
    }

    /// @notice Get the current address (useful for debugging context)
    function getCurrentAddress() external view returns (address) {
        return address(this);
    }

    /// @notice Get msg.sender for debugging
    function getMsgSender() external view returns (address) {
        return msg.sender;
    }

    function getId() external view returns (uint256) {
        return id;
    }
    // ──────────────────────────────────────────────────────────────────────────────
    //                          Public / External methods
    // ──────────────────────────────────────────────────────────────────────────────

    function initialize(Key calldata _key, bytes32 _initialGuardian) external initializer {
        // bytes32 digest = getDigestToInit(_key, _initialGuardian);

        // if (!_checkSignature(digest, _signature)) {
        //     revert OpenfortBaseAccount7702V1__InvalidSignature();
        // }

        unchecked {
            ++id;
        }

        keyHash = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
        initialGuardian = _initialGuardian;

        // Request proxy delegation initialization to ensure storage is set
        // LibEIP7702.requestProxyDelegationInitialization();
    }

    /// @notice Debug version of initialize without modifier and signature check
    function initializeDebug(Key calldata _key, bytes32 _initialGuardian) external {
        unchecked {
            ++id;
        }

        keyHash = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
        initialGuardian = _initialGuardian;

        // Request proxy delegation initialization to ensure storage is set
        LibEIP7702.requestProxyDelegationInitialization();
    }

    /// @notice Check what address the signature verification expects
    function getExpectedSigner(Key calldata _key, bytes32 _initialGuardian, bytes memory _signature)
        external
        view
        returns (address expectedSigner, address currentThis, bytes32 digest)
    {
        digest = getDigestToInit(_key, _initialGuardian);
        expectedSigner = ECDSA.recover(digest, _signature);
        currentThis = address(this);
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

    function _checkSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return ECDSA.recover(hash, signature) == address(this);
    }

    function upgradeProxyDelegation(address newImplementation) public virtual {
        require(msg.sender == address(this), "not owner");
        LibEIP7702.upgradeProxyDelegation(newImplementation);
    }
}
