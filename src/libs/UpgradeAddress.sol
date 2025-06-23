// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EntryPointLib
 * @notice Helper library that provides mutable storage-backed addresses for
 *         (1) the ERC-4337 EntryPoint singleton and
 *         (2) the WebAuthnVerifier singleton,
 *         while still consuming just *one storage slot each* and requiring
 *         no extra boolean flags.
 *
 *         Each slot encodes:
 *             [1 bit flag | 95 bits unused | 160-bit address]
 *
 *         When the MSB flag is clear, the caller should fall back to a compile-
 *         time constant supplied as argument. When the flag is set, the packed
 *         address is used instead.
 */
library UpgradeAddress {
    error UpgradeAddress__AddressCantBeZero();
    error UpgradeAddress__AddressNotCanonical();

    /* --------------------------------------------------------------------- */
    /*                               SLOT LAYOUT                             */
    /* --------------------------------------------------------------------- */

    //  _EP_SLOT = (keccak256("openfort.entrypoint.storage") - 1) & ~0xff
    bytes32 internal constant _EP_SLOT =
        0x4e696bb2fc09e5383cb7d4063d5fb8f6e0701a72d9523e5f996ae73b7c89e800;

    //  _VERIFIER_SLOT = (keccak256("openfort.webauthnverifier.storage") - 1) & ~0xff
    bytes32 internal constant _VERIFIER_SLOT =
        0xfd39baddba6b1a9197cb18b09396db32f340e9b468af2bcc8f997735c03db200;
    // flage if overriden
    uint256 internal constant _OVERRIDDEN_FLAG = 1 << 255;

    /* --------------------------------------------------------------------- */
    /*                                   EVENTS                              */
    /* --------------------------------------------------------------------- */

    /// @notice Emitted when the EntryPoint contract address is updated
    /// @dev This event is fired when the account's EntryPoint reference is changed,
    ///      which affects how UserOperations are processed and validated. Critical for
    ///      tracking account abstraction infrastructure changes
    /// @param previous The address of the previous EntryPoint contract that was replaced
    /// @param current The address of the new EntryPoint contract that is now active
    event EntryPointUpdated(address indexed previous, address indexed current);

    /// @notice Emitted when the WebAuthn verifier contract address is updated
    /// @dev This event is triggered when the account updates its WebAuthn signature
    ///      verification contract, affecting how WebAuthn and P256 signatures are validated.
    ///      Important for tracking authentication infrastructure changes
    /// @param previous The address of the previous WebAuthn verifier contract that was replaced
    /// @param current The address of the new WebAuthn verifier contract that is now active
    event WebAuthnVerifierUpdated(address indexed previous, address indexed current);

    /* --------------------------------------------------------------------- */
    /*                              PUBLIC HELPERS                           */
    /* --------------------------------------------------------------------- */

    /// @notice Returns the active EntryPoint address, defaulting to `_fallback`.
    function entryPoint(address _fallback) internal view returns (address ep) {
        uint256 packed;
        assembly {
            packed := sload(_EP_SLOT)
        }
        ep = _isOverridden(packed) ? _unpack(packed) : _fallback;
    }

    /// @notice Returns the active WebAuthnVerifier address, defaulting to `_fallback`.
    function webAuthnVerifier(address _fallback) internal view returns (address v) {
        uint256 packed;
        assembly {
            packed := sload(_VERIFIER_SLOT)
        }
        v = _isOverridden(packed) ? _unpack(packed) : _fallback;
    }

    /// @notice Permanently overrides the EntryPoint address.
    /// @dev Re-calling simply replaces the value.
    function setEntryPoint(address newEp) internal {
        require(newEp != address(0), UpgradeAddress__AddressCantBeZero());
        address oldEp;
        uint256 currentPacked;
        assembly {
            currentPacked := sload(_EP_SLOT)
        }
        if (_isOverridden(currentPacked)) {
            oldEp = _unpack(currentPacked);
        }
        uint256 packed = _pack(newEp);
        assembly {
            sstore(_EP_SLOT, packed)
        }
        emit EntryPointUpdated(oldEp, newEp);
    }

    /// @notice Permanently overrides the WebAuthnVerifier address.
    function setWebAuthnVerifier(address newV) internal {
        require(newV != address(0), UpgradeAddress__AddressCantBeZero());
        address oldV;
        uint256 currentPacked;
        assembly {
            currentPacked := sload(_VERIFIER_SLOT)
        }
        if (_isOverridden(currentPacked)) {
            oldV = _unpack(currentPacked);
        }
        uint256 packed = _pack(newV);
        assembly {
            sstore(_VERIFIER_SLOT, packed)
        }
        emit WebAuthnVerifierUpdated(oldV, newV);
    }

    /* --------------------------------------------------------------------- */
    /*                            INTERNAL UTILITIES                         */
    /* --------------------------------------------------------------------- */

    /// @dev Packs an address and sets the MSB flag.
    function _pack(address addr) private pure returns (uint256 packed) {
        uint256 a;
        assembly {
            a := addr
        }
        if (a >> 160 != 0) {
            revert UpgradeAddress__AddressNotCanonical();
        }
        packed = (a | _OVERRIDDEN_FLAG);
    }

    /// @dev Extracts the address from a packed word.
    function _unpack(uint256 packed) private pure returns (address) {
        return address(uint160(packed & ~_OVERRIDDEN_FLAG));
    }

    /// @dev True if the MSB flag is set.
    function _isOverridden(uint256 packed) private pure returns (bool) {
        return packed & _OVERRIDDEN_FLAG != 0;
    }
}
