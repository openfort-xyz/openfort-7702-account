// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IKeysManager} from "src/interfaces/IKeysManager.sol";

// Keep in sync with your project’s PubKey definition.
struct PubKey { bytes32 x; bytes32 y; }

library SigLengthLib {
    /// @notice Verifies the outer `(KeyType.WEBAUTHN, bytes inner)` size matches the
    ///         canonical ABI encoding of the decoded WebAuthn fields.
    /// @dev    No assembly, no padding math: decode -> re-encode -> compare.
    /// @param  outerLen  userOp.signature.length
    /// @param  inner     the `bytes` payload you got from `(KeyType, bytes)` decoding
    function assertOuterMatchesDecoded(uint256 outerLen, bytes memory inner) internal pure {
        (
            bool requireUV,
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeIndex,
            uint256 typeIndex,
            bytes32 r,
            bytes32 s,
            PubKey memory pubKey
        ) = abi.decode(
            inner, (bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey)
        );

        // Canonical inner per your encoder:
        // abi.encode(requireUV, authenticatorData, clientDataJSON, challengeIndex, typeIndex, r, s, pubKey)
        bytes memory reencodedInner = abi.encode(
            requireUV,
            authenticatorData,
            clientDataJSON,
            challengeIndex,
            typeIndex,
            r,
            s,
            pubKey
        );

        // Outer is abi.encode(KeyType.WEBAUTHN, inner)
        // = 64 (two head words) + 32 (bytes length) + padded inner.
        // reencodedInner.length is already canonical/padded, so:
        uint256 expectedOuterLen = 96 + reencodedInner.length;

        if (outerLen != expectedOuterLen) {
            revert IKeysManager.KeyManager__InvalidSignatureLength();
        }
    }
}