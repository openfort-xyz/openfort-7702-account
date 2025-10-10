// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @title IWebAuthnVerifier
/// @notice Interface for contracts that validate WebAuthn / P-256 signatures.
interface IWebAuthnVerifier {
    /**
     * @notice Verify a WebAuthn signature by supplying the unpacked auth payload.
     * @param challenge Challenge that was signed.
     * @param requireUserVerification Whether UV must be enforced.
     * @param authenticatorData Authenticator data blob.
     * @param clientDataJSON Client data JSON string.
     * @param challengeIndex Offset of `challenge` within `clientDataJSON`.
     * @param typeIndex Offset of the WebAuthn `type` string.
     * @param r Signature `r` component.
     * @param s Signature `s` component.
     * @param x Public key X coordinate.
     * @param y Public key Y coordinate.
     * @return isValid True if signature passes verification.
     */
    function verifySignature(
        bytes32 challenge,
        bool requireUserVerification,
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint256 challengeIndex,
        uint256 typeIndex,
        bytes32 r,
        bytes32 s,
        bytes32 x,
        bytes32 y
    ) external view returns (bool isValid);

    /**
     * @notice Verify a WebAuthn signature where the auth payload is pre-encoded.
     * @param challenge Challenge bytes (already encoded).
     * @param requireUserVerification Whether UV must be enforced.
     * @param encodedAuth Packed WebAuthn auth payload.
     * @param x Public key X coordinate.
     * @param y Public key Y coordinate.
     * @return isValid True if signature passes verification.
     */
    function verifyEncodedSignature(
        bytes memory challenge,
        bool requireUserVerification,
        bytes memory encodedAuth,
        bytes32 x,
        bytes32 y
    ) external view returns (bool isValid);

    /**
     * @notice Verify a WebAuthn signature where the auth payload is compact encoded.
     * @param challenge Challenge bytes (already encoded).
     * @param requireUserVerification Whether UV must be enforced.
     * @param encodedAuth Compact WebAuthn auth payload.
     * @param x Public key X coordinate.
     * @param y Public key Y coordinate.
     * @return isValid True if signature passes verification.
     */
    function verifyCompactSignature(
        bytes memory challenge,
        bool requireUserVerification,
        bytes memory encodedAuth,
        bytes32 x,
        bytes32 y
    ) external view returns (bool isValid);

    /**
     * @notice Verify a raw P-256 signature (outside WebAuthn flows).
     * @param hash Message hash being validated.
     * @param r Signature `r` component.
     * @param s Signature `s` component.
     * @param x Public key X coordinate.
     * @param y Public key Y coordinate.
     * @return isValid True if signature passes verification.
     */
    function verifyP256Signature(bytes32 hash, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        external
        view
        returns (bool isValid);
}
