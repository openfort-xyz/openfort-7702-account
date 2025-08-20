// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

interface IWebAuthnVerifier {
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

    function verifyEncodedSignature(
        bytes memory challenge,
        bool requireUserVerification,
        bytes memory encodedAuth,
        bytes32 x,
        bytes32 y
    ) external view returns (bool isValid);

    function verifyCompactSignature(
        bytes memory challenge,
        bool requireUserVerification,
        bytes memory encodedAuth,
        bytes32 x,
        bytes32 y
    ) external view returns (bool isValid);

    function verifyP256Signature(bytes32 hash, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        external
        view
        returns (bool isValid);
}
