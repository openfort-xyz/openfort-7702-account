// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {P256} from "src/libs/P256.sol";
import {WebAuthn} from "lib/webauthn-sol/src/WebAuthn.sol";

/**
 * @title WebAuthnVerifier
 * @author openfort@0xkoiner
 * @notice A simple contract to verify WebAuthn signatures
 * @dev Uses Solady's WebAuthn and P256 libraries for verification
 */
contract WebAuthnVerifierV2 {
    /**
     * @notice Verifies a WebAuthn signature using the Solady library
     * @param challenge The challenge that was signed
     * @param requireUserVerification Whether to require user verification
     * @param authenticatorData The authenticator data from the WebAuthn response
     * @param clientDataJSON The client data JSON from the WebAuthn response
     * @param challengeIndex Index of the challenge in the client data JSON
     * @param typeIndex Index of the type in the client data JSON
     * @param r The r-component of the signature
     * @param s The s-component of the signature
     * @param x The x-coordinate of the public key
     * @param y The y-coordinate of the public key
     * @return isValid Whether the signature is valid
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
    ) external view returns (bool isValid) {
        uint256 rUint = uint256(r);
        uint256 sUint = uint256(s);
        uint256 xUint = uint256(x);
        uint256 yUint = uint256(y);

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            authenticatorData: authenticatorData,
            clientDataJSON: clientDataJSON,
            challengeIndex: challengeIndex,
            typeIndex: typeIndex,
            r: rUint,
            s: sUint
        });

        bytes memory challengeBytes = toBytes(challenge);
        isValid = WebAuthn.verify(challengeBytes, requireUserVerification, auth, xUint, yUint);

        return isValid;
    }

    /**
     * @notice Verifies a P256 signature directly (without WebAuthn)
     * @param hash The hash to verify
     * @param r The r-component of the signature
     * @param s The s-component of the signature
     * @param x The x-coordinate of the public key
     * @param y The y-coordinate of the public key
     * @return isValid Whether the signature is valid
     */
    function verifyP256Signature(bytes32 hash, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        external
        view
        returns (bool isValid)
    {
        return P256.verifySignature(hash, r, s, x, y);
    }

    // @audit-question: Fuzz test? Converting as well?
    function toBytes(bytes32 data) internal pure returns (bytes memory result) {
        result = new bytes(32);
        assembly {
            mstore(add(result, 32), data)
        }
    }
}
