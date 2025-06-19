// SPDX-License-Identifier: MIT
// @audit-info ⚠️: Fixed Pragma -> ^0.8.29
pragma solidity ^0.8.4;

import {WebAuthn} from "src/libs/WebAuthn.sol";
import {P256} from "src/libs/P256.sol";
import {Test, console2 as console} from "lib/forge-std/src/test.sol";

/**
 * @title WebAuthnVerifier
 * @author openfort@0xkoiner
 * @notice A simple contract to verify WebAuthn signatures
 * @dev Uses Solady's WebAuthn and P256 libraries for verification
 */
contract WebAuthnVerifier {
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
    function verifySoladySignature(
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
    ) public view returns (bool isValid) {
        // @audit-info ⚠️: Can be external
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            authenticatorData: authenticatorData,
            clientDataJSON: clientDataJSON,
            challengeIndex: challengeIndex,
            typeIndex: typeIndex,
            r: r,
            s: s
        });

        // Todo: test of Converting good or not
        bytes memory challengeBytes = toBytes(challenge);
        isValid = WebAuthn.verify(challengeBytes, requireUserVerification, auth, x, y);

        return isValid;
    }

    /**
     * @notice Verifies a WebAuthn signature using encoded auth data
     * @param challenge The challenge that was signed
     * @param requireUserVerification Whether to require user verification
     * @param encodedAuth The encoded WebAuthn auth data
     * @param x The x-coordinate of the public key
     * @param y The y-coordinate of the public key
     * @return isValid Whether the signature is valid
     */
    function verifyEncodedSignature(
        bytes memory challenge, // @audit-info ⚠️: Should be bytes32 like in `verifySoladySignature`
        bool requireUserVerification,
        bytes memory encodedAuth,
        bytes32 x,
        bytes32 y
    ) public view returns (bool isValid) {
        // @audit-info ⚠️: Can be external
        // @audit-info ⚠️: Have to convert  bytes32 memory challenge to bytes
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.tryDecodeAuth(encodedAuth);

        isValid = WebAuthn.verify(challenge, requireUserVerification, auth, x, y);

        return isValid;
    }

    /**
     * @notice Verifies a WebAuthn signature using compact encoded auth data
     * @param challenge The challenge that was signed
     * @param requireUserVerification Whether to require user verification
     * @param encodedAuth The compact encoded WebAuthn auth data
     * @param x The x-coordinate of the public key
     * @param y The y-coordinate of the public key
     * @return isValid Whether the signature is valid
     */
    function verifyCompactSignature(
        bytes memory challenge, // @audit-info ⚠️: Should be bytes32 like in `verifySoladySignature`
        bool requireUserVerification,
        bytes memory encodedAuth,
        bytes32 x,
        bytes32 y
    ) public view returns (bool isValid) {
        // @audit-info ⚠️: Can be external
        // @audit-info ⚠️: Have to convert  bytes32 memory challenge to bytes
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.tryDecodeAuthCompact(encodedAuth);

        isValid = WebAuthn.verify(challenge, requireUserVerification, auth, x, y);

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
        public
        view
        returns (bool isValid)
    {
        // @audit-info ⚠️: Can be external
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

/// @audit-question: Working as well in all available chains with Pectra Ugrd?
/**
 * 🚨 [FAIL: P256VerificationFailed()] test_BNB() (gas: 521368)
 * 🚨 [FAIL: P256VerificationFailed()] test_Bera() (gas: 520246)
 * 🚨 [FAIL: P256VerificationFailed()] test_GNO() (gas: 519203)
 * 🚨 [FAIL: P256VerificationFailed()] test_Ink() (gas: 519044)
 */
/// @audit-first-round: ✅
/// @audit-Critical: 🔴🔴🔴 Library of Solady not working in the chains of
/**
 * 🔴🔴🔴 [FAIL: assertion failed] test_BNB_Solady() (gas: 338007)
 * 🔴🔴🔴 [FAIL: assertion failed] test_Base_Solady() (gas: 336198)
 * 🔴🔴🔴 [FAIL: assertion failed] test_Bera_Solady() (gas: 338491)
 * 🔴🔴🔴 [FAIL: assertion failed] test_GNO_Solady() (gas: 337909)
 * 🔴🔴🔴 [FAIL: assertion failed] test_Ink_Solady() (gas: 338227)
 */
