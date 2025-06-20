// SDPX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {P256} from "lib/solady/src/utils/P256.sol";
import {WebAuthn} from "lib/webauthn-sol/src/WebAuthn.sol";
import {Test, console2 as console} from "lib/forge-std/src/test.sol";
import {WebAuthn as WebAuthnVerifierSolady} from "lib/solady/src/utils/WebAuthn.sol";

contract WebAuthnOneChain is Test {
    // @author Coinbase (https://github.com/base-org/webauthn-sol)
    Verifier v;
    // @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/WebAuthn.sol)
    VerifierSolady vS;

    bytes32 constant PUBLIC_KEY_X =
        hex"f014cc9fb4edba3c439a22423f580ad29cb177dbd5af224e4d068ef6374df083";
    bytes32 constant PUBLIC_KEY_Y =
        hex"f4c5322095ffa8db8344b7675f82eeadd2a17af4d9db9d4d4c582e8839ca391e";

    bytes public constant CHALLENGE =
        hex"cea3e080968320575bc01fbe2293a690683e321ac28cfb95a234e4b959e4fcfa";

    bytes32 public constant SIGNATURE_R =
        hex"cf1d727573eee8b3d301ab94aec432c1b7953969dcdf71388d14385630378a80";
    bytes32 public constant SIGNATURE_S =
        hex"417d9bafa3acecdbba348f851c1efc93c7ed780e2eddc7046767a1998db4f0c8";

    bytes public constant AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";

    string public constant CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"zqPggJaDIFdbwB--IpOmkGg-MhrCjPuVojTkuVnk_Po\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    uint256 public constant CHALLENGE_INDEX = 23;
    uint256 public constant TYPE_INDEX = 1;

    function setUp() public {
        v = new Verifier();
        vS = new VerifierSolady();
    }

    function test_Verify() public view {
        bool isValid = v.verify(
            CHALLENGE,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            SIGNATURE_R,
            SIGNATURE_S,
            PUBLIC_KEY_X,
            PUBLIC_KEY_Y
        );

        assertTrue(isValid);
    }

    function test_Solady() public view {
        bool isValid = vS.verifySoladySignature(
            CHALLENGE,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            SIGNATURE_R,
            SIGNATURE_S,
            PUBLIC_KEY_X,
            PUBLIC_KEY_Y
        );

        bool res = vS.hasPrecompileOrVerifier();
        console.log("hasPrecompileOrVerifier", res);
        assertTrue(isValid);
    }
}

contract Verifier {
    function verify(
        bytes memory challenge,
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
        uint256 rUint = uint256(r);
        uint256 sUint = uint256(s);
        uint256 xUint = uint256(x);
        uint256 yUint = uint256(y);

        // @audit-info ⚠️: Can be external
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            authenticatorData: authenticatorData,
            clientDataJSON: clientDataJSON,
            challengeIndex: challengeIndex,
            typeIndex: typeIndex,
            r: rUint,
            s: sUint
        });

        // Todo: test of Converting good or not
        // bytes memory challengeBytes = toBytes(challenge);
        isValid = WebAuthn.verify(challenge, requireUserVerification, auth, xUint, yUint);

        return isValid;
    }

    function toBytes(bytes32 data) internal pure returns (bytes memory result) {
        result = new bytes(32);
        assembly {
            mstore(add(result, 32), data)
        }
    }
}

contract VerifierSolady {
    function verifySoladySignature(
        bytes memory challenge,
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
        WebAuthnVerifierSolady.WebAuthnAuth memory auth = WebAuthnVerifierSolady.WebAuthnAuth({
            authenticatorData: authenticatorData,
            clientDataJSON: clientDataJSON,
            challengeIndex: challengeIndex,
            typeIndex: typeIndex,
            r: r,
            s: s
        });

        // Todo: test of Converting good or not
        // bytes memory challengeBytes = toBytes(challenge);
        isValid = WebAuthnVerifierSolady.verify(challenge, requireUserVerification, auth, x, y);

        return isValid;
    }

    function toBytes(bytes32 data) internal pure returns (bytes memory result) {
        result = new bytes(32);
        assembly {
            mstore(add(result, 32), data)
        }
    }

    function hasPrecompileOrVerifier() public view returns (bool result) {
        result = P256.hasPrecompileOrVerifier();
    }
}
