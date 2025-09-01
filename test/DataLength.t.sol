// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Base} from "test/Base.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {SigLengthLib} from "src/libs/SigLengthLib.sol";

contract DataLength is Base {
    Key internal keyMK;
    PubKey internal pubKeyMK;
    string EOA = "EOA";
    string WEBAUTHN = "WEBAUTHN";
    string P256 = "EOA";

    TestLargeSignature tsl;

    function setUp() public {
        (owner, ownerPk) = makeAddrAndKey("owner");
        tsl = new TestLargeSignature();
    }

    function test_EOALength() public view {
        bytes32 hash = keccak256("Hash");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory _signature = encodeEOASignature(signature);

        PackedUserOperation memory userOp = _getUserOp();
        userOp.signature = _signature;
        _printLength(EOA, userOp);
    }

    function test_WebAuthnLength() public view {
        PubKey memory pubKeyExecuteBatch =
            PubKey({x: BATCH_VALID_PUBLIC_KEY_X, y: BATCH_VALID_PUBLIC_KEY_Y});

        bytes memory signature = encodeWebAuthnSignature(
            true,
            BATCH_AUTHENTICATOR_DATA,
            BATCH_CLIENT_DATA_JSON,
            BATCH_CHALLENGE_INDEX,
            BATCH_TYPE_INDEX,
            BATCH_VALID_SIGNATURE_R,
            BATCH_VALID_SIGNATURE_S,
            pubKeyExecuteBatch
        );

        PackedUserOperation memory userOp = _getUserOp();
        userOp.signature = signature;
        _printLength(WEBAUTHN, userOp);
    }

    function test_P256Length() public view {
        PubKey memory pubKeyExecuteBatch =
            PubKey({x: MINT_P256_PUBLIC_KEY_X, y: MINT_P256_PUBLIC_KEY_Y});

        bytes memory signature = encodeP256Signature(
            MINT_P256_SIGNATURE_R, MINT_P256_SIGNATURE_S, pubKeyExecuteBatch, KeyType.P256
        );

        PackedUserOperation memory userOp = _getUserOp();
        userOp.signature = signature;
        _printLength(P256, userOp);
    }

    function _printLength(string storage _type, PackedUserOperation memory userOp) internal pure {
        console.log("%s : %d", _type, userOp.signature.length);
    }

    function test_WebAuthnLib_Canonical_Pass() public view {
        PubKey memory pk = PubKey({x: BATCH_VALID_PUBLIC_KEY_X, y: BATCH_VALID_PUBLIC_KEY_Y});

        bytes memory inner = abi.encode(
            true,
            BATCH_AUTHENTICATOR_DATA,
            BATCH_CLIENT_DATA_JSON,
            BATCH_CHALLENGE_INDEX,
            BATCH_TYPE_INDEX,
            BATCH_VALID_SIGNATURE_R,
            BATCH_VALID_SIGNATURE_S,
            pk
        );
        bytes memory outer = abi.encode(KeyType.WEBAUTHN, inner);

        (KeyType t, bytes memory sigData) = abi.decode(outer, (KeyType, bytes));
        assertEq(uint8(t), uint8(KeyType.WEBAUTHN), "keyType mismatch");

        (, bytes memory authenticatorData, string memory clientDataJSON,,,,,) =
            abi.decode(sigData, (bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey));

        SigLengthLib.assertWebAuthnOuterLen(
            outer.length, authenticatorData.length, bytes(clientDataJSON).length
        );
    }

    function test_Revert() public view {
        PackedUserOperation memory op = _getUserOp();

        PubKey memory pk = PubKey({x: BATCH_VALID_PUBLIC_KEY_X, y: BATCH_VALID_PUBLIC_KEY_Y});

        bytes memory inner = abi.encode(
            true,
            BATCH_AUTHENTICATOR_DATA,
            BATCH_CLIENT_DATA_JSON,
            BATCH_CHALLENGE_INDEX,
            BATCH_TYPE_INDEX,
            BATCH_VALID_SIGNATURE_R,
            BATCH_VALID_SIGNATURE_S,
            pk
        );
        bytes memory outer = abi.encode(KeyType.WEBAUTHN, inner);
        // bytes memory outerBigSize = abi.encodePacked(outer, hex"00");
        op.signature = outer;

        bytes32 userOpHash = keccak256("HASH");
        tsl.validateSignature(op, userOpHash);
    }

    function test_WebAuthnLib_TrailingByteOnOuter_Revert() public {
        PubKey memory pk = PubKey({x: BATCH_VALID_PUBLIC_KEY_X, y: BATCH_VALID_PUBLIC_KEY_Y});

        bytes memory inner = abi.encode(
            true,
            BATCH_AUTHENTICATOR_DATA,
            BATCH_CLIENT_DATA_JSON,
            BATCH_CHALLENGE_INDEX,
            BATCH_TYPE_INDEX,
            BATCH_VALID_SIGNATURE_R,
            BATCH_VALID_SIGNATURE_S,
            pk
        );
        bytes memory outer = abi.encode(KeyType.WEBAUTHN, inner);
        bytes memory badOuter = abi.encodePacked(outer, outer); // extra junk

        (, bytes memory sigData) = abi.decode(badOuter, (KeyType, bytes));

        (, bytes memory authenticatorData, string memory clientDataJSON,,,,,) =
            abi.decode(sigData, (bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey));

        vm.expectRevert(IKeysManager.KeyManager__InvalidSignatureLength.selector);
        this._assertOuterMatchesDecoded(
            badOuter.length, authenticatorData.length, bytes(clientDataJSON).length
        );
    }

    function test_WebAuthnLib_TrailingByteInsideInner_Revert() public {
        PubKey memory pk = PubKey({x: BATCH_VALID_PUBLIC_KEY_X, y: BATCH_VALID_PUBLIC_KEY_Y});

        bytes memory inner = abi.encode(
            true,
            BATCH_AUTHENTICATOR_DATA,
            BATCH_CLIENT_DATA_JSON,
            BATCH_CHALLENGE_INDEX,
            BATCH_TYPE_INDEX,
            BATCH_VALID_SIGNATURE_R,
            BATCH_VALID_SIGNATURE_S,
            pk
        );

        bytes memory badInner = abi.encodePacked(inner, inner);
        bytes memory outer = abi.encode(KeyType.WEBAUTHN, badInner);

        (, bytes memory sigData) = abi.decode(outer, (KeyType, bytes));

        (, bytes memory authenticatorData, string memory clientDataJSON,,,,,) =
            abi.decode(sigData, (bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey));

        vm.expectRevert(IKeysManager.KeyManager__InvalidSignatureLength.selector);
        this._assertOuterMatchesDecoded(
            outer.length, authenticatorData.length, bytes(clientDataJSON).length
        );
    }

    function test_WebAuthnLib_VariableClientDataJSON_Pass() public view {
        PubKey memory pk = PubKey({x: BATCH_VALID_PUBLIC_KEY_X, y: BATCH_VALID_PUBLIC_KEY_Y});

        string memory longerJSON = string(abi.encodePacked(BATCH_CLIENT_DATA_JSON, "/v2"));

        bytes memory inner = abi.encode(
            true,
            BATCH_AUTHENTICATOR_DATA,
            longerJSON,
            BATCH_CHALLENGE_INDEX,
            BATCH_TYPE_INDEX,
            BATCH_VALID_SIGNATURE_R,
            BATCH_VALID_SIGNATURE_S,
            pk
        );
        bytes memory outer = abi.encode(KeyType.WEBAUTHN, inner);

        (, bytes memory sigData) = abi.decode(outer, (KeyType, bytes));

        (, bytes memory authenticatorData, string memory clientDataJSON,,,,,) =
            abi.decode(sigData, (bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey));

        SigLengthLib.assertWebAuthnOuterLen(
            outer.length, authenticatorData.length, bytes(clientDataJSON).length
        );
    }

    function test_WebAuthnLib_VariableAuthenticatorData_Pass() public view {
        PubKey memory pk = PubKey({x: BATCH_VALID_PUBLIC_KEY_X, y: BATCH_VALID_PUBLIC_KEY_Y});

        bytes memory longerAD = bytes.concat(BATCH_AUTHENTICATOR_DATA, hex"00");

        bytes memory inner = abi.encode(
            true,
            longerAD,
            BATCH_CLIENT_DATA_JSON,
            BATCH_CHALLENGE_INDEX,
            BATCH_TYPE_INDEX,
            BATCH_VALID_SIGNATURE_R,
            BATCH_VALID_SIGNATURE_S,
            pk
        );
        bytes memory outer = abi.encode(KeyType.WEBAUTHN, inner);

        (, bytes memory sigData) = abi.decode(outer, (KeyType, bytes));
        (, bytes memory authenticatorData, string memory clientDataJSON,,,,,) =
            abi.decode(sigData, (bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey));

        SigLengthLib.assertWebAuthnOuterLen(
            outer.length, authenticatorData.length, bytes(clientDataJSON).length
        );
    }

    function _assertOuterMatchesDecoded(
        uint256 outerLen,
        uint256 authenticatorDataLen,
        uint256 clientDataJSONLen
    ) external pure {
        SigLengthLib.assertWebAuthnOuterLen(outerLen, authenticatorDataLen, clientDataJSONLen);
    }

    function _getUserOp() internal pure returns (PackedUserOperation memory userOp) {
        userOp.sender = address(0);
        userOp.nonce = 1;
        userOp.initCode = hex"";
        userOp.callData = hex"";
        userOp.accountGasLimits = hex"";
        userOp.preVerificationGas = 1;
        userOp.gasFees = hex"";
        userOp.paymasterAndData = hex"";
        userOp.signature = hex"";
    }

    function encodeWebAuthnSignature(
        bool requireUserVerification,
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint256 challengeIndex,
        uint256 typeIndex,
        bytes32 r,
        bytes32 s,
        PubKey memory pubKey
    ) internal pure returns (bytes memory) {
        return abi.encode(
            KeyType.WEBAUTHN,
            requireUserVerification,
            authenticatorData,
            clientDataJSON,
            challengeIndex,
            typeIndex,
            r,
            s,
            pubKey
        );
    }

    function encodeP256Signature(bytes32 r, bytes32 s, PubKey memory pubKey, KeyType _keyType)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory inner = abi.encode(r, s, pubKey);
        return abi.encode(_keyType, inner);
    }

    function encodeEOASignature(bytes memory _signature) internal pure returns (bytes memory) {
        return abi.encode(KeyType.EOA, _signature);
    }
}

contract TestLargeSignature {
    using SigLengthLib for bytes;

    enum KeyType {
        EOA,
        WEBAUTHN,
        P256,
        P256NONKEY
    }

    struct PubKey {
        bytes32 x;
        bytes32 y;
    }

    function validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        public
        pure
    {
        (, bytes memory sigData) = abi.decode(userOp.signature, (KeyType, bytes));
        _validateKeyTypeWEBAUTHN(sigData, userOpHash, userOp);
    }

    function _validateKeyTypeWEBAUTHN(
        bytes memory signature,
        bytes32, /*userOpHash*/
        PackedUserOperation calldata userOp
    ) private pure {
        // decode everything in one shot
        (, bytes memory authenticatorData, string memory clientDataJSON,,,,,) =
            abi.decode(signature, (bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey));

        SigLengthLib.assertWebAuthnOuterLen(
            userOp.signature.length, authenticatorData.length, bytes(clientDataJSON).length
        );
    }

    function test_GasPolicySlot() public {
        bytes32 slot = keccak256(abi.encode(uint256(keccak256("openfort.webauthnverifier.storage")) - 1)) & ~bytes32(uint256(0xff));
        console.logBytes32(slot);
    }
}
