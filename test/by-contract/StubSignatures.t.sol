// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract StubSignature is Deploy {
    PubKey internal pK_SK;
    PubKey internal pK;

    function setUp() public virtual override {
        super.setUp();
        _populateWebAuthn("execution.json", ".batch");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );
        _createQuickFreshKey(false);
    }
    function test_getEOAStubSig() external view {
        PackedUserOperation memory userOp = _getFreshUserOp();
        bytes memory signature = _signUserOp(userOp);
        userOp.signature = abi.encodePacked(_encodeEOASignature(signature), keccak256("more-bytes"));

        console.log("signature", vm.toString(userOp.signature));
    }

    function test_getWebAuthnStubSig() external {
        PackedUserOperation memory userOp = _getFreshUserOp();
        _populateWebAuthn("eth.json", ".eth");
        pK_SK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK_SK);

        console.log("signature", vm.toString(userOp.signature));
    }

    function test_getP256StubSig() external {
        PackedUserOperation memory userOp = _getFreshUserOp();
        pK_SK = PubKey({x: keccak256("x.P256"), y: keccak256("y.P256")});
        userOp.signature = _encodeP256Signature(DEF_P256.R, DEF_P256.S, pK_SK, KeyType.P256);

        console.log("signature", vm.toString(userOp.signature));
    }

    function test_getP256NonKeyStubSig() external {
        PackedUserOperation memory userOp = _getFreshUserOp();
        pK_SK = PubKey({x: keccak256("x.P256"), y: keccak256("y.P256")});
        userOp.signature = _encodeP256Signature(DEF_P256.R, DEF_P256.S, pK_SK, KeyType.P256NONKEY);

        console.log("signature", vm.toString(userOp.signature));
    }
}
