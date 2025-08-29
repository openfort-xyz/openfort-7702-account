// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {BaseContract} from "test/by-contract/BaseContract.t.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract OPF7702Test is BaseContract {
    function test_validateSignatureRevertInvalidKeyType() public {
        PackedUserOperation memory op = _getUserOpFresh();

        bytes32 hash = keccak256("Hash");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, hash);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes memory signature = abi.encode(uint8(5), sig);

        op.signature = signature;

        _etch();

        vm.expectRevert();
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(op, hash, 0);
    }

    function test_validateSignatureRevertInvalidSignatureLengthEOA() public {
        PackedUserOperation memory op = _getUserOpFresh();

        bytes32 hash = keccak256("Hash");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, hash);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes memory signature = abi.encode(KeyType.EOA, sig, sig);

        op.signature = signature;

        _etch();

        vm.expectRevert(KeyManager__InvalidSignatureLength.selector);
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(op, hash, 0);
    }

    function test_validateSignatureRevertInvalidSignatureLengthP256() public {
        PackedUserOperation memory op = _getUserOpFresh();
        bytes32 hash = keccak256("Hash");

        bytes memory signature = account.encodeP256Signature(
            P256NOKEY_SIGNATURE_R, P256NOKEY_SIGNATURE_S, pubKeySK, KeyType.P256NONKEY
        );

        bytes memory largeSignature = abi.encodePacked(signature, signature);
        op.signature = largeSignature;

        _etch();

        vm.expectRevert(KeyManager__InvalidSignatureLength.selector);
        vm.prank(ENTRYPOINT_V8);
        account.validateUserOp(op, hash, 0);
    }

    function test_validateKeyTypeEOA_SIG_VALIDATION_FAILED() public {
        Key memory keySK2 = PubKey({x: bytes32(0), y: bytes32(0)});
        PubKey memory pubKeySK2 = Key({pubKey: pubKeySK, eoaAddress: sender, keyType: KeyType.EOA});
        KeyReg memory keyDataSKEOA = KeyReg({
            validUntil: validUntil,
            validAfter: 0,
            limit: 10,
            whitelisting: true,
            contractAddress: ETH_RECIVE,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 1e18
        });
    }
}
