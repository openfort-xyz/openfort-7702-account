// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {OpenfortBaseAccount7702V1SessionKey} from "contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract CheckIsValidSignature is Script {
    address constant SMART_ACCOUNT = 0x6386b339C3DEc11635C5829025eFE8964DE03b05;
    address constant ENTRY_POINT = 0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B;

    function run() external view {
        // Load private key from environment
        uint256 ownerPk = vm.envUint("PRIVATE_KEY_OPENFORT_USER_7702");
        address owner = vm.addr(ownerPk);

        OpenfortBaseAccount7702V1SessionKey smartAccount = OpenfortBaseAccount7702V1SessionKey(payable(SMART_ACCOUNT));
        IEntryPoint entryPoint = IEntryPoint(ENTRY_POINT);

        // Prepare dummy userOp
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: SMART_ACCOUNT,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: hex"",
            signature: hex""
        });

        // Get userOpHash and digest
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 digest = smartAccount.getDigestToSign(userOpHash);

        // Sign digest off-chain
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Call isValidSignature on Sepolia
        bytes4 magicValue = smartAccount.isValidSignature(userOpHash, sig);

        console.log("Signer:", owner);
        console.logBytes32(digest);
        console.log("Signature valid:", magicValue == 0x1626ba7e);
    }
}