// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {OpenfortBaseAccount7702V1SessionKey} from "contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract ExecuteViaEntryPointOwner is Script {
    address constant SMART_ACCOUNT = 0x6386b339C3DEc11635C5829025eFE8964DE03b05;
    address constant ENTRY_POINT = 0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B;
    address constant CONTRACT = 0xA84E4F9D72cb37A8276090D3FC50895BD8E5Aaf1;

    function run() external {
        uint256 ownerPk = vm.envUint("PRIVATE_KEY_OPENFORT_USER_7702");
        address owner = vm.addr(ownerPk);

        OpenfortBaseAccount7702V1SessionKey smartAccount = OpenfortBaseAccount7702V1SessionKey(payable(SMART_ACCOUNT));
        IEntryPoint entryPoint = IEntryPoint(ENTRY_POINT);

        vm.startBroadcast(ownerPk);

        // Construct a Transaction[] array
        OpenfortBaseAccount7702V1SessionKey.Transaction[] memory txs = new OpenfortBaseAccount7702V1SessionKey.Transaction[](1);
        txs[0] = OpenfortBaseAccount7702V1SessionKey.Transaction({
            to: CONTRACT,
            value: 0.0002 ether,
            data: hex""
        });

        // Correctly encode callData for execute(Transaction[])
        bytes memory callData = abi.encodeWithSelector(
            0x3f707e6b,
            txs
        );

        // Build UserOp
        uint256 nonce = entryPoint.getNonce(SMART_ACCOUNT, 1);
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: SMART_ACCOUNT,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(400000, 300000),
            preVerificationGas: 1000000,
            gasFees: _packGasFees(80 gwei, 15 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });

        // Get digest from smart account
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 digest = smartAccount.getDigestToSign(userOpHash);

        // Sign digest with owner key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory rawSig = abi.encodePacked(r, s, v);
        bytes memory fullSignature = abi.encode(0, rawSig); // 0 == KeyType.EOA

        // Attach signature
        userOp.signature = fullSignature;

        // Send operation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        entryPoint.handleOps{gas: 1000000}(ops, payable(owner));

        vm.stopBroadcast();
    }

    function _packAccountGasLimits(uint256 callGasLimit, uint256 verificationGasLimit)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((callGasLimit << 128) | verificationGasLimit);
    }

    function _packGasFees(uint256 maxFeePerGas, uint256 maxPriorityFeePerGas)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((maxFeePerGas << 128) | maxPriorityFeePerGas);
    }
}