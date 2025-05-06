// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {OpenfortBaseAccount7702V1SessionKey} from "contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ISessionKey} from "contracts/interfaces/ISessionkey.sol";

contract ExecuteViaEntryPointOwner is Script {
    address constant SMART_ACCOUNT = 0x6386b339C3DEc11635C5829025eFE8964DE03b05;
    address constant ENTRY_POINT = 0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B;
    address constant CONTRACT = 0xA84E4F9D72cb37A8276090D3FC50895BD8E5Aaf1;
    address constant TOKEN = 0xd1F228d963E6910412a021aF009583B239b4aA77;

    bytes32 constant VALID_PUBLIC_KEY_X = 0x349f670ed4e7cd75f89f1a253d3794b1c52be51a9b03579f7160ae88121e7878;
    bytes32 constant VALID_PUBLIC_KEY_Y = 0x0a0e01b7c0626be1b8dc3846d145ef31287a555873581ad6f8bee21914ee5eb1;
    bytes public constant CHALLENGE = hex"ddddbeee";
    bytes32 public constant VALID_SIGNATURE_R = 0x70b14935dd469e1952920e0164f06cbd809f0ab5a8d033395f8f4051643dac39;
    bytes32 public constant VALID_SIGNATURE_S = 0x5b71c773e78a3104b7bca532f3ce9ac9b13e6d9a4aad2b8d99114c362ffff585;
    bytes public constant AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";
    string public constant CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"3d2-7g\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";
    uint256 public constant CHALLENGE_INDEX = 23;
    uint256 public constant TYPE_INDEX = 1;

    function run() external {
        uint256 ownerPk = vm.envUint("PRIVATE_KEY_OPENFORT_USER_7702");
        address owner = vm.addr(ownerPk);

        OpenfortBaseAccount7702V1SessionKey smartAccount = OpenfortBaseAccount7702V1SessionKey(payable(SMART_ACCOUNT));
        IEntryPoint entryPoint = IEntryPoint(ENTRY_POINT);

        vm.startBroadcast(ownerPk);

        // Correctly encode callData for execute(Transaction[])
        bytes memory callData = abi.encodeWithSelector(
            0xb61d27f6,
            TOKEN,
            0 ether,
            hex"095ea7b3000000000000000000000000abcdefabcdef1234567890abcdef1234567890120000000000000000000000000000000000000000000000000000000000000000"
        );

        ISessionKey.PubKey memory pubKey = ISessionKey.PubKey({
            x: VALID_PUBLIC_KEY_X,
            y: VALID_PUBLIC_KEY_Y
        });

        bytes memory _signature = smartAccount.encodeWebAuthnSignature(
            CHALLENGE,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            VALID_SIGNATURE_R,
            VALID_SIGNATURE_S,
            pubKey
        );
        
        // Build UserOp
        uint256 nonce = entryPoint.getNonce(SMART_ACCOUNT, 1);
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: SMART_ACCOUNT,
            nonce: nonce,
            initCode: hex"7702",
            callData: callData,
            accountGasLimits: _packAccountGasLimits(400000, 300000),
            preVerificationGas: 800000,
            gasFees: _packGasFees(80 gwei, 15 gwei),
            paymasterAndData: hex"",
            signature: hex""
        });


        bytes memory fullSignature = _signature;

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