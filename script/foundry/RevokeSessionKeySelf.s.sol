// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {OpenfortBaseAccount7702V1SessionKey} from "contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol";
import {ISessionKey} from "contracts/interfaces/ISessionkey.sol";

contract RevokeSelfCall is Script {
    address constant SMART_ACCOUNT = 0x6386b339C3DEc11635C5829025eFE8964DE03b05;
    address constant ENTRY_POINT = 0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B;
    address constant WEBAUTHN_VERIFIER = 0xc3F5De14f8925cAB747a531B53FE2094C2C5f597;
    address constant BURN_ADDRESS = address(0);

    bytes32 constant VALID_PUBLIC_KEY_X = 0xf03e98af7cae9db7b92fcda32babdb1fc641a3700246a578b6d72b055c3cd521;
    bytes32 constant VALID_PUBLIC_KEY_Y = 0x8aefd582dd60ad24e4c12c59ea5013cf24e8847f2d024e64feab5a327c404c74;

    function run() external {
        // Step 1: Deploy the implementation
        OpenfortBaseAccount7702V1SessionKey implementation = new OpenfortBaseAccount7702V1SessionKey(
            ENTRY_POINT,
            WEBAUTHN_VERIFIER
        );

        // Step 2: Prepare EIP-7702 compliant code (0xef0100 + implementation address)
        bytes memory code = abi.encodePacked(
            hex"ef0100",
            address(implementation)
        );

        // Step 3: Etch the code to the smart account
        vm.etch(SMART_ACCOUNT, code);

        // Step 4: Broadcast as the smart account itself (EIP-7702 logic)
        vm.startBroadcast(SMART_ACCOUNT);

        OpenfortBaseAccount7702V1SessionKey smartAccount = OpenfortBaseAccount7702V1SessionKey(payable(SMART_ACCOUNT));

        // Prepare key and structs
        ISessionKey.PubKey memory pubKey = ISessionKey.PubKey({
            x: VALID_PUBLIC_KEY_X,
            y: VALID_PUBLIC_KEY_Y
        });

        ISessionKey.Key memory key = ISessionKey.Key({
            pubKey: pubKey,
            eoaAddress: BURN_ADDRESS,
            keyType: ISessionKey.KeyType.WEBAUTHN
        });

        // Step 5: Call registerSessionKey directly (msg.sender == address(this))
        smartAccount.revokeSessionKey(
            key
        );

        vm.stopBroadcast();
    }
}