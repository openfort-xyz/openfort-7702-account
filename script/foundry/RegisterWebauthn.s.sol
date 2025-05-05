// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {OpenfortBaseAccount7702V1SessionKey} from "contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol";
import {SpendLimit} from "contracts/utils/SpendLimit.sol";
import {ISessionKey} from "contracts/interfaces/ISessionkey.sol";

contract RegisterWebAuthnSelfCall is Script {
    address constant SMART_ACCOUNT = 0x6386b339C3DEc11635C5829025eFE8964DE03b05;
    address constant BURN_ADDRESS = address(0);
    address constant TOKEN_ADDRESS = 0x51fCe89b9f6D4c530698f181167043e1bB4abf89;
    address constant CONTRACT = 0x51fCe89b9f6D4c530698f181167043e1bB4abf89;
    address constant ENTRY_POINT = 0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B;
    address constant WEBAUTHN_VERIFIER = 0xc3F5De14f8925cAB747a531B53FE2094C2C5f597;
    bytes4[] public selectors;

    uint256 constant SPEND_LIMIT = 10 ether;
    uint256 constant ETH_LIMIT = 0.5 ether;
    uint48 constant LIMIT = 3;

    bytes32 constant VALID_PUBLIC_KEY_X = 0x2637cbe61c480641a9fedf677760ef035201785af1efc56eaa926adf4ba3cc7c;
    bytes32 constant VALID_PUBLIC_KEY_Y = 0x0dcaeabc653a0a4ac8fed81bea1fee2b1329ce6c295161abafc6c338fd466c68;

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

        SpendLimit.SpendTokenInfo memory spendTokenInfo = SpendLimit.SpendTokenInfo({
            token: TOKEN_ADDRESS,
            limit: SPEND_LIMIT
        });

        selectors.push(0xa9059cbb); // transfer(address,uint256)

        // Step 5: Call registerSessionKey directly (msg.sender == address(this))
        smartAccount.registerSessionKey(
            key,
            uint48(1748764133),
            uint48(0),
            uint48(0),
            true,
            CONTRACT,
            spendTokenInfo,
            selectors,
            ETH_LIMIT
        );

        vm.stopBroadcast();
    }
}