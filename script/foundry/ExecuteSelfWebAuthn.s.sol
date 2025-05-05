// SDPX-License-Identifier: MIT

pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import {OpenfortBaseAccount7702V1SessionKey} from "contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol";
import {WebAuthnVerifier} from "contracts/utils/WebAuthnVerifier.sol";
import {ISessionKey} from "contracts/interfaces/ISessionkey.sol";

contract ExecuteSelfWebAuthn is Script {
    address constant SMART_ACCOUNT = 0x6386b339C3DEc11635C5829025eFE8964DE03b05;
    address constant BURN_ADDRESS = address(0);
    address constant CONTRACT = 0x51fCe89b9f6D4c530698f181167043e1bB4abf89;
    address constant ENTRY_POINT = 0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B;
    address constant WEBAUTHN_VERIFIER = 0xc3F5De14f8925cAB747a531B53FE2094C2C5f597;

    bytes32 constant VALID_PUBLIC_KEY_X = 0x2637cbe61c480641a9fedf677760ef035201785af1efc56eaa926adf4ba3cc7c;
    bytes32 constant VALID_PUBLIC_KEY_Y = 0x0dcaeabc653a0a4ac8fed81bea1fee2b1329ce6c295161abafc6c338fd466c68;
    bytes public constant CHALLENGE = hex"deaddead";
    bytes32 public constant VALID_SIGNATURE_R = 0x1cf4b83168a7bc3fbf8eb6bb36d7172ae5b865ce29d6956fcd179553667c3c98;
    bytes32 public constant VALID_SIGNATURE_S = 0x238416b299e6f0ec4ac0344730e4ece562dfb0e1ecc06d3ab56061b82b282217;
    bytes public constant AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";
    string public constant CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"3q3erQ\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";
    uint256 public constant CHALLENGE_INDEX = 23;
    uint256 public constant TYPE_INDEX = 1;

    bytes32 private constant P256_VERIFIER = 0x2562256225622562256225622562256225622562256225622562256225622562;

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
        WebAuthnVerifier webAuthnVerifier = WebAuthnVerifier(WEBAUTHN_VERIFIER);

        bytes32 _hash = P256_VERIFIER;

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

        // console.logBytes(_signature);
        bytes4 magicValue = smartAccount.isValidSignature(_hash, _signature);
        bool usedChallenge = smartAccount.usedChallenges(CHALLENGE);
        console.log("usedChallenge", usedChallenge);

        console.logBytes4(magicValue);

        bool isValid = webAuthnVerifier.verifySoladySignature(
            CHALLENGE,
            true,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CHALLENGE_INDEX,
            TYPE_INDEX,
            VALID_SIGNATURE_R,
            VALID_SIGNATURE_S,
            VALID_PUBLIC_KEY_X,
            VALID_PUBLIC_KEY_Y
        );
        console.log("isValid", isValid);

        bytes32 keyHash = keccak256(abi.encodePacked(VALID_PUBLIC_KEY_X, VALID_PUBLIC_KEY_Y));
        (bool isActive, uint48 validUntil, uint48 validAfter, uint256 limit) = smartAccount.getSessionKeyData(keyHash);

        console.log("isActive", isActive);
        console.log("validUntil", validUntil);
        console.log("validAfter", validAfter);
        console.log("limit", limit);
        vm.stopBroadcast();
    }
}