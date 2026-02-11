// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";

contract StubSignature is Test, IKey { 
    function test_getStubWebAuthn() external pure {
        PubKey memory pk = PubKey({
            x: 0x8b945dc1f4a3877208944e8244fde736be9b002c5468695f54604b2cf749ed67,
            y: 0x0ffbdcfccab58d8d4f9b34699095bf67aca0cf02e9607e0be2029f2f2fece140
        });

        bool requireUserVerification = true;
        bytes memory authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";
        string memory clientDataJSON = "{\"type\":\"webauthn.get\",\"challenge\":\"55-dm6TunyNiRokYdql0KFh8J6YO6DDS_lEJgwd3dX0\",\"origin\":\"http://localhost:3000\"crossOrigin\":false";
        uint256 challengeIndex = 23;
        uint256 typeIndex = 1;
        bytes32 r = 0x362890f84f2e5047c9d71a33d0168fe548ea0bbe4f0a5b350df8783a6d8c254c;
        bytes32 s = 0x4b9d4e01e0edd7c6ec1500866a87c9e6708a1cc3dd9a7ae7342c2b8529e86c68;

        bytes memory inner = abi.encode(
            requireUserVerification,
            authenticatorData,
            clientDataJSON,
            challengeIndex,
            typeIndex,
            r,
            s,
            pk
        );

        // console.log("inner", vm.toString(inner));

        bytes memory sig = abi.encode(KeyType.WEBAUTHN, inner);

        console.log("sig", vm.toString(sig));

    }
}
