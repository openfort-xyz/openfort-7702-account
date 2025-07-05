// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {OPF7702Test} from "src/upgradeable/OPF7702Test.sol";
import {LibEIP7702} from "lib/solady/src/accounts/LibEIP7702.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";

contract StorageTest is Test, IKey {
    OPF7702Test public opf;
    address public proxy;
    address public implementation;

    Key public key;
    PubKey public pubKey;

    address public constant ENTRY_POINT = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address public constant WEBAUTHN_VERIFIER = 0xeD43b3a3D00d791BC0B353666b5780B0F9245CC1;

    address public owner;

    function setUp() public {
        owner = makeAddr("owner");
        opf = new OPF7702Test(ENTRY_POINT, WEBAUTHN_VERIFIER);
        implementation = address(opf);

        proxy = LibEIP7702.deployProxy(implementation, address(0));

        bytes memory delegationCode = abi.encodePacked(bytes3(0xef0100), proxy);
        vm.etch(owner, delegationCode);

        console.log("Implementation:", implementation);
        console.log("Proxy:", proxy);
        console.log("Owner:", owner);
        console.log("Owner delegation (should be proxy):", LibEIP7702.delegationOf(owner));
        console.log("Proxy implementation:", LibEIP7702.implementationOf(proxy));
        console.log("Is proxy valid EIP7702Proxy:", LibEIP7702.isEIP7702Proxy(proxy));
    }

    function test_CheckImpl() public {
        bytes memory callData = abi.encodeWithSelector(OPF7702Test.implementation.selector);

        (bool r, bytes memory impl) = owner.call{value: 0}(callData);

        console.log("r", r);
        console.log("implementation", implementation);
        console.logBytes(impl);

        if (!r) {
            console.log("Call failed - checking delegation chain");
            console.log("Owner -> Proxy delegation:", LibEIP7702.delegationOf(owner));
            console.log("Proxy implementation:", LibEIP7702.implementationOf(proxy));
            console.log("Is owner EIP7702 Proxy:", LibEIP7702.isEIP7702Proxy(owner));
            console.log("Is proxy EIP7702 Proxy:", LibEIP7702.isEIP7702Proxy(proxy));

            (bool directProxyCall,) = proxy.call{value: 0}(callData);
            console.log("Direct proxy call success:", directProxyCall);
        } else {
            console.log("SUCCESS! Delegation chain working: Owner -> Proxy -> Implementation");
        }
    }

    function test_Init() public {
        bytes memory idCallData = abi.encodeWithSelector(OPF7702Test.getId.selector);
        (bool r, bytes memory id) = owner.call{value: 0}(idCallData);
        console.log("r", r);
        console.logBytes(id);

        pubKey = PubKey({x: bytes32(0), y: bytes32(0)});
        key = Key({pubKey: pubKey, eoaAddress: owner, keyType: KeyType.EOA});
        bytes32 initG = keccak256(abi.encodePacked(address(10101)));

        bytes memory callData = abi.encodeWithSelector(OPF7702Test.initialize.selector, key, initG);
        (bool r2, bytes memory id2) = owner.call{value: 0}(callData);
        console.log("r2", r2);
        console.logBytes(id2);

        bytes memory initGCallData = abi.encodeWithSignature("initialGuardian()");
        (bool r3, bytes memory id3) = owner.call{value: 0}(initGCallData);
        console.log("r3", r3);
        console.logBytes(id3);
        console.logBytes32(initG);

        (bool r4, bytes memory newId) = owner.call{value: 0}(idCallData);
        if (r4) {
            console.log("New ID after init:");
            console.logBytes(newId);
        }

        bytes memory keyHashCallData = abi.encodeWithSignature("keyHash()");
        (bool r5, bytes memory id5) = owner.call{value: 0}(keyHashCallData);
        console.log("r5", r5);
        console.logBytes(id5);
        console.logBytes32(keccak256(abi.encodePacked(pubKey.x, pubKey.y)));
    }
}
