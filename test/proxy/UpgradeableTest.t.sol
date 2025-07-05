// SPDX-License-IDentifier: MIT

pragma solidity 0.8.29;

import {Base} from "test/Base.sol";
import {Upgradable} from "test/proxy/Upgradeable.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {LibEIP7702} from "lib/solady/src/accounts/LibEIP7702.sol";
import {MessageHashUtils} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

contract UpgradeableTest is Base {
    Upgradable upg;
    address public proxy;
    address public implementation;

    Key k;
    PubKey pK;

    bytes32 private constant TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function setUp() external {
        upg = new Upgradable();
        implementation = address(upg);
        proxy = LibEIP7702.deployProxy(implementation, address(0));
        
        bytes memory delegationCode = abi.encodePacked(bytes3(0xef0100), proxy);
        vm.etch(owner, delegationCode);
    }

    function test_Init() external {
        pK = PubKey({x: VALID_PUBLIC_KEY_X, y: VALID_PUBLIC_KEY_Y});
        k = Key({
            pubKey: pK,
            eoaAddress: address(0),
            keyType: KeyType.WEBAUTHN
        });

        bytes32 initialGuardian = keccak256(abi.encodePacked(sender));

        bytes32 structHash = keccak256(
            abi.encode(
                RECOVER_TYPEHASH,
                k.pubKey.x,
                k.pubKey.y,
                k.eoaAddress,
                k.keyType,
                initialGuardian
            )
        );

        string memory name = "OPF7702Recoverable";
        string memory version = "1";

        bytes32 domainSeparator = keccak256(abi.encode(TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner));
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory callData = abi.encodeWithSelector(Upgradable.initialize.selector, k, signature, initialGuardian);

        bytes memory delegationCode = abi.encodePacked(bytes3(0xef0100), proxy);
        vm.etch(owner, delegationCode);

        vm.prank(owner);
        (bool res,) = owner.call{value: 0}(callData);

        console.log("res", res);
    }
}