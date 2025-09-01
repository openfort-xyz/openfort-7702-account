// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {console2 as console} from "lib/forge-std/src/Test.sol";
import {BaseContract} from "test/by-contract/BaseContract.t.sol";

contract KeysManagerTest is BaseContract {
    // Todo init with Bad MK limit = 1 || whitelisting = true
    bytes32 _x = keccak256("x");
    bytes32 _y = keccak256("y");
    address random = makeAddr("random");
    bytes4[] selEmpt;

    function test_registerKeyWithRootKey() public {
        (PubKey memory pk, Key memory k, KeyReg memory kReg) = _createAnyKey(
            _x,
            _y,
            random,
            KeyType.P256,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            0,
            10,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();

        vm.expectEmit(true, false, false, false);
        emit KeyRegistrated(keccak256(abi.encodePacked(pk.x, pk.y)));
        vm.prank(owner);
        account.registerKey(k, kReg);
    }

    function test_registerKeyWithEP() public {
        (PubKey memory pk, Key memory k, KeyReg memory kReg) = _createAnyKey(
            _x,
            _y,
            random,
            KeyType.P256,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            0,
            10,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();

        vm.expectEmit(true, false, false, false);
        emit KeyRegistrated(keccak256(abi.encodePacked(pk.x, pk.y)));
        vm.prank(ENTRYPOINT_V8);
        account.registerKey(k, kReg);
    }

    function test_registerKeyRevertsUnauthorizedCaller() public {
        (, Key memory k, KeyReg memory kReg) = _createAnyKey(
            _x,
            _y,
            random,
            KeyType.P256,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            0,
            10,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();

        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(sender);
        account.registerKey(k, kReg);
    }

    function test_registerKeyRevertsMustIncludeLimits() public {
        (, Key memory k, KeyReg memory kReg) = _createAnyKey(
            _x,
            _y,
            random,
            KeyType.P256,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            0,
            0,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();

        vm.expectRevert(KeyManager__MustIncludeLimits.selector);
        vm.prank(owner);
        account.registerKey(k, kReg);
    }

    function test_registerKeyRevertKeyRegistered() public {
        (, Key memory k, KeyReg memory kReg) = _createAnyKey(
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y,
            random,
            KeyType.P256NONKEY,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            0,
            10,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();

        vm.expectRevert(KeyManager__KeyRegistered.selector);
        vm.prank(owner);
        account.registerKey(k, kReg);
    }

    function test_registerKeyRevertInvalidTimestamp() public {
        (, Key memory k, KeyReg memory kReg) = _createAnyKey(
            P256NOKEY_PUBLIC_KEY_X,
            P256NOKEY_PUBLIC_KEY_Y,
            random,
            KeyType.P256NONKEY,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            uint48(block.timestamp + 2 days),
            10,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();

        vm.expectRevert(KeyManager__InvalidTimestamp.selector);
        vm.prank(owner);
        account.registerKey(k, kReg);
    }

    function test_registerKeyReverAddressCantBeZeroToken() public {
        (, Key memory k, KeyReg memory kReg) = _createAnyKey(
            _x,
            _y,
            random,
            KeyType.P256NONKEY,
            address(0),
            100e18,
            uint48(block.timestamp + 10 days),
            uint48(block.timestamp + 2 days),
            10,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();

        vm.expectRevert(KeyManager__AddressCantBeZero.selector);
        vm.prank(owner);
        account.registerKey(k, kReg);
    }

    function test_registerKeyReverAddressCantBeZeroContract() public {
        (, Key memory k, KeyReg memory kReg) = _createAnyKey(
            _x,
            _y,
            random,
            KeyType.P256NONKEY,
            TOKEN,
            100e18,
            uint48(block.timestamp + 10 days),
            uint48(block.timestamp + 2 days),
            10,
            address(0),
            0.1e18,
            selEmpt
        );

        _etch();

        vm.expectRevert(KeyManager__AddressCantBeZero.selector);
        vm.prank(owner);
        account.registerKey(k, kReg);
    }

    function test_registerKeyRevertySelectorsListTooBig() public {
        bytes4[] memory sel = new bytes4[](20);

        for (uint256 i = 0; i < sel.length;) {
            sel[i] = hex"a9059cbb";

            unchecked {
                i++;
            }
        }

        (, Key memory k, KeyReg memory kReg) = _createAnyKey(
            _x,
            _y,
            random,
            KeyType.P256,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            0,
            10,
            ETH_RECIVE,
            0.1e18,
            sel
        );

        _etch();

        vm.expectRevert(KeyManager__SelectorsListTooBig.selector);
        vm.prank(owner);
        account.registerKey(k, kReg);
    }

    function test_revokeKey() public {
        (PubKey memory pk, Key memory k, KeyReg memory kReg) = _createAnyKey(
            _x,
            _y,
            random,
            KeyType.P256,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            0,
            10,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();

        vm.expectEmit(true, false, false, false);
        emit KeyRegistrated(keccak256(abi.encodePacked(pk.x, pk.y)));
        vm.prank(owner);
        account.registerKey(k, kReg);

        vm.expectEmit(true, false, false, false);
        emit KeyRevoked(keccak256(abi.encodePacked(pk.x, pk.y)));
        vm.prank(owner);
        account.revokeKey(k);
    }

    function test_revokeKeyRevertKeyInactive() public {
        (PubKey memory pk, Key memory k, KeyReg memory kReg) = _createAnyKey(
            _x,
            _y,
            random,
            KeyType.P256,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            0,
            10,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();

        vm.expectEmit(true, false, false, false);
        emit KeyRegistrated(keccak256(abi.encodePacked(pk.x, pk.y)));
        vm.prank(owner);
        account.registerKey(k, kReg);

        vm.expectEmit(true, false, false, false);
        emit KeyRevoked(keccak256(abi.encodePacked(pk.x, pk.y)));
        vm.prank(owner);
        account.revokeKey(k);

        vm.expectRevert(KeyManager__KeyInactive.selector);
        vm.prank(owner);
        account.revokeKey(k);
    }

    function test_getKeyRegistrationInfo() public view {
        (KeyType keyType, bool isActive) = account.getKeyRegistrationInfo(0);

        assertTrue(isActive);

        assertEq(uint256(keyType), uint256(KeyType.WEBAUTHN));
    }

    function test_getKeyById() public view {
        Key memory k = account.getKeyById(0);

        assertEq(uint256(k.keyType), uint256(KeyType.WEBAUTHN));
        assertEq(k.eoaAddress, address(0));
        assertEq(k.pubKey.x, PUBLIC_KEY_X);
        assertEq(k.pubKey.y, PUBLIC_KEY_Y);
    }

    function test_getKeyData() public view {
        (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit) =
            account.getKeyData(keccak256(abi.encodePacked(PUBLIC_KEY_X, PUBLIC_KEY_Y)));

        assertTrue(isActive);
        assertEq(validUntil, type(uint48).max);
        assertEq(validAfter, 0);
        assertEq(limit, 0);
    }

    function test_isKeyActive() public view {
        bool isActive = account.isKeyActive(keccak256(abi.encodePacked(PUBLIC_KEY_X, PUBLIC_KEY_Y)));

        assertTrue(isActive);
    }

    function test_registerKeyKeyManager__KeyRevoked() public {
        Key memory k = account.getKeyById(1);

        _etch();
        vm.prank(owner);
        account.revokeKey(k);

        (,, KeyReg memory kReg) = _createAnyKey(
            _x,
            _y,
            random,
            KeyType.P256,
            TOKEN,
            100e18,
            uint48(block.timestamp + 1 days),
            0,
            10,
            ETH_RECIVE,
            0.1e18,
            selEmpt
        );

        _etch();
        vm.expectRevert(KeyManager__KeyRevoked.selector);
        vm.prank(owner);
        account.registerKey(k, kReg);
    }
}
