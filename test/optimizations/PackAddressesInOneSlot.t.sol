// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Test, console2 as console} from "lib/forge-std/src/Test.sol";

contract PackAddressesInOneSlot is Test {
    address constant GAS_POLICY = 0x0000FEeaB9F73EAa49583aC15357a8673098D971;
    address constant WEBAUTHN_VERIFIER = 0x0000256A4eB4642E668CD371aeDE4b004295ad65;

    function test_PackedAddressesToOneSlot() public {}
}
