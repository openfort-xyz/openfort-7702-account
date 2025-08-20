// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import { Test, console2 as console } from "lib/forge-std/src/Test.sol";

contract Slot is Test {
    function test_PrintSlot() public pure {
        bytes32 slot =
            keccak256(abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)) & ~bytes32(uint256(0xff));
        console.logBytes32(slot);
    }
}
