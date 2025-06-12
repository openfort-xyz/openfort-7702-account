// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {MockERC20} from "contracts/mocks/MockERC20.sol";
import {Test, console2 as console} from "forge-std/Test.sol";

contract Base is Test {
    function getMockERC20() external returns(MockERC20) {
       MockERC20 mockERC20 = new MockERC20();
       return mockERC20;
    }
}