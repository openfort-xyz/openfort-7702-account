// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Vm} from "lib/forge-std/src/Vm.sol";
import {Constants} from "../data/Constants.sol";
import {ZkEmailHelpers} from "./ZkEmailHelpers.t.sol";
import {LibBytes} from "lib/solady/src/utils/LibBytes.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

abstract contract Helpers is ZkEmailHelpers {
    // ------------------------------------------------------------------------------------
    //
    //                                  Helper Functions
    //
    // ------------------------------------------------------------------------------------

    // Fund an address with ETH
    function _deal(address _to, uint256 _amount) internal {
        vm.deal(_to, _amount);
    }
}
