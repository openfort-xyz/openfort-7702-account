// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {OPF7702Test} from "src/upgradeable/OPF7702Test.sol";
import {LibEIP7702} from "lib/solady/src/accounts/LibEIP7702.sol";

contract OPF7702Proxy {
    address public immutable delegationImplementation;
    address public immutable delegationProxy;

    constructor(address _ep, address _waV) payable {
        delegationImplementation = address(new OPF7702Test(_ep, _waV));
        delegationProxy = LibEIP7702.deployProxy(delegationImplementation, address(0));
    }
}
