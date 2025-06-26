// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {LibEIP7702} from "lib/solady/src/accounts/LibEIP7702.sol";

/**
 * @title UpgradeableOpenfortProxy (Non-upgradeable)
 * @notice Contract to create the proxies
 * It inherits from:
 *  - ERC1967Proxy
 */
contract OPF7702Proxy {
    address public immutable delegationProxy;

    constructor(address _delegationImplementation) payable {
        delegationProxy = LibEIP7702.deployProxy(_delegationImplementation, address(0));
    }
}
