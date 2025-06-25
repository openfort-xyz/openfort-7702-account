// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {ERC1967Proxy} from "lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title UpgradeableOpenfortProxy (Non-upgradeable)
 * @notice Contract to create the proxies
 * It inherits from:
 *  - ERC1967Proxy
 */
contract UpgradeableOpenfortProxy is ERC1967Proxy layout at 107588995614188179791452663824698570634674667931787294340862201729294267929600 {
    constructor(address _logic, bytes memory _data) ERC1967Proxy(_logic, _data) {}

    function implementation() external view returns (address) {
        return _implementation();
    }
}
