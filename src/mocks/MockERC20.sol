// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import { ERC20 } from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Openfort7702", "OPF7702") { }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
