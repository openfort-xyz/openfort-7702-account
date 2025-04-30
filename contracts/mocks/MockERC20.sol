// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("MockERC20", "MC20") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
