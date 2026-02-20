// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {
    ERC20Permit
} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract MockERC20Permit is ERC20Permit {
    constructor() payable ERC20("MockERC20Permit", "MERC") ERC20Permit("MockERC20Permit") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
        return true;
    }
}
