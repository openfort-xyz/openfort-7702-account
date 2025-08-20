// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import { ReentrancyGuard } from "lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

contract SimpleContract is ReentrancyGuard, Ownable {
    /// @notice Emitted when deposit is added for gas fees
    event DepositAdded(address indexed source, uint256 amount);

    /// @notice Emitted when withdrawal is made
    event WithdrawalMade(address indexed to, uint256 amount);

    constructor(address initialOwner) Ownable(initialOwner) { }

    fallback() external payable {
        emit DepositAdded(msg.sender, msg.value);
    }

    receive() external payable {
        emit DepositAdded(msg.sender, msg.value);
    }

    /// @notice Allows owner to withdraw funds
    /// @param amount Amount to withdraw (0 for full balance)
    function withdraw(uint256 amount) external onlyOwner nonReentrant {
        uint256 withdrawAmount = amount == 0 ? address(this).balance : amount;
        require(withdrawAmount <= address(this).balance, "Insufficient balance");

        (bool success,) = payable(owner()).call{ value: withdrawAmount }("");
        require(success, "Withdrawal failed");

        emit WithdrawalMade(owner(), withdrawAmount);
    }

    /// @notice Get contract balance
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
