// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import "lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC721/utils/ERC721Holder.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC1155/utils/ERC1155Holder.sol";

/// @title IBaseOPF7702
/// @notice Interface for BaseOPF7702 (ERC-4337 / Account Abstraction account)
/// @dev Declares all externally-visible state, functions, and events.
interface IBaseOPF7702 is IAccount, IERC1271, IERC165, IERC721Receiver, IERC1155Receiver {
    // =============================================================
    //                            ERRORS
    // =============================================================

    error OpenfortBaseAccount7702V1__InvalidSignature();
    /// @notice msg.sender not from address(this) and nit from Entry Point
    error OpenfortBaseAccount7702V1_UnauthorizedCaller();

    // =============================================================
    //                             EVENTS
    // =============================================================

    /// @notice Emitted when ETH is deposited into this account for covering gas fees.
    /// @param source The address that sent the ETH deposit.
    /// @param amount The amount of ETH deposited.
    event DepositAdded(address indexed source, uint256 amount);

    // =============================================================
    //                        EXTERNAL FUNCTIONS
    // =============================================================

    /// @notice Returns the entry point contract used by this account.
    /// @return The `IEntryPoint` implementation address.
    /// @dev Required by `IAccount` interface to route UserOperations.
    function entryPoint() external view returns (IEntryPoint);

    /// @notice Checks if the contract implements a given interface.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return `true` if this contract supports `interfaceId`, `false` otherwise.
    /// @dev Combines ERC-165, IAccount, IERC1271, ERC721Receiver, and ERC1155Receiver.
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
