/*
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░     ░░░░░░        ░░░         ░    ░░░░░   ░        ░░░░░░     ░░░░░░        ░░░░░           ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
▒▒▒   ▒▒▒▒   ▒▒▒   ▒▒▒▒   ▒   ▒▒▒▒▒▒▒  ▒   ▒▒▒   ▒   ▒▒▒▒▒▒▒▒▒   ▒▒▒▒   ▒▒▒   ▒▒▒▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒      ▒   ▒      ▒   ▒▒▒▒▒   ▒▒▒▒▒▒▒   ▒  ▒▒▒
▒   ▒▒▒▒▒▒▒▒   ▒   ▒▒▒▒   ▒   ▒▒▒▒▒▒▒   ▒   ▒▒   ▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒   ▒   ▒▒▒▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒   ▒▒▒▒   ▒▒   ▒▒▒  ▒▒▒▒▒   
▓   ▓▓▓▓▓▓▓▓   ▓        ▓▓▓       ▓▓▓   ▓▓   ▓   ▓       ▓▓▓   ▓▓▓▓▓▓▓▓   ▓  ▓   ▓▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓   ▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓
▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓  ▓   ▓   ▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓   ▓▓▓▓▓▓   ▓▓▓▓   ▓▓▓▓
▓▓▓   ▓▓▓▓▓   ▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓▓  ▓  ▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓   ▓▓   ▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓   ▓▓▓▓   ▓▓▓   ▓▓▓▓▓▓
█████     ██████   ████████         █   ██████   █   ███████████     ██████   ██████   █████   █████████   ████████   ████████    █████         █
█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
 */

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {IBaseOPF7702} from "src/interfaces/IBaseOPF7702.sol";
import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

import "src/interfaces/IERC7821.sol";
import "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import "lib/openzeppelin-contracts/contracts/utils/introspection/ERC165.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC721/utils/ERC721Holder.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC1155/utils/ERC1155Holder.sol";

/// @title BaseOPF7702
/// @author Openfort@0xkoiner
/// @notice Abstract base contract implementing an ERC-4337 (Account Abstraction) account with Openfort entry point integration.
/// @dev Inherits from IAccount (ERC-4337), BaseAccount (Openfort core logic), ERC165, ERC1271, and token receiver interfaces for ERC721 and ERC1155.
abstract contract BaseOPF7702 is
    IAccount,
    BaseAccount,
    IERC165,
    IERC7821,
    IERC1271,
    ERC721Holder,
    ERC1155Holder
{
    // =============================================================
    //                          CONSTANTS
    // =============================================================

    /// @dev Number of storage slots to clear in `_clearStorage`.
    uint256 private constant _NUM_CLEAR_SLOTS = 3;

    // =============================================================
    //                          STATE VARIABLES
    // =============================================================

    /// @notice The EntryPoint singleton contract used to dispatch user operations.
    address internal immutable ENTRY_POINT;

    // =============================================================
    //                       RECEIVE / FALLBACK
    // =============================================================

    /// @notice Fallback function to receive ETH without data.
    /// @dev `msg.data` does not match any function signature.
    fallback() external payable {}

    /// @notice Receive function to handle plain ETH transfers.
    /// @dev Emits `DepositAdded` event whenever ETH is received.
    receive() external payable {
        emit IBaseOPF7702.DepositAdded(msg.sender, msg.value);
    }

    // =============================================================
    //                        INTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice Clears the contract’s custom storage slots for reinitialization purposes.
     * @dev Uses inline assembly to set three consecutive storage slots (starting at keccak256("openfort.baseAccount.7702.v1")) to zero.
     *      Useful when proxy patterns or re-deployment require resetting specific storage.
     */
    function _clearStorage() internal {
        bytes32 baseSlot = keccak256("openfort.baseAccount.7702.v1");
        for (uint256 i = 0; i < _NUM_CLEAR_SLOTS;) {
            bytes32 slot = bytes32(uint256(baseSlot) + i);
            assembly {
                sstore(slot, 0)
            }
            unchecked {
                i++;
            }
        }
    }

    /**
     * @notice Ensures that only authorized callers can forward calls to this account.
     * @dev Overrides `BaseAccount._requireForExecute`. Only `address(this)` (self-call) or the designated `entryPoint()` can execute.
     *      Reverts with a generic require message if the caller is unauthorized.
     */
    function _requireForExecute() internal view virtual override {
        require(
            msg.sender == address(this) || msg.sender == address(entryPoint()),
            IBaseOPF7702.OpenfortBaseAccount7702V1_UnauthorizedCaller()
        );
    }

    // =============================================================
    //                    GETTERS PUBLIC FUNCTIONS
    // =============================================================

    /**
     * @notice Returns the entry point contract used by this account.
     * @return The `IEntryPoint` implementation address.
     * @dev Required by `IAccount` interface to route UserOperations.
     */
    function entryPoint() public view override returns (IEntryPoint) {
        return IEntryPoint(ENTRY_POINT);
    }

    /// @notice Checks if the contract implements a given interface.
    /// @param _interfaceId The interface identifier, as specified in ERC-165.
    /// @return `true` if this contract supports `_interfaceId`, `false` otherwise.
    /// @dev Overrides ERC1155Holder and IERC165’s `supportsInterface`.
    function supportsInterface(bytes4 _interfaceId)
        public
        pure
        override(ERC1155Holder, IERC165)
        returns (bool)
    {
        return _interfaceId == type(IERC165).interfaceId
            || _interfaceId == type(IAccount).interfaceId || _interfaceId == type(IERC1271).interfaceId
            || _interfaceId == type(IERC1155Receiver).interfaceId
            || _interfaceId == type(IERC721Receiver).interfaceId
            || _interfaceId == type(IERC7821).interfaceId;
    }
}
