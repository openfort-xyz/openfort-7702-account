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

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

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
    IERC1271,
    ERC721Holder,
    ERC1155Holder
{
    // =============================================================
    //                            ERRORS
    // =============================================================

    /// @notice Thrown when the provided nonce equals the current nonce (replay protection).
    error OpenfortBaseAccount7702V1__InvalidNonce();
    /// @notice Thrown when a signature fails verification.
    error OpenfortBaseAccount7702V1__InvalidSignature();
    /// @notice Thrown when the signature or transaction validity has expired.
    error OpenfortBaseAccount7702V1__ValidationExpired();
    /// @notice Thrown when the provided transaction length is invalid.
    error OpenfortBaseAccount7702V1__InvalidTransactionLength();
    /// @notice Thrown when the transaction target address is invalid.
    error OpenfortBaseAccount7702V1__InvalidTransactionTarget();
    /// @notice Thrown when a low-level call within a transaction fails.
    /// @param returnData The data returned by the failing call.
    error OpenfortBaseAccount7702V1__TransactionFailed(bytes returnData);

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

    /// @notice Current transaction nonce, used to prevent replay attacks.
    uint256 public nonce;

    // =============================================================
    //                             EVENTS
    // =============================================================

    /// @notice Emitted when ETH is deposited into this account for covering gas fees.
    /// @param source The address that sent the ETH deposit.
    /// @param amount The amount of ETH deposited.
    event DepositAdded(address indexed source, uint256 amount);

    // =============================================================
    //                       RECEIVE / FALLBACK
    // =============================================================

    /// @notice Fallback function to receive ETH without data.
    /// @dev `msg.data` does not match any function signature.
    fallback() external payable {}

    /// @notice Receive function to handle plain ETH transfers.
    /// @dev Emits `DepositAdded` event whenever ETH is received.
    receive() external payable {
        emit DepositAdded(msg.sender, msg.value);
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
     * @notice Verifies that the validation deadline has not passed.
     * @param _validUntil The UNIX timestamp until which the validation signatures remain valid.
     * @dev If the current block timestamp exceeds `_validUntil`, reverts with `ValidationExpired`.
     */
    function _notExpired(uint256 _validUntil) internal view {
        if (block.timestamp > _validUntil) {
            revert OpenfortBaseAccount7702V1__ValidationExpired();
        }
    }

    /**
     * @notice Validates that the provided nonce differs from the stored nonce.
     * @param _nonce The nonce from the user operation to compare.
     * @dev Reverts with `InvalidNonce` if `_nonce` equals the current `nonce`. Overrides `IAccount._validateNonce`.
     */
    function _validateNonce(uint256 _nonce) internal view override {
        if (_nonce == nonce) {
            revert OpenfortBaseAccount7702V1__InvalidNonce();
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
            "BaseOPF7702: unauthorized caller"
        );
    }

    // =============================================================
    //                         PUBLIC FUNCTIONS
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
            || _interfaceId == type(IERC721Receiver).interfaceId;
    }
}
