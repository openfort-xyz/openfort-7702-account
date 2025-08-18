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

    /// @notice Thrown when ECDSA signature recovery fails or signature is not from expected ephemeral key
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

    /// @notice Emitted when the EntryPoint contract address is updated
    /// @dev This event is fired when the account's EntryPoint reference is changed,
    ///      which affects how UserOperations are processed and validated
    /// @param newEntryPoint The address of the new EntryPoint contract
    event EntryPointUpdated(address indexed newEntryPoint);

    /// @notice Emitted when the WebAuthn verifier contract address is updated
    /// @dev This event is triggered when the account updates its WebAuthn signature
    ///      verification contract, affecting how WebAuthn signatures are validated
    /// @param newVerifier The address of the new WebAuthn verifier contract
    event WebAuthnVerifierUpdated(address indexed newVerifier);

    // =============================================================
    //                        EXTERNAL FUNCTIONS
    // =============================================================

    /// @notice Updates the EntryPoint contract address used by this account
    /// @param _entryPoint The new EntryPoint contract address to set
    /// @dev Only callable by authorized parties (self or current EntryPoint).
    ///      Uses UpgradeAddress library to handle the update logic
    function setEntryPoint(address _entryPoint) external;

    /// @notice Updates the WebAuthn verifier contract address used by this account
    /// @param _webAuthnVerifier The new WebAuthn verifier contract address to set
    /// @dev Only callable by authorized parties (self or current EntryPoint).
    ///      Uses UpgradeAddress library to handle the update logic
    function setWebAuthnVerifier(address _webAuthnVerifier) external;

    /// @notice Returns the entry point contract used by this account.
    /// @return The `IEntryPoint` implementation address.
    /// @dev Required by `IAccount` interface to route UserOperations.
    function entryPoint() external view returns (IEntryPoint);

    /**
     * @notice Returns the webAuthn verifier contract used by this account.
     * @return The `address` of implementation.
     */
    function webAuthnVerifier() external view returns (address);

    /// @notice Checks if the contract implements a given interface.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return `true` if this contract supports `interfaceId`, `false` otherwise.
    /// @dev Combines ERC-165, IAccount, IERC1271, ERC721Receiver, and ERC1155Receiver.
    function supportsInterface(bytes4 interfaceId) external view returns (bool);

    /// @notice Called by an ERC777 token contract whenever tokens are being moved or created into this account
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata)
        external
        pure;
}
