// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IERC165} from "lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";
import {IERC1271} from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {IERC721Receiver} from
    "lib/openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from
    "lib/openzeppelin-contracts/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC777Recipient} from
    "lib/openzeppelin-contracts/contracts/interfaces/IERC777Recipient.sol";

/// @title IBaseOPF7702
/// @notice Canonical surface for the shared Openfort 7702 account logic.
/// @dev Mirrors the public/external API exposed via `BaseOPF7702`.
interface IBaseOPF7702 is
    IAccount,
    IERC165,
    IERC1271,
    IERC721Receiver,
    IERC1155Receiver,
    IERC777Recipient
{
    // =============================================================
    //                            ERRORS
    // =============================================================

    /// @notice Thrown when signature validation fails for a user operation.
    error OpenfortBaseAccount7702V1__InvalidSignature();
    /// @notice Thrown when a privileged function is invoked by an unauthorized caller.
    error OpenfortBaseAccount7702V1_UnauthorizedCaller();
    /// @notice Thrown when attempting to update an address with the same value already stored.
    error BaseOPF7702__NoChangeUpdateContractAddress();

    // =============================================================
    //                             EVENTS
    // =============================================================

    /// @notice Emitted whenever ETH is deposited for this account.
    /// @param source Address that supplied the deposit.
    /// @param amount Amount of ETH credited.
    event DepositAdded(address indexed source, uint256 amount);

    /// @notice Emitted when the EntryPoint contract address is updated.
    /// @param newEntryPoint Address of the new EntryPoint singleton.
    event EntryPointUpdated(address indexed newEntryPoint);

    /// @notice Emitted when the WebAuthn verifier contract address is updated.
    /// @param newVerifier Address of the new verifier.
    event WebAuthnVerifierUpdated(address indexed newVerifier);

    // =============================================================
    //                        EXTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice Update the EntryPoint singleton used for ERC-4337 validation.
     * @param _entryPoint New EntryPoint contract address.
     */
    function setEntryPoint(address _entryPoint) external;

    /**
     * @notice Update the WebAuthn verifier singleton.
     * @param _webAuthnVerifier New verifier contract address.
     */
    function setWebAuthnVerifier(address _webAuthnVerifier) external;

    /**
     * @notice Update the Gas Policy contract used for custodial session keys.
     * @param _gasPolicy New gas-policy contract address.
     */
    function setGasPolicy(address _gasPolicy) external;

    /**
     * @notice Return the active EntryPoint contract.
     */
    function entryPoint() external view returns (IEntryPoint);

    /**
     * @notice Return the active WebAuthn verifier contract.
     */
    function webAuthnVerifier() external view returns (address);

    /**
     * @notice Return the active Gas Policy contract.
     */
    function gasPolicy() external view returns (address);

    /**
     * @notice ERC-165 detector.
     * @param interfaceId Interface identifier to query.
     * @return True if the interface is supported.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);

    /**
     * @notice ERC-777 callback invoked when tokens are sent or minted to this account.
     * @param operator Address initiating the transfer/mint.
     * @param from     Source address (zero for mints).
     * @param to       Recipient address (`address(this)`).
     * @param amount   Amount of tokens transferred.
     * @param userData User-provided metadata.
     * @param operatorData Operator-provided metadata.
     */
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external pure;
}
