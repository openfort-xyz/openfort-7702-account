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

import {UpgradeAddress} from "src/libs/UpgradeAddress.sol";
import {IBaseOPF7702} from "src/interfaces/IBaseOPF7702.sol";
import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

import "src/interfaces/IERC7821.sol";
import "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import "lib/openzeppelin-contracts/contracts/utils/introspection/ERC165.sol";
import "lib/openzeppelin-contracts/contracts/interfaces/IERC777Recipient.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC721/utils/ERC721Holder.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC1155/utils/ERC1155Holder.sol";

/// @title BaseOPF7702
/// @author Openfort@0xkoiner
/// @notice Abstract base contract implementing an ERC-4337 (Account Abstraction) account with Openfort entry point
/// integration.
/// @dev Inherits from IAccount (ERC-4337), BaseAccount (Openfort core logic), ERC165, ERC1271, and token receiver
/// interfaces for ERC721 and ERC1155.
abstract contract BaseOPF7702 is
    IERC165,
    IERC1271,
    IERC7821,
    BaseAccount,
    ERC721Holder,
    ERC1155Holder,
    IERC777Recipient
{
    using UpgradeAddress for address;

    /// @notice Revert if msg.sender != entryPoint()
    error NotFromEntryPoint();
    /// @notice Revert if _entryPoint/_webAuthnVerifier/_gasPolicy == previous
    error BaseOPF7702__NoChangeUpdateContractAddress();

    // =============================================================
    //                          STATE VARIABLES
    // =============================================================

    /// @notice The EntryPoint singleton contract used to dispatch user operations.
    address internal immutable ENTRY_POINT;

    /// @notice The WebAuthn Verifier singleton contract used to verify WebAuthn and P256 signatures.
    address public immutable WEBAUTHN_VERIFIER;

    /// @notice The Gas Policy Verifier singleton contract used to verify and set gas policy of session keys.
    address public immutable GAS_POLICY;

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

    // ──────────────────────────────────────────────────────────────────────────────
    //                          Public / External methods
    // ──────────────────────────────────────────────────────────────────────────────

    /// @notice Updates the EntryPoint contract address used by this account
    /// @param _entryPoint The new EntryPoint contract address to set
    /// @dev Only callable by authorized parties (self or current EntryPoint).
    ///      Uses UpgradeAddress library to handle the update logic
    function setEntryPoint(address _entryPoint) external {
        _requireForExecute();
        address previous = address(entryPoint());
        if (_entryPoint == previous) revert BaseOPF7702__NoChangeUpdateContractAddress();

        _entryPoint.setEntryPoint();

        emit UpgradeAddress.EntryPointUpdated(previous, address(entryPoint()));
    }

    /// @notice Updates the WebAuthn verifier contract address used by this account
    /// @param _webAuthnVerifier The new WebAuthn verifier contract address to set
    /// @dev Only callable by authorized parties (self or current EntryPoint).
    ///      Uses UpgradeAddress library to handle the update logic
    function setWebAuthnVerifier(address _webAuthnVerifier) external {
        _requireForExecute();
        address previous = webAuthnVerifier();
        if (_webAuthnVerifier == previous) revert BaseOPF7702__NoChangeUpdateContractAddress();

        _webAuthnVerifier.setWebAuthnVerifier();

        emit UpgradeAddress.WebAuthnVerifierUpdated(previous, webAuthnVerifier());
    }

    /// @notice Updates the Gas Policy contract address used by this account
    /// @param _gasPolicy The new WebAuthn Gas Policy contract address to set
    /// @dev Only callable by authorized parties (self or current EntryPoint).
    ///      Uses UpgradeAddress library to handle the update logic
    function setGasPolicy(address _gasPolicy) external {
        _requireForExecute();
        address previous = address(gasPolicy());
        if (_gasPolicy == previous) revert BaseOPF7702__NoChangeUpdateContractAddress();

        _gasPolicy.setGasPolicy();

        emit UpgradeAddress.GasPolicyUpdated(previous, gasPolicy());
    }

    // =============================================================
    //                        INTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice Clears the contract’s custom storage slots for reinitialization purposes.
     * @dev Uses inline assembly to set three consecutive storage slots
     *      keccak256(abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)) & ~bytes32(uint256(0xff)) to
     * zero.
     *      Useful when proxy patterns or re-deployment require resetting specific storage.
     */
    function _clearStorage() internal {
        bytes32 baseSlot = keccak256(
            abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)
        ) & ~bytes32(uint256(0xff));

        // clear slot 0, _EP_SLOT & _VERIFIER_SLOT & _GAS_SLOT
        bytes32 epSlot = UpgradeAddress._EP_SLOT;
        bytes32 verifierSlot = UpgradeAddress._VERIFIER_SLOT;
        bytes32 gasPolicySlot = UpgradeAddress._GAS_POLICY_SLOT;
        assembly {
            sstore(baseSlot, 0)
            sstore(epSlot, 0)
            sstore(verifierSlot, 0)
            sstore(gasPolicySlot, 0)
        }

        // Clear ReentrancyGuard status (S+4) to a safe state (0 is fine; first guarded call will set + normalize to 1)
        assembly {
            sstore(add(baseSlot, 4), 0)
        }

        // ---- Clear composite structs:
        // recoveryData: starts at base+8, size 4 slots  -> [8,9,10,11]
        // guardiansData: starts at base+12, size 3 slots -> [12,13,14]
        unchecked {
            for (uint256 i = 6; i <= 14; ++i) {
                bytes32 slot = bytes32(uint256(baseSlot) + i);
                assembly {
                    sstore(slot, 0)
                }
            }
        }
    }
    /**
     * ╭------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------╮
     * | Name             | Type                                     | Slot                                                                           | Offset | Bytes | Contract                     |
     * +==============================================================================================================================================================================================+
     * | id               | uint256                                  | 107588995614188179791452663824698570634674667931787294340862201729294267929600 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
     * |------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
     * | idKeys           | mapping(uint256 => struct IKey.Key)      | 107588995614188179791452663824698570634674667931787294340862201729294267929601 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
     * |------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
     * | keys             | mapping(bytes32 => struct IKey.KeyData)  | 107588995614188179791452663824698570634674667931787294340862201729294267929602 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
     * |------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
     * | usedChallenges   | mapping(bytes32 => bool)                 | 107588995614188179791452663824698570634674667931787294340862201729294267929603 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
     * |------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
     * | _status          | uint256                                  | 107588995614188179791452663824698570634674667931787294340862201729294267929604 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
     * |------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
     * | _initialized     | uint64                                   | 107588995614188179791452663824698570634674667931787294340862201729294267929605 | 0      | 8     | src/core/OPFMain.sol:OPFMain |
     * |------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
     * | _initializing    | bool                                     | 107588995614188179791452663824698570634674667931787294340862201729294267929605 | 8      | 1     | src/core/OPFMain.sol:OPFMain |
     * |------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
     * | _nameFallback    | string                                   | 107588995614188179791452663824698570634674667931787294340862201729294267929606 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
     * |------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
     * | _versionFallback | string                                   | 107588995614188179791452663824698570634674667931787294340862201729294267929607 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
     * |------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
     * | recoveryData     | struct IOPF7702Recoverable.RecoveryData  | 107588995614188179791452663824698570634674667931787294340862201729294267929608 | 0      | 128   | src/core/OPFMain.sol:OPFMain |
     * |------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
     * | guardiansData    | struct IOPF7702Recoverable.GuardiansData | 107588995614188179791452663824698570634674667931787294340862201729294267929612 | 0      | 96    | src/core/OPFMain.sol:OPFMain |
     * ╰------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------╯
     */

    /**
     * @notice Ensures that only authorized callers can forward calls to this account.
     * @dev Overrides `BaseAccount._requireForExecute`. Only `address(this)` (self-call) or the designated
     * `entryPoint()` can execute.
     *      Reverts with a generic require message if the caller is unauthorized.
     */
    function _requireForExecute() internal view virtual override {
        require(
            msg.sender == address(this) || msg.sender == address(entryPoint()),
            IBaseOPF7702.OpenfortBaseAccount7702V1_UnauthorizedCaller()
        );
    }

    function _requireFromEntryPoint() internal view virtual override {
        require(msg.sender == address(entryPoint()), NotFromEntryPoint());
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
        return IEntryPoint(UpgradeAddress.entryPoint(ENTRY_POINT));
    }

    /**
     * @notice Returns the webAuthn verifier contract used by this account.
     * @return The `address` of implementation.
     */
    function webAuthnVerifier() public view returns (address) {
        return UpgradeAddress.webAuthnVerifier(WEBAUTHN_VERIFIER);
    }

    /**
     * @notice Returns the Gas Policy contract used by this account.
     * @return The `address` of implementation.
     */
    function gasPolicy() public view returns (address) {
        return UpgradeAddress.gasPolicy(GAS_POLICY);
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
            || _interfaceId == type(IERC7821).interfaceId
            || _interfaceId == type(IERC721Receiver).interfaceId
            || _interfaceId == type(IERC1155Receiver).interfaceId
            || _interfaceId == type(IERC777Recipient).interfaceId;
    }

    /// @notice Called by an ERC777 token contract whenever tokens are being moved or created into this account
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external pure override {}
}
