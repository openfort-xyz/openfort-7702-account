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
pragma solidity 0.8.29;

import {LibEIP7702} from "solady/accounts/LibEIP7702.sol";
import {OPF7702Recoverable} from "src/core/OPF7702Recoverable.sol";

/**
 * @title   Openfort Base Account 7702 with ERC-4337 Support
 * @author  Openfort@0xkoiner
 * @notice  Smart contract wallet implementing EIP-7702 + ERC-4337 with guardian-based recovery and multi-format keys.
 * @dev
 *  • EIP-4337 integration via EntryPoint
 *  • EIP-7702 support (e.g., setCode)
 *  • Multi-scheme keys: EOA (ECDSA), WebAuthn, P256/P256NONKEY
 *  • ETH/token spending limits + selector whitelists
 *  • ERC-1271 on-chain signature support
 *  • Reentrancy protection & explicit nonce replay prevention
 *
 * /// @dev keccak256(abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)) & ~bytes32(uint256(0xff))
 * Layout storage slot:
 *    0xeddd36aac8c71936fe1d5edb073ff947aa7c1b6174e87c15677c96ab9ad95400
 *    == 107588995614188179791452663824698570634674667931787294340862201729294267929600
 */
contract OPFMain is OPF7702Recoverable layout at 107588995614188179791452663824698570634674667931787294340862201729294267929600 {
    /**
     * @param _entryPoint       ERC-4337 EntryPoint address.
     * @param _webAuthnVerifier WebAuthn verifier contract for P-256/WebAuthn signature checks.
     * @param _gasPolicy        Gas/UserOp policy contract (used for custodial key policy init).
     * @param _recoveryManager  Social Recovery Manager contract that manages guardians & recovery flow.
     */
    constructor(
        address _entryPoint,
        address _webAuthnVerifier,
        address _gasPolicy,
        address _recoveryManager
    ) OPF7702Recoverable(_entryPoint, _webAuthnVerifier, _gasPolicy, _recoveryManager) {}

    /**
     * @notice Updates the delegated implementation used by the EIP-7702 authority proxy.
     * @dev    Has no effect if the authority is not currently delegated via an EIP-7702 proxy.
     *         The `newImplementation` contract must expose an `upgradeProxyDelegation` entry point
     *         (or equivalent) to allow future upgrades.
     * @param newImplementation Address of the implementation contract to delegate to.
     */
    function upgradeProxyDelegation(address newImplementation) public virtual {
        _requireForExecute();
        LibEIP7702.upgradeProxyDelegation(newImplementation);
    }
}
