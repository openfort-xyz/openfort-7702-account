// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {SignersData} from "././SignersData.t.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";

contract Data is IKey, IKeysManager, SignersData {
    /* ──────────────────────────────────────────────────────────────── structs ──── */
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /* ──────────────────────────────────────────────────────────────── set data ──── */
    address internal constant ANY_TARGET = 0x3232323232323232323232323232323232323232;
    bytes4 internal constant ANY_FN_SEL = 0x32323232;
    bytes4 internal constant EMPTY_CALLDATA_FN_SEL = 0xe0e0e0e0;
    address internal constant NATIVE_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /* ──────────────────────────────────────────────────────────────── hashes ──── */
    bytes32 constant TYPE_HASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 constant RECOVER_TYPEHASH =
        0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;
    bytes32 constant INIT_TYPEHASH =
        0x82dc6262fca76342c646d126714aa4005dfcd866448478747905b2e7b9837183;

    /* ──────────────────────────────────────────────────────────────── addresses ──── */
    address constant ENTRYPOINT_V8 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address constant WEBAUTHN_VERIFIER = 0x83b7acb5A6aa8A34A97bdA13182aEA787AC3f10d;

    /* ──────────────────────────────────────────────────────────────── recovery data ──── */
    uint256 constant RECOVERY_PERIOD = 2 days;
    uint256 constant LOCK_PERIOD = 5 days;
    uint256 constant SECURITY_PERIOD = 1.5 days;
    uint256 constant SECURITY_WINDOW = 0.5 days;

    /* ──────────────────────────────────────────────────────────────── gas policy data ──── */
    uint256 constant DEFAULT_PVG = 110_000; // packaging/bytes for P-256/WebAuthn-ish signatures
    uint256 constant DEFAULT_VGL = 360_000; // validation (session key checks, EIP-1271/P-256 parsing)
    uint256 constant DEFAULT_CGL = 240_000; // ERC20 transfer/batch-ish execution
    uint256 constant DEFAULT_PMV = 60_000; // paymaster validate (if used)
    uint256 constant DEFAULT_PO = 60_000; // postOp (token charge/refund)

    /* ──────────────────────────────────────────────────────────────── execution mode erc7821 ──── */
    bytes32 internal constant mode_1 = bytes32(uint256(0x01000000000000000000) << (22 * 8));
    bytes32 internal constant mode_3 = bytes32(uint256(0x01000000000078210002) << (22 * 8));
}
