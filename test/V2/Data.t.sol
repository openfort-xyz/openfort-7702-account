// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import "lib/forge-std/src/StdJson.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {Test} from "lib/forge-std/src/Test.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";

contract Data is Test, IKey, IKeysManager {
    /* ──────────────────────────────────────────────────────────────── structs ──── */
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    struct WebAuthn {
        bool UVR;
        bytes AUTHENTICATOR_DATA;
        string CLIENT_DATA_JSON;
        uint256 CHALLENGE_INDEX;
        uint256 TYPE_INDEX;
        bytes32 R;
        bytes32 S;
        bytes32 X;
        bytes32 Y;
    }

    struct P256 {
        bytes32 R;
        bytes32 S;
        bytes32 X;
        bytes32 Y;
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

    /* ───────────────────────────────────────────────────────────── master key ETH Module ── */
    string public json_eth_dep = vm.readFile("test/data/eth.json");

    bytes32 public ETH_CHALLENGE = stdJson.readBytes32(json_eth_dep, ".eth.challenge");

    bytes32 public ETH_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_dep, ".eth.x");
    bytes32 public ETH_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_dep, ".eth.y");

    bytes32 public ETH_SIGNATURE_R = stdJson.readBytes32(json_eth_dep, ".eth.signature.r");
    bytes32 public ETH_SIGNATURE_S = stdJson.readBytes32(json_eth_dep, ".eth.signature.s");

    uint256 public ETH_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_dep, ".eth.metadata.challengeIndex");
    uint256 public ETH_TYPE_INDEX = stdJson.readUint(json_eth_dep, ".eth.metadata.typeIndex");
    bool public ETH_UVR = stdJson.readBool(json_eth_dep, ".eth.metadata.userVerificationRequired");

    bytes public ETH_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_dep, ".eth.metadata.authenticatorData");

    string public ETH_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_dep, ".eth.metadata.clientDataJSON");

    WebAuthn ETH_WEBAUTHN = WebAuthn({
        UVR: ETH_UVR,
        AUTHENTICATOR_DATA: ETH_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: ETH_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: ETH_CHALLENGE_INDEX,
        TYPE_INDEX: ETH_TYPE_INDEX,
        R: ETH_SIGNATURE_R,
        S: ETH_SIGNATURE_S,
        X: ETH_PUBLIC_KEY_X,
        Y: ETH_PUBLIC_KEY_Y
    });

    bytes32 public ETH_BATCH_CHALLENGE = stdJson.readBytes32(json_eth_dep, ".eth_batch.challenge");

    bytes32 public ETH_BATCH_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_dep, ".eth_batch.x");
    bytes32 public ETH_BATCH_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_dep, ".eth_batch.y");

    bytes32 public ETH_BATCH_SIGNATURE_R =
        stdJson.readBytes32(json_eth_dep, ".eth_batch.signature.r");
    bytes32 public ETH_BATCH_SIGNATURE_S =
        stdJson.readBytes32(json_eth_dep, ".eth_batch.signature.s");

    uint256 public ETH_BATCH_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_dep, ".eth_batch.metadata.challengeIndex");
    uint256 public ETH_BATCH_TYPE_INDEX =
        stdJson.readUint(json_eth_dep, ".eth_batch.metadata.typeIndex");
    bool public ETH_BATCH_UVR =
        stdJson.readBool(json_eth_dep, ".eth_batch.metadata.userVerificationRequired");

    bytes public ETH_BATCH_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_dep, ".eth_batch.metadata.authenticatorData");

    string public ETH_BATCH_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_dep, ".eth_batch.metadata.clientDataJSON");

    WebAuthn ETH_BATCH_WEBAUTHN = WebAuthn({
        UVR: ETH_BATCH_UVR,
        AUTHENTICATOR_DATA: ETH_BATCH_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: ETH_BATCH_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: ETH_BATCH_CHALLENGE_INDEX,
        TYPE_INDEX: ETH_BATCH_TYPE_INDEX,
        R: ETH_BATCH_SIGNATURE_R,
        S: ETH_BATCH_SIGNATURE_S,
        X: ETH_BATCH_PUBLIC_KEY_X,
        Y: ETH_BATCH_PUBLIC_KEY_Y
    });

    /* ───────────────────────────────────────────────────────────── P256 ETH Module ── */
    string public json_eth_p256 = vm.readFile("test/data/p256_eth.json");

    bytes32 ETH_P256_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_p256, ".result.P256_xHex");
    bytes32 ETH_P256_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_p256, ".result.P256_yHex");

    bytes32 ETH_P256_SIGNATURE_R = stdJson.readBytes32(json_eth_p256, ".result.P256_lowSR");
    bytes32 ETH_P256_SIGNATURE_S = stdJson.readBytes32(json_eth_p256, ".result.P256_lowSS");

    P256 ETH_P256 = P256({
        R: ETH_P256_SIGNATURE_R,
        S: ETH_P256_SIGNATURE_S,
        X: ETH_P256_PUBLIC_KEY_X,
        Y: ETH_P256_PUBLIC_KEY_Y
    });

    bytes32 ETH_P256_NON_PUBLIC_KEY_X =
        stdJson.readBytes32(json_eth_p256, ".result2.P256NONKEY_xHex");
    bytes32 ETH_P256_NON_PUBLIC_KEY_Y =
        stdJson.readBytes32(json_eth_p256, ".result2.P256NONKEY_yHex");

    bytes32 ETH_P256_NON_SIGNATURE_R =
        stdJson.readBytes32(json_eth_p256, ".result2.P256NONKEY_rHex");
    bytes32 ETH_P256_NON_SIGNATURE_S =
        stdJson.readBytes32(json_eth_p256, ".result2.P256NONKEY_sHex");

    P256 ETH_P256_NON = P256({
        R: ETH_P256_NON_SIGNATURE_R,
        S: ETH_P256_NON_SIGNATURE_S,
        X: ETH_P256_NON_PUBLIC_KEY_X,
        Y: ETH_P256_NON_PUBLIC_KEY_Y
    });

    string public json_eth_batch_p256 = vm.readFile("test/data/p256_eth_batch.json");

    bytes32 ETH_BATCH_P256_PUBLIC_KEY_X =
        stdJson.readBytes32(json_eth_batch_p256, ".result.P256_xHex");
    bytes32 ETH_BATCH_P256_PUBLIC_KEY_Y =
        stdJson.readBytes32(json_eth_batch_p256, ".result.P256_yHex");

    bytes32 ETH_BATCH_P256_SIGNATURE_R =
        stdJson.readBytes32(json_eth_batch_p256, ".result.P256_lowSR");
    bytes32 ETH_BATCH_P256_SIGNATURE_S =
        stdJson.readBytes32(json_eth_batch_p256, ".result.P256_lowSS");

    P256 ETH_BATCH_P256 = P256({
        R: ETH_BATCH_P256_SIGNATURE_R,
        S: ETH_BATCH_P256_SIGNATURE_S,
        X: ETH_BATCH_P256_PUBLIC_KEY_X,
        Y: ETH_BATCH_P256_PUBLIC_KEY_Y
    });

    bytes32 ETH_BATCH_P256_NON_PUBLIC_KEY_X =
        stdJson.readBytes32(json_eth_batch_p256, ".result2.P256NONKEY_xHex");
    bytes32 ETH_BATCH_P256_NON_PUBLIC_KEY_Y =
        stdJson.readBytes32(json_eth_batch_p256, ".result2.P256NONKEY_yHex");

    bytes32 ETH_BATCH_P256_NON_SIGNATURE_R =
        stdJson.readBytes32(json_eth_batch_p256, ".result2.P256NONKEY_rHex");
    bytes32 ETH_BATCH_P256_NON_SIGNATURE_S =
        stdJson.readBytes32(json_eth_batch_p256, ".result2.P256NONKEY_sHex");

    P256 ETH_BATCH_P256_NON = P256({
        R: ETH_BATCH_P256_NON_SIGNATURE_R,
        S: ETH_BATCH_P256_NON_SIGNATURE_S,
        X: ETH_BATCH_P256_NON_PUBLIC_KEY_X,
        Y: ETH_BATCH_P256_NON_PUBLIC_KEY_Y
    });

    /* ───────────────────────────────────────────────────────────── master key Execution Module ── */
    string public json_eth_exe = vm.readFile("test/data/execution.json");

    bytes32 public EXE_CHALLENGE = stdJson.readBytes32(json_eth_exe, ".batch.challenge");

    bytes32 public EXE_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_exe, ".batch.x");
    bytes32 public EXE_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_exe, ".batch.y");

    bytes32 public EXE_SIGNATURE_R = stdJson.readBytes32(json_eth_exe, ".batch.signature.r");
    bytes32 public EXE_SIGNATURE_S = stdJson.readBytes32(json_eth_exe, ".batch.signature.s");

    uint256 public EXE_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_exe, ".batch.metadata.challengeIndex");
    uint256 public EXE_TYPE_INDEX = stdJson.readUint(json_eth_exe, ".batch.metadata.typeIndex");
    bool public EXE_UVR = stdJson.readBool(json_eth_exe, ".batch.metadata.userVerificationRequired");

    bytes public EXE_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_exe, ".batch.metadata.authenticatorData");

    string public EXE_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_exe, ".batch.metadata.clientDataJSON");

    WebAuthn EXE_WEBAUTHN = WebAuthn({
        UVR: EXE_UVR,
        AUTHENTICATOR_DATA: EXE_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: EXE_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: EXE_CHALLENGE_INDEX,
        TYPE_INDEX: EXE_TYPE_INDEX,
        R: EXE_SIGNATURE_R,
        S: EXE_SIGNATURE_S,
        X: EXE_PUBLIC_KEY_X,
        Y: EXE_PUBLIC_KEY_Y
    });

    bytes32 public EXE_BATCH_CHALLENGE =
        stdJson.readBytes32(json_eth_exe, ".batchofbatches.challenge");

    bytes32 public EXE_BATCH_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_exe, ".batchofbatches.x");
    bytes32 public EXE_BATCH_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_exe, ".batchofbatches.y");

    bytes32 public EXE_BATCH_SIGNATURE_R =
        stdJson.readBytes32(json_eth_exe, ".batchofbatches.signature.r");
    bytes32 public EXE_BATCH_SIGNATURE_S =
        stdJson.readBytes32(json_eth_exe, ".batchofbatches.signature.s");

    uint256 public EXE_BATCH_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_exe, ".batchofbatches.metadata.challengeIndex");
    uint256 public EXE_BATCH_TYPE_INDEX =
        stdJson.readUint(json_eth_exe, ".batchofbatches.metadata.typeIndex");
    bool public EXE_BATCH_UVR =
        stdJson.readBool(json_eth_exe, ".batchofbatches.metadata.userVerificationRequired");

    bytes public EXE_BATCH_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_exe, ".batchofbatches.metadata.authenticatorData");

    string public EXE_BATCH_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_exe, ".batchofbatches.metadata.clientDataJSON");

    WebAuthn EXE_BATCH_WEBAUTHN = WebAuthn({
        UVR: EXE_BATCH_UVR,
        AUTHENTICATOR_DATA: EXE_BATCH_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: EXE_BATCH_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: EXE_BATCH_CHALLENGE_INDEX,
        TYPE_INDEX: EXE_BATCH_TYPE_INDEX,
        R: EXE_BATCH_SIGNATURE_R,
        S: EXE_BATCH_SIGNATURE_S,
        X: EXE_BATCH_PUBLIC_KEY_X,
        Y: EXE_BATCH_PUBLIC_KEY_Y
    });

    /* ───────────────────────────────────────────────────────────── P256 Execution Module ── */
    string public json_exe_p256 = vm.readFile("test/data/p256_exe.json");

    bytes32 EXE_P256_PUBLIC_KEY_X = stdJson.readBytes32(json_exe_p256, ".result.P256_xHex");
    bytes32 EXE_P256_PUBLIC_KEY_Y = stdJson.readBytes32(json_exe_p256, ".result.P256_yHex");

    bytes32 EXE_P256_SIGNATURE_R = stdJson.readBytes32(json_exe_p256, ".result.P256_lowSR");
    bytes32 EXE_P256_SIGNATURE_S = stdJson.readBytes32(json_exe_p256, ".result.P256_lowSS");

    P256 EXE_P256 = P256({
        R: EXE_P256_SIGNATURE_R,
        S: EXE_P256_SIGNATURE_S,
        X: EXE_P256_PUBLIC_KEY_X,
        Y: EXE_P256_PUBLIC_KEY_Y
    });

    bytes32 EXE_P256_NON_PUBLIC_KEY_X =
        stdJson.readBytes32(json_exe_p256, ".result2.P256NONKEY_xHex");
    bytes32 EXE_P256_NON_PUBLIC_KEY_Y =
        stdJson.readBytes32(json_exe_p256, ".result2.P256NONKEY_yHex");

    bytes32 EXE_P256_NON_SIGNATURE_R =
        stdJson.readBytes32(json_exe_p256, ".result2.P256NONKEY_rHex");
    bytes32 EXE_P256_NON_SIGNATURE_S =
        stdJson.readBytes32(json_exe_p256, ".result2.P256NONKEY_sHex");

    P256 EXE_P256_NON = P256({
        R: EXE_P256_NON_SIGNATURE_R,
        S: EXE_P256_NON_SIGNATURE_S,
        X: EXE_P256_NON_PUBLIC_KEY_X,
        Y: EXE_P256_NON_PUBLIC_KEY_Y
    });

    string public json_exe_batch_p256 = vm.readFile("test/data/p256_exe_batch.json");

    bytes32 EXE_BATCH_P256_PUBLIC_KEY_X =
        stdJson.readBytes32(json_exe_batch_p256, ".result.P256_xHex");
    bytes32 EXE_BATCH_P256_PUBLIC_KEY_Y =
        stdJson.readBytes32(json_exe_batch_p256, ".result.P256_yHex");

    bytes32 EXE_BATCH_P256_SIGNATURE_R =
        stdJson.readBytes32(json_exe_batch_p256, ".result.P256_lowSR");
    bytes32 EXE_BATCH_P256_SIGNATURE_S =
        stdJson.readBytes32(json_exe_batch_p256, ".result.P256_lowSS");

    P256 EXE_BATCH_P256 = P256({
        R: EXE_BATCH_P256_SIGNATURE_R,
        S: EXE_BATCH_P256_SIGNATURE_S,
        X: EXE_BATCH_P256_PUBLIC_KEY_X,
        Y: EXE_BATCH_P256_PUBLIC_KEY_Y
    });

    bytes32 EXE_BATCH_P256_NON_PUBLIC_KEY_X =
        stdJson.readBytes32(json_exe_batch_p256, ".result2.P256NONKEY_xHex");
    bytes32 EXE_BATCH_P256_NON_PUBLIC_KEY_Y =
        stdJson.readBytes32(json_exe_batch_p256, ".result2.P256NONKEY_yHex");

    bytes32 EXE_BATCH_P256_NON_SIGNATURE_R =
        stdJson.readBytes32(json_exe_batch_p256, ".result2.P256NONKEY_rHex");
    bytes32 EXE_BATCH_P256_NON_SIGNATURE_S =
        stdJson.readBytes32(json_exe_batch_p256, ".result2.P256NONKEY_sHex");

    P256 EXE_BATCH_P256_NON = P256({
        R: EXE_BATCH_P256_NON_SIGNATURE_R,
        S: EXE_BATCH_P256_NON_SIGNATURE_S,
        X: EXE_BATCH_P256_NON_PUBLIC_KEY_X,
        Y: EXE_BATCH_P256_NON_PUBLIC_KEY_Y
    });
}
