// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import "lib/forge-std/src/StdJson.sol";
import {Test} from "lib/forge-std/src/Test.sol";

contract SignersData is Test {
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

    /* ───────────────────────────────────────────────────────────── master key KeysManager Module ── */
    string public json_eth_key = vm.readFile("test/data/keysmanager.json");

    bytes32 public KEY_CHALLENGE = stdJson.readBytes32(json_eth_key, ".keys_register.challenge");

    bytes32 public KEY_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_key, ".keys_register.x");
    bytes32 public KEY_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_key, ".keys_register.y");

    bytes32 public KEY_SIGNATURE_R = stdJson.readBytes32(json_eth_key, ".keys_register.signature.r");
    bytes32 public KEY_SIGNATURE_S = stdJson.readBytes32(json_eth_key, ".keys_register.signature.s");

    uint256 public KEY_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_register.metadata.challengeIndex");
    uint256 public KEY_TYPE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_register.metadata.typeIndex");
    bool public KEY_UVR =
        stdJson.readBool(json_eth_key, ".keys_register.metadata.userVerificationRequired");

    bytes public KEY_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_key, ".keys_register.metadata.authenticatorData");

    string public KEY_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_key, ".keys_register.metadata.clientDataJSON");

    WebAuthn KEY_WEBAUTHN = WebAuthn({
        UVR: KEY_UVR,
        AUTHENTICATOR_DATA: KEY_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: KEY_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: KEY_CHALLENGE_INDEX,
        TYPE_INDEX: KEY_TYPE_INDEX,
        R: KEY_SIGNATURE_R,
        S: KEY_SIGNATURE_S,
        X: KEY_PUBLIC_KEY_X,
        Y: KEY_PUBLIC_KEY_Y
    });

    bytes32 public KEYR_CHALLENGE = stdJson.readBytes32(json_eth_key, ".keys_revoke.challenge");

    bytes32 public KEYR_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_key, ".keys_revoke.x");
    bytes32 public KEYR_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_key, ".keys_revoke.y");

    bytes32 public KEYR_SIGNATURE_R = stdJson.readBytes32(json_eth_key, ".keys_revoke.signature.r");
    bytes32 public KEYR_SIGNATURE_S = stdJson.readBytes32(json_eth_key, ".keys_revoke.signature.s");

    uint256 public KEYR_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_revoke.metadata.challengeIndex");
    uint256 public KEYR_TYPE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_revoke.metadata.typeIndex");
    bool public KEYR_UVR =
        stdJson.readBool(json_eth_key, ".keys_revoke.metadata.userVerificationRequired");

    bytes public KEYR_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_key, ".keys_revoke.metadata.authenticatorData");

    string public KEYR_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_key, ".keys_revoke.metadata.clientDataJSON");

    WebAuthn KEYR_WEBAUTHN = WebAuthn({
        UVR: KEYR_UVR,
        AUTHENTICATOR_DATA: KEYR_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: KEYR_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: KEYR_CHALLENGE_INDEX,
        TYPE_INDEX: KEYR_TYPE_INDEX,
        R: KEYR_SIGNATURE_R,
        S: KEYR_SIGNATURE_S,
        X: KEYR_PUBLIC_KEY_X,
        Y: KEYR_PUBLIC_KEY_Y
    });

    bytes32 public KEYT_CHALLENGE = stdJson.readBytes32(json_eth_key, ".keys_token.challenge");

    bytes32 public KEYT_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_key, ".keys_token.x");
    bytes32 public KEYT_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_key, ".keys_token.y");

    bytes32 public KEYT_SIGNATURE_R = stdJson.readBytes32(json_eth_key, ".keys_token.signature.r");
    bytes32 public KEYT_SIGNATURE_S = stdJson.readBytes32(json_eth_key, ".keys_token.signature.s");

    uint256 public KEYT_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_token.metadata.challengeIndex");
    uint256 public KEYT_TYPE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_token.metadata.typeIndex");
    bool public KEYT_UVR =
        stdJson.readBool(json_eth_key, ".keys_token.metadata.userVerificationRequired");

    bytes public KEYT_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_key, ".keys_token.metadata.authenticatorData");

    string public KEYT_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_key, ".keys_token.metadata.clientDataJSON");

    WebAuthn KEYT_WEBAUTHN = WebAuthn({
        UVR: KEYT_UVR,
        AUTHENTICATOR_DATA: KEYT_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: KEYT_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: KEYT_CHALLENGE_INDEX,
        TYPE_INDEX: KEYT_TYPE_INDEX,
        R: KEYT_SIGNATURE_R,
        S: KEYT_SIGNATURE_S,
        X: KEYT_PUBLIC_KEY_X,
        Y: KEYT_PUBLIC_KEY_Y
    });

    bytes32 public KEYU_CHALLENGE = stdJson.readBytes32(json_eth_key, ".keys_token_update.challenge");

    bytes32 public KEYU_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_key, ".keys_token_update.x");
    bytes32 public KEYU_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_key, ".keys_token_update.y");

    bytes32 public KEYU_SIGNATURE_R = stdJson.readBytes32(json_eth_key, ".keys_token_update.signature.r");
    bytes32 public KEYU_SIGNATURE_S = stdJson.readBytes32(json_eth_key, ".keys_token_update.signature.s");

    uint256 public KEYU_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_token_update.metadata.challengeIndex");
    uint256 public KEYU_TYPE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_token_update.metadata.typeIndex");
    bool public KEYU_UVR =
        stdJson.readBool(json_eth_key, ".keys_token_update.metadata.userVerificationRequired");

    bytes public KEYU_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_key, ".keys_token_update.metadata.authenticatorData");

    string public KEYU_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_key, ".keys_token_update.metadata.clientDataJSON");

    WebAuthn KEYU_WEBAUTHN = WebAuthn({
        UVR: KEYU_UVR,
        AUTHENTICATOR_DATA: KEYU_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: KEYU_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: KEYU_CHALLENGE_INDEX,
        TYPE_INDEX: KEYU_TYPE_INDEX,
        R: KEYU_SIGNATURE_R,
        S: KEYU_SIGNATURE_S,
        X: KEYU_PUBLIC_KEY_X,
        Y: KEYU_PUBLIC_KEY_Y
    });

    bytes32 public KEYUK_CHALLENGE = stdJson.readBytes32(json_eth_key, ".keys_update_key.challenge");

    bytes32 public KEYUK_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_key, ".keys_update_key.x");
    bytes32 public KEYUK_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_key, ".keys_update_key.y");

    bytes32 public KEYUK_SIGNATURE_R = stdJson.readBytes32(json_eth_key, ".keys_update_key.signature.r");
    bytes32 public KEYUK_SIGNATURE_S = stdJson.readBytes32(json_eth_key, ".keys_update_key.signature.s");

    uint256 public KEYUK_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_update_key.metadata.challengeIndex");
    uint256 public KEYUK_TYPE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_update_key.metadata.typeIndex");
    bool public KEYUK_UVR =
        stdJson.readBool(json_eth_key, ".keys_update_key.metadata.userVerificationRequired");

    bytes public KEYUK_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_key, ".keys_update_key.metadata.authenticatorData");

    string public KEYUK_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_key, ".keys_update_key.metadata.clientDataJSON");

    WebAuthn KEYUK_WEBAUTHN = WebAuthn({
        UVR: KEYUK_UVR,
        AUTHENTICATOR_DATA: KEYUK_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: KEYUK_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: KEYUK_CHALLENGE_INDEX,
        TYPE_INDEX: KEYUK_TYPE_INDEX,
        R: KEYUK_SIGNATURE_R,
        S: KEYUK_SIGNATURE_S,
        X: KEYUK_PUBLIC_KEY_X,
        Y: KEYUK_PUBLIC_KEY_Y
    });

    bytes32 public KEYCC_CHALLENGE = stdJson.readBytes32(json_eth_key, ".keys_can_call.challenge");

    bytes32 public KEYCC_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_key, ".keys_can_call.x");
    bytes32 public KEYCC_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_key, ".keys_can_call.y");

    bytes32 public KEYCC_SIGNATURE_R = stdJson.readBytes32(json_eth_key, ".keys_can_call.signature.r");
    bytes32 public KEYCC_SIGNATURE_S = stdJson.readBytes32(json_eth_key, ".keys_can_call.signature.s");

    uint256 public KEYCC_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_can_call.metadata.challengeIndex");
    uint256 public KEYCC_TYPE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_can_call.metadata.typeIndex");
    bool public KEYCC_UVR =
        stdJson.readBool(json_eth_key, ".keys_can_call.metadata.userVerificationRequired");

    bytes public KEYCC_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_key, ".keys_can_call.metadata.authenticatorData");

    string public KEYCC_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_key, ".keys_can_call.metadata.clientDataJSON");

    WebAuthn KEYCC_WEBAUTHN = WebAuthn({
        UVR: KEYCC_UVR,
        AUTHENTICATOR_DATA: KEYCC_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: KEYCC_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: KEYCC_CHALLENGE_INDEX,
        TYPE_INDEX: KEYCC_TYPE_INDEX,
        R: KEYCC_SIGNATURE_R,
        S: KEYCC_SIGNATURE_S,
        X: KEYCC_PUBLIC_KEY_X,
        Y: KEYCC_PUBLIC_KEY_Y
    });

    bytes32 public KEYCCR_CHALLENGE = stdJson.readBytes32(json_eth_key, ".keys_can_call_remove.challenge");

    bytes32 public KEYCCR_PUBLIC_KEY_X = stdJson.readBytes32(json_eth_key, ".keys_can_call_remove.x");
    bytes32 public KEYCCR_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth_key, ".keys_can_call_remove.y");

    bytes32 public KEYCCR_SIGNATURE_R = stdJson.readBytes32(json_eth_key, ".keys_can_call_remove.signature.r");
    bytes32 public KEYCCR_SIGNATURE_S = stdJson.readBytes32(json_eth_key, ".keys_can_call_remove.signature.s");

    uint256 public KEYCCR_CHALLENGE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_can_call_remove.metadata.challengeIndex");
    uint256 public KEYCCR_TYPE_INDEX =
        stdJson.readUint(json_eth_key, ".keys_can_call_remove.metadata.typeIndex");
    bool public KEYCCR_UVR =
        stdJson.readBool(json_eth_key, ".keys_can_call_remove.metadata.userVerificationRequired");

    bytes public KEYCCR_AUTHENTICATOR_DATA =
        stdJson.readBytes(json_eth_key, ".keys_can_call_remove.metadata.authenticatorData");

    string public KEYCCR_CLIENT_DATA_JSON =
        stdJson.readString(json_eth_key, ".keys_can_call_remove.metadata.clientDataJSON");

    WebAuthn KEYCCR_WEBAUTHN = WebAuthn({
        UVR: KEYCC_UVR,
        AUTHENTICATOR_DATA: KEYCCR_AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON: KEYCCR_CLIENT_DATA_JSON,
        CHALLENGE_INDEX: KEYCCR_CHALLENGE_INDEX,
        TYPE_INDEX: KEYCCR_TYPE_INDEX,
        R: KEYCCR_SIGNATURE_R,
        S: KEYCCR_SIGNATURE_S,
        X: KEYCCR_PUBLIC_KEY_X,
        Y: KEYCCR_PUBLIC_KEY_Y
    });
}