// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "lib/forge-std/src/StdJson.sol";
import { Proofs } from "./Proofs.t.sol";

/**
 * @title RecoveryProofs
 * @notice Loads recovery proof data from RecoveryProofsData.json
 * @dev Mirrors Proofs.t.sol structure for recovery-specific proofs
 *
 * Inheritance: Contracts → Proofs → Data → AAHelpers → ProoverHelpers → Helpers → RecoveryProofs
 */
abstract contract RecoveryProofs is Proofs {
    using stdJson for string;

    // ============================================================================
    // STRUCTS
    // ============================================================================

    struct RecoveryProof {
        string DOMAIN;
        bytes32 PUBLIC_KEY_HASH;
        bytes32 EMAIL_NULLIFIER;
        uint256 TIMESTAMP;
        bytes32 ACCOUNT_SALT;
        bool IS_CODE_EXIST;
        bytes PROOF;
    }

    // ============================================================================
    // STATE
    // ============================================================================

    RecoveryProof guardian1_RecoveryProof;
    RecoveryProof guardian2_RecoveryProof;

    string public path_recovery;
    string public json_proofs_recovery = vm.readFile("src/data/proofs/RecoveryProofsDataGeneral.json");
    string public json_proofs_key_eoa_recovery = vm.readFile("src/data/proofs/RecoveryProofsDataEOA.json");
    string public json_proofs_key_webAuthn_recovery = vm.readFile("src/data/proofs/RecoveryProofsDataWebAuthn.json");

    // ============================================================================
    // LOADING FUNCTIONS
    // ============================================================================

    function _loadGuardian1_RecoveryProof() internal {
        guardian1_RecoveryProof.DOMAIN = stdJson.readString(path_recovery, ".Guardian1_RecoveryProof.domain");
        guardian1_RecoveryProof.PUBLIC_KEY_HASH =
            stdJson.readBytes32(path_recovery, ".Guardian1_RecoveryProof.public_key_hash");
        guardian1_RecoveryProof.EMAIL_NULLIFIER =
            stdJson.readBytes32(path_recovery, ".Guardian1_RecoveryProof.email_nullifier");
        guardian1_RecoveryProof.TIMESTAMP = stdJson.readUint(path_recovery, ".Guardian1_RecoveryProof.timestamp");
        guardian1_RecoveryProof.ACCOUNT_SALT =
            stdJson.readBytes32(path_recovery, ".Guardian1_RecoveryProof.account_salt");
        guardian1_RecoveryProof.IS_CODE_EXIST =
            stdJson.readBool(path_recovery, ".Guardian1_RecoveryProof.is_code_exist");
        guardian1_RecoveryProof.PROOF = stdJson.readBytes(path_recovery, ".Guardian1_RecoveryProof.proof");
    }

    function _loadGuardian2_RecoveryProof() internal {
        guardian2_RecoveryProof.DOMAIN = stdJson.readString(path_recovery, ".Guardian2_RecoveryProof.domain");
        guardian2_RecoveryProof.PUBLIC_KEY_HASH =
            stdJson.readBytes32(path_recovery, ".Guardian2_RecoveryProof.public_key_hash");
        guardian2_RecoveryProof.EMAIL_NULLIFIER =
            stdJson.readBytes32(path_recovery, ".Guardian2_RecoveryProof.email_nullifier");
        guardian2_RecoveryProof.TIMESTAMP = stdJson.readUint(path_recovery, ".Guardian2_RecoveryProof.timestamp");
        guardian2_RecoveryProof.ACCOUNT_SALT =
            stdJson.readBytes32(path_recovery, ".Guardian2_RecoveryProof.account_salt");
        guardian2_RecoveryProof.IS_CODE_EXIST =
            stdJson.readBool(path_recovery, ".Guardian2_RecoveryProof.is_code_exist");
        guardian2_RecoveryProof.PROOF = stdJson.readBytes(path_recovery, ".Guardian2_RecoveryProof.proof");
    }

    /**
     * @notice Load all recovery proofs
     */
    function _loadAllRecoveryProofs(ProofType _proofType) internal {
        if (_proofType == ProofType.SAFE) {
            path_recovery = json_proofs_recovery;
        } else if (_proofType == ProofType.EOA_KEY_TYPE) {
            path_recovery = json_proofs_key_eoa_recovery;
        } else if (_proofType == ProofType.WEBAUTHN_KEY_TYPE) {
            path_recovery = json_proofs_key_webAuthn_recovery;
        }
        _loadGuardian1_RecoveryProof();
        _loadGuardian2_RecoveryProof();
    }

    // ============================================================================
    // VALIDATION FUNCTIONS
    // ============================================================================

    /**
     * @notice Check if a recovery proof is a placeholder (needs real proof)
     * @dev Returns false for real proofs (256 bytes)
     */
    function isRecoveryPlaceholder(bytes memory proof) internal pure returns (bool) {
        return proof.length == 1 && proof[0] == 0x01;
    }

    /**
     * @notice Verify recovery proof has correct length
     */
    function isValidRecoveryProofLength(bytes memory proof) internal pure returns (bool) {
        return proof.length == 256;
    }
}
