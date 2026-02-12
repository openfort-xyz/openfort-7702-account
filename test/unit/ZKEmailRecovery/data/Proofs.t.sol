// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "lib/forge-std/src/StdJson.sol";
import {Etch} from "./Etch.t.sol";

abstract contract Proofs is Etch {
    enum ProofType {
        SAFE,
        EOA_KEY_TYPE,
        WEBAUTHN_KEY_TYPE
    }

    struct GuardianProof {
        string DOMAIN;
        bytes32 PUBLIC_KEY_HASH;
        bytes32 EMAIL_NULLIFIER;
        uint256 TIMESTAMP;
        bytes32 ACCOUNT_SALT;
        bool IS_CODE_EXIST;
        bytes PROOF;
        uint256[34] PUBLIC_SIGNALS;
    }

    GuardianProof guardian1_Proof;
    GuardianProof guardian2_Proof;

    string public path;
    string public json_proofs = vm.readFile("src/data/proofs/ProofsDataGeneral.json");
    string public json_proofs_key_eoa = vm.readFile("src/data/proofs/ProofsDataKeyEOA.json");
    string public json_proofs_key_webAuthn =
        vm.readFile("src/data/proofs/ProofsDataKeyWebAuthn.json");

    function _loadAllProofs(ProofType _proofType) internal {
        if (_proofType == ProofType.SAFE) {
            path = json_proofs;
        } else if (_proofType == ProofType.EOA_KEY_TYPE) {
            path = json_proofs_key_eoa;
        } else if (_proofType == ProofType.WEBAUTHN_KEY_TYPE) {
            path = json_proofs_key_webAuthn;
        }
        _loadGuardian1_Proof();
        _loadGuardian2_Proof();
    }

    function _loadGuardian1_Proof() internal {
        guardian1_Proof.DOMAIN = stdJson.readString(path, ".Guardian1_Proof.domain");
        guardian1_Proof.PUBLIC_KEY_HASH =
            stdJson.readBytes32(path, ".Guardian1_Proof.public_key_hash");
        guardian1_Proof.EMAIL_NULLIFIER =
            stdJson.readBytes32(path, ".Guardian1_Proof.email_nullifier");
        guardian1_Proof.TIMESTAMP = stdJson.readUint(path, ".Guardian1_Proof.timestamp");
        guardian1_Proof.ACCOUNT_SALT = stdJson.readBytes32(path, ".Guardian1_Proof.account_salt");
        guardian1_Proof.IS_CODE_EXIST = stdJson.readBool(path, ".Guardian1_Proof.is_code_exist");
        guardian1_Proof.PROOF = stdJson.readBytes(path, ".Guardian1_Proof.proof");

        // Load public signals array
        for (uint256 i = 0; i < 34; i++) {
            string memory key =
                string.concat(".Guardian1_Proof.public_signals[", vm.toString(i), "]");
            guardian1_Proof.PUBLIC_SIGNALS[i] = stdJson.readUint(path, key);
        }
    }

    function _loadGuardian2_Proof() internal {
        guardian2_Proof.DOMAIN = stdJson.readString(path, ".Guardian2_Proof.domain");
        guardian2_Proof.PUBLIC_KEY_HASH =
            stdJson.readBytes32(path, ".Guardian2_Proof.public_key_hash");
        guardian2_Proof.EMAIL_NULLIFIER =
            stdJson.readBytes32(path, ".Guardian2_Proof.email_nullifier");
        guardian2_Proof.TIMESTAMP = stdJson.readUint(path, ".Guardian2_Proof.timestamp");
        guardian2_Proof.ACCOUNT_SALT = stdJson.readBytes32(path, ".Guardian2_Proof.account_salt");
        guardian2_Proof.IS_CODE_EXIST = stdJson.readBool(path, ".Guardian2_Proof.is_code_exist");
        guardian2_Proof.PROOF = stdJson.readBytes(path, ".Guardian2_Proof.proof");

        // Load public signals array
        for (uint256 i = 0; i < 34; i++) {
            string memory key =
                string.concat(".Guardian2_Proof.public_signals[", vm.toString(i), "]");
            guardian2_Proof.PUBLIC_SIGNALS[i] = stdJson.readUint(path, key);
        }
    }

    /**
     * @notice Check if a proof is a placeholder (needs real proof)
     * @dev Returns false for real proofs (256 bytes)
     */
    function isPlaceholder(bytes memory proof) internal pure returns (bool) {
        return proof.length == 1 && proof[0] == 0x01;
    }

    /**
     * @notice Get the expected proof length for valid Groth16 proofs
     * @dev 2 uint256 (pA) + 4 uint256 (pB) + 2 uint256 (pC) = 8 * 32 = 256 bytes
     */
    function expectedProofLength() internal pure returns (uint256) {
        return 256;
    }

    /**
     * @notice Verify proof has correct length
     */
    function isValidProofLength(bytes memory proof) internal pure returns (bool) {
        return proof.length == 256;
    }

    /**
     * @notice Get the public signals for verification (Guardian 1)
     * @dev Returns loaded signals from JSON, not hardcoded values
     */
    function getPublicSignals() internal view returns (uint256[34] memory) {
        return guardian1_Proof.PUBLIC_SIGNALS;
    }

    /**
     * @notice Get the public signals for Guardian 2
     */
    function getPublicSignals2() internal view returns (uint256[34] memory) {
        return guardian2_Proof.PUBLIC_SIGNALS;
    }
}
