// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {AAHelpers} from "./AAHelpers.t.sol";
import {Constants} from "../data/Constants.sol";
import {EmailAuthMsg, EmailProof} from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";

abstract contract ProoverHelpers is AAHelpers {
    // ------------------------------------------------------------------------------------
    //
    //                          Real ZK Proof Guardian Acceptance
    //
    // ------------------------------------------------------------------------------------
    /**
     * @notice Register DKIM public key hash on-chain for a domain
     * @dev This must be called before guardian acceptance for real proofs
     *      Skips if already registered to avoid "public key hash is already set" errors
     * @param _domain The email domain (e.g., "openfort.xyz")
     * @param _publicKeyHash The DKIM public key hash
     * @param _authorizer The address authorizing this DKIM key (typically the account owner)
     */
    function _registerDKIMPublicKeyHash(
        string memory _domain,
        bytes32 _publicKeyHash,
        address _authorizer
    ) internal {
        // Skip if already registered
        if (_isDKIMRegistered(_domain, _publicKeyHash, _authorizer)) {
            return;
        }

        // When msg.sender == authorizer, no signature is needed
        vm.prank(_authorizer);
        dkimRegistry.setDKIMPublicKeyHash(_domain, _publicKeyHash, _authorizer, bytes(""));
    }

    /**
     * @notice Check if DKIM public key hash is already registered
     * @param _domain The email domain
     * @param _publicKeyHash The DKIM public key hash
     * @param _authorizer The authorizer address
     * @return bool True if the public key hash is valid
     */
    function _isDKIMRegistered(string memory _domain, bytes32 _publicKeyHash, address _authorizer)
        internal
        view
        returns (bool)
    {
        try dkimRegistry.isDKIMPublicKeyHashValid(_domain, _publicKeyHash, _authorizer) returns (
            bool isValid
        ) {
            return isValid;
        } catch {
            return false;
        }
    }

    /**
     * @notice Build EmailAuthMsg with real proof data
     * @dev Uses proof data from ProofData.sol libraries
     * @param _emailNullifier The actual email nullifier computed by the circuit
     * @param _isCodeExist Whether the account code exists (from circuit output)
     */
    function _buildEmailAuthMsgReal(
        address _account,
        string memory _domain,
        bytes32 _publicKeyHash,
        uint256 _timestamp,
        bytes32 _accountSalt,
        bytes32 _emailNullifier,
        bool _isCodeExist,
        bytes memory _proof
    ) internal view returns (EmailAuthMsg memory) {
        bytes[] memory commandParams = new bytes[](1);
        commandParams[0] = abi.encode(_account);

        // Use the actual email nullifier from circuit output (NOT computed here)
        EmailProof memory emailProof = EmailProof({
            domainName: _domain,
            publicKeyHash: _publicKeyHash,
            timestamp: _timestamp,
            maskedCommand: string.concat("Accept guardian request for ", vm.toString(_account)),
            emailNullifier: _emailNullifier,
            accountSalt: _accountSalt,
            isCodeExist: _isCodeExist,
            proof: _proof
        });

        return EmailAuthMsg({
            templateId: universalEmailRecoveryModule.computeAcceptanceTemplateId(0),
            commandParams: commandParams,
            skippedCommandPrefix: 0,
            proof: emailProof
        });
    }
}
