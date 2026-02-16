// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "../interfaces/IKeyV2.sol";
import { Helpers } from "./Helpers.t.sol";
import { Constants } from "../data/Constants.sol";
import { ProoverHelpers } from "./ProoverHelpers.t.sol";
import { RecoveryProofs } from "../data/RecoveryProofs.t.sol";
import { Simple7702Account } from "../mocks/Simple7702Account.sol";
import { MockValidator } from "../mocks/MockValidator.sol";
import { IKey } from "../interfaces/IKey.sol";
import { EmailAuthMsg, EmailProof } from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import { IGuardianManager } from "zk-email-recovery-contracts/email-recovery/src/interfaces/IGuardianManager.sol";
import {
    GuardianStorage,
    GuardianStatus
} from "zk-email-recovery-contracts/email-recovery/src/libraries/EnumerableGuardianMap.sol";

abstract contract ZkEmailHelpers is ProoverHelpers, IKey {
    // ============================================================================
    // CONSTANTS
    // ============================================================================

    // Recovery delay (12 hours default)
    uint256 constant RECOVERY_DELAY = 12 hours;

    // Recovery expiry (2 weeks default)
    uint256 constant RECOVERY_EXPIRY = 14 days;

    // ------------------------------------------------------------------------------------
    //
    //                                    ZK-Email Helpers
    //
    // ------------------------------------------------------------------------------------

    function _computeGuardianAddress(address _owner, bytes32 _salt) internal view returns (address) {
        return universalEmailRecoveryModule.computeEmailAuthAddress(_owner, _salt);
    }

    function _createInstallData(
        address _mockValidator,
        address[] memory _guardians,
        uint256[] memory _weights
    )
        internal
        pure
        returns (bytes memory)
    {
        // Encode install data for the recovery module
        // Format: abi.encode(validator, isInstalledContext, initialSelector, guardians, weights, threshold, delay,
        // expiry)

        bytes memory isInstalledContext = bytes("");
        bytes4 functionSelector = bytes4(keccak256("changeOwner(address)"));

        return abi.encode(
            _mockValidator, // validator to recover
            isInstalledContext,
            functionSelector,
            _guardians,
            _weights,
            Constants.THRESHOLD,
            Constants.DELAY,
            Constants.EXPIRY
        );
    }

    function _createInstallDataWithCustomSelector(
        address _mockValidator,
        address[] memory _guardians,
        uint256[] memory _weights
    )
        internal
        pure
        returns (bytes memory)
    {
        // Encode install data for the recovery module
        // Format: abi.encode(validator, isInstalledContext, initialSelector, guardians, weights, threshold, delay,
        // expiry)

        bytes memory isInstalledContext = bytes("");
        bytes4 functionSelector = Simple7702Account.startRecovery.selector;

        return abi.encode(
            _mockValidator, // validator to recover
            isInstalledContext,
            functionSelector,
            _guardians,
            _weights,
            Constants.THRESHOLD,
            Constants.DELAY,
            Constants.EXPIRY
        );
    }

    /**
     * @notice Create install data with Safe-compatible swapOwner selector
     * @dev When validator == account (integrated validator pattern), the deployed
     *      UniversalEmailRecoveryModule only allows Safe selectors. This function
     *      uses swapOwner which is allowed.
     */
    function _createInstallDataWithSwapOwner(
        address _validator,
        address[] memory _guardians,
        uint256[] memory _weights
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes memory isInstalledContext = bytes("");
        // Safe's swapOwner selector: 0xe318b52b
        bytes4 functionSelector = bytes4(keccak256("swapOwner(address,address,address)"));

        return abi.encode(
            _validator,
            isInstalledContext,
            functionSelector,
            _guardians,
            _weights,
            Constants.THRESHOLD,
            Constants.DELAY,
            Constants.EXPIRY
        );
    }

    /**
     * @notice Create install data for Key-based recovery with external MockValidator
     * @dev Uses MockValidator.startRecovery(Key) selector which is allowed when
     *      validator != account (external validator pattern)
     * @param _validator The external MockValidator address
     * @param _guardians Array of guardian addresses
     * @param _weights Array of guardian weights
     */
    function _createInstallDataForKeyRecovery(
        address _validator,
        address[] memory _guardians,
        uint256[] memory _weights
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes memory isInstalledContext = bytes("");
        // Use Simple7702Account.startRecovery.selector (0xec094925) to match ZK proof recoveryDataHash
        bytes4 functionSelector = Simple7702Account.startRecovery.selector;

        return abi.encode(
            _validator,
            isInstalledContext,
            functionSelector,
            _guardians,
            _weights,
            Constants.THRESHOLD,
            Constants.DELAY,
            Constants.EXPIRY
        );
    }

    function _getGuardianConfig(address account)
        internal
        view
        returns (uint256 guardianCount, uint256 totalWeight, uint256 acceptedWeight, uint256 threshold)
    {
        // Call getGuardianConfig on the recovery module
        IGuardianManager.GuardianConfig memory config = universalEmailRecoveryModule.getGuardianConfig(account);

        return (config.guardianCount, config.totalWeight, config.acceptedWeight, config.threshold);
    }

    function _getGuardianStatus(
        address account,
        address guardian
    )
        internal
        view
        returns (uint256 status, uint256 weight)
    {
        // Call getGuardian on the recovery module
        GuardianStorage memory guardianStorage = universalEmailRecoveryModule.getGuardian(account, guardian);

        return (uint256(guardianStorage.status), guardianStorage.weight);
    }

    // ============================================================================
    // RECOVERY DATA COMPUTATION
    // ============================================================================

    /**
     * @notice Compute recovery data hash for address-based recovery
     * @dev Matches official pattern: keccak256(abi.encode(validator, recoveryCalldata))
     * @param _validator The validator address
     * @param _newOwner The new owner address
     * @return recoveryData The encoded recovery data
     * @return recoveryDataHash The keccak256 hash
     */
    function _computeRecoveryDataHash(
        address _validator,
        address _newOwner
    )
        internal
        pure
        returns (bytes memory recoveryData, bytes32 recoveryDataHash)
    {
        // Encode changeOwner(newOwner) call
        // Selector: bytes4(keccak256("changeOwner(address)")) = 0xa6f9dae1
        bytes memory recoveryCallData = abi.encodeWithSelector(bytes4(0xa6f9dae1), _newOwner);

        // Encode recovery data: abi.encode(validator, calldata)
        recoveryData = abi.encode(_validator, recoveryCallData);

        // Hash it
        recoveryDataHash = keccak256(recoveryData);
    }

    /**
     * @notice Compute recovery data hash for Key-based recovery
     * @dev Used when recovery function is startRecovery(Key) instead of changeOwner(address)
     * @param _validator The validator address (account IS the validator in integrated setup)
     * @param _newOwnerKey The new owner Key struct
     * @return recoveryData The encoded recovery data
     * @return recoveryDataHash The keccak256 hash
     */
    function _computeRecoveryDataHashForKey(
        address _validator,
        Key memory _newOwnerKey
    )
        internal
        pure
        returns (bytes memory recoveryData, bytes32 recoveryDataHash)
    {
        // Encode startRecovery(Key) call
        // Key struct: PubKey pubKey, address eoaAddress, KeyType keyType
        bytes memory recoveryCallData = abi.encodeWithSelector(Simple7702Account.startRecovery.selector, _newOwnerKey);

        // Encode recovery data: abi.encode(validator, calldata)
        recoveryData = abi.encode(_validator, recoveryCallData);

        // Hash it
        recoveryDataHash = keccak256(recoveryData);
    }

    function _computeRecoveryDataHashForKey(
        address _validator,
        IKeyV2.KeyDataReg memory _newOwnerKey
    )
        internal
        pure
        returns (bytes memory recoveryData, bytes32 recoveryDataHash)
    {
        // Encode startRecovery(KeyDataReg) call
        // Must use Simple7702Account.startRecovery.selector (0xec094925) to match the ZK proofs
        bytes memory recoveryCallData = abi.encodeWithSelector(Simple7702Account.startRecovery.selector, _newOwnerKey);

        // Encode recovery data: abi.encode(validator, calldata)
        recoveryData = abi.encode(_validator, recoveryCallData);

        // Hash it
        recoveryDataHash = keccak256(recoveryData);
    }

    /**
     * @notice Compute recovery data hash for Safe-compatible swapOwner recovery
     * @dev Used when account IS the validator (integrated validator pattern).
     *      The deployed UniversalEmailRecoveryModule only allows Safe selectors
     *      when validator == account, so we use swapOwner.
     * @param _validator The validator address (same as account address)
     * @param _newOwner The new owner address
     * @return recoveryData The encoded recovery data
     * @return recoveryDataHash The keccak256 hash
     */
    function _computeRecoveryDataHashForSwapOwner(
        address _validator,
        address _newOwner
    )
        internal
        pure
        returns (bytes memory recoveryData, bytes32 recoveryDataHash)
    {
        // Encode swapOwner(prevOwner, oldOwner, newOwner) call
        // For our purposes, prevOwner and oldOwner are ignored by the account
        // Using address(0) for unused parameters
        bytes memory recoveryCallData = abi.encodeWithSelector(
            bytes4(keccak256("swapOwner(address,address,address)")),
            address(0), // prevOwner (ignored)
            address(0), // oldOwner (ignored)
            _newOwner
        );

        // Encode recovery data: abi.encode(validator, calldata)
        recoveryData = abi.encode(_validator, recoveryCallData);

        // Hash it
        recoveryDataHash = keccak256(recoveryData);
    }

    // ============================================================================
    // EMAIL AUTH MSG BUILDING
    // ============================================================================

    /**
     * @notice Build EmailAuthMsg for recovery with real proof data
     * @dev Uses recovery proof data from RecoveryProofs.t.sol
     *
     * Key differences from acceptance:
     * - templateId: computeRecoveryTemplateId(0) instead of computeAcceptanceTemplateId(0)
     * - commandParams: 2 params [accountAddress, recoveryDataHashString]
     * - maskedCommand: "Recover account {addr} using recovery hash {hash}"
     *
     * @param _account The account to recover
     * @param _recoveryDataHash The keccak256 hash of recovery data
     * @param _domain Email domain
     * @param _publicKeyHash DKIM public key hash
     * @param _timestamp Email timestamp
     * @param _accountSalt Guardian's account salt
     * @param _emailNullifier Email nullifier (prevents replay)
     * @param _isCodeExist Whether account code exists
     * @param _proof The Groth16 proof bytes
     */
    function _buildRecoveryEmailAuthMsg(
        address _account,
        bytes32 _recoveryDataHash,
        string memory _domain,
        bytes32 _publicKeyHash,
        uint256 _timestamp,
        bytes32 _accountSalt,
        bytes32 _emailNullifier,
        bool _isCodeExist,
        bytes memory _proof
    )
        internal
        view
        returns (EmailAuthMsg memory)
    {
        // Recovery has 2 command params (vs 1 for acceptance)
        bytes[] memory commandParams = new bytes[](2);
        commandParams[0] = abi.encode(_account);
        // The hash is passed as a string in the command
        commandParams[1] = abi.encode(_bytes32ToString(_recoveryDataHash));

        // Masked command format: "Recover account 0x... using recovery hash 0x..."
        string memory maskedCommand = string.concat(
            "Recover account ", vm.toString(_account), " using recovery hash ", _bytes32ToString(_recoveryDataHash)
        );

        EmailProof memory emailProof = EmailProof({
            domainName: _domain,
            publicKeyHash: _publicKeyHash,
            timestamp: _timestamp,
            maskedCommand: maskedCommand,
            emailNullifier: _emailNullifier,
            accountSalt: _accountSalt,
            isCodeExist: _isCodeExist,
            proof: _proof
        });

        return EmailAuthMsg({
            templateId: universalEmailRecoveryModule.computeRecoveryTemplateId(0),
            commandParams: commandParams,
            skippedCommandPrefix: 0,
            proof: emailProof
        });
    }

    /**
     * @notice Build recovery EmailAuthMsg using Guardian 1's proof data
     */
    function _buildRecoveryEmailAuthMsgGuardian1(
        address _account,
        bytes32 _recoveryDataHash
    )
        internal
        view
        returns (EmailAuthMsg memory)
    {
        return _buildRecoveryEmailAuthMsg(
            _account,
            _recoveryDataHash,
            guardian1_RecoveryProof.DOMAIN,
            guardian1_RecoveryProof.PUBLIC_KEY_HASH,
            guardian1_RecoveryProof.TIMESTAMP,
            guardian1_RecoveryProof.ACCOUNT_SALT,
            guardian1_RecoveryProof.EMAIL_NULLIFIER,
            guardian1_RecoveryProof.IS_CODE_EXIST,
            guardian1_RecoveryProof.PROOF
        );
    }

    /**
     * @notice Build recovery EmailAuthMsg using Guardian 2's proof data
     */
    function _buildRecoveryEmailAuthMsgGuardian2(
        address _account,
        bytes32 _recoveryDataHash
    )
        internal
        view
        returns (EmailAuthMsg memory)
    {
        return _buildRecoveryEmailAuthMsg(
            _account,
            _recoveryDataHash,
            guardian2_RecoveryProof.DOMAIN,
            guardian2_RecoveryProof.PUBLIC_KEY_HASH,
            guardian2_RecoveryProof.TIMESTAMP,
            guardian2_RecoveryProof.ACCOUNT_SALT,
            guardian2_RecoveryProof.EMAIL_NULLIFIER,
            guardian2_RecoveryProof.IS_CODE_EXIST,
            guardian2_RecoveryProof.PROOF
        );
    }

    // ============================================================================
    // RECOVERY STATE HELPERS
    // ============================================================================

    /**
     * @notice Get recovery request for an account
     * @param _account The account address
     * @return executeAfter Timestamp after which recovery can execute
     * @return executeBefore Timestamp before which recovery must execute
     * @return currentWeight Current accumulated guardian weight
     * @return recoveryDataHash The stored recovery data hash
     */
    function _getRecoveryRequest(address _account)
        internal
        view
        returns (uint256 executeAfter, uint256 executeBefore, uint256 currentWeight, bytes32 recoveryDataHash)
    {
        return universalEmailRecoveryModule.getRecoveryRequest(_account);
    }

    /**
     * @notice Check if recovery threshold is met
     * @param _account The account address
     * @return True if currentWeight >= threshold
     */
    function _isRecoveryThresholdMet(address _account) internal view returns (bool) {
        (, uint256 executeBefore, uint256 currentWeight,) = _getRecoveryRequest(_account);
        (,,, uint256 threshold) = _getGuardianConfig(_account);

        // If executeBefore > 0, threshold was met and timelock started
        return executeBefore > 0 && currentWeight >= threshold;
    }

    /**
     * @notice Check if recovery is ready to execute
     * @param _account The account address
     * @return True if timelock passed and not expired
     */
    function _isRecoveryReadyToExecute(address _account) internal view returns (bool) {
        (uint256 executeAfter, uint256 executeBefore,,) = _getRecoveryRequest(_account);

        if (executeAfter == 0 || executeBefore == 0) {
            return false;
        }

        return block.timestamp >= executeAfter && block.timestamp < executeBefore;
    }

    // ============================================================================
    // UTILITY FUNCTIONS
    // ============================================================================

    /**
     * @notice Convert bytes32 to hex string with 0x prefix
     * @dev Required for recovery command which expects hash as string
     */
    function _bytes32ToString(bytes32 _bytes) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(66); // 0x + 64 hex chars

        str[0] = "0";
        str[1] = "x";

        for (uint256 i = 0; i < 32; i++) {
            str[2 + i * 2] = alphabet[uint8(_bytes[i] >> 4)];
            str[3 + i * 2] = alphabet[uint8(_bytes[i] & 0x0f)];
        }

        return string(str);
    }
}
