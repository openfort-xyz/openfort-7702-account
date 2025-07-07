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

import {Execution} from "src/core/Execution.sol";
import {KeyHashLib} from "src/libs/KeyHashLib.sol";
import {IWebAuthnVerifier} from "src/interfaces/IWebAuthnVerifier.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {KeyDataValidationLib as KeyValidation} from "src/libs/KeyDataValidationLib.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCESS,
    _packValidationData
} from "lib/account-abstraction/contracts/core/Helpers.sol";

/**
 * @title   Openfort Base Account 7702 with ERC-4337 Support
 * @author  Openfort@0xkoiner
 * @notice  Smart contract wallet implementing EIP-7702 + ERC-4337 + multi-format keys.
 * @dev
 *  • EIP-4337 integration via EntryPoint
 *  • EIP-7702 support (e.g., setCode)
 *  • Multi-scheme keys: EOA (ECDSA), WebAuthn, P256/P256NONKEY
 *  • ETH/token spending limits + selector whitelists
 *  • ERC-1271 on-chain signature support
 *  • Reentrancy protection & explicit nonce replay prevention
 *
 */
contract OPF7702 is Execution {
    using ECDSA for bytes32;
    using KeyHashLib for Key;
    using KeyHashLib for PubKey;
    using KeyHashLib for address;
    using KeyValidation for KeyData;

    /// @notice Address of this implementation contract
    address public immutable _OPENFORT_CONTRACT_ADDRESS;

    constructor(address _entryPoint, address _webAuthnVerifier) {
        ENTRY_POINT = _entryPoint;
        WEBAUTHN_VERIFIER = _webAuthnVerifier;
        _OPENFORT_CONTRACT_ADDRESS = address(this);
        _disableInitializers();
    }

    /**
     * @notice EIP-4337 signature validation hook — routes to the correct key type validator.
     * @dev
     *  • Extracts `(KeyType, bytes)` from `userOp.signature`.
     *  • Dispatches to:
     *     - `_validateKeyTypeEOA`
     *     - `_validateKeyTypeWEBAUTHN`
     *     - `_validateKeyTypeP256`
     *
     * @param userOp      The packed user operation coming from EntryPoint.
     * @param userOpHash  The precomputed hash of `userOp`.
     * @return Packed validation data (`_packValidationData`) or `SIG_VALIDATION_FAILED`.
     */
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256)
    {
        // decode signature envelope: first word is KeyType, second is the raw payload
        (KeyType sigType, bytes memory sigData) = abi.decode(userOp.signature, (KeyType, bytes));

        if (sigType == KeyType.EOA) {
            return _validateKeyTypeEOA(sigData, userOpHash, userOp.callData);
        }
        if (sigType == KeyType.WEBAUTHN) {
            return _validateKeyTypeWEBAUTHN(userOpHash, userOp.signature, userOp.callData);
        }
        if (sigType == KeyType.P256 || sigType == KeyType.P256NONKEY) {
            return _validateKeyTypeP256(sigData, userOpHash, userOp.callData, sigType);
        }
        return SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Validates an EOA (ECDSA) key signature.
     * @param sigData     Raw signature bytes (64 or 65 bytes).
     * @param userOpHash  The user operation hash.
     * @param callData    The calldata to be executed if approved.
     * @return Packed validation output, or SIG_VALIDATION_FAILED.
     */
    function _validateKeyTypeEOA(bytes memory sigData, bytes32 userOpHash, bytes calldata callData)
        private
        returns (uint256)
    {
        address signer = ECDSA.recover(userOpHash, sigData);
        if (signer == address(0)) {
            return SIG_VALIDATION_FAILED;
        }
        // if masterKey (this contract) signed it, immediate success
        if (signer == address(this)) {
            return SIG_VALIDATION_SUCCESS;
        }

        // load the key for this EOA
        KeyData storage sKey = keys[signer.computeKeyId()];

        bool isValid = _keyValidation(sKey);

        if (!isValid) return SIG_VALIDATION_FAILED;

        // master key → immediate success
        if (sKey.masterKey) {
            return SIG_VALIDATION_SUCCESS;
        }

        if (isValidKey(callData, sKey)) {
            return _packValidationData(false, sKey.validUntil, sKey.validAfter);
        }
        return SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Validates a WebAuthn‐type signature (Solady verifier).
     * @dev
     *  • Reject reused challenges.
     *  • Verify with `verifySignature`.
     *  • If master Key, immediate success.
     *  • Otherwise, call `isValidKey(...)`.
     *
     * @param userOpHash  The userOp hash (served as challenge).
     * @param signature   ABI-encoded payload: (KeyType, bool requireUV, bytes authData, string clientDataJSON, uint256 challengeIdx, uint256 typeIdx, bytes32 r, bytes32 s, PubKey pubKey).
     * @param callData    The calldata to authorize.
     * @return Packed validation output, or SIG_VALIDATION_FAILED.
     */
    function _validateKeyTypeWEBAUTHN(
        bytes32 userOpHash,
        bytes calldata signature,
        bytes calldata callData
    ) private returns (uint256) {
        // decode everything in one shot
        (
            ,
            bool requireUV,
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeIndex,
            uint256 typeIndex,
            bytes32 r,
            bytes32 s,
            PubKey memory pubKey
        ) = abi.decode(
            signature, (KeyType, bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey)
        );

        if (usedChallenges[userOpHash]) {
            return SIG_VALIDATION_FAILED;
        }
        usedChallenges[userOpHash] = true; // mark challenge as used

        bool sigOk = IWebAuthnVerifier(webAuthnVerifier()).verifySignature(
            userOpHash,
            requireUV,
            authenticatorData,
            clientDataJSON,
            challengeIndex,
            typeIndex,
            r,
            s,
            pubKey.x,
            pubKey.y
        );
        if (!sigOk) {
            return SIG_VALIDATION_FAILED;
        }

        KeyData storage sKey = keys[pubKey.computeKeyId()];

        bool isValid = _keyValidation(sKey);

        if (!isValid) return SIG_VALIDATION_FAILED;

        // master key → immediate success
        if (sKey.masterKey) {
            return SIG_VALIDATION_SUCCESS;
        }

        if (isValidKey(callData, sKey)) {
            return _packValidationData(false, sKey.validUntil, sKey.validAfter);
        }
        return SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Validates P-256 / P-256NONKEY signatures.
     * @dev
     *  • For P256NONKEY, first SHA-256 the hash.
     *  • Then `verifyP256Signature(...)`.
     *  • If master Key, immediate success.
     *  • Otherwise, call `isValidKey(...)`.
     *
     * @param sigData     Encoded bytes: (r, s, PubKey).
     * @param userOpHash  The original userOp hash.
     * @param callData    The calldata to authorize.
     * @param sigType     KeyType.P256 or KeyType.P256NONKEY.
     * @return Packed validation output, or SIG_VALIDATION_FAILED.
     */
    function _validateKeyTypeP256(
        bytes memory sigData,
        bytes32 userOpHash,
        bytes calldata callData,
        KeyType sigType
    ) private returns (uint256) {
        (bytes32 r, bytes32 sSig, PubKey memory pubKey) =
            abi.decode(sigData, (bytes32, bytes32, PubKey));

        if (usedChallenges[userOpHash]) {
            return SIG_VALIDATION_FAILED;
        }
        usedChallenges[userOpHash] = true;

        if (sigType == KeyType.P256NONKEY) {
            userOpHash = EfficientHashLib.sha2(userOpHash);
        }

        bool sigOk = IWebAuthnVerifier(webAuthnVerifier()).verifyP256Signature(
            userOpHash, r, sSig, pubKey.x, pubKey.y
        );
        if (!sigOk) {
            return SIG_VALIDATION_FAILED;
        }

        KeyData storage sKey = keys[pubKey.computeKeyId()];

        bool isValid = _keyValidation(sKey);

        if (!isValid) return SIG_VALIDATION_FAILED;

        if (isValidKey(callData, sKey)) {
            return _packValidationData(false, sKey.validUntil, sKey.validAfter);
        }
        return SIG_VALIDATION_FAILED;
    }

    /// @notice Validates if a key is registered and active
    /// @param sKey Storage reference to the key data to validate
    /// @return isValid True if key is both registered and active, false otherwise
    function _keyValidation(KeyData storage sKey) internal view returns (bool isValid) {
        // Check if key is valid and active
        if (!sKey.isRegistered() || !sKey.isActive) {
            return false; // Early return for invalid key
        }

        return true;
    }

    /**
     * @notice Determines if a given key may perform `execute` or `executeBatch`.
     * @dev
     *  • Loads the correct `KeyData` based on `KeyType`:
     *      – WEBAUTHN/P256/P256NONKEY/EOA → `keys[keccak(pubKey.x,pubKey.y)]`
     *  • Checks: validUntil != 0, isActive.
     *  • Extracts the first 4 bytes of `_callData` and calls:
     *      – `_validateExecuteCall(...)`
     *      – `_validateExecuteBatchCall(...)`
     * @param _callData  The calldata (starting with selector).
     * @return True if permitted, false otherwise.
     */
    function isValidKey(bytes calldata _callData, KeyData storage sKey)
        internal
        virtual
        returns (bool)
    {
        // Extract function selector from callData
        bytes4 funcSelector = bytes4(_callData[:4]);

        if (funcSelector == 0xe9ae5c53) {
            return _validateExecuteCall(sKey, _callData);
        }
        return false;
    }

    /**
     * @notice Validates a single `execute(target, value, data)` call.
     * @dev
     *  • Decode `(address toContract, uint256 amount, bytes innerData)`.
     *  • If `toContract == address(this)`, revert.
     *  • If `masterKey`, immediate true.
     *  • Else enforce:
     *      - limit > 0
     *      - ethLimit ≥ amount
     *      - `bytes4(innerData)` ∈ `allowedSelectors`
     *      - Decrement `limit` and subtract `amount` from `ethLimit`
     *      - If `spendTokenInfo.token == toContract`, call `_validateTokenSpend(...)`
     *      - If `whitelisting`, ensure `toContract` ∈ `whitelist`
     *
     * @param sKey       Storage reference of the KeyData
     * @param _callData  Encoded as: `execute(address,uint256,bytes)`
     * @return True if allowed, false otherwise.
     */
    function _validateExecuteCall(KeyData storage sKey, bytes calldata _callData)
        internal
        returns (bool)
    {
        bytes32 mode;
        bytes memory executionData;
        (mode, executionData) = abi.decode(_callData[4:], (bytes32, bytes));

        if (mode == mode_1) {
            Call[] memory calls = abi.decode(executionData, (Call[]));
            for (uint256 i = 0; i < calls.length; i++) {
                if (!_validateCall(sKey, calls[i])) {
                    return false;
                }
            }
            return true;
        }

        if (mode == mode_3) {
            bytes[] memory batches = abi.decode(executionData, (bytes[]));
            for (uint256 i = 0; i < batches.length; i++) {
                Call[] memory calls = abi.decode(batches[i], (Call[]));
                for (uint256 j = 0; j < calls.length; j++) {
                    if (!_validateCall(sKey, calls[j])) {
                        return false;
                    }
                }
            }
            return true;
        }

        return false;
    }

    function _validateCall(KeyData storage sKey, Call memory call) private returns (bool) {
        if (call.target == address(this)) return false;
        if (!sKey.passesCallGuards(call.value)) return false;

        bytes memory innerData = call.data;
        bytes4 innerSelector;
        assembly {
            innerSelector := mload(add(innerData, 0x20))
        }

        if (!_isAllowedSelector(sKey.allowedSelectors, innerSelector)) {
            return false;
        }

        sKey.consumeQuota();
        if (call.value > 0) {
            unchecked {
                sKey.ethLimit -= call.value;
            }
        }

        if (sKey.spendTokenInfo.token == call.target) {
            bool validSpend = _validateTokenSpend(sKey, innerData);
            if (!validSpend) return false;
        }

        if (!sKey.whitelisting || !sKey.whitelist[call.target]) {
            return false;
        }
        return true;
    }

    /**
     * @notice Validates a token transfer against the key’s token spend limit.
     * @dev Loads `value` from the last 32 bytes of `innerData` (standard ERC-20 `_transfer(address,uint256)` signature).
     * @param sKey      Storage reference of the KeyData
     * @param innerData The full encoded call data to the token contract.
     * @return True if `value ≤ sKey.spendTokenInfo.limit`; false if it exceeds or is invalid.
     */
    function _validateTokenSpend(KeyData storage sKey, bytes memory innerData)
        internal
        override
        returns (bool)
    {
        uint256 len = innerData.length;
        // load the last 32 bytes from innerData
        uint256 value;
        assembly {
            value := mload(add(add(innerData, 0x20), sub(len, 0x20)))
        }
        if (value > sKey.spendTokenInfo.limit) {
            return false;
        }
        if (value > 0) {
            sKey.spendTokenInfo.limit -= value;
        }
        return true;
    }

    /**
     * @notice Checks whether `selector` is included in the `selectors` array.
     * @param selectors Array of allowed selectors (in storage).
     * @param selector  The 4-byte function selector to check.
     * @return True if found; false otherwise.
     */
    function _isAllowedSelector(bytes4[] storage selectors, bytes4 selector)
        internal
        view
        returns (bool)
    {
        uint256 len = selectors.length;
        for (uint256 i = 0; i < len;) {
            if (selectors[i] == selector) {
                return true;
            }
            unchecked {
                ++i;
            }
        }
        return false;
    }

    /**
     * @notice ERC-1271 on-chain signature validation.
     * @dev
     *  • Read the first 32 bytes of `_signature` to detect `KeyType`.
     *  • Dispatch to `_validateWebAuthnSignature` or `_validateP256Signature`, or ECDSA path.
     *  • EOA (ECDSA) path recovers `signer`. If `signer == this`, return `isValidSignature.selector`.
     *    Else, load `key = keys[keyHash]` and enforce:
     *      - validUntil > now ≥ validAfter
     *      - (masterKey or limit≥1)
     * @param _hash       The hash that was signed.
     * @param _signature  The signature blob to verify.
     * @return `this.isValidSignature.selector` if valid; otherwise `0xffffffff`.
     */
    function isValidSignature(bytes32 _hash, bytes memory _signature)
        external
        view
        returns (bytes4)
    {
        if (_signature.length < 32) {
            return bytes4(0xffffffff);
        }

        // read the leading 32 bytes to know KeyType
        uint256 keyTypeWord;
        assembly {
            keyTypeWord := mload(add(_signature, 32))
        }

        if (keyTypeWord == uint256(KeyType.WEBAUTHN)) {
            return _validateWebAuthnSignature(_signature, _hash);
        }
        if (keyTypeWord == uint256(KeyType.P256) || keyTypeWord == uint256(KeyType.P256NONKEY)) {
            return _validateP256Signature(_signature, _hash);
        }
        // otherwise, assume ECDSA
        if (_signature.length == 64 || _signature.length == 65) {
            return _validateEOASignature(_signature, _hash);
        }
        return bytes4(0xffffffff);
    }

    /**
     * @notice Validate a EOA signature on-chain via ERC-1271.
     * @param _signature  v,r,s components of signature
     * @param _hash       The hash to verify.
     * @return `this.isValidSignature.selector` if valid; otherwise `0xffffffff`.
     */
    function _validateEOASignature(bytes memory _signature, bytes32 _hash)
        internal
        view
        returns (bytes4)
    {
        address signer = ECDSA.recover(_hash, _signature);
        if (signer == address(0)) {
            return bytes4(0xffffffff);
        }
        if (signer == address(this)) {
            return this.isValidSignature.selector;
        }

        bytes32 keyHash = signer.computeKeyId();
        KeyData storage sKey = keys[keyHash];

        if (sKey.masterKey) return this.isValidSignature.selector;

        // validity window
        if (!sKey.passesBaseChecks() || !sKey.hasQuota()) {
            return bytes4(0xffffffff);
        }
        return this.isValidSignature.selector;
    }

    /**
     * @notice Validate a WebAuthn signature on-chain via ERC-1271.
     * @param _signature  ABI-encoded: (KeyType, bool UV, bytes authData, string cDataJSON, uint256 cIdx, uint256 tIdx, bytes32 r, bytes32 s, PubKey pubKey)
     * @param _hash       The hash to verify.
     * @return `this.isValidSignature.selector` if valid; otherwise `0xffffffff`.
     */
    function _validateWebAuthnSignature(bytes memory _signature, bytes32 _hash)
        internal
        view
        returns (bytes4)
    {
        (
            ,
            bool requireUV,
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeIndex,
            uint256 typeIndex,
            bytes32 r,
            bytes32 s,
            PubKey memory pubKey
        ) = abi.decode(
            _signature, (KeyType, bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey)
        );

        if (usedChallenges[_hash]) {
            return bytes4(0xffffffff);
        }
        bool sigOk = IWebAuthnVerifier(webAuthnVerifier()).verifySignature(
            _hash,
            requireUV,
            authenticatorData,
            clientDataJSON,
            challengeIndex,
            typeIndex,
            r,
            s,
            pubKey.x,
            pubKey.y
        );
        if (!sigOk) {
            return bytes4(0xffffffff);
        }

        bytes32 keyHash = pubKey.computeKeyId();
        KeyData storage sKey = keys[keyHash];

        if (sKey.masterKey) return this.isValidSignature.selector;

        if (!sKey.passesBaseChecks() || !sKey.hasQuota()) {
            return bytes4(0xffffffff);
        }
        return this.isValidSignature.selector;
    }

    /**
     * @notice Validate a P-256 / P-256NONKEY signature on-chain via ERC-1271.
     * @param _signature  ABI-encoded: (KeyType, bytes(inner: r, s, PubKey))
     * @param _hash       The hash to verify.
     * @return `this.isValidSignature.selector` if valid; otherwise `0xffffffff`.
     */
    function _validateP256Signature(bytes memory _signature, bytes32 _hash)
        internal
        view
        returns (bytes4)
    {
        (KeyType kt, bytes memory inner) = abi.decode(_signature, (KeyType, bytes));
        (bytes32 r, bytes32 s, PubKey memory pubKey) = abi.decode(inner, (bytes32, bytes32, PubKey));

        if (usedChallenges[_hash]) {
            return bytes4(0xffffffff);
        }

        bytes32 hashToCheck = _hash;
        if (kt == KeyType.P256NONKEY) {
            hashToCheck = EfficientHashLib.sha2(_hash);
        }

        bool sigOk = IWebAuthnVerifier(webAuthnVerifier()).verifyP256Signature(
            hashToCheck, r, s, pubKey.x, pubKey.y
        );
        if (!sigOk) {
            return bytes4(0xffffffff);
        }

        bytes32 keyHash = pubKey.computeKeyId();
        KeyData storage sKey = keys[keyHash];
        if (!sKey.passesBaseChecks() || !sKey.hasQuota()) {
            return bytes4(0xffffffff);
        }
        return this.isValidSignature.selector;
    }

    /**
     * @notice Internal helper to validate an ECDSA signature over `hash`.
     * @param hash       The digest that was signed.
     * @param signature  The signature bytes (v,r,s) or 64-byte compact.
     * @return True if recovered == this contract, false otherwise.
     */
    function _checkSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return ECDSA.recover(hash, signature) == address(this);
    }
}
