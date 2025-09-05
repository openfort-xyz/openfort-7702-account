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
import {SigLengthLib} from "src/libs/SigLengthLib.sol";
import {IUserOpPolicy} from "src/interfaces/IPolicy.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
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
import {Initializable} from "src/libs/Initializable.sol";

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
contract OPF7702 is Execution, Initializable {
    using ECDSA for bytes32;
    using KeyHashLib for Key;
    using KeyHashLib for PubKey;
    using SigLengthLib for bytes;
    using KeyHashLib for address;
    using KeyValidation for KeyData;

    /// @notice Address of this implementation contract
    address public immutable _OPENFORT_CONTRACT_ADDRESS;

    constructor(address _entryPoint, address _webAuthnVerifier, address _gasPolicy) {
        ENTRY_POINT = _entryPoint;
        WEBAUTHN_VERIFIER = _webAuthnVerifier;
        GAS_POLICY = _gasPolicy;
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

        _checkValidSignatureLength(sigType, userOp.signature.length);

        if (sigType == KeyType.EOA) {
            return _validateKeyTypeEOA(sigData, userOpHash, userOp);
        }
        if (sigType == KeyType.WEBAUTHN) {
            return _validateKeyTypeWEBAUTHN(sigData, userOpHash, userOp);
        }
        if (sigType == KeyType.P256 || sigType == KeyType.P256NONKEY) {
            return _validateKeyTypeP256(sigData, userOpHash, userOp, sigType);
        }

        // Todo; No need to Revret,  the decode will revert on incorrect type
        revert IKeysManager.KeyManager__InvalidKeyType();
    }

    /// @dev validate and enforces per-key-type length bounds, uses to avoid
    ///      copying attacker-supplied padding before the check.
    function _checkValidSignatureLength(KeyType sigType, uint256 sigLength) private pure {
        if (sigType == KeyType.EOA) {
            if (sigLength > 192) {
                revert IKeysManager.KeyManager__InvalidSignatureLength();
            }
        } else if (sigType == KeyType.P256 || sigType == KeyType.P256NONKEY) {
            if (sigLength > 224) {
                revert IKeysManager.KeyManager__InvalidSignatureLength();
            }
        }
    }

    /**
     * @notice Validates an EOA (ECDSA) key signature.
     * @param signature     Raw signature bytes (64 or 65 bytes).
     * @param userOpHash  The user operation hash.
     * @param userOp      The packed user operation coming from EntryPoint.
     * @return Packed validation output, or SIG_VALIDATION_FAILED.
     */
    function _validateKeyTypeEOA(
        bytes memory signature,
        bytes32 userOpHash,
        PackedUserOperation calldata userOp
    ) private returns (uint256) {
        address signer = ECDSA.recover(userOpHash, signature);

        // if masterKey (this contract) signed it, immediate success
        if (signer == address(this)) {
            return SIG_VALIDATION_SUCCESS;
        }

        // load the key for this EOA
        bytes32 keyId = signer.computeKeyId();
        KeyData storage sKey = keys[keyId];

        bool isValid = _keyValidation(sKey);

        // master key → immediate success
        if (sKey.masterKey && isValid) {
            return SIG_VALIDATION_SUCCESS;
        }

        uint256 isValidGas = IUserOpPolicy(GAS_POLICY).checkUserOpPolicy(keyId, userOp);

        if (isValidKey(userOp.callData, sKey) && isValid && isValidGas == 0) {
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
     * @param signature   ABI-encoded payload: (KeyType, bool requireUV, bytes authData, string clientDataJSON, uint256
     * challengeIdx, uint256 typeIdx, bytes32 r, bytes32 s, PubKey pubKey).
     * @param userOp      The packed user operation coming from EntryPoint.
     * @return Packed validation output, or SIG_VALIDATION_FAILED.
     */
    function _validateKeyTypeWEBAUTHN(
        bytes memory signature,
        bytes32 userOpHash,
        PackedUserOperation calldata userOp
    ) private returns (uint256) {
        // decode everything in one shot
        (
            bool requireUV,
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeIndex,
            uint256 typeIndex,
            bytes32 r,
            bytes32 s,
            PubKey memory pubKey
        ) = abi.decode(signature, (bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey));

        SigLengthLib.assertWebAuthnOuterLen(
            userOp.signature.length, authenticatorData.length, bytes(clientDataJSON).length
        );

        if (usedChallenges[userOpHash]) {
            revert IKeysManager.KeyManager__UsedChallenge();
        }

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

        bytes32 keyId = pubKey.computeKeyId();
        KeyData storage sKey = keys[keyId];

        bool isValid = _keyValidation(sKey);

        usedChallenges[userOpHash] = true; // mark challenge as used

        if (sKey.masterKey && isValid && sigOk) {
            return SIG_VALIDATION_SUCCESS;
        }

        uint256 isValidGas = IUserOpPolicy(GAS_POLICY).checkUserOpPolicy(keyId, userOp);

        if (isValidKey(userOp.callData, sKey) && isValid && sigOk && isValidGas == 0) {
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
     * @param signature     Encoded bytes: (r, s, PubKey).
     * @param userOpHash  The original userOp hash.
     * @param userOp      The packed user operation coming from EntryPoint.
     * @param sigType     KeyType.P256 or KeyType.P256NONKEY.
     * @return Packed validation output, or SIG_VALIDATION_FAILED.
     */
    function _validateKeyTypeP256(
        bytes memory signature,
        bytes32 userOpHash,
        PackedUserOperation calldata userOp,
        KeyType sigType
    ) private returns (uint256) {
        (bytes32 r, bytes32 sSig, PubKey memory pubKey) =
            abi.decode(signature, (bytes32, bytes32, PubKey));

        bytes32 challenge =
            (sigType == KeyType.P256NONKEY) ? EfficientHashLib.sha2(userOpHash) : userOpHash;

        if (usedChallenges[challenge]) {
            revert IKeysManager.KeyManager__UsedChallenge();
        }

        bool sigOk = IWebAuthnVerifier(webAuthnVerifier()).verifyP256Signature(
            challenge, r, sSig, pubKey.x, pubKey.y
        );

        bytes32 keyId = pubKey.computeKeyId();
        KeyData storage sKey = keys[keyId];

        bool isValid = _keyValidation(sKey);

        usedChallenges[challenge] = true;

        uint256 isValidGas = IUserOpPolicy(GAS_POLICY).checkUserOpPolicy(keyId, userOp);

        if (isValidKey(userOp.callData, sKey) && isValid && sigOk && isValidGas == 0) {
            return _packValidationData(false, sKey.validUntil, sKey.validAfter);
        }

        return SIG_VALIDATION_FAILED;
    }

    /// @notice Validates if a key is registered and active
    /// @param sKey Storage reference to the key data to validate
    /// @return isValid True if key is both registered and active, false otherwise
    function _keyValidation(KeyData storage sKey) internal view returns (bool isValid) {
        // Check if key is valid and active
        if (!(sKey.isRegistered() && sKey.isActive)) {
            return false; // Early return for invalid key
        }

        return true;
    }

    /// @dev Authorizes `_callData` for `sKey`.
    ///      Supports only `execute(bytes32,bytes)` (selector 0xe9ae5c53) and
    ///      defers granular checks to `_validateExecuteCall(...)`.
    ///      Unknown selectors return false. May consume per-key quotas/limits downstream.
    function isValidKey(bytes calldata _callData, KeyData storage sKey)
        internal
        virtual
        returns (bool)
    {
        // Extract function selector from callData execute(bytes32,bytes)
        bytes4 funcSelector = bytes4(_callData[:4]);

        if (funcSelector == 0xe9ae5c53) {
            return _validateExecuteCall(sKey, _callData);
        }
        return false;
    }

    /**
     * @notice Validates a single `execute(target, value, data)` call.
     * @dev
     *  • Decode `execute(bytes32,bytes)`.
     *  • If `toContract == address(this)`, revert.
     *  • If `masterKey`, immediate true.
     *  • Else enforce:
     *      - limit > 0
     *      - ethLimit ≥ amount
     *      - `bytes4(innerData)` ∈ `allowedSelectors`
     *      - Decrement `limit` and subtract `amount` from `ethLimit`
     *      - If `spendTokenInfo.token == toContract`, call `_validateTokenSpend(...)`
     *      - If whitelisting enable and target is whitelisted
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

        if (!(sKey.whitelisting && sKey.whitelist[call.target])) {
            return false;
        }
        return true;
    }

    /**
     * @notice Validates a token transfer against the key’s token spend limit.
     * @dev Loads `value` from the last 32 bytes of `innerData` (standard ERC-20 `_transfer(address,uint256)`
     * signature).
     * @dev Out of scope (not supported): Extended/alternative token interfaces where spend cannot be
     *      inferred from the trailing 32 bytes, including but not limited to:
     *        - ERC-777 (`send`, operator functions and hooks)
     *        - ERC-1363 (`transferAndCall`, etc.)
     *        - ERC-4626 vaults (`deposit`, `mint`, `withdraw`, `redeem`, etc.)
     *        - Allowance changes (`approve`, `increaseAllowance`, `decreaseAllowance`)
     *        - Permit-style signatures (EIP-2612) or any function where the amount is not the last arg.
     *      Calls to those selectors MUST be blocked elsewhere (e.g., via `allowedSelectors`) because
     *      this function will not correctly measure spend and may produce misleading deductions.
     * @param sKey      Storage reference of the KeyData
     * @param innerData The full encoded call data to the token contract.
     * @return True if `value ≤ sKey.spendTokenInfo.limit`; false if it exceeds or is invalid.
     */
    function _validateTokenSpend(KeyData storage sKey, bytes memory innerData)
        internal
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
            unchecked {
                sKey.spendTokenInfo.limit -= value;
            }
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
     * @dev `isValidSignature` used only in case of RootKey/Master Key (EOA/WebAuthn) signer.
     *  • EOA (ECDSA) path recovers `signer`. If `signer == this`, return `isValidSignature.selector`.
     *    Else packed WebAuthn signature, load `key = keys[keyHash]` and enforce:
     *      - (masterKey)
     * @dev The session key does not undergo ERC-1271 validation, preventing granted roles
     *      from utilizing Permit2 to bypass the established spending policy limits defined in the signature.
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

        if (_signature.length == 64 || _signature.length == 65) {
            return _validateEOASignature(_signature, _hash);
        } else {
            return _validateWebAuthnSignature(_signature, _hash);
        }
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
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(_hash, _signature);
        if (err != ECDSA.RecoverError.NoError) {
            return bytes4(0xffffffff);
        }

        if (signer == address(this)) {
            return this.isValidSignature.selector;
        }

        bytes32 keyHash = signer.computeKeyId();
        KeyData storage sKey = keys[keyHash];

        if (sKey.masterKey) return this.isValidSignature.selector;

        return bytes4(0xffffffff);
    }

    /**
     * @notice Validate a WebAuthn signature on-chain via ERC-1271.
     * @param _signature  ABI-encoded: (bool UV, bytes authData, string cDataJSON, uint256 cIdx, uint256 tIdx, bytes32
     * r, bytes32 s, PubKey pubKey)
     * @param _hash       The hash to verify.
     * @return `this.isValidSignature.selector` if valid; otherwise `0xffffffff`.
     */
    function _validateWebAuthnSignature(bytes memory _signature, bytes32 _hash)
        internal
        view
        returns (bytes4)
    {
        bool requireUV;
        bytes memory authenticatorData;
        string memory clientDataJSON;
        uint256 challengeIndex;
        uint256 typeIndex;
        bytes32 r;
        bytes32 s;
        PubKey memory pubKey;

        try this._decodeWebAuthn1271(_signature) returns (
            bool _requireUV,
            bytes memory _authData,
            string memory _cData,
            uint256 _cIdx,
            uint256 _tIdx,
            bytes32 _r,
            bytes32 _s,
            PubKey memory _pk
        ) {
            requireUV = _requireUV;
            authenticatorData = _authData;
            clientDataJSON = _cData;
            challengeIndex = _cIdx;
            typeIndex = _tIdx;
            r = _r;
            s = _s;
            pubKey = _pk;
        } catch {
            return bytes4(0xffffffff);
        }

        if (usedChallenges[_hash]) {
            return bytes4(0xffffffff);
        }

        bool sigOk;
        try IWebAuthnVerifier(webAuthnVerifier()).verifySignature(
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
        ) returns (bool ok) {
            sigOk = ok;
        } catch {
            return bytes4(0xffffffff);
        }

        if (!sigOk) {
            return bytes4(0xffffffff);
        }

        bytes32 keyHash = pubKey.computeKeyId();
        KeyData storage sKey = keys[keyHash];

        if (sKey.masterKey) return this.isValidSignature.selector;

        return bytes4(0xffffffff);
    }

    /// @dev helper ONLY for 1271 decoding so we can try/catch
    function _decodeWebAuthn1271(bytes memory sig)
        external
        pure
        returns (
            bool requireUV,
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeIndex,
            uint256 typeIndex,
            bytes32 r,
            bytes32 s,
            PubKey memory pubKey
        )
    {
        return abi.decode(sig, (bool, bytes, string, uint256, uint256, bytes32, bytes32, PubKey));
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
