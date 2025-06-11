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
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCESS,
    _packValidationData
} from "lib/account-abstraction/contracts/core/Helpers.sol";

/**
 * @title   Openfort Base Account 7702 with ERC-4337 Support
 * @author  Openfort — https://openfort.xyz
 * @notice  Smart contract wallet implementing EIP-7702 + ERC-4337 + multi-format keys.
 * @dev
 *  • EIP-4337 integration via EntryPoint
 *  • EIP-7702 support (e.g., setCode)
 *  • Multi-scheme keys: EOA (ECDSA), WebAuthn, P256/P256NONKEY
 *  • ETH/token spending limits + selector whitelists
 *  • ERC-1271 on-chain signature support
 *  • Reentrancy protection & explicit nonce replay prevention
 *
 * Layout storage slot (keccak256):
 *  "openfort.baseAccount.7702.v1" =
 *    0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
 *    == 57943590311362240630886240343495690972153947532773266946162183175043753177960
 */
contract OPF7702 is Execution, Initializable, WebAuthnVerifier {
    using ECDSA for bytes32;

    /// @notice Address of this implementation contract
    address public immutable _OPENFORT_CONTRACT_ADDRESS;

    /// @notice Emitted when the account is initialized with a masterKey
    event Initialized(Key indexed masterKey);

    constructor(address _entryPoint) {
        ENTRY_POINT = _entryPoint;
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

        bytes32 keyId = keccak256(abi.encodePacked(signer));
        // load the key for this EOA
        KeyData storage sKey = keys[keyId];

        (Key memory composedKey, bool isValid) = _keyValidation(sKey, signer, KeyType.EOA);

        if (!isValid) return SIG_VALIDATION_FAILED;

        // master key → immediate success
        if (sKey.masterKey) {
            return SIG_VALIDATION_SUCCESS;
        }

        if (isValidKey(composedKey, callData)) {
            return _packValidationData(false, sKey.validUntil, sKey.validAfter);
        }
        return SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Validates a WebAuthn‐type signature (Solady verifier).
     * @dev
     *  • Reject reused challenges.
     *  • Verify with `verifySoladySignature`.
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

        bool sigOk = verifySoladySignature(
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

        bytes32 keyHash = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
        KeyData storage sKey = keys[keyHash];

        (Key memory composedKey, bool isValid) =
            _keyValidation(sKey, DEAD_ADDRESS, KeyType.WEBAUTHN);

        if (!isValid) return SIG_VALIDATION_FAILED;

        // master key → immediate success
        if (sKey.masterKey) {
            return SIG_VALIDATION_SUCCESS;
        }

        if (isValidKey(composedKey, callData)) {
            usedChallenges[userOpHash] = true; // mark challenge as used
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
        if (sigType == KeyType.P256NONKEY) {
            userOpHash = EfficientHashLib.sha2(userOpHash);
        }

        bool sigOk = verifyP256Signature(userOpHash, r, sSig, pubKey.x, pubKey.y);
        if (!sigOk) {
            return SIG_VALIDATION_FAILED;
        }

        bytes32 keyHash = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
        KeyData storage sKey = keys[keyHash];

        (Key memory composedKey, bool isValid) =
            _keyValidation(sKey, DEAD_ADDRESS, KeyType.WEBAUTHN);

        if (!isValid) return SIG_VALIDATION_FAILED;

        if (isValidKey(composedKey, callData)) {
            usedChallenges[userOpHash] = true;
            return _packValidationData(false, sKey.validUntil, sKey.validAfter);
        }
        return SIG_VALIDATION_FAILED;
    }

    function _keyValidation(KeyData storage sKey, address signer, KeyType keyType)
        internal
        view
        returns (Key memory composedKey, bool isValid)
    {
        // Check if key is valid and active
        if (sKey.validUntil == 0 || sKey.whoRegistrated != address(this) || !sKey.isActive) {
            return (composedKey, false); // Early return for invalid key
        }

        // Build the composed key
        composedKey = Key({
            pubKey: PubKey({x: sKey.pubKey.x, y: sKey.pubKey.y}),
            eoaAddress: signer,
            keyType: keyType
        });

        return (composedKey, true);
    }

    /**
     * @notice Determines if a given key may perform `execute` or `executeBatch`.
     * @dev
     *  • Loads the correct `KeyData` based on `KeyType`:
     *      – WEBAUTHN/P256/P256NONKEY/EOA → `keys[keccak(pubKey.x,pubKey.y)]`
     *  • Checks: validUntil != 0, isActive, whoRegistrated == address(this).
     *  • Extracts the first 4 bytes of `_callData` and calls:
     *      – `_validateExecuteCall(...)`
     *      – `_validateExecuteBatchCall(...)`
     *
     * @param _key       The Key struct being tested.
     * @param _callData  The calldata (starting with selector).
     * @return True if permitted, false otherwise.
     */
    function isValidKey(Key memory _key, bytes calldata _callData)
        internal
        virtual
        returns (bool)
    {
        KeyData storage sKey;
        bytes32 keyHash;

        if (_key.keyType == KeyType.EOA) {
            if (_key.eoaAddress == address(0)) return false;
            keyHash = keccak256(abi.encodePacked(_key.eoaAddress));
            sKey = keys[keyHash];
        } else {
            // WEBAUTHN/P256/P256NONKEY share same load path
            keyHash = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
            sKey = keys[keyHash];
        }
        // Basic checks:
        if (sKey.validUntil == 0 || !sKey.isActive || sKey.whoRegistrated != address(this)) {
            return false;
        }

        bytes4 selector = bytes4(_callData[:4]);
        if (selector == EXECUTE_SELECTOR) {
            return _validateExecuteCall(sKey, _callData);
        }
        if (selector == EXECUTEBATCH_SELECTOR) {
            return _validateExecuteBatchCall(sKey, _callData);
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
        (address toContract, uint256 amount, bytes memory innerData) =
            abi.decode(_callData[4:], (address, uint256, bytes));

        if (toContract == address(this)) {
            return false;
        }
        if (sKey.masterKey) {
            return true;
        }
        if (sKey.limit == 0 || sKey.ethLimit < amount) {
            return false;
        }

        bytes4 innerSel = bytes4(innerData);
        if (!_isAllowedSelector(sKey.allowedSelectors, innerSel)) {
            return false;
        }

        unchecked {
            sKey.limit--;
        }
        if (amount > 0) {
            sKey.ethLimit -= amount;
        }

        if (sKey.spendTokenInfo.token == toContract) {
            if (!_validateTokenSpend(sKey, innerData)) {
                return false;
            }
        }

        // if not whitelisting, or toContract is whitelisted, OK
        return !sKey.whitelisting || sKey.whitelist[toContract];
    }

    /**
     * @notice Validates a batch of `executeBatch(targets[], values[], data[])` calls.
     * @dev
     *  • Decode `(address[] toContracts, uint256[] amounts, bytes[] innerDataArray)`.
     *  • If length = 0 or > 9, reject.
     *  • If not `masterKey` then:
     *      - `limit ≥ length`
     *      - Subtract `length` from `limit`
     *  • For each index `i`:
     *      - if `toContracts[i] == address(this)`, reject
     *      - If not `masterKey`:
     *          * `ethLimit ≥ amounts[i]` then subtract
     *          * `bytes4(innerDataArray[i]) ∈ allowedSelectors`
     *          * If `spendTokenInfo.token == toContracts[i]`, call `_validateTokenSpend(...)`
     *          * If `whitelisting`, ensure `toContracts[i] ∈ whitelist`
     *
     * @param sKey       Storage reference of the KeyData
     * @param _callData  Encoded as: `executeBatch(address[],uint256[],bytes[])`
     * @return True if all calls allowed, false otherwise.
     */
    function _validateExecuteBatchCall(KeyData storage sKey, bytes calldata _callData)
        internal
        returns (bool)
    {
        (address[] memory targets, uint256[] memory amounts, bytes[] memory dataArr) =
            abi.decode(_callData[4:], (address[], uint256[], bytes[]));

        uint256 n = targets.length;
        if (n == 0 || n > MAX_TX) {
            return false;
        }

        if (!sKey.masterKey) {
            if (sKey.limit < n) {
                return false;
            }
            unchecked {
                sKey.limit -= SafeCast.toUint48(n);
            }
        }

        for (uint256 i = 0; i < n;) {
            address toContract = targets[i];
            if (toContract == address(this)) {
                return false;
            }

            if (!sKey.masterKey) {
                uint256 amt = amounts[i];
                if (sKey.ethLimit < amt) {
                    return false;
                }
                sKey.ethLimit -= amt;

                bytes4 innerSel = bytes4(dataArr[i]);
                if (!_isAllowedSelector(sKey.allowedSelectors, innerSel)) {
                    return false;
                }

                if (sKey.spendTokenInfo.token == toContract) {
                    if (!_validateTokenSpend(sKey, dataArr[i])) {
                        return false;
                    }
                }

                if (sKey.whitelisting && !sKey.whitelist[toContract]) {
                    return false;
                }
            }
            unchecked {
                ++i;
            }
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
     *      - whoRegistrated == address(this)
     * @param _hash       The hash that was signed.
     * @param _signature  The signature blob to verify.
     * @return `this.isValidSignature.selector` if valid; otherwise `0xffffffff`.
     */
    function isValidSignature(bytes32 _hash, bytes memory _signature)
        public
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

        bytes32 keyHash = keccak256(abi.encodePacked(signer));
        KeyData storage sKey = keys[keyHash];

        if (sKey.masterKey) return this.isValidSignature.selector;

        // validity window
        if (
            sKey.validUntil == 0 || sKey.validAfter > block.timestamp
                || sKey.validUntil < block.timestamp
        ) {
            return bytes4(0xffffffff);
        }
        // spend limit check
        if (!sKey.masterKey && sKey.limit < 1) {
            return bytes4(0xffffffff);
        }
        if (sKey.whoRegistrated != address(this)) {
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
        bool sigOk = verifySoladySignature(
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

        bytes32 keyHash = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
        KeyData storage sKey = keys[keyHash];

        if (sKey.masterKey) return this.isValidSignature.selector;

        if (
            sKey.validUntil == 0 || sKey.validAfter > block.timestamp
                || sKey.validUntil < block.timestamp
        ) {
            return bytes4(0xffffffff);
        }
        if (!sKey.masterKey && sKey.limit < 1) {
            return bytes4(0xffffffff);
        }
        if (sKey.whoRegistrated != address(this)) {
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
        (bytes32 r, bytes32 sSig, PubKey memory pubKey) =
            abi.decode(inner, (bytes32, bytes32, PubKey));

        if (usedChallenges[_hash]) {
            return bytes4(0xffffffff);
        }

        bytes32 hashToCheck = _hash;
        if (kt == KeyType.P256NONKEY) {
            hashToCheck = EfficientHashLib.sha2(_hash);
        }

        bool sigOk = verifyP256Signature(hashToCheck, r, sSig, pubKey.x, pubKey.y);
        if (!sigOk) {
            return bytes4(0xffffffff);
        }

        bytes32 keyHash = keccak256(abi.encodePacked(pubKey.x, pubKey.y));
        KeyData storage sKey = keys[keyHash];
        if (
            sKey.validUntil == 0 || sKey.validAfter > block.timestamp
                || sKey.validUntil < block.timestamp
        ) {
            return bytes4(0xffffffff);
        }
        if (!sKey.masterKey && sKey.limit < 1) {
            return bytes4(0xffffffff);
        }
        if (sKey.whoRegistrated != address(this)) {
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
