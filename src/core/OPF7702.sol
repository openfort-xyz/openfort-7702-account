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
 * @notice  Smart contract wallet implementing EIP-7702 + ERC-4337 + multi-format session keys.
 * @dev
 *  • EIP-4337 integration via EntryPoint
 *  • EIP-7702 support (e.g., setCode)
 *  • Multi-scheme session keys: EOA (ECDSA), WebAuthn, P256/P256NONKEY
 *  • ETH/token spending limits + selector whitelists
 *  • ERC-1271 on-chain signature support
 *  • Reentrancy protection & explicit nonce replay prevention
 *
 * Layout storage slot (keccak256):
 *  "openfort.baseAccount.7702.v1" =
 *    0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
 *    == 57943590311362240630886240343495690972153947532773266946162183175043753177960
 */
contract OPF7702 is Execution, Initializable, WebAuthnVerifier layout at 57943590311362240630886240343495690972153947532773266946162183175043753177960 {
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
     * @notice Initializes the account with a “master” session key (no spending or whitelist restrictions).
     * @dev
     *  • Callable only via EntryPoint or a self-call.
     *  • Clears previous storage, checks nonce & expiration, verifies signature.
     *  • Registers the provided `_key` as a master session key:
     *     - validUntil = max (never expires)
     *     - validAfter  = 0
     *     - limit       = 0  (master)
     *     - whitelisting = false
     *     - DEAD_ADDRESS placeholder in whitelistedContracts
     *  • Emits `Initialized(_key)`.
     *
     * @param _key              The Key struct (master session key).
     * @param _spendTokenInfo   Token limit info (ignored for master).
     * @param _allowedSelectors Unused selectors (ignored for master).
     * @param _hash             Hash to sign (EIP-712 or UserOp hash).
     * @param _signature        Signature over `_hash` by this contract.
     * @param _validUntil       Expiration timestamp for this initialization.
     * @param _nonce            Nonce to prevent replay.
     */
    function initialize(
        Key calldata _key,
        SpendTokenInfo calldata _spendTokenInfo,
        bytes4[] calldata _allowedSelectors,
        bytes32 _hash,
        bytes memory _signature,
        uint256 _validUntil,
        uint256 _nonce
    ) external initializer {
        _requireForExecute();
        _clearStorage();
        _validateNonce(_nonce);
        _notExpired(_validUntil);

        if (!_checkSignature(_hash, _signature)) {
            revert OpenfortBaseAccount7702V1__InvalidSignature();
        }

        // record new nonce
        nonce = _nonce;

        // register masterKey: never expires, no spending/whitelist restrictions
        registerSessionKey(
            _key,
            type(uint48).max, // validUntil = max
            0, // validAfter = 0
            0, // limit = 0 (master)
            false, // no whitelisting
            DEAD_ADDRESS, // dummy contract address
            _spendTokenInfo, // token info (ignored)
            _allowedSelectors, // selectors (ignored)
            0 // ethLimit = 0
        );

        emit Initialized(_key);
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
     * @notice Validates an EOA (ECDSA) session key signature.
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

        // load the sessionKey for this EOA
        SessionKey storage sKey = sessionKeysEOA[signer];
        // if no active sessionKey, reject
        if (sKey.validUntil == 0 || sKey.whoRegistrated != address(this) || !sKey.isActive) {
            return SIG_VALIDATION_FAILED;
        }

        // build a minimal Key struct to call isValidSessionKey
        Key memory composedKey = Key({
            pubKey: PubKey({x: sKey.pubKey.x, y: sKey.pubKey.y}),
            eoaAddress: signer,
            keyType: KeyType.EOA
        });

        if (isValidSessionKey(composedKey, callData)) {
            return _packValidationData(false, sKey.validUntil, sKey.validAfter);
        }
        return SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Validates a WebAuthn‐type signature (Solady verifier).
     * @dev
     *  • Reject reused challenges.
     *  • Verify with `verifySoladySignature`.
     *  • If master sessionKey, immediate success.
     *  • Otherwise, call `isValidSessionKey(...)`.
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
        SessionKey storage sKey = sessionKeys[keyHash];
        if (sKey.whoRegistrated != address(this) || !sKey.isActive || sKey.validUntil == 0) {
            return SIG_VALIDATION_FAILED;
        }

        // master session key → immediate success
        if (sKey.masterSessionKey) {
            return SIG_VALIDATION_SUCCESS;
        }

        // build minimal Key
        Key memory composedKey = Key({
            pubKey: PubKey({x: sKey.pubKey.x, y: sKey.pubKey.y}),
            eoaAddress: address(0),
            keyType: KeyType.WEBAUTHN
        });

        if (isValidSessionKey(composedKey, callData)) {
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
     *  • If master sessionKey, immediate success.
     *  • Otherwise, call `isValidSessionKey(...)`.
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
        SessionKey storage sKey = sessionKeys[keyHash];
        if (sKey.whoRegistrated != address(this) || !sKey.isActive || sKey.validUntil == 0) {
            return SIG_VALIDATION_FAILED;
        }

        // master session → immediate success
        if (sKey.masterSessionKey) {
            return SIG_VALIDATION_SUCCESS;
        }

        Key memory composedKey = Key({
            pubKey: PubKey({x: sKey.pubKey.x, y: sKey.pubKey.y}),
            eoaAddress: address(0),
            keyType: KeyType.P256
        });

        if (isValidSessionKey(composedKey, callData)) {
            usedChallenges[userOpHash] = true;
            return _packValidationData(false, sKey.validUntil, sKey.validAfter);
        }
        return SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Determines if a given session key may perform `execute` or `executeBatch`.
     * @dev
     *  • Loads the correct `SessionKey` based on `KeyType`:
     *      – WEBAUTHN/P256/P256NONKEY → `sessionKeys[keccak(pubKey.x,pubKey.y)]`
     *      – EOA                 → `sessionKeysEOA[eoaAddress]`
     *  • Checks: validUntil != 0, isActive, whoRegistrated == address(this).
     *  • Extracts the first 4 bytes of `_callData` and calls:
     *      – `_validateExecuteCall(...)`
     *      – `_validateExecuteBatchCall(...)`
     *
     * @param _key       The Key struct being tested.
     * @param _callData  The calldata (starting with selector).
     * @return True if permitted, false otherwise.
     */
    function isValidSessionKey(Key memory _key, bytes calldata _callData)
        internal
        virtual
        returns (bool)
    {
        SessionKey storage sKey;
        if (_key.keyType == KeyType.EOA) {
            address eoaAddr = _key.eoaAddress;
            if (eoaAddr == address(0)) return false;
            sKey = sessionKeysEOA[eoaAddr];
        } else {
            // WEBAUTHN/P256/P256NONKEY share same load path
            bytes32 keyHash = keccak256(abi.encodePacked(_key.pubKey.x, _key.pubKey.y));
            sKey = sessionKeys[keyHash];
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
     *  • If `masterSessionKey`, immediate true.
     *  • Else enforce:
     *      - limit > 0
     *      - ethLimit ≥ amount
     *      - `bytes4(innerData)` ∈ `allowedSelectors`
     *      - Decrement `limit` and subtract `amount` from `ethLimit`
     *      - If `spendTokenInfo.token == toContract`, call `_validateTokenSpend(...)`
     *      - If `whitelisting`, ensure `toContract` ∈ `whitelist`
     *
     * @param sKey       Storage reference of the SessionKey
     * @param _callData  Encoded as: `execute(address,uint256,bytes)`
     * @return True if allowed, false otherwise.
     */
    function _validateExecuteCall(SessionKey storage sKey, bytes calldata _callData)
        internal
        returns (bool)
    {
        (address toContract, uint256 amount, bytes memory innerData) =
            abi.decode(_callData[4:], (address, uint256, bytes));

        if (toContract == address(this)) {
            return false;
        }
        if (sKey.masterSessionKey) {
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
     *  • If not `masterSessionKey` then:
     *      - `limit ≥ length`
     *      - Subtract `length` from `limit`
     *  • For each index `i`:
     *      - if `toContracts[i] == address(this)`, reject
     *      - If not `masterSessionKey`:
     *          * `ethLimit ≥ amounts[i]` then subtract
     *          * `bytes4(innerDataArray[i]) ∈ allowedSelectors`
     *          * If `spendTokenInfo.token == toContracts[i]`, call `_validateTokenSpend(...)`
     *          * If `whitelisting`, ensure `toContracts[i] ∈ whitelist`
     *
     * @param sKey       Storage reference of the SessionKey
     * @param _callData  Encoded as: `executeBatch(address[],uint256[],bytes[])`
     * @return True if all calls allowed, false otherwise.
     */
    function _validateExecuteBatchCall(SessionKey storage sKey, bytes calldata _callData)
        internal
        returns (bool)
    {
        (address[] memory targets, uint256[] memory amounts, bytes[] memory dataArr) =
            abi.decode(_callData[4:], (address[], uint256[], bytes[]));

        uint256 n = targets.length;
        if (n == 0 || n > MAX_TX) {
            return false;
        }

        if (!sKey.masterSessionKey) {
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

            if (!sKey.masterSessionKey) {
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
     * @notice Validates a token transfer against the sessionKey’s token spend limit.
     * @dev Loads `value` from the last 32 bytes of `innerData` (standard ERC-20 `_transfer(address,uint256)` signature).
     * @param sKey      Storage reference of the SessionKey
     * @param innerData The full encoded call data to the token contract.
     * @return True if `value ≤ sKey.spendTokenInfo.limit`; false if it exceeds or is invalid.
     */
    function _validateTokenSpend(SessionKey storage sKey, bytes memory innerData)
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
     *    Else, load `sessionKey = sessionKeysEOA[signer]` and enforce:
     *      - validUntil > now ≥ validAfter
     *      - (masterSessionKey or limit≥1)
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
            address signer = ECDSA.recover(_hash, _signature);
            if (signer == address(0)) {
                return bytes4(0xffffffff);
            }
            if (signer == address(this)) {
                return this.isValidSignature.selector;
            }

            SessionKey storage sKey = sessionKeysEOA[signer];
            // validity window
            if (
                sKey.validUntil == 0 || sKey.validAfter > block.timestamp
                    || sKey.validUntil < block.timestamp
            ) {
                return bytes4(0xffffffff);
            }
            // spend limit check
            if (!sKey.masterSessionKey && sKey.limit < 1) {
                return bytes4(0xffffffff);
            }
            if (sKey.whoRegistrated != address(this)) {
                return bytes4(0xffffffff);
            }
            return this.isValidSignature.selector;
        }
        return bytes4(0xffffffff);
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
        SessionKey storage sKey = sessionKeys[keyHash];
        if (
            sKey.validUntil == 0 || sKey.validAfter > block.timestamp
                || sKey.validUntil < block.timestamp
        ) {
            return bytes4(0xffffffff);
        }
        if (!sKey.masterSessionKey && sKey.limit < 1) {
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
        SessionKey storage sKey = sessionKeys[keyHash];
        if (
            sKey.validUntil == 0 || sKey.validAfter > block.timestamp
                || sKey.validUntil < block.timestamp
        ) {
            return bytes4(0xffffffff);
        }
        if (!sKey.masterSessionKey && sKey.limit < 1) {
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
