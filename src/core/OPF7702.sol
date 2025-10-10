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
import {SigLengthLib} from "src/libs/SigLengthLib.sol";
import {IUserOpPolicy} from "src/interfaces/IPolicy.sol";
import {LibBytes} from "lib/solady/src/utils/LibBytes.sol";
import {KeysManagerLib} from "src/libs/KeysManagerLib.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {DateTimeLib} from "lib/solady/src/utils/DateTimeLib.sol";
import {IWebAuthnVerifier} from "src/interfaces/IWebAuthnVerifier.sol";
import {EfficientHashLib} from "lib/solady/src/utils/EfficientHashLib.sol";
import {EnumerableSetLib} from "lib/solady/src/utils/EnumerableSetLib.sol";
import {FixedPointMathLib as Math} from "lib/solady/src/utils/FixedPointMathLib.sol";
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
 * @custom:inspired-by Ithaca Account (Token Spend & Can Call validation model)
 */
contract OPF7702 is Execution, Initializable {
    using KeysManagerLib for *;
    using EnumerableSetLib for *;
    using ECDSA for bytes32;
    using SigLengthLib for bytes;
    using KeyValidation for KeyData;

    /// @notice Address of this implementation contract
    address public immutable _OPENFORT_CONTRACT_ADDRESS;

    /**
     * @notice Deploys the base account implementation with its immutable dependencies.
     * @param _entryPoint       ERC-4337 EntryPoint address used for UserOperation validation.
     * @param _webAuthnVerifier External verifier contract for WebAuthn/P-256 signatures.
     * @param _gasPolicy        Policy contract invoked for custodial key gas validation.
     */
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

    /**
     * @dev Enforces per-key-type signature length limits before decoding payloads.
     * @param sigType   Key type prefix extracted from the signature envelope.
     * @param sigLength Total length of the signature blob (type + payload).
     */
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
        bytes32 keyId = KeyType.EOA.computeKeyId(abi.encode(signer));
        KeyData storage sKey = keys[keyId];

        bool isValid = _keyValidation(sKey);

        // master key → immediate success
        if (sKey.masterKey && isValid) {
            return SIG_VALIDATION_SUCCESS;
        }

        uint256 isValidGas;
        if (sKey.isDelegatedControl) {
            isValidGas = IUserOpPolicy(GAS_POLICY).checkUserOpPolicy(keyId, userOp);
        }

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
     * @param signature   ABI-encoded payload: (bool requireUV, bytes authData, string clientDataJSON, uint256
     * challengeIdx, uint256 typeIdx, bytes32 r, bytes32 s, PubKey pubKey).
     * @param userOpHash  The userOp hash (served as challenge).
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

        // bytes32 keyId = pubKey.computeKeyId();
        bytes32 keyId = KeyType.WEBAUTHN.computeKeyId(abi.encode(pubKey.x, pubKey.y));
        KeyData storage sKey = keys[keyId];

        bool isValid = _keyValidation(sKey);

        if (sKey.masterKey && isValid && sigOk) {
            return SIG_VALIDATION_SUCCESS;
        }

        uint256 isValidGas;
        if (sKey.isDelegatedControl) {
            isValidGas = IUserOpPolicy(GAS_POLICY).checkUserOpPolicy(keyId, userOp);
        }

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

        bool sigOk = IWebAuthnVerifier(webAuthnVerifier()).verifyP256Signature(
            challenge, r, sSig, pubKey.x, pubKey.y
        );

        // bytes32 keyId = pubKey.computeKeyId();
        bytes32 keyId = KeyType.P256 == sigType
            ? KeyType.P256.computeKeyId(abi.encode(pubKey.x, pubKey.y))
            : KeyType.P256NONKEY.computeKeyId(abi.encode(pubKey.x, pubKey.y));
        KeyData storage sKey = keys[keyId];

        bool isValid = _keyValidation(sKey);

        uint256 isValidGas;
        if (sKey.isDelegatedControl) {
            isValidGas = IUserOpPolicy(GAS_POLICY).checkUserOpPolicy(keyId, userOp);
        }

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

    /**
     * @dev Authorizes `_callData` for `sKey`. Supports only `execute(bytes32,bytes)` (selector 0xe9ae5c53).
     *      Unknown selectors return false. May consume per-key quotas/limits downstream.
     * @param _callData Encoded calldata passed to the account.
     * @param sKey      Storage reference to the key executing the call.
     * @return True if the selector is recognized and validated; false otherwise.
     */
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

    /**
     * @notice Validates a single call against the key’s permissions, spend policy, and quota.
     * @dev Fast-fails on:
     *      - `call.target == address(this)` (self-calls are forbidden).
     *      - `!sKey.hasQuota()` (no remaining tx quota per key).
     *      Derives `keyId` from `(sKey.keyType, sKey.key)` and checks:
     *       - Can-call permission via `_isCanCall(keyId, call.target, call.data)`.
     *       - Token spend policy if applicable:
     *          • Treats native transfers (`call.value > 0`) as spending `NATIVE_ADDRESS`.
     *          • Otherwise uses `call.target` as the token address.
     *          • If a spend rule exists, enforces it via `_isTokenSpend(...)`.
     *      On success, decrements the key’s quota via `sKey.consumeQuota()`.
     * @param sKey  Storage reference to the key data executing the call.
     * @param call  The call to validate (target, value, data).
     * @return True if the call is permitted and quota was consumed; false otherwise.
     */
    function _validateCall(KeyData storage sKey, Call memory call) private returns (bool) {
        if (call.target == address(this)) return false;
        if (!sKey.hasQuota()) return false;

        bytes32 keyId = sKey.keyType.computeKeyId(sKey.key);
        if (!_isCanCall(keyId, call.target, call.data)) {
            return false;
        }

        address token = call.value > 0 ? NATIVE_ADDRESS : call.target;

        if (hasTokenSpend(keyId, token)) {
            if (!_isTokenSpend(keyId, call.target, call.value, call.data)) {
                return false;
            }
        }

        sKey.consumeQuota();

        return true;
    }

    /**
     * @notice Checks whether a key is allowed to call `(target, selector)`.
     * @dev Extracts `fnSel` from calldata (first 4 bytes). Special cases:
     *      - Empty calldata → `fnSel = EMPTY_CALLDATA_FN_SEL` (plain ETH transfer).
     *      Uses the per-key `canExecute` set and supports wildcard matches:
     *      - Exact:        `(target, fnSel)`
     *      - Any fn on t:  `(target, ANY_FN_SEL)`
     *      - Any t for fn: `(ANY_TARGET, fnSel)`
     *      - Full wildcard `(ANY_TARGET, ANY_FN_SEL)`
     *      Returns false if the permission set is empty or no match found.
     * @param _keyId  Identifier of the key.
     * @param _target Target contract/EOA address.
     * @param _data   Calldata used to derive the function selector.
     * @return True if a matching permission is present; false otherwise.
     */
    function _isCanCall(bytes32 _keyId, address _target, bytes memory _data)
        internal
        view
        returns (bool)
    {
        bytes4 fnSel = ANY_FN_SEL;

        if (_data.length >= 4) {
            assembly {
                fnSel := mload(add(_data, 0x20))
            }
        }

        if (_data.length == uint256(0)) fnSel = EMPTY_CALLDATA_FN_SEL;

        EnumerableSetLib.Bytes32Set storage canCallSet = permissions[_keyId].canExecute;

        if (canCallSet.length() != 0) {
            if (canCallSet.contains(KeysManagerLib.packCanExecute(_target, fnSel))) return true;
            if (canCallSet.contains(KeysManagerLib.packCanExecute(_target, ANY_FN_SEL))) {
                return true;
            }
            if (canCallSet.contains(KeysManagerLib.packCanExecute(ANY_TARGET, fnSel))) return true;
            if (canCallSet.contains(KeysManagerLib.packCanExecute(ANY_TARGET, ANY_FN_SEL))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @notice Enforces per-token spend policy for a call, extracting the intended token amount.
     * @dev Determines the selector from `_data`, with special handling:
     *      - Empty calldata → native transfer: `fnSel = EMPTY_CALLDATA_FN_SEL`, `_target = NATIVE_ADDRESS`,
     *        and `tokenAmout = _value`.
     *      - ERC-20 methods recognized (reads the amount via `LibBytes.load`):
     *          • `transfer(address,uint256)`      → selector `0xa9059cbb`, amount at offset `0x24`.
     *          • `transferFrom(address,address,uint256)` → selector `0x23b872dd`, amount at offset `0x44`.
     *          • `approve(address,uint256)`       → selector `0x095ea7b3`, amount at offset `0x24`.
     *      Calls `_manageTokenSpend(_keyId, tokenAddress, tokenAmout)` to apply/reset period counters and
     *      check limit overflow.
     * @param _keyId   Identifier of the key.
     * @param _target  Original call target (token address for ERC-20; replaced with `NATIVE_ADDRESS` for native transfers).
     * @param _value   ETH value sent with the call (used for native transfers).
     * @param _data    Calldata used to determine selector and amount.
     * @return True if the spend fits within the configured limit; false otherwise.
     */
    function _isTokenSpend(bytes32 _keyId, address _target, uint256 _value, bytes memory _data)
        internal
        returns (bool)
    {
        bytes4 fnSel = ANY_FN_SEL;

        if (_data.length >= 4) {
            assembly {
                fnSel := mload(add(_data, 0x20))
            }
        }

        if (_data.length == uint256(0)) fnSel = EMPTY_CALLDATA_FN_SEL;

        uint256 tokenAmout;

        if (fnSel == EMPTY_CALLDATA_FN_SEL) {
            tokenAmout = _value;
            _target = NATIVE_ADDRESS;
        } else if (fnSel == 0xa9059cbb) {
            // `transfer(address,uint256)`.
            tokenAmout = uint256(LibBytes.load(_data, 0x24));
        } else if (fnSel == 0x23b872dd) {
            // `transferFrom(address,address,uint256)`.
            tokenAmout = uint256(LibBytes.load(_data, 0x44));
        } else if (fnSel == 0x095ea7b3) {
            // `approve(address,uint256)`.
            tokenAmout = uint256(LibBytes.load(_data, 0x24));
        }

        if (!_manageTokenSpend(_keyId, _target, tokenAmout)) return false;

        return true;
    }

    /**
     * @notice Updates per-token spend accounting and enforces the per-period limit.
     * @dev Looks up `spendStore[_keyId].tokenData[_target]`. If no rule (`period == 0` or `limit == 0`), returns false.
     *      Computes the start of the current period with `startOfSpendPeriod(block.timestamp, period)`.
     *      If we’ve crossed into a new period, resets `spent` to 0 and sets `lastUpdated = current`.
     *      Checks `(spent + _tokenAmout) <= limit`; on success, increments `spent`.
     * @param _keyId       Identifier of the key.
     * @param _target      Token address (or `NATIVE_ADDRESS` for ETH).
     * @param _tokenAmout  Amount intended to spend in this call.
     * @return True if the rule exists and the amount is within limit; false if no rule or it would exceed the limit.
     */
    function _manageTokenSpend(bytes32 _keyId, address _target, uint256 _tokenAmout)
        private
        returns (bool)
    {
        TokenSpendPeriod storage tokenSpend = spendStore[_keyId].tokenData[_target];
        if (uint8(tokenSpend.period) == 0 || tokenSpend.limit == 0) return false;

        uint256 current = startOfSpendPeriod(block.timestamp, tokenSpend.period);

        if (tokenSpend.lastUpdated < current) {
            tokenSpend.lastUpdated = current;
            tokenSpend.spent = 0;
        }

        if ((tokenSpend.spent + _tokenAmout) > tokenSpend.limit) return false;

        unchecked {
            tokenSpend.spent += _tokenAmout;
        }

        return true;
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

        bytes32 keyHash = KeyType.EOA.computeKeyId(abi.encode(signer));
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

        bytes32 keyHash = KeyType.WEBAUTHN.computeKeyId(abi.encode(pubKey.x, pubKey.y));
        KeyData storage sKey = keys[keyHash];

        if (sKey.masterKey) return this.isValidSignature.selector;

        return bytes4(0xffffffff);
    }

    /**
     * @dev Helper used solely for ERC-1271 decoding via try/catch.
     * @param sig ABI-encoded WebAuthn signature payload.
     * @return requireUV Whether user verification was required.
     * @return authenticatorData Authenticator data blob.
     * @return clientDataJSON Client data JSON string.
     * @return challengeIndex Index of the challenge in the client data.
     * @return typeIndex Index of the type field in the client data.
     * @return r ECDSA `r` coordinate.
     * @return s ECDSA `s` coordinate.
     * @return pubKey Reconstructed public key used for verification.
     */
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

    /**
     * @notice Rounds a Unix timestamp down to the beginning of the requested spend period.
     * @param unixTimestamp Timestamp to round.
     * @param period        Spend period granularity.
     * @return Rounded timestamp aligned with the start of `period`.
     */
    function startOfSpendPeriod(uint256 unixTimestamp, SpendPeriod period)
        public
        pure
        returns (uint256)
    {
        if (period == SpendPeriod.Minute) return Math.rawMul(Math.rawDiv(unixTimestamp, 60), 60);
        if (period == SpendPeriod.Hour) return Math.rawMul(Math.rawDiv(unixTimestamp, 3600), 3600);
        if (period == SpendPeriod.Day) return Math.rawMul(Math.rawDiv(unixTimestamp, 86400), 86400);
        if (period == SpendPeriod.Week) return DateTimeLib.mondayTimestamp(unixTimestamp);
        (uint256 year, uint256 month,) = DateTimeLib.timestampToDate(unixTimestamp);
        // Note: DateTimeLib's months and month-days start from 1.
        if (period == SpendPeriod.Month) return DateTimeLib.dateToTimestamp(year, month, 1);
        if (period == SpendPeriod.Year) return DateTimeLib.dateToTimestamp(year, 1, 1);
        if (period == SpendPeriod.Forever) return 1; // Non-zero to differentiate from not set.
        revert(); // We shouldn't hit here.
    }
}
