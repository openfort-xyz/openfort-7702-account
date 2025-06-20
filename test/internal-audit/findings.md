# Findings Round 1 (no include POC) [only manual review and small test]
Hi team, attaching here my finding to track. Tomorrow i will start with POC. 
The finding will be defined by file .sol and C: critical, H: high, L: low, INFO: info, GAS: gas  severity.
@jaume @joan 


BaseOPF7702.sol:
Line44 [INFO]

// @audit-info ⚠️: Natspec
error NotFromEntryPoint();

Line129 [INFO]

// @audit-info ⚠️: Call function entryPoint() to get last addr. of ePoint
function _requireFromEntryPoint() internal view virtual override {
    require(msg.sender == address(UpgradeAddress.entryPoint(ENTRY_POINT)), NotFromEntryPoint());
}

function entryPoint() public view override returns (IEntryPoint) {
    return IEntryPoint(UpgradeAddress.entryPoint(ENTRY_POINT));
}

Line155 [INFO]

    // @audit-info ⚠️: Add support IERC7201
    // @audit-info ⚠️: Add support ERC777 ??
    function supportsInterface(bytes4 _interfaceId)
        public
        pure
        override(ERC1155Holder, IERC165)
        returns (bool)
    {
        return _interfaceId == type(IERC165).interfaceId
            || _interfaceId == type(IAccount).interfaceId || _interfaceId == type(IERC1271).interfaceId
            || _interfaceId == type(IERC1155Receiver).interfaceId
            || _interfaceId == type(IERC721Receiver).interfaceId
            || _interfaceId == type(IERC7821).interfaceId;
    }
}

Execution.sol:
Line39 [H]

    // audit-high 🔴🔴🔴: No nonReentrant portection!!!!
    // audit-question: line execute(mode, batches[i]); rerecursive call. nonReentrant might not help!
    function execute(bytes32 mode, bytes memory executionData) public payable virtual {

Line46 [M]

    function execute(bytes32 mode, bytes memory executionData) public payable virtual {
        uint256 id = _executionModeId(mode);
        if (id == 3) {
            mode ^= bytes32(uint256(3 << (22 * 8)));
            bytes[] memory batches = abi.decode(executionData, (bytes[]));
            // audit-medium 🟠🟠🟠: Checking length of batches and not how many txs inside batches[batch[], batch[], batch[] .......]
            _checkLength(batches.length);
            for (uint256 i; i < batches.length; ++i) {
                execute(mode, batches[i]);
            }
            return;
        }

Line88 [L]

    /// @dev Executes the calls and returns the results.
    /// Reverts and bubbles up error if any call fails.
    function _execute(Call[] memory calls, bytes memory opData) internal virtual {
        if (opData.length == uint256(0)) {
            // @audit-low ⚠️: move to _requireForExecute(); to --> function execute(bytes32 mode, bytes memory executionData)
            _requireForExecute();
            return _execute(calls);
        }
        revert();
    }



KeysManager.sol:

Line347 [GAS]

    // @audit-gas ⚠️: Combine with function encodeP256NonKeySignature and pass Key _key. And enconde the keyType
    function encodeP256Signature(bytes32 r, bytes32 s, PubKey memory pubKey)
        external
        pure
        returns (bytes memory)
    {
        bytes memory inner = abi.encode(r, s, pubKey);
        return abi.encode(KeyType.P256, inner);
    }

    /**
     * @notice Encodes a P-256 non-key signature payload (KeyType.P256NONKEY).
     * @param r       R component of the P-256 signature (32 bytes).
     * @param s       S component of the P-256 signature (32 bytes).
     * @param pubKey  Public key (x, y) used for signing.
     * @return ABI‐encoded payload as: KeyType.P256NONKEY, abi.encode(r, s, pubKey).
     */
    // @audit-gas ⚠️: Combine with function encodeP256Signature and pass Key _key. And enconde the keyType
    function encodeP256NonKeySignature(bytes32 r, bytes32 s, PubKey memory pubKey)
        external
        pure
        returns (bytes memory)
    {
        bytes memory inner = abi.encode(r, s, pubKey);
        return abi.encode(KeyType.P256NONKEY, inner);
    }



OPF7702.sol:
Line18 [INFO]

// @audit-info ⚠️: Unused import
import {UpgradeAddress} from "src/libs/UpgradeAddress.sol";

Line54 [M]

    /// @notice Address of this implementation contract
    // audit-medium 🟠: will be cleared during initialize. Convert to immutable
    address public _OPENFORT_CONTRACT_ADDRESS;

Line169 [INFO]

        // @audit-info ⚠️: usedChallenges does nothing useful, get nonce in EPOINT during get digets to sign
        if (usedChallenges[userOpHash]) {
            return SIG_VALIDATION_FAILED;
        }

Line205 [M] {if not using usedChallenges based on trusted EPOINT managing nonces}

        if (isValidKey(composedKey, callData)) {
            // @audit-info ⚠️: usedChallenges does nothing useful
            // @audit-medium 🟠🟠🟠: mark challenge as used in the beggining. masterKey can be replayed!!! nust come after checking directly
            usedChallenges[userOpHash] = true; // mark challenge as used
            return _packValidationData(false, sKey.validUntil, sKey.validAfter);
        }
        return SIG_VALIDATION_FAILED;

Line308 [GAS]

        // @audit-info ⚠️: Dont need checking of `_key.eoaAddress == address(0)`. revoke key will be active = false.
        if (_key.keyType == KeyType.EOA) {
            if (_key.eoaAddress == address(0)) return false;
             // @audit-info ⚠️: can compute for all
            keyHash = _key.computeKeyId();
            sKey = keys[keyHash];
        } else {
            // @audit-info ⚠️: can compute for all
            // WEBAUTHN/P256/P256NONKEY share same load path
            keyHash = _key.computeKeyId();
            sKey = keys[keyHash];
        }

Line322 [L]

    function isValidKey(Key memory _key, bytes calldata _callData)
        internal
        virtual
        returns (bool)
        // @audit-low ⚠️: Double cheking. Checked in `function _keyValidation`
        if (!sKey.isRegistered() || !sKey.isActive) {
            return false;
        }

    function _keyValidation(KeyData storage sKey, address signer, KeyType keyType)
        internal
        view
        returns (Key memory composedKey, bool isValid)
    {
        // Check if key is valid and active
        if (!sKey.isRegistered() || !sKey.isActive) {
            return (composedKey, false); // Early return for invalid key
        }


OPF7702Recoverable.sol:
Line135 [M]

        // @audit-medium 🟠🟠🟠: getDigestToSign() signing: no data in `recoveryData`
        /**
            abi.encode(
                RECOVER_TYPEHASH,
                recoveryData.key,: address 0
                recoveryData.executeAfter,: 0
                recoveryData.guardiansRequired: 0
            )
         */
        bytes32 digest = getDigestToSign();

        // Todo: Use EIP712 to initialize account
        if (!_checkSignature(digest, _signature)) {
            revert IBaseOPF7702.OpenfortBaseAccount7702V1__InvalidSignature();

Line120 [L]

    // @audit-low ⚠️: pass bytes32 and not _initialGuardian address
    // @audit-question: If user passing not masterKey it will init the account? Assume the app and user checking that init masterKey
    // @audit-question: No checks if pubKey(x,y) is `0`...  assume correct data.
    // @audit-question: Can be frontrun with other key?
    // msg.sender ->  msg.sender == address(this) || msg.sender == address(entryPoint())
    function initialize(
        Key calldata _key,
        KeyReg calldata _keyData,
        bytes memory _signature,
        address _initialGuardian
    ) external initializer {

Also refer to All functions in the file getting param _guardian as address. Must to hash the address off-chain and pass to as bytes32
Since we won't discover the guardians addresses in case of offline attack. (Privacy)

Line394 [M] : No checking if the new owner is current masterKey

    function startRecovery(Key memory _recoveryKey) external virtual {
        // @audit-low ⚠️: pass bytes32 and not address
        if (!isGuardian(msg.sender)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();
        }

        _requireRecovery(false);
        if (isLocked()) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        bool hasAddress = _recoveryKey.eoaAddress != address(0);
        bool hasPubKey = _recoveryKey.pubKey.x != bytes32(0) || _recoveryKey.pubKey.y != bytes32(0);
        if (!hasAddress && !hasPubKey) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }

        // @audit-question: Could be DoS if propose masterKey?
        // @audit-question: no checking if it old masterKey
        if (isGuardian(_recoveryKey.eoaAddress)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeOwner();
        }

        uint64 executeAfter = SafeCast.toUint64(block.timestamp + recoveryPeriod);
        uint32 quorum = SafeCast.toUint32(Math.ceilDiv(guardianCount(), 2));

        emit IOPF7702Recoverable.RecoveryStarted(executeAfter, quorum);

        recoveryData = IOPF7702Recoverable.RecoveryData({
            key: _recoveryKey,
            executeAfter: executeAfter,
            guardiansRequired: quorum
        });

        _setLock(block.timestamp + lockPeriod);
    }


WebAuthnVerifier.sol
Line136 [C] Lib of solady not working in many networks with Pectra. 
Alternative: Coinbase (https://github.com/base-org/webauthn-sol)

/// @audit-question: Working as well in all available chains with Pectra Ugrd?
/**
 * 🚨 [FAIL: P256VerificationFailed()] test_BNB() (gas: 521368)
 * 🚨 [FAIL: P256VerificationFailed()] test_Bera() (gas: 520246)
 * 🚨 [FAIL: P256VerificationFailed()] test_GNO() (gas: 519203)
 * 🚨 [FAIL: P256VerificationFailed()] test_Ink() (gas: 519044)
 */

/// @audit-Critical: 🔴🔴🔴 Library of Solady not working in the chains of
/**
 * 🔴🔴🔴 [FAIL: assertion failed] test_BNB_Solady() (gas: 338007)
 * 🔴🔴🔴 [FAIL: assertion failed] test_Base_Solady() (gas: 336198)
 * 🔴🔴🔴 [FAIL: assertion failed] test_Bera_Solady() (gas: 338491)
 * 🔴🔴🔴 [FAIL: assertion failed] test_GNO_Solady() (gas: 337909)
 * 🔴🔴🔴 [FAIL: assertion failed] test_Ink_Solady() (gas: 338227)
 */



@jaume @joan 
Questions and Thoughts:
Hi team,
Dropping here some stuff i found. Its not bug or vulnerability. Just some stuff keep in my mind.


Recovery Module: Possible to propose function startRecovery(Key memory _recoveryKey) external virtual new owner with old MasterKey (EOA or WebAuthn) and function completeRecovery(bytes[] calldata _signatures) external virtual with old masterKey.

My thoughts: Lets assume the owner will provide correct and valid Key to recover and the guardian will execute correctly the data.


KeyManager Module: After revoke key function revokeKey(Key calldata _key) external possible register same key and override the inactive key. 

My thoughts: Lets assume the owner will register correct key and not revoked one.


Initialize Module: Possible to initialize account with pubKey(bytes32(0), bytes32(0)) or with limits. 
Means that user might have no access control to account. Will be possible only change masterKey through recovery procces.

function initialize(
        Key calldata _key,
        KeyReg calldata _keyData,
        bytes memory _signature,
        address _initialGuardian
    ) external initializer {

    My thoughts: Lets assume the owner will initialize correct account.