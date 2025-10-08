// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {KeysManagerLib} from "src/libs/KeysManagerLib.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {IOPF7702Recoverable} from "src/interfaces/IOPF7702Recoverable.sol";
import {Math} from "lib/openzeppelin-contracts/contracts/utils/math/Math.sol";
import {SafeCast} from "lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

contract SocialRecoveryManager is EIP712 {
    using ECDSA for bytes32;
    using KeysManagerLib for *;

    bytes32 private constant RECOVER_TYPEHASH =
        0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant NAME_HASH = keccak256("OPF7702Recoverable");
    bytes32 private constant VERSION_HASH = keccak256("1");

    uint256 internal immutable recoveryPeriod;
    uint256 internal immutable lockPeriod;
    uint256 internal immutable securityPeriod;
    uint256 internal immutable securityWindow;

    mapping(address => IOPF7702Recoverable.RecoveryData) public recoveryData;
    mapping(address => IOPF7702Recoverable.GuardiansData) internal guardiansData;

    constructor(
        uint256 _recoveryPeriod,
        uint256 _lockPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow
    ) EIP712("SocialRecoveryManager", "1") {
        if (_lockPeriod < _recoveryPeriod || _recoveryPeriod < _securityPeriod + _securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable_InsecurePeriod();
        }
        recoveryPeriod = _recoveryPeriod;
        lockPeriod = _lockPeriod;
        securityPeriod = _securityPeriod;
        securityWindow = _securityWindow;
    }

    function initializeGuardians(address _account, bytes32 _initialGuardian) external {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        if (_initialGuardian == bytes32(0)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }
        guardiansData[_account].guardians.push(_initialGuardian);
        IOPF7702Recoverable.GuardianIdentity storage gi =
            guardiansData[_account].data[_initialGuardian];

        emit IOPF7702Recoverable.GuardianAdded(_initialGuardian);

        gi.isActive = true;
        gi.index = 0;
        gi.pending = 0;
    }

    function proposeGuardian(address _account, bytes32 _guardian) external {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        if (_guardian == bytes32(0)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (_account.computeHash() == _guardian) {
            revert IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeAddressThis();
        }

        (bytes32 keyId,) = IKeysManager(_account).keyAt(0);

        if (keyId == _guardian) {
            revert IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeCurrentMasterKey();
        }

        if (gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian();

        if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedProposal();
        }

        gi.pending = block.timestamp + securityPeriod;

        emit IOPF7702Recoverable.GuardianProposed(_guardian, gi.pending);
    }

    function confirmGuardianProposal(address _account, bytes32 _guardian) external {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        _requireRecovery(_account, false);
        if (_guardian == bytes32(0)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__AddressCantBeZero();
        }
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownProposal();
        if (block.timestamp < gi.pending) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingProposalNotOver();
        }
        if (block.timestamp > gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingProposalExpired();
        }

        if (gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian();

        emit IOPF7702Recoverable.GuardianAdded(_guardian);

        gi.isActive = true;
        gi.pending = 0;
        gi.index = guardiansData[_account].guardians.length;
        guardiansData[_account].guardians.push(_guardian);
    }

    function cancelGuardianProposal(address _account, bytes32 _guardian) external {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        _requireRecovery(_account, false);
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownProposal();

        if (gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedGuardian();

        emit IOPF7702Recoverable.GuardianProposalCancelled(_guardian);

        gi.pending = 0;
    }

    function revokeGuardian(address _account, bytes32 _guardian) external {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (!gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();

        if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__DuplicatedRevoke();
        }

        gi.pending = block.timestamp + securityPeriod;

        emit IOPF7702Recoverable.GuardianRevocationScheduled(_guardian, gi.pending);
    }

    function confirmGuardianRevocation(address _account, bytes32 _guardian) external {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownRevoke();

        if (block.timestamp < gi.pending) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingRevokeNotOver();
        }
        if (block.timestamp > gi.pending + securityWindow) {
            revert IOPF7702Recoverable.OPF7702Recoverable__PendingRevokeExpired();
        }
        if (!gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();

        uint256 lastIndex = guardiansData[_account].guardians.length - 1;
        bytes32 lastHash = guardiansData[_account].guardians[lastIndex];
        uint256 targetIndex = gi.index;

        if (_guardian != lastHash) {
            guardiansData[_account].guardians[targetIndex] = lastHash;
            guardiansData[_account].data[lastHash].index = targetIndex;
        }
        emit IOPF7702Recoverable.GuardianRemoved(_guardian);

        guardiansData[_account].guardians.pop();

        delete guardiansData[_account].data[_guardian];
    }

    function cancelGuardianRevocation(address _account, bytes32 _guardian) external {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        IOPF7702Recoverable.GuardianIdentity storage gi = guardiansData[_account].data[_guardian];

        if (!gi.isActive) revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();
        if (gi.pending == 0) revert IOPF7702Recoverable.OPF7702Recoverable__UnknownRevoke();

        emit IOPF7702Recoverable.GuardianRevocationCancelled(_guardian);

        guardiansData[_account].data[_guardian].pending = 0;
    }

    function startRecovery(address _account, IKey.KeyDataReg calldata _recoveryKey) external {
        if (!isGuardian(_account, msg.sender.computeHash())) {
            revert IOPF7702Recoverable.OPF7702Recoverable__MustBeGuardian();
        }
        if (
            _recoveryKey.keyType == IKey.KeyType.P256
                || _recoveryKey.keyType == IKey.KeyType.P256NONKEY
        ) {
            revert IOPF7702Recoverable.OPF7702Recoverable__UnsupportedKeyType();
        }

        _requireRecovery(_account, false);
        if (isLocked(_account)) revert IOPF7702Recoverable.OPF7702Recoverable__AccountLocked();

        _recoveryKey.keyCantBeZero();

        bytes32 keyId = _recoveryKey.computeKeyId();

        bool isActive = IKeysManager(_account).isKeyActive(keyId);

        if (isActive) {
            revert IOPF7702Recoverable.OPF7702Recoverable__RecoverCannotBeActiveKey();
        }

        if (isGuardian(_account, keyId)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__GuardianCannotBeOwner();
        }

        uint64 executeAfter = SafeCast.toUint64(block.timestamp + recoveryPeriod);
        uint32 quorum = SafeCast.toUint32(Math.ceilDiv(guardianCount(_account), 2));

        emit IOPF7702Recoverable.RecoveryStarted(executeAfter, quorum);

        recoveryData[_account] = IOPF7702Recoverable.RecoveryData({
            key: _recoveryKey,
            executeAfter: executeAfter,
            guardiansRequired: quorum
        });

        _setLock(_account, block.timestamp + lockPeriod);
    }

    function completeRecovery(address _account, bytes[] calldata _signatures)
        external
        returns (IKey.KeyDataReg memory recoveryOwner)
    {
        _requireRecovery(_account, true);

        IOPF7702Recoverable.RecoveryData memory r = recoveryData[_account];

        if (r.executeAfter > block.timestamp) {
            revert IOPF7702Recoverable.OPF7702Recoverable__OngoingRecovery();
        }

        require(
            r.guardiansRequired > 0,
            IOPF7702Recoverable.OPF7702Recoverable__NoGuardiansSetOnWallet()
        );

        if (r.guardiansRequired != _signatures.length) {
            revert IOPF7702Recoverable.OPF7702Recoverable__InvalidSignatureAmount();
        }

        if (!_validateSignatures(_account, _signatures)) {
            revert IOPF7702Recoverable.OPF7702Recoverable__InvalidRecoverySignatures();
        }

        recoveryOwner = r.key;

        delete recoveryData[_account];

        emit IOPF7702Recoverable.RecoveryCompleted();

        _setLock(_account, 0);
    }

    function cancelRecovery(address _account) external {
        if (msg.sender != _account) revert IOPF7702Recoverable.OPF7702Recoverable__Unauthorized();
        _requireRecovery(_account, true);
        emit IOPF7702Recoverable.RecoveryCancelled();
        delete recoveryData[_account];
        _setLock(_account, 0);
    }

    function _requireRecovery(address _account, bool _isRecovery) internal view {
        if (_isRecovery && recoveryData[_account].executeAfter == 0) {
            revert IOPF7702Recoverable.OPF7702Recoverable__NoOngoingRecovery();
        }
        if (!_isRecovery && recoveryData[_account].executeAfter > 0) {
            revert IOPF7702Recoverable.OPF7702Recoverable__OngoingRecovery();
        }
    }

    function _setLock(address _account, uint256 _releaseAfter) internal {
        emit IOPF7702Recoverable.WalletLocked(_releaseAfter != 0);
        guardiansData[_account].lock = _releaseAfter;
    }

    function getGuardians(address _account) external view returns (bytes32[] memory) {
        bytes32[] memory guardians = new bytes32[](guardiansData[_account].guardians.length);
        uint256 i;
        for (i; i < guardiansData[_account].guardians.length;) {
            guardians[i] = guardiansData[_account].guardians[i];
            unchecked {
                ++i;
            }
        }
        return guardians;
    }

    function getPendingStatusGuardians(address _account, bytes32 _guardian)
        external
        view
        returns (uint256)
    {
        return guardiansData[_account].data[_guardian].pending;
    }

    function isLocked(address _account) public view returns (bool) {
        return guardiansData[_account].lock > block.timestamp;
    }

    function isGuardian(address _account, bytes32 _guardian) public view returns (bool) {
        return guardiansData[_account].data[_guardian].isActive;
    }

    function guardianCount(address _account) public view returns (uint256) {
        return guardiansData[_account].guardians.length;
    }

    function getDigestToSign(address _account) public view returns (bytes32 digest) {
        bytes32 structHash = keccak256(
            abi.encode(
                RECOVER_TYPEHASH,
                recoveryData[_account].key,
                recoveryData[_account].executeAfter,
                recoveryData[_account].guardiansRequired
            )
        );

        digest = _hashTypedDataV4(structHash);
    }

    function _validateSignatures(address _account, bytes[] calldata _signatures)
        internal
        view
        returns (bool)
    {
        bytes32 digest = getDigestToSign(_account);
        bytes32 lastGuardianHash;

        unchecked {
            for (uint256 i; i < _signatures.length; ++i) {
                bytes32 guardianHash;

                address signer = digest.recover(_signatures[i]);
                guardianHash = signer.computeHash();

                if (!guardiansData[_account].data[guardianHash].isActive) return false;

                if (guardianHash <= lastGuardianHash) return false;
                lastGuardianHash = guardianHash;
            }
        }
        return true;
    }
}
