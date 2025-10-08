// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {StdInvariant} from "lib/forge-std/src/StdInvariant.sol";
import {Test} from "lib/forge-std/src/Test.sol";
import {OPFMain} from "src/core/OPFMain.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {KeysManagerLib} from "src/libs/KeysManagerLib.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";
import {IERC165} from "lib/openzeppelin-contracts/contracts/interfaces/IERC165.sol";
import {IERC1271} from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {IERC1155Receiver} from
    "lib/openzeppelin-contracts/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from
    "lib/openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC777Recipient} from
    "lib/openzeppelin-contracts/contracts/interfaces/IERC777Recipient.sol";
import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {IERC7821} from "src/interfaces/IERC7821.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {DeployInvariantHelper} from "./CoreInvariant.t.sol";

contract KeysManagerHandler is Test {
    using KeysManagerLib for *;

    OPFMain public immutable account;
    OPFMain public immutable implementation;
    address public immutable owner;

    address[] internal _trackedTokens;
    address[] internal _callTargets;
    bytes4[] internal _callSelectors;

    constructor(OPFMain _account, OPFMain _implementation, address _owner) {
        account = _account;
        implementation = _implementation;
        owner = _owner;

        _trackedTokens.push(address(new MockERC20()));
        _trackedTokens.push(address(new MockERC20()));
        _trackedTokens.push(address(new MockERC20()));

        _callTargets = new address[](_trackedTokens.length + 1);
        _callTargets[0] = _owner;
        for (uint256 i; i < _trackedTokens.length; ++i) {
            _callTargets[i + 1] = _trackedTokens[i];
        }

        _callSelectors = new bytes4[](4);
        _callSelectors[0] = bytes4(keccak256("transfer(address,uint256)"));
        _callSelectors[1] = bytes4(keccak256("approve(address,uint256)"));
        _callSelectors[2] = bytes4(keccak256("mint(address,uint256)"));
        _callSelectors[3] = bytes4(0);
    }

    // ──────────────────────────────────────── External getters ────────────────────────

    function trackedTokensLength() external view returns (uint256) {
        return _trackedTokens.length;
    }

    function trackedToken(uint256 idx) external view returns (address) {
        return _trackedTokens[idx];
    }

    // ──────────────────────────────────────── Fuzz actions ────────────────────────────

    function registerKey(uint256 seed, bool custodial) external {
        bytes memory key = abi.encode(_keyOwner(seed));
        IKey.KeyDataReg memory keyData = IKey.KeyDataReg({
            keyType: IKey.KeyType.EOA,
            validUntil: _futureValidUntil(seed),
            validAfter: 0,
            limits: _nonZeroLimit(seed),
            key: key,
            keyControl: custodial ? IKey.KeyControl.Custodial : IKey.KeyControl.Self
        });

        bytes32 keyId = keyData.computeKeyId();
        if (account.isKeyActive(keyId)) return;

        _ensureAccountCode();
        vm.prank(owner);
        account.registerKey(keyData);
    }

    function revokeKey(uint256 seed) external {
        bytes32[] memory keys = _activeNonMasterKeys();
        if (keys.length == 0) return;

        bytes32 keyId = keys[seed % keys.length];
        _ensureAccountCode();
        vm.prank(owner);
        account.revokeKey(keyId);
    }

    function pauseKey(uint256 seed) external {
        bytes32[] memory keys = _activeNonMasterKeys();
        if (keys.length == 0) return;

        bytes32 keyId = keys[seed % keys.length];
        _ensureAccountCode();
        vm.prank(owner);
        account.pauseKey(keyId);
    }

    function unpauseKey(uint256 seed) external {
        bytes32[] memory keys = _pausedNonMasterKeys();
        if (keys.length == 0) return;

        bytes32 keyId = keys[seed % keys.length];
        _ensureAccountCode();
        vm.prank(owner);
        account.unpauseKey(keyId);
    }

    function updateKey(uint256 seed, uint48 extendSeed, uint48 limitSeed) external {
        bytes32[] memory keys = _activeNonMasterKeys();
        if (keys.length == 0) return;

        bytes32 keyId = keys[seed % keys.length];
        IKey.KeyData memory data = account.getKey(keyId);

        uint256 candidate = uint256(data.validUntil) + _bounded(extendSeed, 1, 30 days);
        if (candidate >= type(uint48).max) candidate = type(uint48).max - 1;
        if (candidate <= block.timestamp) candidate = block.timestamp + 1;
        if (candidate <= data.validUntil) candidate = uint256(data.validUntil) + 1;

        uint48 newValidUntil = uint48(candidate);
        uint48 newLimit = uint48(_bounded(limitSeed, 1, type(uint48).max - 1));

        _ensureAccountCode();
        vm.prank(owner);
        account.updateKeyData(keyId, newValidUntil, newLimit);
    }

    function setTokenSpend(uint256 keySeed, uint8 tokenSeed, uint8 periodSeed, uint256 limitSeed)
        external
    {
        bytes32[] memory keys = _activeNonMasterKeys();
        if (keys.length == 0) return;

        bytes32 keyId = keys[keySeed % keys.length];
        address token = _trackedTokens[tokenSeed % _trackedTokens.length];
        if (account.hasTokenSpend(keyId, token)) return;

        IKeysManager.SpendPeriod period = _spendPeriod(periodSeed);
        uint256 limit = _bounded(limitSeed, 1, 1e27);

        _ensureAccountCode();
        vm.prank(owner);
        account.setTokenSpend(keyId, token, limit, period);
    }

    function updateTokenSpend(uint256 keySeed, uint8 tokenSeed, uint256 limitSeed) external {
        bytes32[] memory keys = _activeNonMasterKeys();
        if (keys.length == 0) return;

        bytes32 keyId = keys[keySeed % keys.length];
        address token = _trackedTokens[tokenSeed % _trackedTokens.length];
        if (!account.hasTokenSpend(keyId, token)) return;

        uint256 limit = _bounded(limitSeed, 1, 1e27);
        IKeysManager.SpendPeriod period;
        (period,,,) = account.tokenSpend(keyId, token);

        _ensureAccountCode();
        vm.prank(owner);
        account.updateTokenSpend(keyId, token, limit, period);
    }

    function removeTokenSpend(uint256 keySeed, uint8 tokenSeed) external {
        bytes32[] memory keys = _collectKeysWithSpend();
        if (keys.length == 0) return;

        bytes32 keyId = keys[keySeed % keys.length];
        address[] memory tokens = account.spendTokens(keyId);
        if (tokens.length == 0) return;

        address token = tokens[tokenSeed % tokens.length];
        _ensureAccountCode();
        vm.prank(owner);
        account.removeTokenSpend(keyId, token);
    }

    function clearSpendPermissions(uint256 keySeed) external {
        bytes32[] memory keys = _collectKeysWithSpend();
        if (keys.length == 0) return;

        bytes32 keyId = keys[keySeed % keys.length];
        _ensureAccountCode();
        vm.prank(owner);
        account.clearSpendPermissions(keyId);
    }

    function setCanCall(uint256 keySeed, uint8 targetSeed, uint8 selectorSeed, bool can) external {
        bytes32[] memory keys = _activeNonMasterKeys();
        if (keys.length == 0) return;

        bytes32 keyId = keys[keySeed % keys.length];
        address target = _callTargets[targetSeed % _callTargets.length];
        bytes4 selector = _callSelectors[selectorSeed % _callSelectors.length];

        if (!can) {
            // If we want to remove but nothing set, skip to avoid unnecessary writes.
            bytes32 packed = KeysManagerLib.packCanExecute(target, selector);
            bytes32[] memory packedInfos = account.canExecutePackedInfos(keyId);
            bool present;
            for (uint256 i; i < packedInfos.length; ++i) {
                if (packedInfos[i] == packed) {
                    present = true;
                    break;
                }
            }
            if (!present) return;
        }

        _ensureAccountCode();
        vm.prank(owner);
        account.setCanCall(keyId, target, selector, can);
    }

    function clearExecutePermissions(uint256 keySeed) external {
        bytes32[] memory keys = _collectKeysWithExecutePermissions();
        if (keys.length == 0) return;

        bytes32 keyId = keys[keySeed % keys.length];
        _ensureAccountCode();
        vm.prank(owner);
        account.clearExecutePermissions(keyId);
    }

    // ──────────────────────────────────────── Internal helpers ────────────────────────

    function _ensureAccountCode() internal {
        bytes memory designator = abi.encodePacked(bytes3(0xef0100), address(implementation));
        vm.etch(owner, designator);
    }

    function _activeNonMasterKeys() internal view returns (bytes32[] memory results) {
        uint256 total = account.keyCount();
        bytes32[] memory temp = new bytes32[](total);
        uint256 count;

        for (uint256 i; i < total; ++i) {
            (bytes32 keyId, IKey.KeyData memory data) = account.keyAt(i);
            if (keyId != bytes32(0) && data.isActive && !data.masterKey) {
                temp[count++] = keyId;
            }
        }

        results = new bytes32[](count);
        for (uint256 j; j < count; ++j) {
            results[j] = temp[j];
        }
    }

    function _pausedNonMasterKeys() internal view returns (bytes32[] memory results) {
        uint256 total = account.keyCount();
        bytes32[] memory temp = new bytes32[](total);
        uint256 count;

        for (uint256 i; i < total; ++i) {
            (bytes32 keyId, IKey.KeyData memory data) = account.keyAt(i);
            if (keyId != bytes32(0) && !data.masterKey && !data.isActive && data.key.length != 0) {
                temp[count++] = keyId;
            }
        }

        results = new bytes32[](count);
        for (uint256 j; j < count; ++j) {
            results[j] = temp[j];
        }
    }

    function _collectKeysWithSpend() internal view returns (bytes32[] memory results) {
        uint256 total = account.keyCount();
        bytes32[] memory temp = new bytes32[](total);
        uint256 count;

        for (uint256 i; i < total; ++i) {
            (bytes32 keyId,) = account.keyAt(i);
            if (keyId == bytes32(0)) continue;
            if (account.spendTokens(keyId).length > 0) {
                temp[count++] = keyId;
            }
        }

        results = new bytes32[](count);
        for (uint256 j; j < count; ++j) {
            results[j] = temp[j];
        }
    }

    function _collectKeysWithExecutePermissions()
        internal
        view
        returns (bytes32[] memory results)
    {
        uint256 total = account.keyCount();
        bytes32[] memory temp = new bytes32[](total);
        uint256 count;

        for (uint256 i; i < total; ++i) {
            (bytes32 keyId,) = account.keyAt(i);
            if (keyId == bytes32(0)) continue;
            if (account.canExecuteLength(keyId) > 0) {
                temp[count++] = keyId;
            }
        }

        results = new bytes32[](count);
        for (uint256 j; j < count; ++j) {
            results[j] = temp[j];
        }
    }

    function _keyOwner(uint256 seed) internal view returns (address) {
        uint256 pk = uint256(keccak256(abi.encodePacked("keys-manager-owner", seed, block.number)));
        pk |= 1;
        return vm.addr(pk);
    }

    function _futureValidUntil(uint256 seed) internal view returns (uint48) {
        return uint48(_bounded(seed, block.timestamp + 1 days, uint256(type(uint48).max) - 1));
    }

    function _nonZeroLimit(uint256 seed) internal pure returns (uint48) {
        return uint48(_bounded(seed, 1, type(uint48).max - 1));
    }

    function _spendPeriod(uint8 seed) internal pure returns (IKeysManager.SpendPeriod) {
        uint8 count = uint8(uint256(type(IKeysManager.SpendPeriod).max) + 1);
        return IKeysManager.SpendPeriod(uint8(seed % count));
    }

    function _bounded(uint256 seed, uint256 min, uint256 max) internal pure returns (uint256) {
        if (min >= max) return min;
        return (seed % (max - min + 1)) + min;
    }
}

contract KeysManagerInvariantTest is StdInvariant {
    using KeysManagerLib for *;

    KeysManagerHandler internal handler;

    OPFMain internal account;
    OPFMain internal implementation;
    address internal owner;

    function setUp() public {
        DeployInvariantHelper helper = new DeployInvariantHelper();
        helper.runSetup();

        SocialRecoveryManager _recovery;
        address _sender;
        address _guardian;
        bytes32 _initialGuardian;
        uint256 _guardianPk;
        IEntryPoint _entryPoint;
        address _webAuthn;
        address _gasPolicy;

        OPFMain impl;
        OPFMain acct;
        address ownerAddr;

        (
            impl,
            acct,
            _recovery,
            ownerAddr,
            _sender,
            _guardian,
            _initialGuardian,
            _guardianPk,
            _entryPoint,
            _webAuthn,
            _gasPolicy
        ) = helper.state();

        account = acct;
        implementation = impl;
        owner = ownerAddr;

        handler = new KeysManagerHandler(acct, impl, ownerAddr);

        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](11);
        selectors[0] = handler.registerKey.selector;
        selectors[1] = handler.revokeKey.selector;
        selectors[2] = handler.pauseKey.selector;
        selectors[3] = handler.unpauseKey.selector;
        selectors[4] = handler.updateKey.selector;
        selectors[5] = handler.setTokenSpend.selector;
        selectors[6] = handler.updateTokenSpend.selector;
        selectors[7] = handler.removeTokenSpend.selector;
        selectors[8] = handler.clearSpendPermissions.selector;
        selectors[9] = handler.setCanCall.selector;
        selectors[10] = handler.clearExecutePermissions.selector;

        FuzzSelector memory selectorData =
            FuzzSelector({addr: address(handler), selectors: selectors});
        targetSelector(selectorData);
    }

    // ───────────────────────────────────────── Invariants ───────────────────────────

    function invariant_SpendTokensConsistency() public view {
        uint256 total = account.keyCount();

        for (uint256 i; i < total; ++i) {
            (bytes32 keyId,) = account.keyAt(i);
            if (keyId == bytes32(0)) continue;

            address[] memory tokens = account.spendTokens(keyId);

            for (uint256 a; a < tokens.length; ++a) {
                address token = tokens[a];
                require(account.hasTokenSpend(keyId, token), "missing spend entry");
                (, uint256 limit,,) = account.tokenSpend(keyId, token);
                require(limit > 0, "zero limit recorded");

                for (uint256 b = a + 1; b < tokens.length; ++b) {
                    require(tokens[a] != tokens[b], "duplicate token entry");
                }
            }

            uint256 trackedLength = handler.trackedTokensLength();
            for (uint256 t; t < trackedLength; ++t) {
                address tracked = handler.trackedToken(t);
                if (!account.hasTokenSpend(keyId, tracked)) continue;

                bool found;
                for (uint256 a; a < tokens.length; ++a) {
                    if (tokens[a] == tracked) {
                        found = true;
                        break;
                    }
                }
                require(found, "tracked token missing from enumeration");
            }
        }
    }

    function invariant_CanExecuteEnumerationConsistent() public view {
        uint256 total = account.keyCount();

        for (uint256 i; i < total; ++i) {
            (bytes32 keyId,) = account.keyAt(i);
            if (keyId == bytes32(0)) continue;

            bytes32[] memory packedInfos = account.canExecutePackedInfos(keyId);
            uint256 length = account.canExecuteLength(keyId);
            require(packedInfos.length == length, "packed length mismatch");

            for (uint256 j; j < length; ++j) {
                (address target, bytes4 selector) = account.canExecuteAt(keyId, j);
                bytes32 repacked = KeysManagerLib.packCanExecute(target, selector);
                require(repacked == packedInfos[j], "packed entry mismatch");
            }
        }
    }

    function invariant_DelegatedControlKeysHaveLimits() public view {
        uint256 total = account.keyCount();

        for (uint256 i; i < total; ++i) {
            (, IKey.KeyData memory data) = account.keyAt(i);
            if (!data.isDelegatedControl) continue;

            require(!data.masterKey, "delegated master key");
            require(data.limits > 0, "delegated control without limits");
        }
    }

    function invariant_KeyValidityOrdering() public view {
        uint256 total = account.keyCount();

        for (uint256 i; i < total; ++i) {
            (, IKey.KeyData memory data) = account.keyAt(i);
            if (data.validUntil == 0) continue;
            if (data.validUntil == type(uint48).max) continue;

            require(data.validUntil > data.validAfter, "invalid key timestamps");
        }
    }

    function invariant_InterfaceSupport() public view {
        require(account.supportsInterface(type(IERC165).interfaceId), "IERC165 missing");
        require(account.supportsInterface(type(IAccount).interfaceId), "IAccount missing");
        require(account.supportsInterface(type(IERC1271).interfaceId), "IERC1271 missing");
        require(account.supportsInterface(type(IERC7821).interfaceId), "IERC7821 missing");
        require(account.supportsInterface(type(IERC721Receiver).interfaceId), "IERC721 missing");
        require(account.supportsInterface(type(IERC1155Receiver).interfaceId), "IERC1155 missing");
        require(account.supportsInterface(type(IERC777Recipient).interfaceId), "IERC777 missing");
    }
}
