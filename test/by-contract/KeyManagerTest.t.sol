// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";

contract KeyManagerTest is Deploy {
    error OpenfortBaseAccount7702V1_UnauthorizedCaller();

    KeyDataReg kDG;
    KeysManagerV2Helper KMHelper;

    function setUp() public virtual override {
        super.setUp();
        _quickInitializeAccount();
        _initializeAccount();
        KMHelper = new KeysManagerV2Helper();
    }

    function test_AfterInitialize() external view {
        uint256 id = account.id();
        uint256 guardianCount = recoveryManager.guardianCount(owner);
        bool isGuardian = recoveryManager.isGuardian(owner, _initialGuardian);
        bytes32[] memory getGuardians = recoveryManager.getGuardians(owner);
        (bytes32 keyId_0, KeyData memory data_0) = account.keyAt(0);
        (bytes32 keyId_1, KeyData memory data_1) = account.keyAt(1);

        assertEq(2, id);
        assertEq(1, guardianCount);
        assertTrue(isGuardian);

        assertEq(_computeKeyId(mkReg), keyId_0);
        assertTrue(data_0.isActive);
        assertTrue(data_0.masterKey);
        assertFalse(data_0.isDelegatedControl);
        assertEq(uint8(data_0.keyType), uint8(KeyType.WEBAUTHN));
        assertEq(data_0.limits, 0);
        assertEq(data_0.validAfter, 0);
        assertEq(data_0.validUntil, type(uint48).max);
        assertEq(data_0.key, mkReg.key);

        assertEq(_computeKeyId(skReg), keyId_1);
        assertTrue(data_1.isActive);
        assertFalse(data_1.masterKey);
        assertFalse(data_1.isDelegatedControl);
        assertEq(uint8(data_1.keyType), uint8(KeyType.P256NONKEY));
        assertEq(data_1.limits, skReg.limits);
        assertEq(data_1.validAfter, skReg.validAfter);
        assertEq(data_1.validUntil, skReg.validUntil);
        assertEq(data_1.key, skReg.key);

        for (uint256 i = 0; i < getGuardians.length;) {
            assertEq(_initialGuardian, getGuardians[i]);
            unchecked {
                ++i;
            }
        }
    }

    function test_registerKey() public {
        _createKey(100, 101);
        _register();

        assertEq(3, account.id());

        (bytes32 keyId, KeyData memory data) = account.keyAt(2);
        vm.prank(address(account));
        bytes32 result = KMHelper.computeKeyId(data.keyType, data.key);

        assertEq(keyId, result);
        assertEq(uint256(data.keyType), uint256(kDG.keyType));
        assertEq(data.validUntil, kDG.validUntil);
        assertEq(data.validAfter, kDG.validAfter);
        assertEq(data.limits, kDG.limits);
        assertEq(data.key, kDG.key);
        assertTrue(data.isActive);
        assertFalse(data.masterKey);

        KeyData memory k = account.getKey(keyId);
        assertEq(uint256(k.keyType), uint256(kDG.keyType));
        assertEq(k.validUntil, kDG.validUntil);
        assertEq(k.validAfter, kDG.validAfter);
        assertEq(k.limits, kDG.limits);
        assertEq(k.key, kDG.key);
        assertTrue(k.isActive);
        assertFalse(k.masterKey);

        bool isReg = account.isRegistered(keyId);
        assertTrue(isReg);

        bool isAct = account.isKeyActive(keyId);
        assertTrue(isAct);

        uint256 id = account.keyCount();
        assertEq(id, 3);
    }

    function test_registerKeyCustodial() public {
        address eoa = makeAddr("eoa");
        _createCustomFreshKey(
            false,
            KeyType.EOA,
            uint48(block.timestamp + 1 days),
            0,
            20,
            _getKeyEOA(eoa),
            KeyControl.Custodial
        );

        _etch();
        vm.prank(address(account));
        account.registerKey(skReg);

        assertEq(3, account.id());

        (bytes32 keyId, KeyData memory data) = account.keyAt(2);
        vm.prank(address(account));
        bytes32 result = KMHelper.computeKeyId(data.keyType, data.key);

        assertEq(keyId, result);
        assertEq(uint256(data.keyType), uint256(skReg.keyType));
        assertEq(data.validUntil, skReg.validUntil);
        assertEq(data.validAfter, skReg.validAfter);
        assertEq(data.limits, skReg.limits);
        assertEq(data.key, skReg.key);
        assertTrue(data.isActive);
        assertFalse(data.masterKey);

        KeyData memory k = account.getKey(keyId);
        assertEq(uint256(k.keyType), uint256(kDG.keyType));
        assertEq(k.validUntil, skReg.validUntil);
        assertEq(k.validAfter, skReg.validAfter);
        assertEq(k.limits, skReg.limits);
        assertEq(k.key, skReg.key);
        assertTrue(k.isActive);
        assertFalse(k.masterKey);
        assertTrue(k.isDelegatedControl);

        bool isReg = account.isRegistered(keyId);
        assertTrue(isReg);

        bool isAct = account.isKeyActive(keyId);
        assertTrue(isAct);

        uint256 id = account.keyCount();
        assertEq(id, 3);
    }

    function test_setTokenSpend() public {
        _createKey(100, 101);
        _register();

        uint256 _limits = 100e18;
        address _erc20 = address(erc20);
        SpendPeriod setPeriod = SpendPeriod.Month;

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.setTokenSpend(keyId, _erc20, _limits, setPeriod);

        address[] memory tokens = account.spendTokens(keyId);
        for (uint256 i = 0; i < tokens.length;) {
            assertEq(tokens[i], _erc20);
            unchecked {
                i++;
            }
        }

        bool res = account.hasTokenSpend(keyId, _erc20);
        assertTrue(res);

        (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated) =
            account.tokenSpend(keyId, _erc20);
        assertEq(uint8(period), uint8(setPeriod));
        assertEq(limit, _limits);
        assertEq(spent, 0);
        assertEq(lastUpdated, 0);
    }

    function test_setCanCall() public {
        _createKey(100, 101);
        _register();
        address _target = address(erc20);
        bytes4 _funSel = ANY_FN_SEL;
        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.setCanCall(keyId, _target, _funSel, true);

        bytes32[] memory permissions = account.canExecutePackedInfos(keyId);
        bytes32 result = KMHelper._packCanExecute(_target, _funSel);
        for (uint256 i = 0; i < permissions.length;) {
            assertEq(permissions[i], result);
            (address target, bytes4 fnSel) = KMHelper._unpackCanExecute(permissions[i]);
            assertEq(target, _target);
            assertEq(fnSel, _funSel);
            unchecked {
                i++;
            }
        }

        uint256 L = account.canExecuteLength(keyId);
        assertEq(L, 1);

        (address target_, bytes4 fnSel_) = account.canExecuteAt(keyId, 0);
        assertEq(target_, _target);
        assertEq(fnSel_, _funSel);

        bool hasCall = account.hasCanCall(keyId, _target, _funSel);
        assertTrue(hasCall);
    }

    function test_clearExecutePermissions() public {
        _createKey(100, 101);
        _register();
        address _target = address(erc20);
        bytes4 _funSel = ANY_FN_SEL;

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.setCanCall(keyId, _target, _funSel, true);

        _etch();
        vm.prank(address(account));
        account.clearExecutePermissions(keyId);

        bytes32[] memory permissions = account.canExecutePackedInfos(keyId);

        for (uint256 i = 0; i < permissions.length;) {
            assertEq(permissions[i], bytes32(0));
            (address target, bytes4 fnSel) = KMHelper._unpackCanExecute(permissions[i]);
            assertEq(target, address(0));
            assertEq(fnSel, bytes4(0));
            unchecked {
                i++;
            }
        }

        uint256 L = account.canExecuteLength(keyId);
        assertEq(L, 0);
    }

    function test_revokeKey() public {
        _createKey(100, 101);
        _register();
        uint256 _limits = 100e18;
        address _erc20 = address(erc20);
        SpendPeriod setPeriod = SpendPeriod.Month;
        address _target = address(erc20);
        bytes4 _funSel = ANY_FN_SEL;

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.setTokenSpend(keyId, _erc20, _limits, setPeriod);

        _etch();
        vm.prank(address(account));
        account.setCanCall(keyId, _target, _funSel, true);

        _etch();
        vm.prank(address(account));
        account.revokeKey(keyId);

        (, KeyData memory data) = account.keyAt(2);
        assertEq(hex"", data.key);
        assertEq(uint8(0), uint8(data.keyType));
        assertEq(0, data.limits);
        assertEq(0, data.validAfter);
        assertEq(0, data.validUntil);
        assertFalse(data.isActive);
        assertFalse(data.masterKey);

        address[] memory tokens = account.spendTokens(keyId);
        for (uint256 i = 0; i < tokens.length;) {
            assertEq(tokens[i], address(0));
            unchecked {
                i++;
            }
        }

        bool res = account.hasTokenSpend(keyId, _erc20);
        assertFalse(res);

        (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated) =
            account.tokenSpend(keyId, _erc20);
        assertEq(uint8(period), uint8(0));
        assertEq(limit, 0);
        assertEq(spent, 0);
        assertEq(lastUpdated, 0);

        bytes32[] memory permissions = account.canExecutePackedInfos(keyId);

        for (uint256 i = 0; i < permissions.length;) {
            assertEq(permissions[i], bytes32(0));
            (address target, bytes4 fnSel) = KMHelper._unpackCanExecute(permissions[i]);
            assertEq(target, address(0));
            assertEq(fnSel, bytes4(0));
            unchecked {
                i++;
            }
        }

        uint256 L = account.canExecuteLength(keyId);
        assertEq(L, 0);
    }

    function test_updateKeyData() public {
        _createKey(100, 101);
        _register();

        uint48 _validUntil = uint48(block.timestamp + 30 days);
        uint48 _limits = 40;

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.updateKeyData(keyId, _validUntil, _limits);

        (, KeyData memory data) = account.keyAt(2);
        assertEq(_limits, data.limits);
        assertEq(0, data.validAfter);
        assertEq(_validUntil, data.validUntil);
        assertTrue(data.isActive);
    }

    function test_updateTokenSpend() public {
        uint256 _limits = 100e18;
        uint256 _newLimits = 300e18;
        address _erc20 = address(erc20);
        SpendPeriod setPeriod = SpendPeriod.Month;
        SpendPeriod newSetPeriod = SpendPeriod.Year;

        _createKey(100, 101);
        _register();

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.setTokenSpend(keyId, _erc20, _limits, setPeriod);

        _etch();
        vm.prank(address(account));
        account.updateTokenSpend(keyId, _erc20, _newLimits, newSetPeriod);

        address[] memory tokens = account.spendTokens(keyId);
        for (uint256 i = 0; i < tokens.length;) {
            assertEq(tokens[i], _erc20);
            unchecked {
                i++;
            }
        }

        bool res = account.hasTokenSpend(keyId, _erc20);
        assertTrue(res);

        (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated) =
            account.tokenSpend(keyId, _erc20);
        assertEq(uint8(period), uint8(newSetPeriod));
        assertEq(limit, _newLimits);
        assertEq(spent, 0);
        assertEq(lastUpdated, 0);
    }

    function test_removeTokenSpend() public {
        uint256 _limits = 100e18;
        address _erc20 = address(erc20);
        SpendPeriod setPeriod = SpendPeriod.Month;

        _createKey(100, 101);
        _register();

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.setTokenSpend(keyId, _erc20, _limits, setPeriod);

        _etch();
        vm.prank(address(account));
        account.removeTokenSpend(keyId, _erc20);

        address[] memory tokens = account.spendTokens(keyId);
        for (uint256 i = 0; i < tokens.length;) {
            assertEq(tokens[i], address(0));
            unchecked {
                i++;
            }
        }

        bool res = account.hasTokenSpend(keyId, _erc20);
        assertFalse(res);

        (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated) =
            account.tokenSpend(keyId, _erc20);
        assertEq(uint8(period), uint8(0));
        assertEq(limit, 0);
        assertEq(spent, 0);
        assertEq(lastUpdated, 0);
    }

    function test_updateCanCall() public {
        _createKey(100, 101);
        _register();
        address _target = address(erc20);
        bytes4 _funSel = ANY_FN_SEL;

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.setCanCall(keyId, _target, _funSel, true);

        _etch();
        vm.prank(address(account));
        account.setCanCall(keyId, _target, _funSel, false);

        bytes32[] memory permissions = account.canExecutePackedInfos(keyId);

        for (uint256 i = 0; i < permissions.length;) {
            assertEq(permissions[i], bytes32(0));
            (address target, bytes4 fnSel) = KMHelper._unpackCanExecute(permissions[i]);
            assertEq(target, address(0));
            assertEq(fnSel, bytes4(0));
            unchecked {
                i++;
            }
        }

        uint256 L = account.canExecuteLength(keyId);
        assertEq(L, 0);
    }

    function test_pauseKey() public {
        _createKey(100, 101);
        _register();

        assertEq(3, account.id());

        (bytes32 keyId, KeyData memory data) = account.keyAt(2);

        vm.prank(address(account));
        bytes32 result = KMHelper.computeKeyId(data.keyType, data.key);

        assertEq(keyId, result);
        assertEq(uint256(data.keyType), uint256(kDG.keyType));
        assertEq(data.validUntil, kDG.validUntil);
        assertEq(data.validAfter, kDG.validAfter);
        assertEq(data.limits, kDG.limits);
        assertEq(data.key, kDG.key);
        assertTrue(data.isActive);
        assertFalse(data.masterKey);

        _etch();
        vm.prank(address(account));
        account.pauseKey(keyId);

        (, KeyData memory _data) = account.keyAt(2);
        assertFalse(_data.isActive);
    }

    function test_unpauseKey() public {
        _createKey(100, 101);
        _register();

        assertEq(3, account.id());

        (bytes32 keyId, KeyData memory data) = account.keyAt(2);

        vm.prank(address(account));
        bytes32 result = KMHelper.computeKeyId(data.keyType, data.key);

        assertEq(keyId, result);
        assertEq(uint256(data.keyType), uint256(kDG.keyType));
        assertEq(data.validUntil, kDG.validUntil);
        assertEq(data.validAfter, kDG.validAfter);
        assertEq(data.limits, kDG.limits);
        assertEq(data.key, kDG.key);
        assertTrue(data.isActive);
        assertFalse(data.masterKey);

        _etch();
        vm.prank(address(account));
        account.pauseKey(keyId);

        (, KeyData memory _data) = account.keyAt(2);
        assertFalse(_data.isActive);

        _etch();
        vm.prank(address(account));
        account.unpauseKey(keyId);

        (, KeyData memory data_) = account.keyAt(2);
        assertTrue(data_.isActive);
    }

    function _createKey(uint256 _saltX, uint256 _saltY) internal {
        vm.prank(address(account));
        kDG = KMHelper.createDataReg(_saltX, _saltY);
    }

    function _register() internal {
        _etch();
        vm.prank(address(account));
        account.registerKey(kDG);
    }

    function test_registerKeyRevert_MustHaveLimits() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 0, false);
        _etch();
        vm.expectRevert(KeyManager__MustHaveLimits.selector);
        vm.prank(address(account));
        account.registerKey(kDG);
    }

    function test_registerKeyRevert_KeyCantBeZero() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, true);
        _etch();
        vm.expectRevert(KeyManager__KeyCantBeZero.selector);
        vm.prank(address(account));
        account.registerKey(kDG);
    }

    function test_registerKeyRevert_BadTimestamps() public {
        _createKey(
            1010,
            101010,
            uint48(block.timestamp + 10 days),
            uint48(block.timestamp + 11 days),
            10,
            false
        );

        _etch();
        vm.expectRevert(KeyManager__BadTimestamps.selector);
        vm.prank(address(account));
        account.registerKey(kDG);

        _createKey(1010, 101010, type(uint48).max, 0, 10, false);

        _etch();
        vm.expectRevert(KeyManager__BadTimestamps.selector);
        vm.prank(address(account));
        account.registerKey(kDG);

        _createKey(1010, 101010, uint48(block.timestamp - 10 days), 0, 10, false);

        _etch();
        vm.expectRevert(KeyManager__BadTimestamps.selector);
        vm.prank(address(account));
        account.registerKey(kDG);
    }

    function test_registerKeyRevert_KeyRegistered() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

        _etch();
        vm.prank(address(account));
        account.registerKey(kDG);

        _etch();
        vm.expectRevert(KeyManager__KeyRegistered.selector);
        vm.prank(address(account));
        account.registerKey(kDG);
    }

    function test_Revert_KeyNotActive() public {
        _etch();
        vm.expectRevert(KeyManager__KeyNotActive.selector);
        vm.prank(address(account));
        account.revokeKey(hex"12345678");

        _etch();
        vm.expectRevert(KeyManager__KeyNotActive.selector);
        vm.prank(address(account));
        account.setTokenSpend(hex"12345678", address(1234564789), 10e18, SpendPeriod.Month);

        _etch();
        vm.expectRevert(KeyManager__KeyNotActive.selector);
        vm.prank(address(account));
        account.setCanCall(hex"12345678", address(1234564789), 0xdeadbeef, true);

        _etch();
        vm.expectRevert(KeyManager__KeyNotActive.selector);
        vm.prank(address(account));
        account.updateKeyData(hex"12345678", 0, 0);

        _etch();
        vm.expectRevert(KeyManager__KeyNotActive.selector);
        vm.prank(address(account));
        account.updateTokenSpend(hex"12345678", address(123), 0, SpendPeriod.Day);

        _etch();
        vm.expectRevert(KeyManager__KeyNotActive.selector);
        vm.prank(address(account));
        account.removeTokenSpend(hex"12345678", address(123));
    }

    function test_Revert_TokenAddressZero_TargetAddressZero_TargetIsThis_AddressZer() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

        _etch();
        vm.prank(address(account));
        account.registerKey(kDG);

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.expectRevert(KeyManager__AddressZero.selector);
        vm.prank(address(account));
        account.setTokenSpend(keyId, address(0), 10e18, SpendPeriod.Month);

        _etch();
        vm.expectRevert(KeyManager__AddressZero.selector);
        vm.prank(address(account));
        account.setCanCall(keyId, address(0), 0xdeadbabe, true);

        _etch();
        vm.expectRevert(KeyManager__TargetIsThis.selector);
        vm.prank(address(account));
        account.setCanCall(keyId, address(account), 0xdeadbabe, true);

        _etch();
        vm.expectRevert(KeyManager__AddressZero.selector);
        vm.prank(address(account));
        account.updateTokenSpend(keyId, address(0), 0, SpendPeriod.Month);

        _etch();
        vm.expectRevert(KeyManager__MustHaveLimits.selector);
        vm.prank(address(account));
        account.updateTokenSpend(keyId, address(12456), 0, SpendPeriod.Month);
    }

    function test_setTokenSpendRevert_MustHaveLimits() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

        _etch();
        vm.prank(address(account));
        account.registerKey(kDG);

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.expectRevert(KeyManager__MustHaveLimits.selector);
        vm.prank(address(account));
        account.setTokenSpend(keyId, address(12346789), 0, SpendPeriod.Month);
    }

    function test_setTokenSpendRevert_TokenSpendAlreadySet() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

        _etch();
        vm.prank(address(account));
        account.registerKey(kDG);

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.setTokenSpend(keyId, address(erc20), 10e18, SpendPeriod.Month);

        _etch();
        vm.expectRevert(KeyManager__TokenSpendAlreadySet.selector);
        vm.prank(address(account));
        account.setTokenSpend(keyId, address(erc20), 10e18, SpendPeriod.Month);
    }

    function test_updateKeyDataRevert_KeyRegistered_MustHaveLimits() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

        _etch();
        vm.prank(address(account));
        account.registerKey(kDG);

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.expectRevert(KeyManager__BadTimestamps.selector);
        vm.prank(address(account));
        account.updateKeyData(keyId, uint48(block.timestamp + 10 days - 1), 100);

        _etch();
        vm.expectRevert(KeyManager__BadTimestamps.selector);
        vm.prank(address(account));
        account.updateKeyData(keyId, uint48(block.timestamp), 100);

        _etch();
        vm.expectRevert(KeyManager__MustHaveLimits.selector);
        vm.prank(address(account));
        account.updateKeyData(keyId, uint48(block.timestamp + 11 days), 0);
    }

    function test_updateTokenSpend_TokenSpendNotSet() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

        _etch();
        vm.prank(address(account));
        account.registerKey(kDG);

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.setTokenSpend(keyId, address(12346789), 10, SpendPeriod.Month);

        _etch();
        vm.expectRevert(KeyManager__TokenSpendNotSet.selector);
        vm.prank(address(account));
        account.updateTokenSpend(keyId, address(123789), 10, SpendPeriod.Month);
    }

    function test_pauseKey_unpauseKeyRevert_KeyAlreadyPaused_KeyAlreadyActive() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

        _etch();
        vm.prank(address(account));
        account.registerKey(kDG);

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.expectRevert(KeyManager__KeyAlreadyActive.selector);
        vm.prank(address(account));
        account.unpauseKey(keyId);

        _etch();
        vm.prank(address(account));
        account.pauseKey(keyId);

        _etch();
        vm.expectRevert(KeyManager__KeyAlreadyPaused.selector);
        vm.prank(address(account));
        account.pauseKey(keyId);
    }

    function test_requireForExecuteRevert() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.registerKey(kDG);

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.revokeKey(bytes32(0));

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.setTokenSpend(bytes32(0), address(0), 0, SpendPeriod.Month);

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.setCanCall(bytes32(0), address(0), 0xbabebabe, true);

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.updateKeyData(bytes32(0), 0, 0);

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.updateTokenSpend(bytes32(0), address(0), 0, SpendPeriod.Month);

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.removeTokenSpend(bytes32(0), address(0));

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.pauseKey(bytes32(0));

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.unpauseKey(bytes32(0));

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.clearSpendPermissions(bytes32(0));

        _etch();
        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(address(this));
        account.clearExecutePermissions(bytes32(0));
    }

    function test_removeTokenSpend_TokenSpendNotSet() public {
        _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

        _etch();
        vm.prank(address(account));
        account.registerKey(kDG);

        (bytes32 keyId,) = account.keyAt(2);

        _etch();
        vm.prank(address(account));
        account.setTokenSpend(keyId, address(12346789), 10, SpendPeriod.Month);

        _etch();
        vm.expectRevert(KeyManager__TokenSpendNotSet.selector);
        vm.prank(address(account));
        account.removeTokenSpend(keyId, address(123789));
    }

    function _createKey(
        uint256 _saltX,
        uint256 _saltY,
        uint48 _validUntil,
        uint48 _validAfter,
        uint48 _limits,
        bool isBytes32
    ) internal {
        vm.prank(address(account));
        kDG = KMHelper.createDataRegCustom(
            _saltX, _saltY, _validUntil, _validAfter, _limits, isBytes32
        );
    }
}

import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

contract KeysManagerMasterKey is Deploy {
    function setUp() public virtual override {
        super.setUp();
    }

    function test_MKinitializeRevert() external {
        bytes memory _key = new bytes(0);
        _createCustomFreshKey(true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _key, KeyControl.Self);

        vm.expectRevert(KeyManager__KeyCantBeZero.selector);
        _initializeAccount();

        PubKey memory pK = PubKey({x: keccak256("x.MK"), y: keccak256("x.MK")});

        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 1, _getKeyP256(pK), KeyControl.Self
        );

        vm.expectRevert(abi.encodeWithSelector(KeyManager__InvalidMasterKeyReg.selector, mkReg));
        _initializeAccount();

        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 1, 0, _getKeyP256(pK), KeyControl.Self
        );

        vm.expectRevert(abi.encodeWithSelector(KeyManager__InvalidMasterKeyReg.selector, mkReg));
        _initializeAccount();

        _createCustomFreshKey(
            true,
            KeyType.WEBAUTHN,
            uint48(block.timestamp + 10 days),
            0,
            0,
            _getKeyP256(pK),
            KeyControl.Self
        );

        vm.expectRevert(abi.encodeWithSelector(KeyManager__InvalidMasterKeyReg.selector, mkReg));
        _initializeAccount();

        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Custodial
        );

        vm.expectRevert(abi.encodeWithSelector(KeyManager__InvalidMasterKeyReg.selector, mkReg));
        _initializeAccount();

        _createCustomFreshKey(
            true, KeyType.P256, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );

        vm.expectRevert(abi.encodeWithSelector(KeyManager__InvalidMasterKeyReg.selector, mkReg));
        _initializeAccount();

        _createCustomFreshKey(
            true, KeyType.P256NONKEY, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );

        vm.expectRevert(abi.encodeWithSelector(KeyManager__InvalidMasterKeyReg.selector, mkReg));
        _initializeAccount();
    }
}

contract KeysManagerV2Helper is IKey {
    function randomKey(uint256 _saltX, uint256 _saltY) public view returns (bytes32 x, bytes32 y) {
        x = keccak256(
            abi.encode(
                _saltX,
                block.timestamp,
                block.number,
                block.gaslimit,
                msg.sig,
                abi.encode("Coordinate X")
            )
        );
        y = keccak256(
            abi.encode(
                _saltY,
                block.timestamp,
                block.number,
                block.gaslimit,
                msg.sig,
                abi.encode("Coordinate Y")
            )
        );
    }

    function createDataReg(uint256 _saltX, uint256 _saltY)
        public
        view
        returns (KeyDataReg memory kDG)
    {
        (bytes32 x, bytes32 y) = randomKey(_saltX, _saltY);
        kDG = KeyDataReg({
            keyType: KeyType.WEBAUTHN,
            validUntil: uint48(block.timestamp + 10 days),
            validAfter: 0,
            limits: 100,
            key: abi.encode(x, y),
            keyControl: KeyControl.Self
        });
    }

    function createDataRegCustom(
        uint256 _saltX,
        uint256 _saltY,
        uint48 _validUntil,
        uint48 _validAfter,
        uint48 _limits,
        bool _bytes32Zero
    ) public view returns (KeyDataReg memory kDG) {
        bytes memory empty;

        (bytes32 x, bytes32 y) = randomKey(_saltX, _saltY);
        kDG = KeyDataReg({
            keyType: KeyType.WEBAUTHN,
            validUntil: _validUntil,
            validAfter: _validAfter,
            limits: _limits,
            key: _bytes32Zero ? empty : abi.encode(x, y),
            keyControl: KeyControl.Self
        });
    }

    function computeKeyId(KeyType _keyType, bytes calldata _key)
        public
        pure
        returns (bytes32 result)
    {
        uint256 v0 = uint8(_keyType);
        uint256 v1 = uint256(keccak256(_key));
        assembly {
            mstore(0x00, v0)
            mstore(0x20, v1)
            result := keccak256(0x00, 0x40)
        }
    }

    function _packCanExecute(address target, bytes4 fnSel) public pure returns (bytes32 result) {
        assembly ("memory-safe") {
            result := or(shl(96, target), shr(224, fnSel))
        }
    }

    function _unpackCanExecute(bytes32 packed) public pure returns (address target, bytes4 fnSel) {
        assembly ("memory-safe") {
            target := shr(96, packed)
            fnSel := shl(224, packed)
        }
    }
}
