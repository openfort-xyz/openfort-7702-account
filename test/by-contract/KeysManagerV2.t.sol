// // SPDX-License-Identifier: MIT

// pragma solidity ^0.8.29;

// import {IKey} from "src/key-manager-v2/IKey.sol";
// import {MockERC20} from "src/mocks/MockERC20.sol";
// import {IKeyManager} from "src/key-manager-v2/IKeyManager.sol";
// import {KeysManager} from "src/key-manager-v2/KeysManager.sol";
// import {Test, console2 as console} from "lib/forge-std/src/Test.sol";

// contract KeysManagerV2 is Test, IKey, IKeyManager {
//     KeysManager KM;
//     KeysManagerV2Helper KMHelper;
//     MockERC20 erc20;

//     KeyDataReg kDG;

//     uint256 private constant SOLADY_SENTINEL = 0xfbb67fda52d4bfb8bf;

//     function setUp() public {
//         KM = new KeysManager();
//         KMHelper = new KeysManagerV2Helper();
//         erc20 = new MockERC20();
//     }

//     function test_registerKey(uint256 _saltX, uint256 _saltY) public {
//         _createKey(_saltX, _saltY);
//         _register();

//         assertEq(1, KM.id());

//         (bytes32 keyId, KeyData memory data) = KM.keyAt(0);
//         vm.prank(address(KM));
//         bytes32 result = KMHelper.computeKeyId(data.keyType, data.key);

//         assertEq(keyId, result);
//         assertEq(uint256(data.keyType), uint256(kDG.keyType));
//         assertEq(data.validUntil, kDG.validUntil);
//         assertEq(data.validAfter, kDG.validAfter);
//         assertEq(data.limits, kDG.limits);
//         assertEq(data.key, kDG.key);
//         assertTrue(data.isActive);
//         assertFalse(data.masterKey);

//         KeyData memory k = KM.getKey(keyId);
//         assertEq(uint256(k.keyType), uint256(kDG.keyType));
//         assertEq(k.validUntil, kDG.validUntil);
//         assertEq(k.validAfter, kDG.validAfter);
//         assertEq(k.limits, kDG.limits);
//         assertEq(k.key, kDG.key);
//         assertTrue(k.isActive);
//         assertFalse(k.masterKey);

//         bool isReg = KM.isRegistered(keyId);
//         assertTrue(isReg);

//         bool isAct = KM.isKeyActive(keyId);
//         assertTrue(isAct);

//         uint256 id = KM.keyCount();
//         assertEq(id, 1);
//     }

//     function test_setTokenSpend(
//         uint256 _saltX,
//         uint256 _saltY,
//         uint256 _limits,
//         address _erc20,
//         uint8 _period
//     ) public {
//         vm.assume(_erc20 != address(0) && _erc20 != address(uint160(SOLADY_SENTINEL)));
//         _limits = bound(_limits, 1, type(uint256).max);
//         _period = uint8(bound(_period, 0, uint8(type(SpendPeriod).max)));
//         SpendPeriod setPeriod = SpendPeriod(_period);

//         _createKey(_saltX, _saltY);
//         _register();

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.setTokenSpend(keyId, _erc20, _limits, setPeriod);

//         address[] memory tokens = KM.spendTokens(keyId);
//         for (uint256 i = 0; i < tokens.length;) {
//             assertEq(tokens[i], _erc20);
//             unchecked {
//                 i++;
//             }
//         }

//         bool res = KM.hasTokenSpend(keyId, _erc20);
//         assertTrue(res);

//         (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated) =
//             KM.tokenSpend(keyId, _erc20);
//         assertEq(uint8(period), uint8(setPeriod));
//         assertEq(limit, _limits);
//         assertEq(spent, 0);
//         assertEq(lastUpdated, 0);
//     }

//     function test_setCanCall(uint256 _saltX, uint256 _saltY, address _target, bytes4 _funSel)
//         public
//     {
//         vm.assume(_target != address(0) && _target != address(KM));

//         _createKey(_saltX, _saltY);
//         _register();

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.setCanCall(keyId, _target, _funSel, true);

//         bytes32[] memory permissions = KM.canExecutePackedInfos(keyId);
//         bytes32 result = KMHelper._packCanExecute(_target, _funSel);
//         for (uint256 i = 0; i < permissions.length;) {
//             assertEq(permissions[i], result);
//             (address target, bytes4 fnSel) = KMHelper._unpackCanExecute(permissions[i]);
//             assertEq(target, _target);
//             assertEq(fnSel, _funSel);
//             unchecked {
//                 i++;
//             }
//         }

//         uint256 L = KM.canExecuteLength(keyId);
//         assertEq(L, 1);

//         (address target_, bytes4 fnSel_) = KM.canExecuteAt(keyId, 0);
//         assertEq(target_, _target);
//         assertEq(fnSel_, _funSel);

//         bool hasCall = KM.hasCanCall(keyId, _target, _funSel);
//         assertTrue(hasCall);
//     }

//     function test_clearExecutePermissions(
//         uint256 _saltX,
//         uint256 _saltY,
//         address _target,
//         bytes4 _funSel,
//         address _checker
//     ) public {
//         vm.assume(_target != address(0) && _target != address(KM));
//         vm.assume(
//             _target != address(0) && _target != address(uint160(SOLADY_SENTINEL))
//                 && _checker != address(0) && _checker != address(uint160(SOLADY_SENTINEL))
//                 && _target != address(KM) && _checker != address(KM)
//         );

//         _createKey(_saltX, _saltY);
//         _register();

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.setCanCall(keyId, _target, _funSel, true);

//         vm.prank(address(KM));
//         KM.clearExecutePermissions(keyId);

//         bytes32[] memory permissions = KM.canExecutePackedInfos(keyId);

//         for (uint256 i = 0; i < permissions.length;) {
//             assertEq(permissions[i], bytes32(0));
//             (address target, bytes4 fnSel) = KMHelper._unpackCanExecute(permissions[i]);
//             assertEq(target, address(0));
//             assertEq(fnSel, bytes4(0));
//             unchecked {
//                 i++;
//             }
//         }

//         uint256 L = KM.canExecuteLength(keyId);
//         assertEq(L, 0);
//     }

//     function test_revokeKey(
//         uint256 _saltX,
//         uint256 _saltY,
//         uint256 _limits,
//         address _erc20,
//         uint8 _period,
//         address _target,
//         bytes4 _funSel
//     ) public {
//         vm.assume(_erc20 != address(0) && _erc20 != address(uint160(SOLADY_SENTINEL)));
//         _limits = bound(_limits, 1, type(uint256).max);
//         _period = uint8(bound(_period, 0, uint8(type(SpendPeriod).max)));
//         SpendPeriod setPeriod = SpendPeriod(_period);
//         vm.assume(_target != address(0) && _target != address(KM));

//         _createKey(_saltX, _saltY);
//         _register();

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.setTokenSpend(keyId, _erc20, _limits, setPeriod);

//         vm.prank(address(KM));
//         KM.setCanCall(keyId, _target, _funSel, true);

//         vm.prank(address(KM));
//         KM.revokeKey(keyId);

//         (, KeyData memory data) = KM.keyAt(0);
//         assertEq(hex"", data.key);
//         assertEq(uint8(0), uint8(data.keyType));
//         assertEq(0, data.limits);
//         assertEq(0, data.validAfter);
//         assertEq(0, data.validUntil);
//         assertFalse(data.isActive);
//         assertFalse(data.masterKey);

//         address[] memory tokens = KM.spendTokens(keyId);
//         for (uint256 i = 0; i < tokens.length;) {
//             assertEq(tokens[i], address(0));
//             unchecked {
//                 i++;
//             }
//         }

//         bool res = KM.hasTokenSpend(keyId, _erc20);
//         assertFalse(res);

//         (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated) =
//             KM.tokenSpend(keyId, _erc20);
//         assertEq(uint8(period), uint8(0));
//         assertEq(limit, 0);
//         assertEq(spent, 0);
//         assertEq(lastUpdated, 0);

//         bytes32[] memory permissions = KM.canExecutePackedInfos(keyId);

//         for (uint256 i = 0; i < permissions.length;) {
//             assertEq(permissions[i], bytes32(0));
//             (address target, bytes4 fnSel) = KMHelper._unpackCanExecute(permissions[i]);
//             assertEq(target, address(0));
//             assertEq(fnSel, bytes4(0));
//             unchecked {
//                 i++;
//             }
//         }

//         uint256 L = KM.canExecuteLength(keyId);
//         assertEq(L, 0);
//     }

//     function test_updateKeyData(uint256 _saltX, uint256 _saltY, uint48 _validUntil, uint48 _limits)
//         public
//     {
//         uint48 _now = uint48(block.timestamp);
//         uint48 max = type(uint48).max - 1;
//         _validUntil = uint48(bound(_validUntil, _now + 10 days + 1, max));
//         vm.assume(_limits != 0);

//         _createKey(_saltX, _saltY);
//         _register();

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.updateKeyData(keyId, _validUntil, _limits);

//         (, KeyData memory data) = KM.keyAt(0);
//         assertEq(_limits, data.limits);
//         assertEq(0, data.validAfter);
//         assertEq(_validUntil, data.validUntil);
//         assertTrue(data.isActive);
//     }

//     function test_updateTokenSpend(
//         uint256 _saltX,
//         uint256 _saltY,
//         uint256 _limits,
//         address _erc20,
//         uint8 _period,
//         uint256 _newLimits,
//         uint8 _newPeriod
//     ) public {
//         vm.assume(_erc20 != address(0) && _erc20 != address(uint160(SOLADY_SENTINEL)));
//         _limits = bound(_limits, 1, type(uint256).max);
//         _newLimits = bound(_limits, 1, type(uint256).max);
//         _period = uint8(bound(_period, 0, uint8(type(SpendPeriod).max)));
//         SpendPeriod setPeriod = SpendPeriod(_period);
//         _newPeriod = uint8(bound(_period, 0, uint8(type(SpendPeriod).max)));
//         SpendPeriod newSetPeriod = SpendPeriod(_newPeriod);

//         _createKey(_saltX, _saltY);
//         _register();

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.setTokenSpend(keyId, _erc20, _limits, setPeriod);

//         vm.prank(address(KM));
//         KM.updateTokenSpend(keyId, _erc20, _newLimits, newSetPeriod);

//         address[] memory tokens = KM.spendTokens(keyId);
//         for (uint256 i = 0; i < tokens.length;) {
//             assertEq(tokens[i], _erc20);
//             unchecked {
//                 i++;
//             }
//         }

//         bool res = KM.hasTokenSpend(keyId, _erc20);
//         assertTrue(res);

//         (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated) =
//             KM.tokenSpend(keyId, _erc20);
//         assertEq(uint8(period), uint8(newSetPeriod));
//         assertEq(limit, _newLimits);
//         assertEq(spent, 0);
//         assertEq(lastUpdated, 0);
//     }

//     function test_removeTokenSpend(
//         uint256 _saltX,
//         uint256 _saltY,
//         uint256 _limits,
//         address _erc20,
//         uint8 _period
//     ) public {
//         vm.assume(_erc20 != address(0) && _erc20 != address(uint160(SOLADY_SENTINEL)));
//         _limits = bound(_limits, 1, type(uint256).max);
//         _period = uint8(bound(_period, 0, uint8(type(SpendPeriod).max)));
//         SpendPeriod setPeriod = SpendPeriod(_period);

//         _createKey(_saltX, _saltY);
//         _register();

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.setTokenSpend(keyId, _erc20, _limits, setPeriod);

//         vm.prank(address(KM));
//         KM.removeTokenSpend(keyId, _erc20);

//         address[] memory tokens = KM.spendTokens(keyId);
//         for (uint256 i = 0; i < tokens.length;) {
//             assertEq(tokens[i], address(0));
//             unchecked {
//                 i++;
//             }
//         }

//         bool res = KM.hasTokenSpend(keyId, _erc20);
//         assertFalse(res);

//         (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated) =
//             KM.tokenSpend(keyId, _erc20);
//         assertEq(uint8(period), uint8(0));
//         assertEq(limit, 0);
//         assertEq(spent, 0);
//         assertEq(lastUpdated, 0);
//     }

//     function test_updateCanCall(uint256 _saltX, uint256 _saltY, address _target, bytes4 _funSel)
//         public
//     {
//         vm.assume(_target != address(0) && _target != address(KM));

//         _createKey(_saltX, _saltY);
//         _register();

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.setCanCall(keyId, _target, _funSel, true);

//         vm.prank(address(KM));
//         KM.setCanCall(keyId, _target, _funSel, false);

//         bytes32[] memory permissions = KM.canExecutePackedInfos(keyId);

//         for (uint256 i = 0; i < permissions.length;) {
//             assertEq(permissions[i], bytes32(0));
//             (address target, bytes4 fnSel) = KMHelper._unpackCanExecute(permissions[i]);
//             assertEq(target, address(0));
//             assertEq(fnSel, bytes4(0));
//             unchecked {
//                 i++;
//             }
//         }

//         uint256 L = KM.canExecuteLength(keyId);
//         assertEq(L, 0);
//     }

//     function test_pauseKey(uint256 _saltX, uint256 _saltY) public {
//         _createKey(_saltX, _saltY);
//         _register();

//         assertEq(1, KM.id());

//         (bytes32 keyId, KeyData memory data) = KM.keyAt(0);
//         vm.prank(address(KM));
//         bytes32 result = KMHelper.computeKeyId(data.keyType, data.key);

//         assertEq(keyId, result);
//         assertEq(uint256(data.keyType), uint256(kDG.keyType));
//         assertEq(data.validUntil, kDG.validUntil);
//         assertEq(data.validAfter, kDG.validAfter);
//         assertEq(data.limits, kDG.limits);
//         assertEq(data.key, kDG.key);
//         assertTrue(data.isActive);
//         assertFalse(data.masterKey);

//         vm.prank(address(KM));
//         KM.pauseKey(keyId);

//         (, KeyData memory _data) = KM.keyAt(0);
//         assertFalse(_data.isActive);
//     }

//     function test_unpauseKey(uint256 _saltX, uint256 _saltY) public {
//         _createKey(_saltX, _saltY);
//         _register();

//         assertEq(1, KM.id());

//         (bytes32 keyId, KeyData memory data) = KM.keyAt(0);
//         vm.prank(address(KM));
//         bytes32 result = KMHelper.computeKeyId(data.keyType, data.key);

//         assertEq(keyId, result);
//         assertEq(uint256(data.keyType), uint256(kDG.keyType));
//         assertEq(data.validUntil, kDG.validUntil);
//         assertEq(data.validAfter, kDG.validAfter);
//         assertEq(data.limits, kDG.limits);
//         assertEq(data.key, kDG.key);
//         assertTrue(data.isActive);
//         assertFalse(data.masterKey);

//         vm.prank(address(KM));
//         KM.pauseKey(keyId);

//         (, KeyData memory _data) = KM.keyAt(0);
//         assertFalse(_data.isActive);

//         vm.prank(address(KM));
//         KM.unpauseKey(keyId);

//         (, KeyData memory data_) = KM.keyAt(0);
//         assertTrue(data_.isActive);
//     }

//     function _createKey(uint256 _saltX, uint256 _saltY) internal {
//         vm.prank(address(KM));
//         kDG = KMHelper.createDataReg(_saltX, _saltY);
//     }

//     function _register() internal {
//         vm.prank(address(KM));
//         KM.registerKey(kDG);
//     }
// }

// contract KeysManagerV2Reverts is Test, IKey, IKeyManager {
//     KeysManager KM;
//     KeysManagerV2Helper KMHelper;
//     MockERC20 erc20;

//     KeyDataReg kDG;

//     uint256 private constant SOLADY_SENTINEL = 0xfbb67fda52d4bfb8bf;

//     function setUp() public {
//         KM = new KeysManager();
//         KMHelper = new KeysManagerV2Helper();
//         erc20 = new MockERC20();
//     }

//     function test_registerKeyRevert_MustHaveLimits() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 0, false);

//         vm.expectRevert(KeyManager__MustHaveLimits.selector);
//         vm.prank(address(KM));
//         KM.registerKey(kDG);
//     }

//     function test_registerKeyRevert_KeyCantBeZero() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, true);

//         vm.expectRevert(KeyManager__KeyCantBeZero.selector);
//         vm.prank(address(KM));
//         KM.registerKey(kDG);
//     }

//     function test_registerKeyRevert_BadTimestamps() public {
//         _createKey(
//             1010,
//             101010,
//             uint48(block.timestamp + 10 days),
//             uint48(block.timestamp + 11 days),
//             10,
//             false
//         );

//         vm.expectRevert(KeyManager__BadTimestamps.selector);
//         vm.prank(address(KM));
//         KM.registerKey(kDG);

//         _createKey(1010, 101010, type(uint48).max, 0, 10, false);

//         vm.expectRevert(KeyManager__BadTimestamps.selector);
//         vm.prank(address(KM));
//         KM.registerKey(kDG);

//         _createKey(1010, 101010, uint48(block.timestamp - 10 days), 0, 10, false);

//         vm.expectRevert(KeyManager__BadTimestamps.selector);
//         vm.prank(address(KM));
//         KM.registerKey(kDG);
//     }

//     function test_registerKeyRevert_KeyRegistered() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

//         vm.prank(address(KM));
//         KM.registerKey(kDG);

//         vm.expectRevert(KeyManager__KeyRegistered.selector);
//         vm.prank(address(KM));
//         KM.registerKey(kDG);
//     }

//     function test_Revert_KeyNotActive() public {
//         vm.expectRevert(KeyManager__KeyNotActive.selector);
//         vm.prank(address(KM));
//         KM.revokeKey(hex"12345678");

//         vm.expectRevert(KeyManager__KeyNotActive.selector);
//         vm.prank(address(KM));
//         KM.setTokenSpend(hex"12345678", address(1234564789), 10e18, SpendPeriod.Month);

//         vm.expectRevert(KeyManager__KeyNotActive.selector);
//         vm.prank(address(KM));
//         KM.setCanCall(hex"12345678", address(1234564789), 0xdeadbeef, true);

//         vm.expectRevert(KeyManager__KeyNotActive.selector);
//         vm.prank(address(KM));
//         KM.updateKeyData(hex"12345678", 0, 0);

//         vm.expectRevert(KeyManager__KeyNotActive.selector);
//         vm.prank(address(KM));
//         KM.updateTokenSpend(hex"12345678", address(123), 0, SpendPeriod.Day);

//         vm.expectRevert(KeyManager__KeyNotActive.selector);
//         vm.prank(address(KM));
//         KM.removeTokenSpend(hex"12345678", address(123));
//     }

//     function test_Revert_TokenAddressZero_TargetAddressZero_TargetIsThis_AddressZer() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

//         vm.prank(address(KM));
//         KM.registerKey(kDG);

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.expectRevert(KeyManager__AddressZero.selector);
//         vm.prank(address(KM));
//         KM.setTokenSpend(keyId, address(0), 10e18, SpendPeriod.Month);

//         vm.expectRevert(KeyManager__AddressZero.selector);
//         vm.prank(address(KM));
//         KM.setCanCall(keyId, address(0), 0xdeadbabe, true);

//         vm.expectRevert(KeyManager__TargetIsThis.selector);
//         vm.prank(address(KM));
//         KM.setCanCall(keyId, address(KM), 0xdeadbabe, true);

//         vm.expectRevert(KeyManager__AddressZero.selector);
//         vm.prank(address(KM));
//         KM.updateTokenSpend(keyId, address(0), 0, SpendPeriod.Month);

//         vm.expectRevert(KeyManager__MustHaveLimits.selector);
//         vm.prank(address(KM));
//         KM.updateTokenSpend(keyId, address(12456), 0, SpendPeriod.Month);
//     }

//     function test_setTokenSpendRevert_MustHaveLimits() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

//         vm.prank(address(KM));
//         KM.registerKey(kDG);

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.expectRevert(KeyManager__MustHaveLimits.selector);
//         vm.prank(address(KM));
//         KM.setTokenSpend(keyId, address(12346789), 0, SpendPeriod.Month);
//     }

//     function test_setTokenSpendRevert_TokenSpendAlreadySet() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

//         vm.prank(address(KM));
//         KM.registerKey(kDG);

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.setTokenSpend(keyId, address(erc20), 10e18, SpendPeriod.Month);

//         vm.expectRevert(KeyManager__TokenSpendAlreadySet.selector);
//         vm.prank(address(KM));
//         KM.setTokenSpend(keyId, address(erc20), 10e18, SpendPeriod.Month);
//     }

//     function test_updateKeyDataRevert_KeyRegistered_MustHaveLimits() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

//         vm.prank(address(KM));
//         KM.registerKey(kDG);

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.expectRevert(KeyManager__BadTimestamps.selector);
//         vm.prank(address(KM));
//         KM.updateKeyData(keyId, uint48(block.timestamp + 10 days - 1), 100);

//         vm.expectRevert(KeyManager__BadTimestamps.selector);
//         vm.prank(address(KM));
//         KM.updateKeyData(keyId, uint48(block.timestamp), 100);

//         vm.expectRevert(KeyManager__MustHaveLimits.selector);
//         vm.prank(address(KM));
//         KM.updateKeyData(keyId, uint48(block.timestamp + 11 days), 0);
//     }

//     function test_updateTokenSpend_TokenSpendNotSet() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

//         vm.prank(address(KM));
//         KM.registerKey(kDG);

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.setTokenSpend(keyId, address(12346789), 10, SpendPeriod.Month);

//         vm.expectRevert(KeyManager__TokenSpendNotSet.selector);
//         vm.prank(address(KM));
//         KM.updateTokenSpend(keyId, address(123789), 10, SpendPeriod.Month);
//     }

//     function test_pauseKey_unpauseKeyRevert_KeyAlreadyPaused_KeyAlreadyActive() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

//         vm.prank(address(KM));
//         KM.registerKey(kDG);

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.expectRevert(KeyManager__KeyAlreadyActive.selector);
//         vm.prank(address(KM));
//         KM.unpauseKey(keyId);

//         vm.prank(address(KM));
//         KM.pauseKey(keyId);

//         vm.expectRevert(KeyManager__KeyAlreadyPaused.selector);
//         vm.prank(address(KM));
//         KM.pauseKey(keyId);
//     }

//     function test_requireForExecuteRevert() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.registerKey(kDG);

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.revokeKey(bytes32(0));

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.setTokenSpend(bytes32(0), address(0), 0, SpendPeriod.Month);

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.setCanCall(bytes32(0), address(0), 0xbabebabe, true);

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.updateKeyData(bytes32(0), 0, 0);

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.updateTokenSpend(bytes32(0), address(0), 0, SpendPeriod.Month);

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.removeTokenSpend(bytes32(0), address(0));

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.removeCallChecker(bytes32(0), address(0));

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.pauseKey(bytes32(0));

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.unpauseKey(bytes32(0));

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.clearSpendPermissions(bytes32(0));

//         vm.expectRevert(abi.encodePacked("OnlyThis"));
//         vm.prank(address(this));
//         KM.clearExecutePermissions(bytes32(0));
//     }

//     function test_removeTokenSpend_TokenSpendNotSet() public {
//         _createKey(1010, 101010, uint48(block.timestamp + 10 days), 0, 10, false);

//         vm.prank(address(KM));
//         KM.registerKey(kDG);

//         (bytes32 keyId,) = KM.keyAt(0);

//         vm.prank(address(KM));
//         KM.setTokenSpend(keyId, address(12346789), 10, SpendPeriod.Month);

//         vm.expectRevert(KeyManager__TokenSpendNotSet.selector);
//         vm.prank(address(KM));
//         KM.removeTokenSpend(keyId, address(123789));
//     }

//     function _createKey(
//         uint256 _saltX,
//         uint256 _saltY,
//         uint48 _validUntil,
//         uint48 _validAfter,
//         uint48 _limits,
//         bool isBytes32
//     ) internal {
//         vm.prank(address(KM));
//         kDG = KMHelper.createDataRegCustom(
//             _saltX, _saltY, _validUntil, _validAfter, _limits, isBytes32
//         );
//     }
// }

// contract KeysManagerV2Helper is IKey {
//     function randomKey(uint256 _saltX, uint256 _saltY) public view returns (bytes32 x, bytes32 y) {
//         x = keccak256(
//             abi.encode(
//                 _saltX,
//                 block.timestamp,
//                 block.number,
//                 block.gaslimit,
//                 msg.sig,
//                 abi.encode("Coordinate X")
//             )
//         );
//         y = keccak256(
//             abi.encode(
//                 _saltY,
//                 block.timestamp,
//                 block.number,
//                 block.gaslimit,
//                 msg.sig,
//                 abi.encode("Coordinate Y")
//             )
//         );
//     }

//     function createDataReg(uint256 _saltX, uint256 _saltY)
//         public
//         view
//         returns (KeyDataReg memory kDG)
//     {
//         (bytes32 x, bytes32 y) = randomKey(_saltX, _saltY);
//         kDG = KeyDataReg({
//             keyType: KeyType.WEBAUTHN,
//             validUntil: uint48(block.timestamp + 10 days),
//             validAfter: 0,
//             limits: 100,
//             key: abi.encode(x, y)
//         });
//     }

//     function createDataRegCustom(
//         uint256 _saltX,
//         uint256 _saltY,
//         uint48 _validUntil,
//         uint48 _validAfter,
//         uint48 _limits,
//         bool _bytes32Zero
//     ) public view returns (KeyDataReg memory kDG) {
//         bytes memory empty;

//         (bytes32 x, bytes32 y) = randomKey(_saltX, _saltY);
//         kDG = KeyDataReg({
//             keyType: KeyType.WEBAUTHN,
//             validUntil: _validUntil,
//             validAfter: _validAfter,
//             limits: _limits,
//             key: _bytes32Zero ? empty : abi.encode(x, y)
//         });
//     }

//     function computeKeyId(KeyType _keyType, bytes calldata _key)
//         public
//         pure
//         returns (bytes32 result)
//     {
//         uint256 v0 = uint8(_keyType);
//         uint256 v1 = uint256(keccak256(_key));
//         assembly {
//             mstore(0x00, v0)
//             mstore(0x20, v1)
//             result := keccak256(0x00, 0x40)
//         }
//     }

//     function _packCanExecute(address target, bytes4 fnSel) public pure returns (bytes32 result) {
//         assembly ("memory-safe") {
//             result := or(shl(96, target), shr(224, fnSel))
//         }
//     }

//     function _unpackCanExecute(bytes32 packed) public pure returns (address target, bytes4 fnSel) {
//         assembly ("memory-safe") {
//             target := shr(96, packed)
//             fnSel := shl(224, packed)
//         }
//     }
// }
