// SPDX-License-Identifier:MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract Execution is Deploy {
    error OpenfortBaseAccount7702V1__TooManyCalls(uint256 total, uint256 max);
    error OpenfortBaseAccount7702V1__InvalidTransactionLength();

    address reciver;
    PubKey internal pK;
    PubKey internal pK_SK;

    uint256 balanceAccounBefore;
    uint256 balanceAccounAfter;
    uint256 balanceReciverBefore;
    uint256 balanceReciverAfter;

    bytes32[2] internal modes = [mode_1, mode_3];

    modifier registerSkEOASelf() {
        _createCustomFreshKey(
            false,
            KeyType.EOA,
            uint48(block.timestamp + 1 days),
            0,
            10,
            _getKeyEOA(sessionKey),
            KeyControl.Self
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier registerSkP256Self() {
        _populateP256("p256_exe.json", ".result");
        pK_SK = PubKey({x: DEF_P256.X, y: DEF_P256.Y});
        _createCustomFreshKey(
            false,
            KeyType.P256,
            uint48(block.timestamp + 1 days),
            0,
            10,
            _getKeyP256(pK_SK),
            KeyControl.Self
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier registerSkP256SelfBatchs() {
        _populateP256("p256_exe_batch.json", ".result");
        pK_SK = PubKey({x: DEF_P256.X, y: DEF_P256.Y});
        _createCustomFreshKey(
            false,
            KeyType.P256,
            uint48(block.timestamp + 1 days),
            0,
            10,
            _getKeyP256(pK_SK),
            KeyControl.Self
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier registerSkP256NonSelf() {
        _populateP256NON("p256_exe.json", ".result2");
        pK_SK = PubKey({x: DEF_P256.X, y: DEF_P256.Y});
        _createCustomFreshKey(
            false,
            KeyType.P256NONKEY,
            uint48(block.timestamp + 1 days),
            0,
            10,
            _getKeyP256(pK_SK),
            KeyControl.Self
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier registerSkP256NonSelfBatchs() {
        _populateP256NON("p256_exe_batch.json", ".result2");
        pK_SK = PubKey({x: DEF_P256.X, y: DEF_P256.Y});
        _createCustomFreshKey(
            false,
            KeyType.P256NONKEY,
            uint48(block.timestamp + 1 days),
            0,
            10,
            _getKeyP256(pK_SK),
            KeyControl.Self
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier setTokenSpendM(
        KeyType _keyType,
        bytes memory _key,
        address _token,
        uint256 _limit,
        SpendPeriod _period
    ) {
        _etch();
        vm.prank(owner);
        account.setTokenSpend(_computeKeyId(_keyType, _key), _token, _limit, _period);
        _;
    }

    modifier setCanCallM(
        KeyType _keyType,
        bytes memory _key,
        address _target,
        bytes4 _funSel,
        bool _can
    ) {
        _etch();
        vm.prank(owner);
        account.setCanCall(_computeKeyId(_keyType, _key), _target, _funSel, _can);
        _;
    }

    function setUp() public override {
        super.setUp();
        reciver = makeAddr("reciver");
        _populateWebAuthn("execution.json", ".batch");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );
        _createQuickFreshKey(false);

        _initializeAccount();
    }

    function test_ExecuteDirectWithRootKey() external {
        _getBalances(true);
        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        Call[] memory calls = _getCalls(1, address(erc20), 0, data);
        bytes memory executionData = abi.encode(calls);

        _etch();
        vm.prank(owner);
        account.execute(mode_1, executionData);

        _getBalances(false);
        _assertBalances(int256(10e18), false);
    }

    function test_ExecuteBatchDirectWithRootKey() external {
        _getBalances(true);
        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        Call[] memory calls = _getCalls(3, address(erc20), 0, data);
        bytes memory executionData = abi.encode(calls);

        _etch();
        vm.prank(owner);
        account.execute(mode_1, executionData);

        _getBalances(false);
        _assertBalances(int256(10e18 * 3), false);
    }

    function test_ExecuteBatchDirectWithRootKeyRevertInvalidTransactionLength() external {
        _getBalances(true);
        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        Call[] memory calls = _getCalls(10, address(erc20), 0, data);
        bytes memory executionData = abi.encode(calls);

        _etch();
        vm.expectRevert(
            abi.encodeWithSelector(OpenfortBaseAccount7702V1__InvalidTransactionLength.selector)
        );
        vm.prank(owner);
        account.execute(mode_1, executionData);
    }

    function test_ExecuteAAWithRootKey() external {
        _getBalances(true);
        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        Call[] memory calls = _getCalls(1, address(erc20), 0, data);
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18), false);
    }

    function test_ExecuteBatchAAWithRootKey() external {
        _getBalances(true);
        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        Call[] memory calls = _getCalls(3, address(erc20), 0, data);
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18 * 3), false);
    }

    function test_executeMode3RevertTooManyCalls() public {
        Call[] memory calls_1 = new Call[](6);
        Call[] memory calls_2 = new Call[](6);
        Call[] memory calls_3 = new Call[](6);

        bytes memory dataHex = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);

        for (uint256 i = 0; i < calls_1.length;) {
            calls_1[i] = Call({target: address(erc20), value: 0, data: dataHex});
            calls_2[i] = Call({target: address(erc20), value: 0, data: dataHex});
            calls_3[i] = Call({target: address(erc20), value: 0, data: dataHex});
            unchecked {
                i++;
            }
        }

        bytes memory batch1Data = abi.encode(calls_1);
        bytes memory batch2Data = abi.encode(calls_2);
        bytes memory batch3Data = abi.encode(calls_3);

        bytes[] memory batches = new bytes[](3);
        batches[0] = batch1Data;
        batches[1] = batch2Data;
        batches[2] = batch3Data;

        bytes memory executionData = abi.encode(batches);

        _etch();

        vm.expectRevert(
            abi.encodeWithSelector(OpenfortBaseAccount7702V1__TooManyCalls.selector, 10, 9)
        );
        vm.prank(owner);
        account.execute(mode_3, executionData);
    }

    function test_ExecuteBatchAAWithRootKeyAndTrasfer() external {
        _getBalances(true);
        bytes memory data_mint = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory data_transfer =
            abi.encodeWithSelector(IERC20.transfer.selector, reciver, 10e18);
        Call[] memory calls = new Call[](2);
        calls[0] = _createCall(address(erc20), 0, data_mint);
        calls[1] = _createCall(address(erc20), 0, data_transfer);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18), true);
    }

    function test_ExecuteBatchofBatchesAAWithRootKeyAndTrasfer() external {
        _getBalances(true);

        address[] memory targets = new address[](3);
        targets[0] = address(erc20);
        targets[1] = address(erc20);
        targets[2] = address(erc20);

        uint256[] memory values = new uint256[](3);

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        datas[1] = abi.encodeWithSelector(IERC20.transfer.selector, reciver, 10e18);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packBatchOfBatches(3, targets, values, datas),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18 * 3), true);
    }

    function test_ExecuteBatchAAWithSKEOASelfAndTrasfer()
        external
        registerSkEOASelf
        setTokenSpendM(KeyType.EOA, _getKeyEOA(sessionKey), address(erc20), 10 ether, SpendPeriod.Month)
        setCanCallM(KeyType.EOA, _getKeyEOA(sessionKey), address(erc20), ANY_FN_SEL, true)
    {
        _getBalances(true);
        bytes memory data_mint = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory data_transfer =
            abi.encodeWithSelector(IERC20.transfer.selector, reciver, 10e18);
        Call[] memory calls = new Call[](2);
        calls[0] = _createCall(address(erc20), 0, data_mint);
        calls[1] = _createCall(address(erc20), 0, data_transfer);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOpWithSK(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18), true);
    }

    function test_ExecuteBatchofBatchesAAWithSKEOASelfAndTrasfer()
        external
        registerSkEOASelf
        setTokenSpendM(KeyType.EOA, _getKeyEOA(sessionKey), address(erc20), 30 ether, SpendPeriod.Month)
        setCanCallM(KeyType.EOA, _getKeyEOA(sessionKey), address(erc20), ANY_FN_SEL, true)
    {
        _getBalances(true);

        address[] memory targets = new address[](3);
        targets[0] = address(erc20);
        targets[1] = address(erc20);
        targets[2] = address(erc20);

        uint256[] memory values = new uint256[](3);

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        datas[1] = abi.encodeWithSelector(IERC20.transfer.selector, reciver, 10e18);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packBatchOfBatches(3, targets, values, datas),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOpWithSK(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18 * 3), true);
    }

    function test_ExecuteBatchAAWithMKAndTrasfer() external {
        _getBalances(true);
        bytes memory data_mint = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory data_transfer =
            abi.encodeWithSelector(IERC20.transfer.selector, reciver, 10e18);
        Call[] memory calls = new Call[](2);
        calls[0] = _createCall(address(erc20), 0, data_mint);
        calls[1] = _createCall(address(erc20), 0, data_transfer);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        _populateWebAuthn("execution.json", ".batch");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18), true);
    }

    function test_ExecuteBatchofBatchesAAWithMKAndTrasfer() external {
        _getBalances(true);

        address[] memory targets = new address[](3);
        targets[0] = address(erc20);
        targets[1] = address(erc20);
        targets[2] = address(erc20);

        uint256[] memory values = new uint256[](3);

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        datas[1] = abi.encodeWithSelector(IERC20.transfer.selector, reciver, 10e18);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packBatchOfBatches(3, targets, values, datas),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        _populateWebAuthn("execution.json", ".batchofbatches");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18 * 3), true);
    }

    function test_ExecuteBatchAAWithSKP256SelfAndTrasfer()
        external
        registerSkP256Self
        setTokenSpendM(KeyType.P256, _getKeyP256(pK_SK), address(erc20), 10 ether, SpendPeriod.Month)
        setCanCallM(KeyType.P256, _getKeyP256(pK_SK), address(erc20), ANY_FN_SEL, true)
    {
        _getBalances(true);
        bytes memory data_mint = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory data_transfer =
            abi.encodeWithSelector(IERC20.transfer.selector, reciver, 10e18);
        Call[] memory calls = new Call[](2);
        calls[0] = _createCall(address(erc20), 0, data_mint);
        calls[1] = _createCall(address(erc20), 0, data_transfer);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        userOp.signature = _encodeP256Signature(DEF_P256.R, DEF_P256.S, pK_SK, KeyType.P256);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18), true);
    }

    function test_ExecuteBatchofBatchesAAWithSKP256SelfAndTrasfer()
        external
        registerSkP256SelfBatchs
        setTokenSpendM(KeyType.P256, _getKeyP256(pK_SK), address(erc20), 30 ether, SpendPeriod.Month)
        setCanCallM(KeyType.P256, _getKeyP256(pK_SK), address(erc20), ANY_FN_SEL, true)
    {
        _getBalances(true);

        address[] memory targets = new address[](3);
        targets[0] = address(erc20);
        targets[1] = address(erc20);
        targets[2] = address(erc20);

        uint256[] memory values = new uint256[](3);

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        datas[1] = abi.encodeWithSelector(IERC20.transfer.selector, reciver, 10e18);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packBatchOfBatches(3, targets, values, datas),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        userOp.signature = _encodeP256Signature(DEF_P256.R, DEF_P256.S, pK_SK, KeyType.P256);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18 * 3), true);
    }

    function test_ExecuteBatchAAWithSKP256NonSelfAndTrasfer()
        external
        registerSkP256NonSelf
        setTokenSpendM(
            KeyType.P256NONKEY,
            _getKeyP256(pK_SK),
            address(erc20),
            10 ether,
            SpendPeriod.Month
        )
        setCanCallM(KeyType.P256NONKEY, _getKeyP256(pK_SK), address(erc20), ANY_FN_SEL, true)
    {
        _getBalances(true);
        bytes memory data_mint = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory data_transfer =
            abi.encodeWithSelector(IERC20.transfer.selector, reciver, 10e18);
        Call[] memory calls = new Call[](2);
        calls[0] = _createCall(address(erc20), 0, data_mint);
        calls[1] = _createCall(address(erc20), 0, data_transfer);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        userOp.signature = _encodeP256Signature(DEF_P256.R, DEF_P256.S, pK_SK, KeyType.P256NONKEY);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18), true);
    }

    function test_ExecuteBatchofBatchesAAWithSKP256NonSelfAndTrasfer()
        external
        registerSkP256NonSelfBatchs
        setTokenSpendM(
            KeyType.P256NONKEY,
            _getKeyP256(pK_SK),
            address(erc20),
            30 ether,
            SpendPeriod.Month
        )
        setCanCallM(KeyType.P256NONKEY, _getKeyP256(pK_SK), address(erc20), ANY_FN_SEL, true)
    {
        _getBalances(true);

        address[] memory targets = new address[](3);
        targets[0] = address(erc20);
        targets[1] = address(erc20);
        targets[2] = address(erc20);

        uint256[] memory values = new uint256[](3);

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        datas[1] = abi.encodeWithSelector(IERC20.transfer.selector, reciver, 10e18);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packBatchOfBatches(3, targets, values, datas),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        userOp.signature = _encodeP256Signature(DEF_P256.R, DEF_P256.S, pK_SK, KeyType.P256NONKEY);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(int256(10e18 * 3), true);
    }

    function test_supportsExecutionMode() public view {
        for (uint256 i = 0; i < modes.length;) {
            bool res = account.supportsExecutionMode(modes[i]);
            assertTrue(res);

            unchecked {
                i++;
            }
        }
    }

    function _getBalances(bool isBefore) internal {
        if (isBefore) {
            balanceAccounBefore = IERC20(erc20).balanceOf(owner);
            balanceReciverBefore = IERC20(erc20).balanceOf(reciver);
        } else {
            balanceAccounAfter = IERC20(erc20).balanceOf(owner);
            balanceReciverAfter = IERC20(erc20).balanceOf(reciver);
        }
    }

    function _assertBalances(int256 _value, bool _includeReciver) internal view {
        if (!_includeReciver) {
            assertEq(int256(balanceAccounBefore) + _value, int256(balanceAccounAfter));
        } else if (_includeReciver) {
            assertEq(int256(balanceReciverBefore) + _value, int256(balanceReciverAfter));
        }
    }

    function _relayUserOp(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }

    function _packBatchOfBatches(
        uint256 _indx,
        address[] memory _targets,
        uint256[] memory _values,
        bytes[] memory _datas
    ) internal pure returns (bytes memory callData) {
        bytes[] memory batches = new bytes[](_indx);

        for (uint256 i = 0; i < _indx; i++) {
            Call[] memory calls = new Call[](_datas.length);

            for (uint256 j = 0; j < _datas.length; j++) {
                calls[j] = Call({target: _targets[i], value: _values[i], data: _datas[j]});
            }

            batches[i] = abi.encode(calls);
        }

        bytes memory executionData = abi.encode(batches);
        callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_3, executionData
        );
    }
}
