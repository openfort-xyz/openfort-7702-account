// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract DepositAndTransferETH is Deploy {
    address reciver;
    PubKey internal pK;
    PubKey internal pK_SK;

    uint256 balanceAccounBefore;
    uint256 balanceAccounAfter;
    uint256 balanceReciverBefore;
    uint256 balanceReciverAfter;

    modifier registerSkEOASelf() {
        _createCustomFreshKey(
            false,
            KeyType.EOA,
            uint48(block.timestamp + 1 days),
            0,
            3,
            _getKeyEOA(sessionKey),
            KeyControl.Self
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier registerSkP256Self() {
        pK_SK = PubKey({x: ETH_P256.X, y: ETH_P256.Y});
        _createCustomFreshKey(
            false,
            KeyType.P256,
            uint48(block.timestamp + 1 days),
            0,
            3,
            _getKeyP256(pK_SK),
            KeyControl.Self
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier registerSkP256SelfBatch() {
        pK_SK = PubKey({x: ETH_BATCH_P256.X, y: ETH_BATCH_P256.Y});
        _createCustomFreshKey(
            false,
            KeyType.P256,
            uint48(block.timestamp + 1 days),
            0,
            3,
            _getKeyP256(pK_SK),
            KeyControl.Self
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier registerSkP256NonSelf() {
        pK_SK = PubKey({x: ETH_P256_NON.X, y: ETH_P256_NON.Y});
        _createCustomFreshKey(
            false,
            KeyType.P256NONKEY,
            uint48(block.timestamp + 1 days),
            0,
            3,
            _getKeyP256(pK_SK),
            KeyControl.Self
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier registerSkP256NonSelfBatch() {
        pK_SK = PubKey({x: ETH_BATCH_P256_NON.X, y: ETH_BATCH_P256_NON.Y});
        _createCustomFreshKey(
            false,
            KeyType.P256NONKEY,
            uint48(block.timestamp + 1 days),
            0,
            3,
            _getKeyP256(pK_SK),
            KeyControl.Self
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier setTokenSpend(
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

    modifier setCanCall(
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
        pK = PubKey({x: ETH_WEBAUTHN.X, y: ETH_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );
        _createQuickFreshKey(false);

        _initializeAccount();
    }

    function test_DepositNativeFromEOA() external {
        deal(reciver, 10e18);
        _getBalances(true);

        _etch();
        vm.prank(reciver);
        (bool res,) = owner.call{value: 0.1e18}(hex"");
        assertTrue(res);

        _getBalances(false);
        assertEq(balanceAccounBefore + 0.1 ether, balanceAccounAfter);
        assertEq(balanceReciverBefore - 0.1 ether, balanceReciverAfter);
    }

    function test_TransferDirectFromAccount() external {
        _getBalances(true);

        _etch();
        vm.prank(owner);
        (bool res,) = reciver.call{value: 0.1e18}(hex"");
        assertTrue(res);

        _getBalances(false);
        _assertBalances(0.1 ether);
    }

    function test_ExecuteDirectWithRootKey() external {
        _getBalances(true);
        Call[] memory calls = _getCalls(1, reciver, 0.1 ether, hex"");

        bytes memory executionData = abi.encode(calls);

        _etch();
        vm.prank(owner);
        account.execute(mode_1, executionData);

        _getBalances(false);
        _assertBalances(0.1 ether);
    }

    function test_ExecuteAAWithRootKey() external {
        _getBalances(true);
        Call[] memory calls = _getCalls(1, reciver, 0.1 ether, hex"");

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
        _assertBalances(0.1 ether);
    }

    function test_ExecuteAABatchWithRootKey() external {
        _getBalances(true);
        Call[] memory calls = _getCalls(3, reciver, 0.1 ether, hex"");

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
        _assertBalances(0.3 ether);
    }

    function test_ExecuteAAWithMK() external {
        _getBalances(true);
        Call[] memory calls = _getCalls(1, reciver, 0.1 ether, hex"");

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

        userOp.signature = _getSignedUserOpByWebAuthn(ETH_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(0.1 ether);
    }

    function test_ExecuteAABatchWithMK() external {
        _getBalances(true);
        Call[] memory calls = _getCalls(3, reciver, 0.1 ether, hex"");

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

        userOp.signature = _getSignedUserOpByWebAuthn(ETH_BATCH_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(0.3 ether);
    }

    function test_ExecuteAAWithSKEOASelf()
        external
        registerSkEOASelf
        setTokenSpend(KeyType.EOA, _getKeyEOA(sessionKey), NATIVE_ADDRESS, 0.1 ether, SpendPeriod.Month)
        setCanCall(KeyType.EOA, _getKeyEOA(sessionKey), NATIVE_ADDRESS, EMPTY_CALLDATA_FN_SEL, true)
        setCanCall(KeyType.EOA, _getKeyEOA(sessionKey), reciver, EMPTY_CALLDATA_FN_SEL, true)
    {
        _getBalances(true);
        Call[] memory calls = _getCalls(1, reciver, 0.1 ether, hex"");

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
        _assertBalances(0.1 ether);
    }

    function test_ExecuteBatchAAWithSKEOASelf()
        external
        registerSkEOASelf
        setTokenSpend(KeyType.EOA, _getKeyEOA(sessionKey), NATIVE_ADDRESS, 0.3 ether, SpendPeriod.Month)
        setCanCall(KeyType.EOA, _getKeyEOA(sessionKey), NATIVE_ADDRESS, EMPTY_CALLDATA_FN_SEL, true)
        setCanCall(KeyType.EOA, _getKeyEOA(sessionKey), reciver, EMPTY_CALLDATA_FN_SEL, true)
    {
        _getBalances(true);
        Call[] memory calls = _getCalls(3, reciver, 0.1 ether, hex"");

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
        _assertBalances(0.3 ether);
    }

    function test_ExecuteAAWithSKP256Self()
        external
        registerSkP256Self
        setTokenSpend(KeyType.P256, _getKeyP256(pK_SK), NATIVE_ADDRESS, 0.1 ether, SpendPeriod.Month)
        setCanCall(KeyType.P256, _getKeyP256(pK_SK), NATIVE_ADDRESS, EMPTY_CALLDATA_FN_SEL, true)
        setCanCall(KeyType.P256, _getKeyP256(pK_SK), reciver, EMPTY_CALLDATA_FN_SEL, true)
    {
        _getBalances(true);
        Call[] memory calls = _getCalls(1, reciver, 0.1 ether, hex"");

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

        userOp.signature = _encodeP256Signature(ETH_P256.R, ETH_P256.S, pK_SK, KeyType.P256);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(0.1 ether);
    }

    function test_ExecuteAABatchWithSKP256Self()
        external
        registerSkP256SelfBatch
        setTokenSpend(KeyType.P256, _getKeyP256(pK_SK), NATIVE_ADDRESS, 0.3 ether, SpendPeriod.Month)
        setCanCall(KeyType.P256, _getKeyP256(pK_SK), NATIVE_ADDRESS, EMPTY_CALLDATA_FN_SEL, true)
        setCanCall(KeyType.P256, _getKeyP256(pK_SK), reciver, EMPTY_CALLDATA_FN_SEL, true)
    {
        _getBalances(true);
        Call[] memory calls = _getCalls(3, reciver, 0.1 ether, hex"");

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

        userOp.signature =
            _encodeP256Signature(ETH_BATCH_P256.R, ETH_BATCH_P256.S, pK_SK, KeyType.P256);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(0.3 ether);
    }

    function test_ExecuteAAWithSKP256NonSelf()
        external
        registerSkP256NonSelf
        setTokenSpend(
            KeyType.P256NONKEY,
            _getKeyP256(pK_SK),
            NATIVE_ADDRESS,
            0.1 ether,
            SpendPeriod.Month
        )
        setCanCall(KeyType.P256NONKEY, _getKeyP256(pK_SK), NATIVE_ADDRESS, EMPTY_CALLDATA_FN_SEL, true)
        setCanCall(KeyType.P256NONKEY, _getKeyP256(pK_SK), reciver, EMPTY_CALLDATA_FN_SEL, true)
    {
        _getBalances(true);
        Call[] memory calls = _getCalls(1, reciver, 0.1 ether, hex"");

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

        userOp.signature =
            _encodeP256Signature(ETH_P256_NON.R, ETH_P256_NON.S, pK_SK, KeyType.P256NONKEY);

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(0.1 ether);
    }

    function test_ExecuteAABatchWithSKP256NonSelf()
        external
        registerSkP256NonSelfBatch
        setTokenSpend(
            KeyType.P256NONKEY,
            _getKeyP256(pK_SK),
            NATIVE_ADDRESS,
            0.3 ether,
            SpendPeriod.Month
        )
        setCanCall(KeyType.P256NONKEY, _getKeyP256(pK_SK), NATIVE_ADDRESS, EMPTY_CALLDATA_FN_SEL, true)
        setCanCall(KeyType.P256NONKEY, _getKeyP256(pK_SK), reciver, EMPTY_CALLDATA_FN_SEL, true)
    {
        _getBalances(true);
        Call[] memory calls = _getCalls(3, reciver, 0.1 ether, hex"");

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

        userOp.signature = _encodeP256Signature(
            ETH_BATCH_P256_NON.R, ETH_BATCH_P256_NON.S, pK_SK, KeyType.P256NONKEY
        );

        _relayUserOp(userOp);

        _getBalances(false);
        _assertBalances(0.3 ether);
    }

    function _getBalances(bool isBefore) internal {
        if (isBefore) {
            balanceAccounBefore = owner.balance;
            balanceReciverBefore = reciver.balance;
        } else {
            balanceAccounAfter = owner.balance;
            balanceReciverAfter = reciver.balance;
        }
    }

    function _assertBalances(uint256 _value) internal view {
        assertEq(balanceAccounBefore - _value, balanceAccounAfter);
        assertEq(balanceReciverBefore + _value, balanceReciverAfter);
    }

    function _relayUserOp(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }
}
