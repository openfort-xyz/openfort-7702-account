// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract OPF7702WithDiffKeys is Deploy {
    uint256 mkPK;
    address mk;
    uint256 skPK;
    address sk;
    address reciver;
    PubKey internal pK_SK;

    uint256 balanceAccounBefore;
    uint256 balanceAccounAfter;
    uint256 balanceReciverBefore;
    uint256 balanceReciverAfter;

    modifier registerSkEOACustodial() {
        _createCustomFreshKey(
            false,
            KeyType.EOA,
            uint48(block.timestamp + 1 days),
            0,
            10,
            _getKeyEOA(sk),
            KeyControl.Custodial
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier registerSkWebAuthnCustodial() {
        _populateWebAuthn("eth.json", ".eth");
        pK_SK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            false,
            KeyType.WEBAUTHN,
            uint48(block.timestamp + 1 days),
            0,
            10,
            _getKeyP256(pK_SK),
            KeyControl.Custodial
        );
        _etch();
        vm.prank(owner);
        account.registerKey(skReg);
        _;
    }

    modifier registerSkP256Custodial() {
        _populateP256("p256_eth.json", ".result");
        pK_SK = PubKey({x: DEF_P256.X, y: DEF_P256.Y});
        _createCustomFreshKey(
            false,
            KeyType.P256,
            uint48(block.timestamp + 1 days),
            0,
            3,
            _getKeyP256(pK_SK),
            KeyControl.Custodial
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
        (mk, mkPK) = makeAddrAndKey("EOA-MK");
        (sk, skPK) = makeAddrAndKey("EOA-SK");
        reciver = makeAddr("reciver");

        _createCustomFreshKey(
            true, KeyType.EOA, type(uint48).max, 0, 0, _getKeyEOA(mk), KeyControl.Self
        );

        _initializeAccount();
    }

    function test_sentUserOpWithMKEOA() external registerSkEOACustodial {
        Call[] memory calls = _getCalls(1, sessionKey, 10.1 ether, hex"");
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp, mkPK);
        userOp.signature = _encodeEOASignature(signature);

        bytes32 userOpHash = _getUserOpHash(userOp);

        uint256 res = _sendUserOp(userOp, userOpHash);
        assertEq(res, 0);
    }

    function test_sentUserOpWithSKEOA()
        external
        registerSkEOACustodial
        setTokenSpendM(KeyType.EOA, _getKeyEOA(sk), address(erc20), 10 ether, SpendPeriod.Month)
        setCanCallM(KeyType.EOA, _getKeyEOA(sk), address(erc20), ANY_FN_SEL, true)
    {
        _getBalances(true, false);
        bytes memory data_mint = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory data_transfer =
            abi.encodeWithSelector(IERC20.transfer.selector, sessionKey, 10e18);
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

        bytes memory signature = _signUserOp(userOp, skPK);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getBalances(false, false);
        _assertBalances(int256(10e18), true);
    }

    function test_sentUserOpWithSKEOAFailedAllValidations()
        external
        registerSkEOACustodial
        setTokenSpendM(KeyType.EOA, _getKeyEOA(sk), address(erc20), 10 ether, SpendPeriod.Month)
        setCanCallM(KeyType.EOA, _getKeyEOA(sk), address(erc20), ANY_FN_SEL, true)
    {
        Call[] memory calls = new Call[](1);
        calls[0] = _createCall(address(123456), 1 ether, hex"");

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp, skPK);
        userOp.signature = _encodeEOASignature(signature);

        bytes32 userOpHash = _getUserOpHash(userOp);

        uint256 res = _sendUserOp(userOp, userOpHash);
        assertEq(res, 1);
    }

    function test_sentUserOpWithSKWebAuthnFailedAllValidations()
        external
        registerSkWebAuthnCustodial
        setTokenSpendM(
            KeyType.WEBAUTHN,
            _getKeyP256(pK_SK),
            address(erc20),
            10 ether,
            SpendPeriod.Month
        )
        setCanCallM(KeyType.WEBAUTHN, _getKeyP256(pK_SK), address(erc20), ANY_FN_SEL, true)
    {
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

        _populateWebAuthn("eth.json", ".eth");
        pK_SK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK_SK);

        uint256 res = _sendUserOp(userOp, userOpHash);
        assertEq(res, 1);
    }

    function test_sentUserOpWithSKWebAuthn()
        external
        registerSkWebAuthnCustodial
        setTokenSpendM(
            KeyType.WEBAUTHN,
            _getKeyP256(pK_SK),
            NATIVE_ADDRESS,
            10 ether,
            SpendPeriod.Month
        )
        setCanCallM(KeyType.WEBAUTHN, _getKeyP256(pK_SK), reciver, ANY_FN_SEL, true)
    {
        _getBalances(true, true);
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

        _populateWebAuthn("eth.json", ".eth");
        pK_SK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK_SK);

        _relayUserOp(userOp);

        _getBalances(false, true);
        _assertBalances(0.1 ether);
    }

    function test_ExecuteAAWithSKP256SelfFailedAllValidations()
        external
        registerSkP256Custodial
        setTokenSpendM(KeyType.P256, _getKeyP256(pK_SK), NATIVE_ADDRESS, 0.1 ether, SpendPeriod.Month)
        setCanCallM(KeyType.P256, _getKeyP256(pK_SK), NATIVE_ADDRESS, EMPTY_CALLDATA_FN_SEL, true)
        setCanCallM(KeyType.P256, _getKeyP256(pK_SK), reciver, EMPTY_CALLDATA_FN_SEL, true)
    {
        Call[] memory calls = _getCalls(1, reciver, 30 ether, hex"");

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

        uint256 res = _sendUserOp(userOp, userOpHash);
        assertEq(res, 1);
    }

    function test_sentUserOpWithSKEOAFailedKeyValidation()
        external
        registerSkEOACustodial
        setTokenSpendM(KeyType.EOA, _getKeyEOA(sk), address(erc20), 10 ether, SpendPeriod.Month)
        setCanCallM(KeyType.EOA, _getKeyEOA(sk), address(erc20), ANY_FN_SEL, true)
    {
        _etch();
        vm.prank(owner);
        account.pauseKey(_computeKeyId(KeyType.EOA, _getKeyEOA(sk)));

        Call[] memory calls = new Call[](1);
        calls[0] = _createCall(address(erc20), 0, hex"");

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp, skPK);
        userOp.signature = _encodeEOASignature(signature);

        bytes32 userOpHash = _getUserOpHash(userOp);

        uint256 res = _sendUserOp(userOp, userOpHash);
        assertEq(res, 1);
    }

    function test_sentUserOpWithSKEOAFailedIsValidKey()
        external
        registerSkEOACustodial
        setTokenSpendM(KeyType.EOA, _getKeyEOA(sk), address(erc20), 10 ether, SpendPeriod.Month)
        setCanCallM(KeyType.EOA, _getKeyEOA(sk), address(erc20), ANY_FN_SEL, true)
    {
        Call[] memory calls = new Call[](1);
        calls[0] = _createCall(address(erc20), 0, hex"");

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        userOp.callData = hex"bebebabe";

        bytes memory signature = _signUserOp(userOp, skPK);
        userOp.signature = _encodeEOASignature(signature);

        bytes32 userOpHash = _getUserOpHash(userOp);

        uint256 res = _sendUserOp(userOp, userOpHash);
        assertEq(res, 1);
    }

    function test_sentBatchUserOpWithSKEOAFailedKeyValidation()
        external
        registerSkEOACustodial
        setTokenSpendM(KeyType.EOA, _getKeyEOA(sk), address(erc20), 10 ether, SpendPeriod.Month)
        setCanCallM(KeyType.EOA, _getKeyEOA(sk), address(erc20), ANY_FN_SEL, true)
    {
        address[] memory targets = new address[](3);
        targets[0] = address(erc20);
        targets[1] = address(erc20);
        targets[2] = address(erc20);

        uint256[] memory values = new uint256[](3);

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(MockERC20.mint.selector, owner, 100e18);
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

        bytes memory signature = _signUserOp(userOp, skPK);
        userOp.signature = _encodeEOASignature(signature);

        bytes32 userOpHash = _getUserOpHash(userOp);

        uint256 res = _sendUserOp(userOp, userOpHash);
        assertEq(res, 1);
    }

    function test_sentUserOpWithSKEOAFailedBadMode()
        external
        registerSkEOACustodial
        setTokenSpendM(KeyType.EOA, _getKeyEOA(sk), address(erc20), 10 ether, SpendPeriod.Month)
        setCanCallM(KeyType.EOA, _getKeyEOA(sk), address(erc20), ANY_FN_SEL, true)
    {
        Call[] memory calls = new Call[](1);
        calls[0] = _createCall(address(erc20), 0, hex"");

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(keccak256("bad-mode"), calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp, skPK);
        userOp.signature = _encodeEOASignature(signature);

        bytes32 userOpHash = _getUserOpHash(userOp);

        uint256 res = _sendUserOp(userOp, userOpHash);
        assertEq(res, 1);
    }

    function test_sentUserOpWithSKEOAAllPaths()
        external
        registerSkEOACustodial
        setTokenSpendM(KeyType.EOA, _getKeyEOA(sk), address(erc20), 100 ether, SpendPeriod.Forever)
        setCanCallM(KeyType.EOA, _getKeyEOA(sk), ANY_TARGET, ANY_FN_SEL, true)
    {
        _getBalances(true, false);
        bytes memory data_mint = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory data_approve = abi.encodeWithSelector(IERC20.approve.selector, reciver, 10e18);
        bytes memory data_transferFrom =
            abi.encodeWithSelector(IERC20.transferFrom.selector, owner, reciver, 0);
        bytes memory data_transfer =
            abi.encodeWithSelector(IERC20.transfer.selector, sessionKey, 10e18);
        Call[] memory calls = new Call[](4);
        calls[0] = _createCall(address(erc20), 0, data_mint);
        calls[1] = _createCall(address(erc20), 0, data_transfer);
        calls[2] = _createCall(address(erc20), 0, data_approve);
        calls[3] = _createCall(address(erc20), 0, data_transferFrom);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp, skPK);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getBalances(false, false);
        _assertBalances(int256(10e18), true);
    }

    function _sendUserOp(PackedUserOperation memory _userOp, bytes32 _userOpHash)
        internal
        returns (uint256 res)
    {
        _etch();
        vm.prank(ENTRYPOINT_V8);
        res = account.validateUserOp(_userOp, _userOpHash, 0);
    }

    function _relayUserOp(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }

    function _getBalances(bool isBefore, bool isETH) internal {
        if (isETH) {
            if (isBefore) {
                balanceAccounBefore = owner.balance;
                balanceReciverBefore = reciver.balance;
            } else {
                balanceAccounAfter = owner.balance;
                balanceReciverAfter = reciver.balance;
            }
        } else {
            if (isBefore) {
                balanceAccounBefore = IERC20(erc20).balanceOf(owner);
                balanceReciverBefore = IERC20(erc20).balanceOf(sessionKey);
            } else {
                balanceAccounAfter = IERC20(erc20).balanceOf(owner);
                balanceReciverAfter = IERC20(erc20).balanceOf(sessionKey);
            }
        }
    }

    function _getBalances(bool isBefore) internal {}

    function _assertBalances(int256 _value, bool _includeReciver) internal view {
        if (!_includeReciver) {
            assertEq(int256(balanceAccounBefore) + _value, int256(balanceAccounAfter));
        } else if (_includeReciver) {
            assertEq(int256(balanceReciverBefore) + _value, int256(balanceReciverAfter));
        }
    }

    function _assertBalances(uint256 _value) internal view {
        assertEq(balanceAccounBefore - _value, balanceAccounAfter);
        assertEq(balanceReciverBefore + _value, balanceReciverAfter);
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
