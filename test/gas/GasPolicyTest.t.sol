// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {GasPolicy} from "src/utils/GasPolicy.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IUserOpPolicy} from "src/interfaces/IPolicy.sol";

error GasPolicy__InitializationIncorrect();
error GasPolicy__AccountMustBeSender();
error GasPolicy__IdExistAlready();
error GasPolicy__ZeroBudgets();
error GasPolicy__BadLimit();
error GasPolicy_GasLimitHigh();

contract GasPolicyTest is Test {
    GasPolicy gP;

    address account;
    bytes32 internal constant CONFIG_ID = bytes32(uint256(1));

    function setUp() public {
        gP = new GasPolicy(110_000, 360_000, 240_000, 60_000, 60_000);

        account = makeAddr("account");

        deal(account, 10e18);
    }

    function test_Init() public view {
        uint256 balance = account.balance;
        assertEq(balance, 10e18);
    }

    function test_initializeGasPolicy() public {
        bytes32 configId = keccak256(abi.encodePacked(bytes32(0), bytes32(0)));
        _initGas(configId);

        // UPDATED: gas-only tuple (gasLimit, gasUsed)
        (uint128 gasLimit, uint128 gasUsed) = gP.getGasConfig(configId, account);
        console.log(gasLimit);
        console.log(gasUsed);
    }

    function test_CheckUserOpPolicy() public {
        bytes32 configId = keccak256(abi.encodePacked(bytes32(0), bytes32(0)));
        _initGas(configId);

        uint256 c = 3;
        for (uint256 i = 0; i < c; i++) {
            PackedUserOperation memory userOp = PackedUserOperation({
                sender: account,
                nonce: 0,
                initCode: hex"",
                callData: hex"",
                accountGasLimits: 0x0000000000000000000000000000f091000000000000000000000000000141e7,
                preVerificationGas: 93_673,
                gasFees: 0x00000000000000000000000000011b9800000000000000000000000000dd8ec0,
                paymasterAndData: hex"888888888888ec68a58ab8094cc1ad20ba3d24020000000000000000000000000000912d0000000000000000000000000000000101000068a45c8b0000000000004ba7d7cb7cb2b66d62ac6fc35b13ef9e57baf1fe65f6a9fca6d3594c4fbb7f5c540b12df258c93df4206a846980479cd9e6baa05dff4b9ac5328c94d4cd1d51c1c",
                signature: hex""
            });

            vm.prank(account);
            uint256 res = gP.checkUserOpPolicy(configId, userOp);
            console.log(i);
            console.log(res);
            assertEq(res, 0, "VALIDATION_FAILED");
        }
    }

    function test_constructor_RevertsWhenDefaultZero() public {
        vm.expectRevert(GasPolicy__InitializationIncorrect.selector);
        new GasPolicy(0, 1, 1, 1, 1);
    }

    function test_initializeGasPolicyManual_RevertNotSender() public {
        vm.expectRevert(GasPolicy__AccountMustBeSender.selector);
        gP.initializeGasPolicy(account, CONFIG_ID, bytes16(uint128(1)));
    }

    function test_initializeGasPolicyManual_RevertIdExists() public {
        _initGasManual(CONFIG_ID, 5);
        vm.prank(account);
        vm.expectRevert(GasPolicy__IdExistAlready.selector);
        gP.initializeGasPolicy(account, CONFIG_ID, bytes16(uint128(5)));
    }

    function test_initializeGasPolicyManual_RevertZeroBudget() public {
        vm.prank(account);
        vm.expectRevert(GasPolicy__ZeroBudgets.selector);
        gP.initializeGasPolicy(account, CONFIG_ID, bytes16(0));
    }

    function test_initializeGasPolicyManual_SetsConfig() public {
        vm.prank(account);
        gP.initializeGasPolicy(account, CONFIG_ID, bytes16(uint128(10)));

        (uint128 gasLimit, uint128 gasUsed) = gP.getGasConfig(CONFIG_ID, account);
        assertEq(gasLimit, 10);
        assertEq(gasUsed, 0);
    }

    function test_initializeGasPolicyAuto_RevertNotSender() public {
        vm.expectRevert(GasPolicy__AccountMustBeSender.selector);
        gP.initializeGasPolicy(account, CONFIG_ID, uint256(1));
    }

    function test_initializeGasPolicyAuto_RevertIdExists() public {
        _initGas(CONFIG_ID);
        vm.prank(account);
        vm.expectRevert(GasPolicy__IdExistAlready.selector);
        gP.initializeGasPolicy(account, CONFIG_ID, uint256(1));
    }

    function test_initializeGasPolicyAuto_RevertLimitZero() public {
        vm.prank(account);
        vm.expectRevert(GasPolicy__BadLimit.selector);
        gP.initializeGasPolicy(account, CONFIG_ID, uint256(0));
    }

    function test_initializeGasPolicyAuto_RevertLimitAboveUint32() public {
        vm.prank(account);
        vm.expectRevert(GasPolicy__BadLimit.selector);
        gP.initializeGasPolicy(account, CONFIG_ID, uint256(type(uint32).max) + 1);
    }

    function test_initializeGasPolicyAuto_RevertGasLimitHighMulOverflow() public {
        uint256 huge = 1 << 240;
        GasPolicy heavy = new GasPolicy(huge, huge, huge, huge, huge);
        address other = makeAddr("heavy");
        vm.deal(other, 1 ether);
        vm.prank(other);
        vm.expectRevert(GasPolicy_GasLimitHigh.selector);
        heavy.initializeGasPolicy(other, bytes32("heavy"), uint256(type(uint32).max));
    }

    function test_initializeGasPolicyAuto_RevertGasLimitHighPerOp() public {
        uint256 large = 1 << 130;
        GasPolicy high = new GasPolicy(large, 1, 1, 1, 1);
        address other = makeAddr("high");
        vm.deal(other, 1 ether);
        vm.prank(other);
        vm.expectRevert(GasPolicy_GasLimitHigh.selector);
        high.initializeGasPolicy(other, bytes32("high"), uint256(1));
    }

    function test_checkUserOpPolicy_UnauthorizedCaller() public {
        PackedUserOperation memory userOp = _buildUserOp(
            account,
            10,
            _packAccountGasLimits(0, 0),
            bytes32(0),
            hex""
        );
        uint256 res = gP.checkUserOpPolicy(CONFIG_ID, userOp);
        assertEq(res, 1);
    }

    function test_checkUserOpPolicy_NotInitialized() public {
        PackedUserOperation memory userOp = _buildUserOp(
            account,
            10,
            _packAccountGasLimits(0, 0),
            bytes32(0),
            hex""
        );
        vm.prank(account);
        uint256 res = gP.checkUserOpPolicy(CONFIG_ID, userOp);
        assertEq(res, 1);
    }

    function test_checkUserOpPolicy_GasLimitExceeded() public {
        bytes32 configId = keccak256("manual");
        _initGasManual(configId, 50);
        PackedUserOperation memory userOp = _buildUserOp(
            account,
            60,
            _packAccountGasLimits(0, 0),
            bytes32(0),
            hex""
        );
        vm.prank(account);
        uint256 res = gP.checkUserOpPolicy(configId, userOp);
        assertEq(res, 1);
    }

    function test_checkUserOpPolicy_EnvelopeOverflow() public {
        bytes32 configId = keccak256("overflow");
        _initGasManual(configId, 100);

        bytes32 outerSlot = keccak256(abi.encode(configId, uint256(0)));
        bytes32 baseSlot = keccak256(abi.encode(account, outerSlot));

        vm.store(address(gP), baseSlot, bytes32(uint256(0)));
        vm.store(
            address(gP), bytes32(uint256(baseSlot) + 1), bytes32(uint256(1))
        );

        PackedUserOperation memory userOp = _buildUserOp(
            account,
            type(uint128).max,
            _packAccountGasLimits(1, 0),
            _packGasFees(0, 0),
            hex""
        );

        vm.prank(account);
        uint256 res = gP.checkUserOpPolicy(configId, userOp);
        assertEq(res, 1);
    }

    function test_checkUserOpPolicy_NoPaymasterSuccess() public {
        _initGas(CONFIG_ID);
        PackedUserOperation memory userOp = _buildUserOp(
            account,
            50_000,
            _packAccountGasLimits(40_000, 30_000),
            _packGasFees(0, 0),
            hex""
        );
        vm.prank(account);
        uint256 res = gP.checkUserOpPolicy(CONFIG_ID, userOp);
        assertEq(res, 0);
        (uint128 gasLimit, uint128 gasUsed) = gP.getGasConfig(CONFIG_ID, account);
        assertGt(gasLimit, 0);
        assertGt(gasUsed, 0);
    }

    function test_checkUserOpPolicy_WithPaymasterSuccess() public {
        _initGas(CONFIG_ID);
        bytes memory paymasterData =
            hex"888888888888ec68a58ab8094cc1ad20ba3d24020000000000000000000000000000912d0000000000000000000000000000000101000068a45c8b0000000000004ba7d7cb7cb2b66d62ac6fc35b13ef9e57baf1fe65f6a9fca6d3594c4fbb7f5c540b12df258c93df4206a846980479cd9e6baa05dff4b9ac5328c94d4cd1d51c1c";
        PackedUserOperation memory userOp = _buildUserOp(
            account,
            60_000,
            _packAccountGasLimits(70_000, 80_000),
            _packGasFees(0, 0),
            paymasterData
        );
        vm.prank(account);
        uint256 res = gP.checkUserOpPolicy(CONFIG_ID, userOp);
        assertEq(res, 0);
    }

    function test_getGasConfigEx_ReturnsStruct() public {
        _initGas(CONFIG_ID);
        IUserOpPolicy.GasLimitConfig memory cfg = gP.getGasConfigEx(CONFIG_ID, account);
        assertTrue(cfg.initialized);
        assertGt(cfg.gasLimit, 0);
    }

    function _initGas(bytes32 configId) internal {
        vm.prank(account);
        gP.initializeGasPolicy(account, configId, uint256(3));
    }

    function _initGasManual(bytes32 configId, uint128 gasLimit) internal {
        vm.prank(account);
        gP.initializeGasPolicy(account, configId, bytes16(gasLimit));
    }

    function _buildUserOp(
        address sender,
        uint256 preVerificationGas,
        bytes32 accountGasLimits,
        bytes32 gasFees,
        bytes memory paymasterAndData
    ) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: accountGasLimits,
            preVerificationGas: preVerificationGas,
            gasFees: gasFees,
            paymasterAndData: paymasterAndData,
            signature: hex""
        });
    }

    function _packAccountGasLimits(uint256 callGasLimit, uint256 verificationGasLimit)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((verificationGasLimit << 128) | callGasLimit);
    }

    function _packGasFees(uint256 maxFeePerGas, uint256 maxPriorityFeePerGas)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((maxFeePerGas << 128) | maxPriorityFeePerGas);
    }
}
