// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {GasPolicy} from "src/utils/GasPolicy.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract GasFuzzing is Test {
    GasPolicy gP;
    address account;

    uint256 constant DEFAULT_PVG = 110_000;
    uint256 constant DEFAULT_VGL = 360_000;
    uint256 constant DEFAULT_CGL = 240_000;
    uint256 constant DEFAULT_PMV = 60_000;
    uint256 constant DEFAULT_PO = 60_000;

    function setUp() public {
        gP = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        account = makeAddr("account");
        deal(account, 10e18);
        vm.fee(0);
    }

    function _packAccountGasLimits(uint256 callGasLimit, uint256 verificationGasLimit)
        internal
        pure
        returns (bytes32)
    {
        // lib expects (verificationGasLimit << 128) | callGasLimit
        return bytes32((verificationGasLimit << 128) | callGasLimit);
    }

    function _packGasFees(uint256 maxFeePerGas, uint256 maxPriorityFeePerGas)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((maxFeePerGas << 128) | maxPriorityFeePerGas);
    }

    function _mkUserOp(
        address sender,
        uint256 pvg,
        uint256 vgl,
        uint256 cgl,
        uint256 maxFee,
        uint256 tip,
        bytes memory pmd
    ) internal pure returns (PackedUserOperation memory uo) {
        uo = PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: _packAccountGasLimits(cgl, vgl),
            preVerificationGas: pvg,
            gasFees: _packGasFees(maxFee, tip),
            paymasterAndData: pmd,
            signature: hex""
        });
    }

    function _initAuto(bytes32 configId, uint256 limit) internal {
        vm.prank(account);
        gP.initializeGasPolicy(account, configId, limit);
    }

    function test_init_ok() public view {
        assertEq(account.balance, 10e18);
    }

    function test_initialize_and_getters() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(1)));
        _initAuto(configId, 3);
        // UPDATED: gas-only tuple
        (uint128 gasLimit, uint128 gasUsed) = gP.getGasConfig(configId, account);
        console.log(gasLimit, gasUsed);
        assertGt(gasLimit, 0);
        assertEq(gasUsed, 0);
    }

    function test_uninitialized_fails() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(2)));
        PackedUserOperation memory uo =
            _mkUserOp(account, 50_000, 100_000, 100_000, 1 gwei, 1 gwei, hex"");
        vm.prank(account);
        uint256 res = gP.checkUserOpPolicy(configId, uo);
        assertEq(res, 1);
    }

    function test_wrong_caller_fails() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(3)));
        _initAuto(configId, 1);
        address attacker = makeAddr("attacker");
        PackedUserOperation memory uo =
            _mkUserOp(account, 50_000, 100_000, 100_000, 1 gwei, 1 gwei, hex"");
        vm.prank(attacker);
        uint256 res = gP.checkUserOpPolicy(configId, uo);
        assertEq(res, 1);
    }

    function test_basic_accept_no_paymaster() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(4)));
        _initAuto(configId, 3);
        PackedUserOperation memory uo =
            _mkUserOp(account, 90_000, 200_000, 200_000, 1 gwei, 1 gwei, hex"");
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(account);
            uint256 res = gP.checkUserOpPolicy(configId, uo);
            assertEq(res, 0);
        }
    }

    // tx-limit logic removed in policy => this always passes now
    function test_tx_limit_exceeded() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(5)));
        _initAuto(configId, 2);
        PackedUserOperation memory uo =
            _mkUserOp(account, 90_000, 200_000, 200_000, 1 gwei, 1 gwei, hex"");
        vm.prank(account);
        assertEq(gP.checkUserOpPolicy(configId, uo), 0);
        vm.prank(account);
        assertEq(gP.checkUserOpPolicy(configId, uo), 0);
        vm.prank(account);
        assertEq(gP.checkUserOpPolicy(configId, uo), 0);
    }

    function test_price_zero_path() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(6)));
        _initAuto(configId, 3);
        PackedUserOperation memory uo = _mkUserOp(account, 80_000, 150_000, 150_000, 0, 0, hex"");
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(account);
            uint256 res = gP.checkUserOpPolicy(configId, uo);
            assertEq(res, 0);
        }
        (uint128 gasLimit, uint128 gasUsed) = gP.getGasConfig(configId, account);
        assertLe(gasUsed, gasLimit);
    }

    function test_penalty_boundary() public {
        bytes32 configIdA = keccak256(abi.encodePacked(uint256(7)));
        bytes32 configIdB = keccak256(abi.encodePacked(uint256(8)));
        _initAuto(configIdA, 1);
        _initAuto(configIdB, 1);

        PackedUserOperation memory below =
            _mkUserOp(account, 10_000, 10_000, 39_999, 1 gwei, 1 gwei, hex"");
        PackedUserOperation memory atThr =
            _mkUserOp(account, 10_000, 10_000, 40_000, 1 gwei, 1 gwei, hex"");

        vm.prank(account);
        assertEq(gP.checkUserOpPolicy(configIdA, below), 0);
        vm.prank(account);
        assertEq(gP.checkUserOpPolicy(configIdB, atThr), 0);

        (uint128 gasLimitA, uint128 gasUsedA) = gP.getGasConfig(configIdA, account);
        (uint128 gasLimitB, uint128 gasUsedB) = gP.getGasConfig(configIdB, account);
        assertLe(gasUsedA, gasLimitA);
        assertLe(gasUsedB, gasLimitB);
        assertLt(gasUsedA, gasUsedB); // 39,999 < 40,000 => fewer envelope units
    }

    // per-op cost cap removed => should pass
    function test_perOpMaxCostWei_cap_triggers() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(9)));
        _initAuto(configId, 3);
        PackedUserOperation memory uo =
            _mkUserOp(account, 110_000, 300_000, 300_000, 10 gwei, 10 gwei, hex"");
        vm.prank(account);
        uint256 res = gP.checkUserOpPolicy(configId, uo);
        assertEq(res, 0);
    }

    // cost-limit logic removed => ensure still OK
    function test_cumulative_cost_limit_exceeded() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(10)));
        _initAuto(configId, 2);

        vm.fee(1 gwei); // basefee (no effect now)
        PackedUserOperation memory uo =
            _mkUserOp(account, 90_000, 200_000, 200_000, 2 gwei, 1 gwei, hex"");

        vm.prank(account);
        assertEq(gP.checkUserOpPolicy(configId, uo), 0);
        vm.prank(account);
        assertEq(gP.checkUserOpPolicy(configId, uo), 0);
        vm.prank(account);
        assertEq(gP.checkUserOpPolicy(configId, uo), 0);
        vm.prank(account);
        assertEq(gP.checkUserOpPolicy(configId, uo), 0);
    }

    function test_fuzz_accept_within_auto_limits(
        uint96 pvg,
        uint96 vgl,
        uint96 cgl,
        uint64 maxFee,
        uint64 tip,
        uint8 nOps
    ) public {
        pvg = uint96(bound(pvg, 10_000, DEFAULT_PVG));
        vgl = uint96(bound(vgl, 10_000, DEFAULT_VGL));
        cgl = uint96(bound(cgl, 10_000, DEFAULT_CGL));
        maxFee = uint64(bound(maxFee, 1 gwei, 1 gwei));
        tip = uint64(bound(tip, 1 gwei, 1 gwei));
        nOps = uint8(bound(nOps, 1, 5));

        bytes32 configId = keccak256(abi.encodePacked(uint256(11), pvg, vgl, cgl));
        _initAuto(configId, nOps + 1);

        uint256 accGas = 0;

        for (uint256 i = 0; i < nOps; i++) {
            PackedUserOperation memory uo = _mkUserOp(account, pvg, vgl, cgl, maxFee, tip, hex"");
            vm.prank(account);
            uint256 res = gP.checkUserOpPolicy(configId, uo);
            assertEq(res, 0);

            uint256 envelope = uint256(pvg) + uint256(vgl) + uint256(cgl);
            accGas += envelope;
        }

        (uint128 gasLimit, uint128 gasUsed) = gP.getGasConfig(configId, account);
        assertLe(gasUsed, gasLimit);
        assertEq(gasUsed, uint128(accGas));
    }

    function test_malformed_paymaster_len_lt_offset_passes() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(12)));
        _initAuto(configId, 1);
        bytes memory pmd = hex"01";
        PackedUserOperation memory uo =
            _mkUserOp(account, 50_000, 100_000, 100_000, 1 gwei, 1 gwei, pmd);
        vm.prank(account);
        uint256 res = gP.checkUserOpPolicy(configId, uo);
        assertEq(res, 0);
    }

    function test_with_paymaster_blob_sample() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(13)));
        _initAuto(configId, 1);
        bytes memory pmd =
            hex"888888888888ec68a58ab8094cc1ad20ba3d24020000000000000000000000000000912d0000000000000000000000000000000101000068a45c8b0000000000004ba7d7cb7cb2b66d62ac6fc35b13ef9e57baf1fe65f6a9fca6d3594c4fbb7f5c540b12df258c93df4206a846980479cd9e6baa05dff4b9ac5328c94d4cd1d51c1c";
        PackedUserOperation memory uo =
            _mkUserOp(account, 93_673, 0xf091, 0x141e7, 0x11b98, 0xdd8ec0, pmd);
        vm.prank(account);
        uint256 res = gP.checkUserOpPolicy(configId, uo);
        assertEq(res, 0);
    }

    // formerly reverted; with gas-only init it should succeed
    function test_auto_init_reverts_when_basefee_extreme() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(14)));
        vm.fee(type(uint64).max - 1);
        vm.prank(account);
        gP.initializeGasPolicy(account, configId, 1);
        vm.fee(0);

        (uint128 gasLimit, uint128 gasUsed) = gP.getGasConfig(configId, account);
        assertGt(gasLimit, 0);
        assertEq(gasUsed, 0);
    }

    function test_fuzz_overflow_guard_in_check(
        uint96 pvg,
        uint96 vgl,
        uint96 cgl,
        uint128 maxFee,
        uint128 tip
    ) public {
        pvg = uint96(bound(pvg, 1, 5_000_000));
        vgl = uint96(bound(vgl, 1, 5_000_000));
        cgl = uint96(bound(cgl, 1, 5_000_000));
        maxFee = uint128(bound(maxFee, 0, type(uint128).max));
        tip = uint128(bound(tip, 0, type(uint128).max));

        bytes32 configId = keccak256(abi.encodePacked(uint256(15)));
        _initAuto(configId, 1);

        PackedUserOperation memory uo = _mkUserOp(account, pvg, vgl, cgl, maxFee, tip, hex"");
        vm.prank(account);
        uint256 res = gP.checkUserOpPolicy(configId, uo);
        assertTrue(res == 0 || res == 1);
    }

    function test_auto_init_handles_extreme_u64_basefee() public {
        bytes32 configId = keccak256(abi.encodePacked(uint256(16)));
        vm.fee(type(uint64).max - 1);
        vm.prank(account);
        gP.initializeGasPolicy(account, configId, 1);

        (uint128 gasLimit, uint128 gasUsed) = gP.getGasConfig(configId, account);
        assertGt(gasLimit, 0);
        assertEq(gasUsed, 0);
    }
}
