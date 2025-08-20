// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {GasPolicy} from "src/utils/GasPolicy.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract GasPolicyTest is Test {
    GasPolicy gP;

    address account;

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

        (uint128 gasLimit, uint128 gasUsed, uint128 costLimit, uint128 costUsed) =
            gP.getGasConfig(configId, account);
        console.log(gasLimit);
        console.log(gasUsed);
        console.log(costLimit);
        console.log(costUsed);
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
                preVerificationGas: 93673,
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

    function _initGas(bytes32 configId) internal {
        vm.prank(account);
        gP.initializeGasPolicy(account, configId, 3);
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
}
