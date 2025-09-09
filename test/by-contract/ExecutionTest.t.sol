// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {console2 as console} from "lib/forge-std/src/Test.sol";
import {BaseContract} from "test/by-contract/BaseContract.t.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC20Mock} from "lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

contract ExecutionTest is BaseContract {
    bytes32 internal constant mode_1 = bytes32(uint256(0x01000000000000000000) << (22 * 8));
    bytes32 internal constant mode_2 = bytes32(uint256(0x01000000000078210001) << (22 * 8));
    bytes32 internal constant mode_3 = bytes32(uint256(0x01000000000078210002) << (22 * 8));

    bytes32[2] internal modes = [mode_1, mode_3];

    function test_supportsExecutionMode() public view {
        for (uint256 i = 0; i < modes.length;) {
            bool res = account.supportsExecutionMode(modes[i]);
            assertTrue(res);

            unchecked {
                i++;
            }
        }
    }

    function test_unsupportsExecutionMode() public view {
        bytes32 mode_0 = bytes32(0);

        bool res = account.supportsExecutionMode(mode_0);

        assertFalse(res);
    }

    function test_executeMode1TargetAddressThis() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: owner, value: 0.1e18, data: hex""});

        bytes memory executionData = abi.encode(calls);

        _etch();

        vm.expectEmit(true, false, false, true);
        emit DepositAdded(owner, 0.1e18);

        vm.prank(owner);
        account.execute(mode_1, executionData);
    }

    function test_executeMode2Revert() public {
        Call[] memory calls = new Call[](1);
        bytes memory dataHex = abi.encodeWithSelector(ERC20Mock.mint.selector, owner, 10e18);
        calls[0] = Call({target: address(mockERC20), value: 0, data: dataHex});

        bytes memory opData = abi.encodeWithSelector(ERC20.approve.selector, sender, 10e18);

        bytes memory executionData = abi.encode(calls, opData);

        _etch();

        vm.expectRevert(OpenfortBaseAccount7702V1__UnsupportedExecutionMode.selector);
        vm.prank(owner);
        account.execute(mode_2, executionData);
    }

    function test_executeIncorrectMode1() public {
        Call[] memory calls = new Call[](1);
        bytes memory dataHex = abi.encodeWithSelector(ERC20Mock.mint.selector, owner, 10e18);
        calls[0] = Call({target: address(mockERC20), value: 0, data: dataHex});

        bytes memory executionData = abi.encode(calls);

        _etch();

        vm.expectRevert();
        vm.prank(owner);
        account.execute(mode_3, executionData);
    }

    function test_executeMode2RevertUnsupportedExecutionMode() public {
        bytes32 mode_un = bytes32(uint256(0x01000000000000000005) << (22 * 8));

        Call[] memory calls = new Call[](1);
        bytes memory dataHex = abi.encodeWithSelector(ERC20Mock.mint.selector, owner, 10e18);
        calls[0] = Call({target: address(mockERC20), value: 0, data: dataHex});

        bytes memory opData = abi.encodeWithSelector(ERC20.approve.selector, sender, 10e18);

        bytes memory executionData = abi.encode(calls, opData);

        _etch();

        vm.expectRevert(OpenfortBaseAccount7702V1__UnsupportedExecutionMode.selector);
        vm.prank(owner);
        account.execute(mode_un, executionData);
    }

    function test_executeMode2RevertManyTxs() public {
        Call[] memory calls = new Call[](11);
        bytes memory dataHex = abi.encodeWithSelector(ERC20Mock.mint.selector, owner, 10e18);

        for (uint256 i = 0; i < calls.length;) {
            calls[i] = Call({target: address(mockERC20), value: 0, data: dataHex});
            unchecked {
                i++;
            }
        }

        bytes memory executionData = abi.encode(calls);

        _etch();

        vm.expectRevert(OpenfortBaseAccount7702V1__InvalidTransactionLength.selector);
        vm.prank(owner);
        account.execute(mode_1, executionData);
    }

    function test_executeMode3RevertTooManyCalls() public {
        Call[] memory calls_1 = new Call[](5);
        Call[] memory calls_2 = new Call[](5);
        Call[] memory calls_3 = new Call[](5);

        bytes memory dataHex = abi.encodeWithSelector(ERC20Mock.mint.selector, owner, 10e18);

        for (uint256 i = 0; i < calls_1.length;) {
            calls_1[i] = Call({target: address(mockERC20), value: 0, data: dataHex});
            calls_2[i] = Call({target: address(mockERC20), value: 0, data: dataHex});
            calls_3[i] = Call({target: address(mockERC20), value: 0, data: dataHex});
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

    function test_Reentrancy() public {
        Reentrancy reentrancy = new Reentrancy(owner);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(reentrancy), value: 0.1e18, data: hex""});

        bytes memory executionData = abi.encode(calls);

        _etch();

        vm.prank(owner);
        account.execute(mode_1, executionData);
    }

    function test_executNotWithOwnerRevert() public {
        Reentrancy reentrancy = new Reentrancy(owner);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(reentrancy), value: 0.1e18, data: hex""});

        bytes memory executionData = abi.encode(calls);

        _etch();

        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);
        vm.prank(sender);
        account.execute(mode_1, executionData);
    }
}

contract Reentrancy {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    bytes32 internal constant mode_1 = bytes32(uint256(0x01000000000000000000) << (22 * 8));

    address public eoa7702;

    receive() external payable {
        attack();
    }

    constructor(address _eoa7702) {
        eoa7702 = _eoa7702;
    }

    function attack() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(this), value: 0.1e18, data: hex""});

        bytes memory executionData = abi.encode(calls);

        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), mode_1, executionData
        );

        (bool res, bytes memory err) = payable(eoa7702).call{value: 0}(callData);

        if (!res) {
            console.logBytes(err);
        }
    }
}
