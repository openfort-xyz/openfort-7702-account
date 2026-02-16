// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Data} from "../data/Data.t.sol";
import {Vm} from "lib/forge-std/src/Vm.sol";
import {Constants} from "../data/Constants.sol";
import {SignatureCheckerLib} from "lib/solady/src/utils/SignatureCheckerLib.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperationLib} from "lib/account-abstraction/contracts/core/UserOperationLib.sol";
import {
    PackedUserOperation
} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

abstract contract AAHelpers is Data {
    // Struct for calls
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    // Mode constant ERC7281
    bytes32 internal constant mode_1 = bytes32(uint256(0x01000000000000000000) << (22 * 8));

    function _depositStake(address _owner, uint256 _depositValue, uint32 _unstakeDelaySec)
        internal
    {
        vm.startPrank(_owner);
        IEntryPoint(Constants.ENTRY_POINT_9).depositTo{value: _depositValue}(_owner);
        IEntryPoint(Constants.ENTRY_POINT_9).addStake{value: _depositValue}(_unstakeDelaySec);
        vm.stopPrank();
    }

    // Get nonce for _sender from EntryPoint
    function _getNonce(address _sender) internal view returns (uint256) {
        return IEntryPoint(Constants.ENTRY_POINT_9).getNonce(_sender, 0);
    }

    // Create UserOperation for AA transaction
    function _getUserOp(address _sender, uint256 _pk, bytes memory _callData)
        internal
        view
        returns (PackedUserOperation[] memory)
    {
        PackedUserOperation[] memory u = new PackedUserOperation[](1);
        u[0].sender = _sender;
        u[0].nonce = _getNonce(_sender);
        u[0].accountGasLimits = bytes32(uint256(1_000_000 | (1_000_000 << 128)));
        u[0].gasFees = bytes32(uint256(1_000_000 | (1_000_000 << 128)));
        u[0].callData = _callData;
        u[0].paymasterAndData = hex"";

        bytes32 userOpHash = IEntryPoint(Constants.ENTRY_POINT_9).getUserOpHash(u[0]);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, userOpHash);
        u[0].signature = abi.encode(uint8(0), abi.encodePacked(r, s, v));

        return u;
    }

    // Helper to create Call struct
    function _createCall(address _target, uint256 _value, bytes memory _data)
        internal
        pure
        returns (Call memory call)
    {
        call = Call({target: _target, value: _value, data: _data});
    }

    // Pack call data for execute function
    function _packCallData(bytes32 _mode, Call[] memory _calls)
        internal
        pure
        returns (bytes memory callData)
    {
        bytes memory executionData = abi.encode(_calls);
        callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), _mode, executionData
        );
    }

    // Relay UserOperation to EntryPoint
    function _relayUserOp(PackedUserOperation[] memory _userOps) internal {
        vm.prank(__RELAYER_ADDRESS, __RELAYER_ADDRESS);
        IEntryPoint(Constants.ENTRY_POINT_9).handleOps(_userOps, payable(__RELAYER_ADDRESS));
    }

    // Etch contract at _account with implementation _implementation using EIP-7702
    function _etch7702(address _account, address _implementation) internal {
        vm.etch(_account, abi.encodePacked(bytes3(0xef0100), address(_implementation)));
    }
}
