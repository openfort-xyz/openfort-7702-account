// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "../Deploy.t.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {IExecution} from "src/interfaces/IExecution.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract ExecutionFuzz is Deploy {
    PubKey internal pK;

    function setUp() public override {
        super.setUp();

        _populateWebAuthn("keysmanager.json", ".keys_register");

        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );

        _createQuickFreshKey(false);
        _initializeAccount();
    }

    function testFuzz_executeWithinLimit(uint8 callCountRaw) external {
        uint256 callCount = bound(uint256(callCountRaw), 1, 9);
        Call[] memory calls = _buildReadCalls(callCount);

        vm.prank(owner);
        account.execute(mode_1, abi.encode(calls));

        uint256 balance = erc20.balanceOf(address(account));
        assertEq(balance, 0);
    }

    function testFuzz_executeTooManyCalls(uint8 callCountRaw) external {
        uint256 callCount = bound(uint256(callCountRaw), 10, 30);
        Call[] memory calls = _buildReadCalls(callCount);

        vm.expectRevert(
            abi.encodeWithSelector(
                IExecution.OpenfortBaseAccount7702V1__InvalidTransactionLength.selector
            )
        );
        vm.prank(owner);
        account.execute(mode_1, abi.encode(calls));
    }

    function testFuzz_executeInvalidMode(bytes32 randomMode) external {
        vm.assume(randomMode != mode_1 && randomMode != mode_3);

        Call[] memory calls = _buildReadCalls(1);

        vm.expectRevert(IExecution.OpenfortBaseAccount7702V1__UnsupportedExecutionMode.selector);
        vm.prank(owner);
        account.execute(randomMode, abi.encode(calls));
    }

    function testFuzz_executeZeroLength() external {
        Call[] memory calls = new Call[](0);

        vm.expectRevert();
        vm.prank(owner);
        account.execute(mode_1, abi.encode(calls));
    }

    function _buildReadCalls(uint256 count) private view returns (Call[] memory calls) {
        calls = new Call[](count);
        bytes memory data = abi.encodeWithSelector(IERC20.balanceOf.selector, address(account));

        for (uint256 i; i < count; ++i) {
            calls[i] = _createCall(address(erc20), 0, data);
        }
    }
}
