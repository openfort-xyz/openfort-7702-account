// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Base} from "test/Base.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {Script, console2 as console} from "lib/forge-std/src/Script.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract MintScript is Script {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    uint256 internal ownerPk = vm.envUint("PRIVATE_KEY_PROXY");
    address internal owner = vm.addr(ownerPk);
    OPF7702 opf;
    address constant TOKEN = 0x9C0b94fb071Ed4066d7C18F4b68968e311A66209;

    uint256 internal senderPk = vm.envUint("PRIVATE_KEY_SENDER");
    address internal sender = vm.addr(senderPk);

    function run() external {
        Call[] memory calls = new Call[](2);
        bytes memory callData = abi.encodeWithSelector(MockERC20.mint.selector, owner, 10e18);
        bytes memory callData2 =
            abi.encodeWithSelector(IERC20(TOKEN).transfer.selector, sender, 5e18);

        calls[0] = Call({target: TOKEN, value: 0, data: callData});
        calls[1] = Call({target: TOKEN, value: 0, data: callData2});
        bytes32 mode = bytes32(uint256(0x01000000000000000000) << (22 * 8));
        bytes memory executionData = abi.encode(calls);

        vm.startBroadcast();
        opf = OPF7702(payable(owner));

        opf.execute(mode, executionData);
        vm.stopBroadcast();

        uint256 balanceOf = IERC20(TOKEN).balanceOf(owner);
        console.log("balanceOf", balanceOf);
    }
}
