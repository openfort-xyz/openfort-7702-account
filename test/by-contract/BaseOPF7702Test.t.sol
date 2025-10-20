// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {BaseOPF7702} from "src/core/BaseOPF7702.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

import "src/interfaces/IERC7821.sol";
import "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import "lib/openzeppelin-contracts/contracts/utils/introspection/ERC165.sol";
import "lib/openzeppelin-contracts/contracts/interfaces/IERC777Recipient.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC721/utils/ERC721Holder.sol";
import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC1155/utils/ERC1155Holder.sol";

contract BaseOPF7702Test is Deploy {
    bytes4[] supportsInterfaces;

    function setUp() public virtual override {
        super.setUp();
        _quickInitializeAccount();
        _initializeAccount();
    }

    function test_supportsInterface() public {
        console.log("/* --------------------------------- test_supportsInterface -------- */");

        supportsInterfaces.push(type(IERC165).interfaceId);
        supportsInterfaces.push(type(IAccount).interfaceId);
        supportsInterfaces.push(type(IERC1271).interfaceId);
        supportsInterfaces.push(type(IERC7821).interfaceId);
        supportsInterfaces.push(type(IERC721Receiver).interfaceId);
        supportsInterfaces.push(type(IERC1155Receiver).interfaceId);
        supportsInterfaces.push(type(IERC777Recipient).interfaceId);

        for (uint256 i = 0; i < supportsInterfaces.length;) {
            bool res = account.supportsInterface(supportsInterfaces[i]);
            assertTrue(res);
            unchecked {
                i++;
            }
        }

        console.log("/* --------------------------------- test_supportsInterface -------- */");
    }

    function test_tokensReceived() public {
        _etch();
        account.tokensReceived(makeAddr("operator"), makeAddr("from"), makeAddr("to"), 1000, "", "");
    }

    function test_setEntryPointRevertsWhenSame() public {
        _etch();
        vm.startPrank(address(account));
        vm.expectRevert(BaseOPF7702.BaseOPF7702__NoChangeUpdateContractAddress.selector);
        account.setEntryPoint(address(entryPoint));
        vm.stopPrank();
    }

    function test_setEntryPointUpdatesAddress() public {
        _etch();
        address newEntryPoint = makeAddr("newEntryPoint");
        vm.startPrank(address(account));
        account.setEntryPoint(newEntryPoint);
        vm.stopPrank();
        assertEq(address(account.entryPoint()), newEntryPoint);
    }

    function test_setWebAuthnVerifierRevertsWhenSame() public {
        _etch();
        vm.startPrank(address(account));
        vm.expectRevert(BaseOPF7702.BaseOPF7702__NoChangeUpdateContractAddress.selector);
        account.setWebAuthnVerifier(WEBAUTHN_VERIFIER);
        vm.stopPrank();
    }

    function test_setWebAuthnVerifierUpdatesAddress() public {
        _etch();
        address newVerifier = makeAddr("newVerifier");
        vm.startPrank(address(account));
        account.setWebAuthnVerifier(newVerifier);
        vm.stopPrank();
        assertEq(account.webAuthnVerifier(), newVerifier);
    }

    function test_setGasPolicyRevertsWhenSame() public {
        _etch();
        vm.startPrank(address(account));
        vm.expectRevert(BaseOPF7702.BaseOPF7702__NoChangeUpdateContractAddress.selector);
        account.setGasPolicy(address(gasPolicy));
        vm.stopPrank();
    }

    function test_setGasPolicyUpdatesAddress() public {
        _etch();
        address newPolicy = makeAddr("newPolicy");
        vm.startPrank(address(account));
        account.setGasPolicy(newPolicy);
        vm.stopPrank();
        assertEq(account.gasPolicy(), newPolicy);
    }

    function test_validateUserOpRevertsWhenNotEntryPoint() public {
        _etch();
        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        vm.expectRevert(BaseOPF7702.NotFromEntryPoint.selector);
        account.validateUserOp(userOp, bytes32(0), 0);
    }
}
