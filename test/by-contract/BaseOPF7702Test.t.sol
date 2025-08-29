// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {console2 as console} from "lib/forge-std/src/Test.sol";
import {BaseContract} from "test/by-contract/BaseContract.t.sol";

import "src/interfaces/IERC7821.sol";
import "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import "lib/openzeppelin-contracts/contracts/utils/introspection/ERC165.sol";
import "lib/openzeppelin-contracts/contracts/interfaces/IERC777Recipient.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC721/utils/ERC721Holder.sol";
import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract BaseOPF7702Test is BaseContract {
    bytes4[] supportsInterfaces;

    function test_setEntryPointWithRootKey() public {
        console.log(
            "/* --------------------------------- test_setEntryPointWithRootKey -------- */"
        );

        address newEP = makeAddr("newEP");
        address previousEP = address(account.entryPoint());

        _etch();

        vm.expectEmit(true, true, false, false);
        emit EntryPointUpdated(previousEP, newEP);

        vm.prank(owner);
        account.setEntryPoint(newEP);

        assertEq(newEP, address(account.entryPoint()));

        console.log(
            "/* --------------------------------- test_setEntryPointWithRootKey -------- */"
        );
    }

    function test_setEntryPointFromEntryPoint() public {
        console.log(
            "/* --------------------------------- test_setEntryPointWithRootKey -------- */"
        );

        address newEP = makeAddr("newEP");
        address previousEP = address(account.entryPoint());

        _etch();

        vm.expectEmit(true, true, false, false);
        emit EntryPointUpdated(previousEP, newEP);

        vm.prank(ENTRYPOINT_V8);
        account.setEntryPoint(newEP);

        assertEq(newEP, address(account.entryPoint()));

        console.log(
            "/* --------------------------------- test_setEntryPointWithRootKey -------- */"
        );
    }

    function test_setEntryPointRevert() public {
        console.log("/* --------------------------------- test_setEntryPointRevert -------- */");

        address newEP = makeAddr("newEP");

        _etch();

        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);

        vm.prank(sender);
        account.setEntryPoint(newEP);

        console.log("/* --------------------------------- test_setEntryPointRevert -------- */");
    }

    function test_setWebAuthnVerifierWithRootKey() public {
        console.log(
            "/* --------------------------------- test_setEntryPointWithRootKey -------- */"
        );

        address newVerif = makeAddr("newVerif");
        address previousVerif = address(account.webAuthnVerifier());

        _etch();

        vm.expectEmit(true, true, false, false);
        emit WebAuthnVerifierUpdated(previousVerif, newVerif);

        vm.prank(owner);
        account.setWebAuthnVerifier(newVerif);

        assertEq(newVerif, address(account.webAuthnVerifier()));

        console.log(
            "/* --------------------------------- test_setEntryPointWithRootKey -------- */"
        );
    }

    function test_setWebAuthnVerifierFromEntryPoint() public {
        console.log(
            "/* --------------------------------- test_setEntryPointWithRootKey -------- */"
        );

        address newVerif = makeAddr("newVerif");
        address previousVerif = address(account.webAuthnVerifier());

        _etch();

        vm.expectEmit(true, true, false, false);
        emit WebAuthnVerifierUpdated(previousVerif, newVerif);

        vm.prank(ENTRYPOINT_V8);
        account.setWebAuthnVerifier(newVerif);

        assertEq(newVerif, address(account.webAuthnVerifier()));

        console.log(
            "/* --------------------------------- test_setEntryPointWithRootKey -------- */"
        );
    }

    function test_setWebAuthnVerifierRevert() public {
        console.log("/* --------------------------------- test_setEntryPointRevert -------- */");

        address newVerif = makeAddr("newVerif");

        _etch();

        vm.expectRevert(OpenfortBaseAccount7702V1_UnauthorizedCaller.selector);

        vm.prank(sender);
        account.setWebAuthnVerifier(newVerif);

        console.log("/* --------------------------------- test_setEntryPointRevert -------- */");
    }

    function test_immutableVariables() public view {
        console.log("/* --------------------------------- test_immutableVariables -------- */");

        address ep = address(account.entryPoint());
        address webAuthn = account.webAuthnVerifier();
        address gasPolicy = account.GAS_POLICY();

        assertTrue(ep != address(0), "EntryPoint should be set");
        assertTrue(webAuthn != address(0), "WebAuthn verifier should be set");
        assertTrue(gasPolicy != address(0), "GasPolicy verifier should be set");

        console.log("/* --------------------------------- test_immutableVariables -------- */");
    }

    function test_zeroAddressInputs() public {
        console.log("/* --------------------------------- test_zeroAddressInputs -------- */");

        _etch();

        vm.expectRevert(UpgradeAddress__AddressCantBeZero.selector);
        vm.prank(owner);
        account.setEntryPoint(address(0));

        vm.expectRevert(UpgradeAddress__AddressCantBeZero.selector);
        vm.prank(owner);
        account.setWebAuthnVerifier(address(0));

        console.log("/* --------------------------------- test_zeroAddressInputs -------- */");
    }

    function test_largeValueETHDeposits() public {
        console.log("/* --------------------------------- test_largeValueETHDeposits -------- */");

        _etch();

        uint256 largeAmount = 1000 ether;

        deal(sender, largeAmount);

        vm.expectEmit(true, false, false, true);
        emit DepositAdded(sender, largeAmount);

        vm.prank(sender);
        (bool success,) = address(account).call{value: largeAmount}("");
        assertTrue(success, "Large ETH transfer should succeed");

        console.log("/* --------------------------------- test_largeValueETHDeposits -------- */");
    }

    function test_fallback_with_various_data() public {
        console.log(
            "/* --------------------------------- test_fallback_with_various_data -------- */"
        );

        _etch();

        bytes[] memory testData = new bytes[](4);
        testData[0] = "";
        testData[1] = abi.encodePacked("short");
        testData[2] = abi.encodePacked("medium length data for testing");
        testData[3] = abi.encodePacked(
            "very long data to test fallback function with large payload",
            "this should exercise different branches in the fallback function",
            "and ensure all code paths are covered properly"
        );

        for (uint256 i = 0; i < testData.length; i++) {
            vm.prank(sender);
            (bool success,) = address(account).call{value: 0.1 ether}(testData[i]);
            assertTrue(success, "Fallback call should succeed");
        }

        console.log(
            "/* --------------------------------- test_fallback_with_various_data -------- */"
        );
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

    function test_onERC721Received() public {
        console.log("/* --------------------------------- test_onERC721Received -------- */");

        _etch();

        uint256 tokenId = mockERC721.mint(sender);

        vm.prank(sender);
        mockERC721.safeTransferFrom(sender, address(account), tokenId);

        assertEq(mockERC721.ownerOf(tokenId), address(account), "Account should own the NFT");

        console.log("/* --------------------------------- test_onERC721Received -------- */");
    }

    function test_onERC1155Received() public {
        console.log("/* --------------------------------- test_onERC1155Received -------- */");

        _etch();

        uint256 tokenId = 1;
        uint256 amount = 100;

        mockERC1155.mint(sender, tokenId, amount, "");

        vm.prank(sender);
        mockERC1155.safeTransferFrom(sender, address(account), tokenId, amount, "");

        assertEq(
            mockERC1155.balanceOf(address(account), tokenId),
            amount,
            "Account should have the tokens"
        );

        console.log("/* --------------------------------- test_onERC1155Received -------- */");
    }

    function test_onERC1155BatchReceived() public {
        console.log("/* --------------------------------- test_onERC1155BatchReceived -------- */");

        _etch();

        uint256[] memory tokenIds = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);

        tokenIds[0] = 1;
        tokenIds[1] = 2;
        amounts[0] = 100;
        amounts[1] = 200;

        mockERC1155.mintBatch(sender, tokenIds, amounts, "");

        vm.prank(sender);
        mockERC1155.safeBatchTransferFrom(sender, address(account), tokenIds, amounts, "");

        assertEq(
            mockERC1155.balanceOf(address(account), tokenIds[0]),
            amounts[0],
            "Account should have token 1"
        );
        assertEq(
            mockERC1155.balanceOf(address(account), tokenIds[1]),
            amounts[1],
            "Account should have token 2"
        );

        console.log("/* --------------------------------- test_onERC1155BatchReceived -------- */");
    }

    function test_validateUserOp() public {
        PackedUserOperation memory userOp = _getUserOpFresh();
        bytes32 userOpHash = bytes32(0);
        uint256 missingAccountFunds = 0;

        _etch();

        vm.expectRevert(NotFromEntryPoint.selector);
        vm.prank(owner);
        account.validateUserOp(userOp, userOpHash, missingAccountFunds);
    }

    function test_tokensReceived() public {
        _etch();

        account.tokensReceived(makeAddr("operator"), makeAddr("from"), makeAddr("to"), 1000, "", "");
    }
}
