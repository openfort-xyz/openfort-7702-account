/// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Test, console2 as console} from "forge-std/Test.sol";

import {TokenCallbackHandler} from "contracts/core/TokenCallbackHandler.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/interfaces/IERC777Recipient.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

contract TokenCallbackHandlerTest is Test {
    TokenCallbackHandler public tokenCallbackHandler;

    function setUp() public {
        tokenCallbackHandler = new TokenCallbackHandler();
    }

    function testonERC721Received() public view {
        bytes4 result = tokenCallbackHandler.onERC721Received(address(0), address(0), 0, "");
        console.logBytes4(bytes4(result));
        assertEq(result, TokenCallbackHandler.onERC721Received.selector);
    }

    function testonERC1155Received() public view {
        bytes4 result = tokenCallbackHandler.onERC1155Received(address(0), address(0), 0, 0, "");
        console.logBytes4(bytes4(result));
        assertEq(result, TokenCallbackHandler.onERC1155Received.selector);
    }

    function testonERC1155BatchReceived() public view {
        bytes4 result = tokenCallbackHandler.onERC1155BatchReceived(address(0), address(0), new uint256[](0), new uint256[](0), "");
        console.logBytes4(bytes4(result));
        assertEq(result, TokenCallbackHandler.onERC1155BatchReceived.selector);
    }

    function testsupportsInterface() public view {
        bool resultIERC165 = tokenCallbackHandler.supportsInterface(type(IERC165).interfaceId);
        bool resultIERC721Receiver = tokenCallbackHandler.supportsInterface(type(IERC721Receiver).interfaceId);
        bool resultIERC777Recipient = tokenCallbackHandler.supportsInterface(type(IERC777Recipient).interfaceId);
        bool resultIERC1155Receiver = tokenCallbackHandler.supportsInterface(type(IERC1155Receiver).interfaceId);
        assertEq(resultIERC165, true);
        assertEq(resultIERC721Receiver, true);
        assertEq(resultIERC777Recipient, true);
        assertEq(resultIERC1155Receiver, true);
    }
    
}