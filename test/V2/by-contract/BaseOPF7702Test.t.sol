// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";

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
}