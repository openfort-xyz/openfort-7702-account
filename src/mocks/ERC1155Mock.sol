// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ERC1155} from "lib/openzeppelin-contracts/contracts/token/ERC1155/ERC1155.sol";

/**
 * @title ERC1155Mock
 * @dev Simple ERC1155 mock for testing token receiver functionality
 */
contract ERC1155Mock is ERC1155 {
    constructor(string memory uri) ERC1155(uri) {}

    /**
     * @dev Mint tokens to the specified address
     */
    function mint(address to, uint256 id, uint256 amount, bytes memory data) external {
        _mint(to, id, amount, data);
    }

    /**
     * @dev Batch mint multiple token types
     */
    function mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) external {
        _mintBatch(to, ids, amounts, data);
    }

    /**
     * @dev Set token URI (optional)
     */
    function setURI(string memory newUri) external {
        _setURI(newUri);
    }
}
