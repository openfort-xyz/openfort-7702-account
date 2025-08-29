// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ERC721} from "lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";

/**
 * @title ERC721Mock
 * @dev Simple ERC721 mock for testing token receiver functionality
 */
contract ERC721Mock is ERC721 {
    uint256 private _currentTokenId = 0;

    constructor(string memory name, string memory symbol) ERC721(name, symbol) {}

    /**
     * @dev Mint a new token to the specified address
     */
    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }

    /**
     * @dev Mint a new token with auto-incrementing ID
     */
    function mint(address to) external returns (uint256) {
        uint256 tokenId = _currentTokenId++;
        _mint(to, tokenId);
        return tokenId;
    }

    /**
     * @dev Batch mint multiple tokens
     */
    function batchMint(address to, uint256 amount) external {
        for (uint256 i = 0; i < amount; i++) {
            _mint(to, _currentTokenId++);
        }
    }
}
