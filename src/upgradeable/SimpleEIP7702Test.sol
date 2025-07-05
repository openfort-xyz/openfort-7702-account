// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibEIP7702} from "solady/accounts/LibEIP7702.sol";
import {Initializable} from "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";

/**
 * @title   Simple EIP7702 Test Implementation
 * @notice  Minimal implementation to test storage and upgrades with latest Solady
 */
contract SimpleEIP7702Test is Initializable {
    // ──────────────────────────────────────────────────────────────────────────────
    //                               Storage vars
    // ──────────────────────────────────────────────────────────────────────────────
    uint256 public counter;
    string public message;
    address public owner;

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Events
    // ──────────────────────────────────────────────────────────────────────────────
    event Initialized(address owner, string message);
    event CounterIncremented(uint256 newValue);
    event MessageUpdated(string newMessage);

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Modifiers
    // ──────────────────────────────────────────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner || msg.sender == address(this), "Not owner");
        _;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Constructor
    // ──────────────────────────────────────────────────────────────────────────────
    constructor() {
        // Prevent implementation from being initialized
        _disableInitializers();
    }

    /// @notice Fallback function to receive ETH without data.
    fallback() external payable {}

    /// @notice Receive function to handle plain ETH transfers.
    receive() external payable {}

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Initialization
    // ──────────────────────────────────────────────────────────────────────────────

    function initialize(address _owner, string memory _message) external initializer {
        owner = _owner;
        message = _message;
        counter = 1; // Start with 1 to confirm initialization worked

        emit Initialized(_owner, _message);

        // Request proxy delegation initialization
        LibEIP7702.requestProxyDelegationInitialization();
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Core Functions
    // ──────────────────────────────────────────────────────────────────────────────

    function incrementCounter() external {
        counter++;
        emit CounterIncremented(counter);
    }

    function setMessage(string memory _message) external onlyOwner {
        message = _message;
        emit MessageUpdated(_message);
    }

    function getInfo() external view returns (uint256, string memory, address) {
        return (counter, message, owner);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Upgrade Functions
    // ──────────────────────────────────────────────────────────────────────────────

    function upgradeProxyDelegation(address newImplementation) external onlyOwner {
        LibEIP7702.upgradeProxyDelegation(newImplementation);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Debug Functions
    // ──────────────────────────────────────────────────────────────────────────────

    /// @notice Get current address for debugging
    function getCurrentAddress() external view returns (address) {
        return address(this);
    }

    /// @notice Get msg.sender for debugging
    function getMsgSender() external view returns (address) {
        return msg.sender;
    }

    /// @notice Get storage at specific slot for debugging
    function getStorageAt(uint256 slot) external view returns (bytes32) {
        bytes32 value;
        assembly {
            value := sload(slot)
        }
        return value;
    }

    /// @notice Get delegation info
    function getDelegationInfo(address account)
        external
        view
        returns (address delegation, address implementation)
    {
        return LibEIP7702.delegationAndImplementationOf(account);
    }

    /// @notice Check if address is EIP7702Proxy
    function isEIP7702Proxy(address target) external view returns (bool) {
        return LibEIP7702.isEIP7702Proxy(target);
    }

    /// @notice Deploy new proxy using latest Solady
    function deployNewProxy(address implementation) external returns (address proxy) {
        proxy = LibEIP7702.deployProxy(implementation, address(0));
    }

    /// @notice Version identifier
    function version() external pure returns (string memory) {
        return "SimpleEIP7702Test-v1.0.0";
    }
}
