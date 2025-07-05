// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibEIP7702} from "solady/accounts/LibEIP7702.sol";
import {Initializable} from "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";

/**
 * @title   Simple EIP7702 Test V2 (Upgrade Test)
 * @notice  Enhanced version with new features to test upgrades
 */
contract SimpleEIP7702TestV2 is Initializable {
    // ──────────────────────────────────────────────────────────────────────────────
    //                               Storage vars (same layout as V1)
    // ──────────────────────────────────────────────────────────────────────────────
    uint256 public counter;
    string public message;
    address public owner;

    // ──────────────────────────────────────────────────────────────────────────────
    //                               NEW Storage vars for V2
    // ──────────────────────────────────────────────────────────────────────────────
    uint256 public multiplier; // NEW in V2
    string public newFeature; // NEW in V2

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Events
    // ──────────────────────────────────────────────────────────────────────────────
    event Initialized(address owner, string message);
    event CounterIncremented(uint256 newValue);
    event MessageUpdated(string newMessage);
    event MultiplierSet(uint256 multiplier); // NEW
    event NewFeatureSet(string feature); // NEW
    event UpgradedToV2(); // NEW

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
    //                               Initialization (V1 compatible)
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
    //                               V2 Initialization
    // ──────────────────────────────────────────────────────────────────────────────

    function initializeV2(uint256 _multiplier, string memory _newFeature) external {
        require(owner != address(0), "Must initialize V1 first");
        require(multiplier == 0, "V2 already initialized"); // Simple check

        multiplier = _multiplier;
        newFeature = _newFeature;

        emit UpgradedToV2();
        emit MultiplierSet(_multiplier);
        emit NewFeatureSet(_newFeature);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //                               Core Functions (V1 compatible)
    // ──────────────────────────────────────────────────────────────────────────────

    function incrementCounter() external {
        // V2 enhancement: use multiplier if set
        if (multiplier > 0) {
            counter += multiplier;
        } else {
            counter++;
        }
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
    //                               NEW V2 Functions
    // ──────────────────────────────────────────────────────────────────────────────

    function setMultiplier(uint256 _multiplier) external onlyOwner {
        multiplier = _multiplier;
        emit MultiplierSet(_multiplier);
    }

    function setNewFeature(string memory _feature) external onlyOwner {
        newFeature = _feature;
        emit NewFeatureSet(_feature);
    }

    function getV2Info() external view returns (uint256, string memory) {
        return (multiplier, newFeature);
    }

    function incrementByAmount(uint256 amount) external {
        counter += amount;
        emit CounterIncremented(counter);
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

    /// @notice Version identifier - UPDATED for V2
    function version() external pure returns (string memory) {
        return "SimpleEIP7702Test-v2.0.0";
    }
}
