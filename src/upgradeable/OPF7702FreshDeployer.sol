// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {OPF7702Test} from "src/upgradeable/OPF7702Test.sol";
import {LibEIP7702} from "lib/solady/src/accounts/LibEIP7702.sol";

contract OPF7702FreshDeployer {
    address public immutable implementation;
    address public immutable proxy;

    // Real addresses from your deployer
    address public constant ENTRY_POINT = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address public constant WEBAUTHN_VERIFIER = 0xeD43b3a3D00d791BC0B353666b5780B0F9245CC1;

    event Deployed(
        address implementation, address proxy, address entryPoint, address webauthnVerifier
    );

    constructor() payable {
        // Deploy YOUR actual OPF7702Test implementation
        implementation = address(new OPF7702Test(ENTRY_POINT, WEBAUTHN_VERIFIER));

        // Deploy EIP7702Proxy using latest Solady with no admin
        proxy = LibEIP7702.deployProxy(implementation, address(0));

        emit Deployed(implementation, proxy, ENTRY_POINT, WEBAUTHN_VERIFIER);
    }

    /// @notice Get the proxy address for EIP-7702 delegation
    function getProxyForDelegation() external view returns (address) {
        return proxy;
    }

    /// @notice Get the implementation address
    function getImplementation() external view returns (address) {
        return implementation;
    }

    /// @notice Test the proxy setup
    function testProxySetup()
        external
        view
        returns (
            address proxyAddr,
            address implAddr,
            bool isValidProxy,
            address proxyImplementation,
            address entryPoint,
            address webauthnVerifier
        )
    {
        proxyAddr = proxy;
        implAddr = implementation;

        // Check if proxy is valid using latest Solady
        isValidProxy = LibEIP7702.isEIP7702Proxy(proxy);

        // Get implementation from proxy
        proxyImplementation = LibEIP7702.implementationOf(proxy);

        // Get constructor parameters
        entryPoint = ENTRY_POINT;
        webauthnVerifier = WEBAUTHN_VERIFIER;
    }

    /// @notice Deploy another proxy for testing
    function deploySecondProxy() external returns (address newProxy) {
        newProxy = LibEIP7702.deployProxy(implementation, address(0));
    }
}
