// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Test, console2} from "lib/forge-std/src/test.sol";

contract ConvertToBytesTest is Test {
    function testFuzz_ConvertToBytes(bytes32 data) public pure {
        bytes memory result = toBytes(data);

        assertEq(result.length, 32, "Length should be 32 bytes");

        bytes32 reconstructed;
        assembly {
            reconstructed := mload(add(result, 32))
        }
        assertEq(reconstructed, data, "Reconstructed data should match input");
    }

    function test_ConvertToBytes_EdgeCases() public pure {
        bytes32 zero;
        bytes memory zeroResult = toBytes(zero);
        assertEq(zeroResult.length, 32, "Zero bytes length should be 32");
        assertEq(bytes32(zeroResult), zero, "Zero bytes should match");

        bytes32 allOnes = bytes32(type(uint256).max);
        bytes memory allOnesResult = toBytes(allOnes);
        assertEq(allOnesResult.length, 32, "All ones length should be 32");
        assertEq(bytes32(allOnesResult), allOnes, "All ones should match");

        bytes32 alternating =
            bytes32(0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA);
        bytes memory alternatingResult = toBytes(alternating);
        assertEq(alternatingResult.length, 32, "Alternating bits length should be 32");
        assertEq(bytes32(alternatingResult), alternating, "Alternating bits should match");
    }

    function testFuzz_ConvertToBytesAndBack(bytes32 data) public pure {
        bytes memory converted = toBytes(data);
        bytes32 reconstructed = bytes32(converted);
        assertEq(reconstructed, data, "Data should be preserved after conversion and back");
    }

    function testFuzz_ConvertToBytes_MemorySafety(bytes32 data) public pure {
        bytes memory result = toBytes(data);

        assertEq(result.length, 32, "Result length should be 32");

        for (uint256 i = 0; i < 32; i++) {
            assertEq(
                result[i],
                bytes1(uint8(uint256(data) >> (248 - i * 8))),
                "Byte at position i should match input"
            );
        }
    }

    function testFuzz_ConvertToBytes_GasUsage(bytes32 data) public view {
        uint256 gasStart = gasleft();
        bytes memory result = toBytes(data);
        uint256 gasUsed = gasStart - gasleft();

        assertEq(result.length, 32, "Length should be 32 bytes");
        assertEq(bytes32(result), data, "Data should match after conversion");

        console2.log("Gas used for conversion:", gasUsed);

        assertTrue(gasUsed < 100000, "Gas usage should be reasonable");
    }

    function testFuzz_ConvertToBytes_Multiple(bytes32[5] memory dataArray) public pure {
        for (uint256 i = 0; i < 5; i++) {
            bytes memory result = toBytes(dataArray[i]);
            assertEq(result.length, 32, "Length should be 32 bytes");
            assertEq(bytes32(result), dataArray[i], "Data should match after conversion");
        }
    }

    function toBytes(bytes32 data) internal pure returns (bytes memory result) {
        result = new bytes(32);
        assembly {
            mstore(add(result, 32), data)
        }
    }

    function toBytesAlternative(bytes32 data) internal pure returns (bytes memory) {
        return abi.encodePacked(data);
    }

    function testFuzz_CompareImplementations(bytes32 data) public pure {
        bytes memory result1 = toBytes(data);
        bytes memory result2 = toBytesAlternative(data);

        assertEq(result1.length, result2.length, "Lengths should match");
        assertEq(keccak256(result1), keccak256(result2), "Results should be identical");
    }
}
