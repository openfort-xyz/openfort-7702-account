// SPDX-License-identifier: MIT

pragma solidity 0.8.29;

import {Test, console2 as console} from "lib/forge-std/src/Test.sol";

contract StorageClearing is Test {
    uint256 constant _NUM_CLEAR_SLOTS = 16;

    bytes32 constant TEST_VALUE_1 = keccak256("test_data_1");
    bytes32 constant TEST_VALUE_2 = keccak256("test_data_2");
    bytes32 constant TEST_VALUE_3 = keccak256("test_data_3");

    function _getBaseSlot() internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1))
            & ~bytes32(uint256(0xff));
    }

    function _initializeStorageSlots() internal {
        bytes32 baseSlot = _getBaseSlot();

        console.log("Initializing storage slots with test data...");

        for (uint256 i = 0; i < _NUM_CLEAR_SLOTS;) {
            bytes32 slot = bytes32(uint256(baseSlot) + i);
            bytes32 testValue;

            if (i % 3 == 0) {
                testValue = TEST_VALUE_1;
            } else if (i % 3 == 1) {
                testValue = TEST_VALUE_2;
            } else {
                testValue = TEST_VALUE_3;
            }

            assembly {
                sstore(slot, testValue)
            }

            console.log("Initialized slot", uint256(baseSlot) + i, "with value:");
            console.logBytes32(testValue);

            unchecked {
                i++;
            }
        }

        console.log("Storage initialization complete.");
    }

    function _verifyStorageExists() internal view returns (bool) {
        bytes32 baseSlot = _getBaseSlot();
        bool hasData = false;

        console.log("Verifying storage slots contain data...");

        for (uint256 i = 0; i < _NUM_CLEAR_SLOTS;) {
            bytes32 slot = bytes32(uint256(baseSlot) + i);
            bytes32 value;

            assembly {
                value := sload(slot)
            }

            if (value != bytes32(0)) {
                hasData = true;
                console.log("Slot", uint256(baseSlot) + i, "contains data:");
                console.logBytes32(value);
            } else {
                console.log("Slot", uint256(baseSlot) + i, "is empty:");
                console.logBytes32(value);
            }

            unchecked {
                i++;
            }
        }

        return hasData;
    }

    function _verifyStorageCleared() internal view returns (bool) {
        bytes32 baseSlot = _getBaseSlot();
        bool allCleared = true;

        console.log("Verifying storage slots are cleared...");

        for (uint256 i = 0; i < _NUM_CLEAR_SLOTS;) {
            bytes32 slot = bytes32(uint256(baseSlot) + i);
            bytes32 value;

            assembly {
                value := sload(slot)
            }

            if (value != bytes32(0)) {
                allCleared = false;
                console.log("ERROR: Slot", uint256(baseSlot) + i, "still contains data:");
                console.logBytes32(value);
            } else {
                console.log("Slot", uint256(baseSlot) + i, "successfully cleared:");
                console.logBytes32(value);
            }

            unchecked {
                i++;
            }
        }

        return allCleared;
    }

    function _clearStorage() internal {
        bytes32 baseSlot = _getBaseSlot();

        console.log("Clearing storage slots...");

        for (uint256 i = 0; i < _NUM_CLEAR_SLOTS;) {
            bytes32 slot = bytes32(uint256(baseSlot) + i);
            uint256 slotN = uint256(baseSlot) + i;

            console.log("Clearing slotN", slotN);

            assembly {
                sstore(slot, 0)
            }

            unchecked {
                i++;
            }
        }

        console.log("Storage clearing complete.");
    }

    function test_clearStorage() public {
        console.log("=== Storage Clearing Test ===");

        _initializeStorageSlots();

        bool hasDataBefore = _verifyStorageExists();
        assertTrue(hasDataBefore, "Storage slots should contain data before clearing");
        console.log("Confirmed: Storage slots contain data");

        _clearStorage();

        bool allClearedAfter = _verifyStorageCleared();
        assertTrue(allClearedAfter, "All storage slots should be cleared after clearing");
        console.log("Confirmed: All storage slots cleared successfully");

        console.log("=== Test Complete ===");
    }

    function test_clearStorageIdempotent() public {
        console.log("=== Idempotent Clearing Test ===");

        _initializeStorageSlots();
        _clearStorage();

        _clearStorage();

        bool allCleared = _verifyStorageCleared();
        assertTrue(allCleared, "Storage should remain cleared after multiple clear operations");

        console.log("Confirmed: Multiple clear operations are safe");
    }
}

/**
 * Storage Layout Reference:
 * ╭----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------╮
 * | Name                       | Type                                     | Slot                                                                           | Offset | Bytes | Contract                     |
 * +========================================================================================================================================================================================================+
 * | id                         | uint256                                  | 107588995614188179791452663824698570634674667931787294340862201729294267929600 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
 * |----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
 * | idKeys                     | mapping(uint256 => struct IKey.Key)      | 107588995614188179791452663824698570634674667931787294340862201729294267929601 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
 * |----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
 * | keys                       | mapping(bytes32 => struct IKey.KeyData)  | 107588995614188179791452663824698570634674667931787294340862201729294267929602 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
 * |----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
 * | usedChallenges             | mapping(bytes32 => bool)                 | 107588995614188179791452663824698570634674667931787294340862201729294267929603 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
 * |----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
 * | _status                    | uint256                                  | 107588995614188179791452663824698570634674667931787294340862201729294267929604 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
 * |----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
 * | _OPENFORT_CONTRACT_ADDRESS | address                                  | 107588995614188179791452663824698570634674667931787294340862201729294267929605 | 0      | 20    | src/core/OPFMain.sol:OPFMain |
 * |----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
 * | _nameFallback              | string                                   | 107588995614188179791452663824698570634674667931787294340862201729294267929606 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
 * |----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
 * | _versionFallback           | string                                   | 107588995614188179791452663824698570634674667931787294340862201729294267929607 | 0      | 32    | src/core/OPFMain.sol:OPFMain |
 * |----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
 * | guardiansData              | struct IOPF7702Recoverable.GuardiansData | 107588995614188179791452663824698570634674667931787294340862201729294267929608 | 0      | 96    | src/core/OPFMain.sol:OPFMain |
 * |----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------|
 * | recoveryData               | struct IOPF7702Recoverable.RecoveryData  | 107588995614188179791452663824698570634674667931787294340862201729294267929611 | 0      | 128   | src/core/OPFMain.sol:OPFMain |
 * ╰----------------------------+------------------------------------------+--------------------------------------------------------------------------------+--------+-------+------------------------------╯
 *
 * Slot Numbers for Reference:
 * 107588995614188179791452663824698570634674667931787294340862201729294267929600-107588995614188179791452663824698570634674667931787294340862201729294267929615
 */
