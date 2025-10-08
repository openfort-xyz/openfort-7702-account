// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {IKey} from "src/interfaces/IKey.sol";
import {Initializable} from "src/libs/Initializable.sol";
import {IKeysManager} from "src/interfaces/IKeysManager.sol";
import {Test, console2 as console} from "lib/forge-std/src/test.sol";
import {EnumerableSetLib} from "lib/solady/src/utils/EnumerableSetLib.sol";
import {EnumerableMapLib} from "lib/solady/src/utils/EnumerableMapLib.sol";
import {ReentrancyGuard} from "lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

contract ClearStorage is Test {
    OPF internal opf;

    bytes32 private constant _EP_SLOT =
        0x4e696bb2fc09e5383cb7d4063d5fb8f6e0701a72d9523e5f996ae73b7c89e800;
    bytes32 private constant _VERIFIER_SLOT =
        0xfd39baddba6b1a9197cb18b09396db32f340e9b468af2bcc8f997735c03db200;
    bytes32 private constant _GAS_POLICY_SLOT =
        0xda9fe820be906bb4b68c951302595f7e1131563db95582cda480475cc85e6800;

    bytes32 private constant _BASE_SENTINEL = bytes32(uint256(0xA1));
    bytes32 private constant _EP_SENTINEL = bytes32(uint256(0xA2));
    bytes32 private constant _VERIFIER_SENTINEL = bytes32(uint256(0xA3));
    bytes32 private constant _GAS_POLICY_SENTINEL = bytes32(uint256(0xA4));
    bytes32 private constant _REENTRANCY_SENTINEL = bytes32(uint256(0xA5));

    function setUp() public {
        opf = new OPF();
    }

    function testClearStorageResetsReservedSlots() public {
        opf.populateReservedSlots(
            _BASE_SENTINEL,
            _EP_SENTINEL,
            _VERIFIER_SENTINEL,
            _GAS_POLICY_SENTINEL,
            _REENTRANCY_SENTINEL
        );

        bytes32 baseSlot = bytes32(_baseSlot());
        bytes32 reentrancySlot = bytes32(_baseSlot() + 5);

        assertEq(vm.load(address(opf), baseSlot), _BASE_SENTINEL);
        assertEq(vm.load(address(opf), reentrancySlot), _REENTRANCY_SENTINEL);
        assertEq(vm.load(address(opf), _EP_SLOT), _EP_SENTINEL);
        assertEq(vm.load(address(opf), _VERIFIER_SLOT), _VERIFIER_SENTINEL);
        assertEq(vm.load(address(opf), _GAS_POLICY_SLOT), _GAS_POLICY_SENTINEL);

        opf._clearStorage();

        assertEq(vm.load(address(opf), baseSlot), bytes32(0));
        assertEq(vm.load(address(opf), reentrancySlot), bytes32(0));
        assertEq(vm.load(address(opf), _EP_SLOT), bytes32(0));
        assertEq(vm.load(address(opf), _VERIFIER_SLOT), bytes32(0));
        assertEq(vm.load(address(opf), _GAS_POLICY_SLOT), bytes32(0));
    }

    function _baseSlot() internal pure returns (uint256) {
        return (
            uint256(keccak256(abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)))
        ) & ~uint256(0xff);
    }
}

contract Storag {
    //  _EP_SLOT = (keccak256("openfort.entrypoint.storage") - 1) & ~0xff
    bytes32 internal constant _EP_SLOT =
        0x4e696bb2fc09e5383cb7d4063d5fb8f6e0701a72d9523e5f996ae73b7c89e800;

    //  _VERIFIER_SLOT = (keccak256("openfort.webauthnverifier.storage") - 1) & ~0xff
    bytes32 internal constant _VERIFIER_SLOT =
        0xfd39baddba6b1a9197cb18b09396db32f340e9b468af2bcc8f997735c03db200;

    //  _VERIFIER_SLOT = (keccak256("openfort.gaspolicy.storage") - 1) & ~0xff
    bytes32 internal constant _GAS_POLICY_SLOT =
        0xda9fe820be906bb4b68c951302595f7e1131563db95582cda480475cc85e6800;

    uint256 public id;
    mapping(uint256 => bytes32) public idKeys;
    mapping(bytes32 => IKey.KeyData) internal keys;

    mapping(bytes32 => IKeysManager.ExecutePermissions) internal permissions;

    mapping(bytes32 => IKeysManager.SpendStorage) internal spendStore;

    function _clearStorage() external {
        bytes32 baseSlot = keccak256(
            abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)
        ) & ~bytes32(uint256(0xff));

        // clear slot 0, _EP_SLOT & _VERIFIER_SLOT & _GAS_SLOT
        bytes32 epSlot = _EP_SLOT;
        bytes32 verifierSlot = _VERIFIER_SLOT;
        bytes32 gasPolicySlot = _GAS_POLICY_SLOT;
        assembly {
            sstore(baseSlot, 0)
            sstore(epSlot, 0)
            sstore(verifierSlot, 0)
            sstore(gasPolicySlot, 0)
        }

        // Clear ReentrancyGuard status (S+5) to a safe state (0 is fine; first guarded call will set + normalize to 1)
        assembly {
            sstore(add(baseSlot, 5), 0)
        }
    }
}

contract OPF is Storag, ReentrancyGuard, Initializable layout at 107588995614188179791452663824698570634674667931787294340862201729294267929600 {
    function populateReservedSlots(
        bytes32 baseValue,
        bytes32 entryPointValue,
        bytes32 verifierValue,
        bytes32 gasPolicyValue,
        bytes32 reentrancyValue
    ) external {
        uint256 baseSlot = (
            uint256(keccak256(abi.encode(uint256(keccak256("openfort.baseAccount.7702.v1")) - 1)))
        ) & ~uint256(0xff);

        bytes32 epSlot = _EP_SLOT;
        bytes32 verifierSlot = _VERIFIER_SLOT;
        bytes32 gasPolicySlot = _GAS_POLICY_SLOT;

        assembly {
            sstore(baseSlot, baseValue)
            sstore(add(baseSlot, 5), reentrancyValue)
            sstore(epSlot, entryPointValue)
            sstore(verifierSlot, verifierValue)
            sstore(gasPolicySlot, gasPolicyValue)
        }
    }
}
