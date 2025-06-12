// // SPDX-License-Identifier: MIT

// pragma solidity ^0.8.29;

// import {Test, console2 as console} from "lib/forge-std/src/Test.sol";

// contract OPFOld {
//     error MustBeGuardian();
//     error AccountLocked();
//     error DuplicatedRevoke();
//     error DuplicatedGuardian();
//     error ZeroAddressNotAllowed();
//     error DuplicatedProposal();
//     error UnknownProposal();
//     error PendingProposalNotOver();
//     error PendingProposalExpired();
//     error OngoingRecovery();
//     error NoOngoingRecovery();
//     error UnknownRevoke();
//     error PendingRevokeNotOver();
//     error PendingRevokeExpired();

//     uint256 internal recoveryPeriod;
//     uint256 internal lockPeriod;
//     uint256 internal securityPeriod;
//     uint256 internal securityWindow;

//     struct GuardianInfo {
//         bool exists;
//         uint256 index;
//         uint256 pending;
//     }

//     struct GuardiansConfig {
//         address[] guardians;
//         mapping(address => GuardianInfo) info;
//         uint256 lock;
//     }

//     struct RecoveryConfig {
//         address recoveryAddress;
//         uint64 executeAfter;
//         uint32 guardiansRequired;
//     }

//     GuardiansConfig internal guardiansConfig;
//     RecoveryConfig public recoveryDetails;

//     constructor(
//         uint256 _recoveryPeriod,
//         uint256 _lockPeriod,
//         uint256 _securityPeriod,
//         uint256 _securityWindow
//     ) {
//         recoveryPeriod = _recoveryPeriod;
//         lockPeriod = _lockPeriod;
//         securityWindow = _securityWindow;
//         securityPeriod = _securityPeriod;
//     }

//     function proposeGuardian(address _guardian) external {
//         if (isLocked()) revert AccountLocked();
//         if (isGuardian(_guardian)) revert DuplicatedGuardian();
//         if (_guardian == address(0)) revert ZeroAddressNotAllowed();

//         if (
//             guardiansConfig.info[_guardian].pending != 0
//                 && block.timestamp <= guardiansConfig.info[_guardian].pending + securityWindow
//         ) {
//             revert DuplicatedProposal();
//         }
//         guardiansConfig.info[_guardian].pending = block.timestamp + securityPeriod;
//     }

//     function confirmGuardianProposal(address _guardian) external {
//         _requireRecovery(false);
//         if (isLocked()) revert AccountLocked();
//         if (guardiansConfig.info[_guardian].pending == 0) revert UnknownProposal();
//         if (guardiansConfig.info[_guardian].pending > block.timestamp) {
//             revert PendingProposalNotOver();
//         }
//         if (block.timestamp > guardiansConfig.info[_guardian].pending + securityWindow) {
//             revert PendingProposalExpired();
//         }
//         if (isGuardian(_guardian)) revert DuplicatedGuardian();

//         guardiansConfig.guardians.push(_guardian);
//         guardiansConfig.info[_guardian].exists = true;
//         guardiansConfig.info[_guardian].index = guardiansConfig.guardians.length - 1;
//         guardiansConfig.info[_guardian].pending = 0;
//     }

//     function revokeGuardian(address _guardian) external {
//         if (!isGuardian(_guardian)) revert MustBeGuardian();
//         if (isLocked()) revert AccountLocked();
//         if (
//             guardiansConfig.info[_guardian].pending > 0
//                 && block.timestamp <= guardiansConfig.info[_guardian].pending + securityWindow
//         ) revert DuplicatedRevoke();

//         guardiansConfig.info[_guardian].pending = block.timestamp + securityPeriod;
//     }

//     function confirmGuardianRevocation(address _guardian) external {
//         if (guardiansConfig.info[_guardian].pending == 0) revert UnknownRevoke();
//         if (isLocked()) revert AccountLocked();
//         if (!isGuardian(_guardian)) revert MustBeGuardian();
//         if (guardiansConfig.info[_guardian].pending > block.timestamp) {
//             revert PendingRevokeNotOver();
//         }
//         if (block.timestamp > guardiansConfig.info[_guardian].pending + securityWindow) {
//             revert PendingRevokeExpired();
//         }

//         address lastGuardian = guardiansConfig.guardians[guardiansConfig.guardians.length - 1];
//         if (_guardian != lastGuardian) {
//             uint256 targetIndex = guardiansConfig.info[_guardian].index;
//             guardiansConfig.guardians[targetIndex] = lastGuardian;
//             guardiansConfig.info[lastGuardian].index = targetIndex;
//         }

//         guardiansConfig.guardians.pop(); // ALERT! beta: review this logic!
//         delete guardiansConfig.info[_guardian];
//     }

//     function cancelGuardianRevocation(address _guardian) external {
//         if (isLocked()) revert AccountLocked();
//         if (!isGuardian(_guardian)) revert UnknownRevoke();
//         if (guardiansConfig.info[_guardian].pending == 0) revert UnknownRevoke();
//         guardiansConfig.info[_guardian].pending = 0;
//     }

//     function isGuardian(address _guardian) public view returns (bool) {
//         return guardiansConfig.info[_guardian].exists;
//     }

//     function isLocked() public view returns (bool) {
//         return guardiansConfig.lock > block.timestamp;
//     }

//     function _requireRecovery(bool _isRecovery) internal view {
//         if (_isRecovery && recoveryDetails.executeAfter == 0) {
//             revert NoOngoingRecovery();
//         }
//         if (!_isRecovery && recoveryDetails.executeAfter > 0) {
//             revert OngoingRecovery();
//         }
//     }
// }

// contract TestBug is Test {
//     OPFOld opf;
//     address public EXECUTORE;

//     uint256 constant RECOVERY_PERIOD = 2 days;
//     uint256 constant LOCK_PERIOD = 5 days;
//     uint256 constant SECURITY_PERIOD = 1.5 days;
//     uint256 constant SECURITY_WINDOW = 0.5 days;

//     address[] guardians;
//     uint256 counter = 6;

//     function setUp() public {
//         opf = new OPFOld(RECOVERY_PERIOD, LOCK_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW);
//         EXECUTORE = makeAddr("EXECUTORE");
//         _proposeGuardian();
//         _confirmGuardianProposal();
//     }

//     function test_DOS() public {
//         uint256 time = block.timestamp;
//         console.log("time", time); // Thu Jun 05 2025 23:36:01 GMT+0000
//         address guardian = guardians[1];

//         vm.prank(EXECUTORE);
//         opf.revokeGuardian(guardian);

//         vm.warp(time + SECURITY_WINDOW + 15 days); // Sat Jun 21 2025 11:36:49 GMT+0000

//         vm.expectRevert(OPFOld.DuplicatedRevoke.selector);
//         vm.prank(EXECUTORE);
//         opf.revokeGuardian(guardian);

//         // vm.prank(EXECUTORE);
//         // opf.cancelGuardianRevocation(guardian);
//     }

//     function _proposeGuardian() internal {
//         guardians = new address[](counter);

//         for (uint256 i = 0; i < counter; i++) {
//             guardians[i] = makeAddr(string(abi.encodePacked("guardian", i)));
//         }

//         for (uint256 i = 0; i < counter; i++) {
//             vm.prank(EXECUTORE);
//             opf.proposeGuardian(guardians[i]);
//         }
//     }

//     function _confirmGuardianProposal() internal {
//         vm.warp(block.timestamp + SECURITY_PERIOD + 1);
//         for (uint256 i = 0; i < counter; i++) {
//             vm.prank(EXECUTORE);
//             opf.confirmGuardianProposal(guardians[i]);

//             bool isExist = opf.isGuardian(guardians[i]);
//             assertTrue(isExist);
//         }
//     }
// }
