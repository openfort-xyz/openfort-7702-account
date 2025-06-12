// /*  █████  OPF7702Recoverable — trimmed to show key changes █████  */

// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.29;

// import {OPF7702} from "src/core/OPF7702.sol";
// import {EIP712} from "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

// contract OPF7702RecoverableD is OPF7702, EIP712 layout at 57943590311362240630886240343495690972153947532773266946162183175043753177960 {
//     /* ───────────────────────────── Errors ───────────────────────────── */
//     error OPF7702Recoverable__AccountLocked();
//     error OPF7702Recoverable__MustBeGuardian();
//     error OPF7702Recoverable__UnknownRevoke();
//     error OPF7702Recoverable__DuplicatedRevoke();
//     error OPF7702Recoverable__PendingRevokeNotOver();
//     error OPF7702Recoverable__PendingRevokeExpired();
//     error OPF7702Recoverable__UnknownProposal();
//     error OPF7702Recoverable__DuplicatedGuardian();

//     /* ───────────────────────────── Events ───────────────────────────── */
//     event GuardianRevocationRequested(bytes32 indexed guardianHash, uint256 executeAfter);
//     event GuardianRevoked(bytes32 indexed guardianHash);

//     /* ───────────────────────────── Storage (excerpt) ────────────────── */
//     struct GuardianIdentity {
//         bool isActive;
//         uint256 index;
//         uint256 pending; // also reused for revocation pending window
//         KeyType keyType;
//     }

//     struct GuardiansData {
//         bytes32[] guardians;
//         mapping(bytes32 => GuardianIdentity) data;
//         uint256 lock;
//     }

//     GuardiansData internal guardiansData;

//     uint256 internal immutable securityPeriod;
//     uint256 internal immutable securityWindow;

//     /* ───────────────────────────── Helpers (excerpt) ────────────────── */
//     function _guardianHash(Key memory _g) internal pure returns (bytes32);
//     function _requireForExecute() internal view;
//     function isLocked() public view returns (bool);
//     function isGuardian(Key memory _g) public view returns (bool);

//     /* ───────────────────────── Guardian REVOCATION ──────────────────── */

//     /**
//      * @notice Owner starts delayed revocation of an active guardian.
//      *         Confirmation follows the same securityPeriod / securityWindow rules
//      *         used for guardian additions.
//      */
//     function revokeGuardian(Key memory _guardian) external {
//         _requireForExecute();
//         if (isLocked()) revert OPF7702Recoverable__AccountLocked();

//         bytes32 gHash = _guardianHash(_guardian);
//         GuardianIdentity storage gi = guardiansData.data[gHash];

//         if (!gi.isActive) revert OPF7702Recoverable__MustBeGuardian();

//         // If another revocation already pending and still in its confirmation window → duplicated
//         if (gi.pending != 0 && block.timestamp <= gi.pending + securityWindow) {
//             revert OPF7702Recoverable__DuplicatedRevoke();
//         }

//         gi.pending = block.timestamp + securityPeriod; // schedule revocation
//         emit GuardianRevocationRequested(gHash, gi.pending);
//     }

//     /**
//      * @notice Anyone can confirm the revocation once the delay has elapsed but
//      *         only within `securityWindow`.
//      */
//     function confirmGuardianRevocation(Key memory _guardian) external {
//         _requireForExecute();
//         if (isLocked()) revert OPF7702Recoverable__AccountLocked();

//         bytes32 gHash = _guardianHash(_guardian);
//         GuardianIdentity storage gi = guardiansData.data[gHash];

//         if (gi.pending == 0) revert OPF7702Recoverable__UnknownRevoke();
//         if (block.timestamp < gi.pending) revert OPF7702Recoverable__PendingRevokeNotOver();
//         if (block.timestamp > gi.pending + securityWindow) {
//             revert OPF7702Recoverable__PendingRevokeExpired();
//         }
//         if (!gi.isActive) revert OPF7702Recoverable__MustBeGuardian();

//         // ---- array swap-and-pop ----
//         uint256 lastIndex = guardiansData.guardians.length - 1;
//         bytes32 lastHash = guardiansData.guardians[lastIndex];
//         uint256 targetIndex = gi.index;

//         if (gHash != lastHash) {
//             guardiansData.guardians[targetIndex] = lastHash;
//             guardiansData.data[lastHash].index = targetIndex;
//         }
//         guardiansData.guardians.pop();

//         delete guardiansData.data[gHash]; // clears mapping entry
//         emit GuardianRevoked(gHash);
//     }
// }
