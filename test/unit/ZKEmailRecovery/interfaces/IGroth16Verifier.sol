// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[34] calldata pubSignals
    ) external view returns (bool);
}
