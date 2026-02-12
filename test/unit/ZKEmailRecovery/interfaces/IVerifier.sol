// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

struct EmailProof {
    string domainName;
    bytes32 publicKeyHash;
    uint256 timestamp;
    string maskedCommand;
    bytes32 emailNullifier;
    bytes32 accountSalt;
    bool isCodeExist;
    bytes proof;
}

interface IVerifier {
    function verifyEmailProof(EmailProof memory proof) external view returns (bool);
    function commandBytes() external view returns (uint256);
}
