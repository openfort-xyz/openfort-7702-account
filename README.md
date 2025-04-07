# Openfort EIP-7702 Smart Contract Accounts
<p style="background-color: black; display: inline-block; padding: 5px;">
  <img src="contracts/Logo_black primary no bg.png" alt="Openfort" style="width: 300px;" />
</p>


This repository contains the implementation of EIP-7702 compatible smart contract accounts by Openfort. These accounts enable account abstraction while leveraging the new capabilities introduced by EIP-7702 (Pectra Updgrade).

## Overview

EIP-7702 (Account Implementation Contract Standard) allows smart contracts to be executed at any address without a deployment transaction. This repository provides various implementations:

1. **OpenfortBaseAccount7702V1**: Standard implementation using EIP-191 signature  verification
2. **OpenfortBaseAccount7702V1_712**: Enhanced implementation using EIP-712 typed data signatures

## Features

- **No Deployment Transaction**: Create and use accounts without expensive deployment transactions
- **Custom Storage Layout**: Fixed storage layout using a predetermined slot
- **Owner Management**: Account ownership with signature-based initialization
- **Batch Transactions**: Execute multiple transactions in a single call
- **Token Support**: Built-in handling for ERC721, ERC777, and ERC1155 tokens
- **Security Measures**: Reentrancy protection and comprehensive validation

## Contract Architecture

### Core Contracts

- `OpenfortBaseAccount7702V1.sol`: Main implementation using standard ECDSA using EIP-191 signatures
- `OpenfortBaseAccount7702V1_712.sol`: Enhanced implementation using EIP-712 typed data signatures
- `TokenCallbackHandler.sol`: Handles callbacks for various token standards

### Supporting Interfaces

- `IOpenfortBaseAccount.sol`: Main interface for account implementations
- `IValidation.sol`: Defines structures for signature validation

## Installation

```bash
# Clone the repository
git clone https://github.com/openfort/openfort-7702-account.git
cd openfort-7702-account

# Install dependencies
forge install
forge test
```

## Technical Details

### Storage Layout

The contracts use a fixed storage layout starting at a specific slot:

```
keccak256("openfort.baseAccount.7702.v1") = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
```

This enables deterministic storage access across different addresses, essential for EIP-7702.

### Signature Verification

- **Standard Version**: Uses ECDSA to verify that the signature was created by the contract address
- **EIP-712 Version**: Uses typed data signing (EIP-712) for more secure signatures with better UX

### Storage Clearing

The contracts provide a `_clearStorage()` function to reset storage slots when reinitializing an account. This ensures clean state transitions.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
