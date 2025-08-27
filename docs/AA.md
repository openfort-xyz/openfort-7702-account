# Account Abstraction Implementation

This page explains how the Openfort EIP-7702 Smart Accounts system implements both EIP-7702 (Account Implementation Contract Standard) and ERC-4337 (Account Abstraction via Entry Point) to provide comprehensive account abstraction functionality. For details about session key permissions and access controls, see Session Keys & Permission System. For social recovery mechanisms, see Social Recovery System.

## Table of Contents

- [EIP-7702 Delegation Architecture](#eip-7702-delegation-architecture)
- [ERC-4337 Integration](#erc-4337-integration)
  - [IAccount Interface Implementation](#iaccount-interface-implementation)
- [Signature Validation Architecture](#signature-validation-architecture)
- [EIP-7702 and ERC-4337 Interoperability](#eip-7702-and-erc-4337-interoperability)
  - [Integration Points](#integration-points)
  - [Execution Contexts](#execution-contexts)
  
## EIP-7702 Delegation Architecture

EIP-7702 enables any Externally Owned Account (EOA) to delegate its code execution to a smart contract implementation without requiring a deployment transaction. The system uses a deterministic storage layout to maintain state consistency across different account addresses.

Delegation Flow
```mermaid
flowchart LR
    subgraph "EIP-7702 Delegation Process"
        EOA["EOA Address"]
        
        subgraph "Implementation Contract"
            SetCode["SET_CODE_TX<br/>delegates to OPF7702"]
            OPF7702["OPF7702.sol<br/>Implementation"]
            BaseOPF["BaseOPF7702.sol<br/>Core Logic"]
        end
        
        subgraph "Storage Layout"
            BaseSlot["Base Storage Slot<br/>keccak256('openfort.baseAccount.7702.v1')"]
            AccountData["AccountData7702<br/>• owner: Key<br/>• nonce: uint256"]
            SessionKeys["Session Keys Mapping<br/>keyHash => KeyData"]
        end
    end

    %% Flow connections
    EOA --> SetCode
    SetCode --> OPF7702
    OPF7702 --> BaseOPF
    BaseOPF --> BaseSlot
    BaseSlot --> AccountData
    BaseSlot --> SessionKeys
```

## ERC-4337 Integration
The system implements the IAccount interface from ERC-4337 to enable UserOperation processing through bundlers and the EntryPoint contract.

```mermaid
flowchart LR
    subgraph "ERC-4337 Flow"
        Bundler["Bundler/Relayer"]
        EntryPoint["EntryPoint Contract<br/>0x0000000071727De22E5E9d8BAf0edAc6f37da032"]
        
        subgraph "BaseOPF7702 Validation"
            ValidateUserOp["validateUserOp()<br/>IAccount interface"]
            SigValidation["_validateSignature()<br/>Key type routing"]
            NonceValidation["_validateNonce()<br/>Replay protection"]
        end
        
        subgraph "Signature Handlers"
            EOAValidator["_validateEOASignature()<br/>ECDSA recovery"]
            WebAuthnValidator["_validateWebAuthnSignature()<br/>P-256 verification"]
            SessionKeyValidator["Session Key Validation<br/>Permissions + signature"]
        end
    end

    %% Flow connections
    Bundler --> EntryPoint
    EntryPoint --> ValidateUserOp
    ValidateUserOp --> SigValidation
    ValidateUserOp --> NonceValidation
    SigValidation --> EOAValidator
    SigValidation --> WebAuthnValidator
    SigValidation --> SessionKeyValidator
```

### IAccount Interface Implementation
The BaseOPF7702 contract implements the required ERC-4337 interface methods:
| Method | Implementation Location | Purpose |
|--------|-------------------------|---------|
| validateUserOp() | BaseOPF7702 | Validates UserOperation signatures and permissions |
| getNonce() | BaseOPF7702 | Returns current nonce for replay protection |
| Signature validation | BaseOPF7702._validateSignature() | Routes to appropriate signature handler |

## Signature Validation Architecture
The system supports multiple signature schemes through a unified validation interface that routes signatures based on key type and context.

```mermaid
flowchart TD
    subgraph "Signature Validation Router"
        UserOpSig["UserOperation.signature"]
        SigLength["_checkValidSignatureLength()<br/>Gas griefing protection"]
        KeyType["Determine Key Type<br/>• EOA<br/>• WEBAUTHN<br/>• P256<br/>• P256NONKEY"]
        
        subgraph "Validation Handlers"
            EOAPath["_validateEOASignature()<br/>• ECDSA recover<br/>• Compare with owner"]
            WebAuthnPath["_validateWebAuthnSignature()<br/>• WebAuthnVerifier call<br/>• P-256 validation"]
            SessionPath["Session Key Validation<br/>• Permission checks<br/>• Signature verification<br/>• Gas Policy"]
        end
        
        Result["ValidationResult<br/>• SIG_VALIDATION_SUCCEEDED<br/>• SIG_VALIDATION_FAILED"]
    end

    %% Flow connections
    UserOpSig --> SigLength
    SigLength --> KeyType
    KeyType -->|EOA| EOAPath
    KeyType -->|WEBAUTHN/P256| WebAuthnPath
    KeyType -->|Session Key| SessionPath
    EOAPath --> Result
    WebAuthnPath --> Result
    SessionPath --> Result
```

## EIP-7702 and ERC-4337 Interoperability
The system seamlessly integrates both standards to provide zero-deployment accounts with full account abstraction capabilities.

### Integration Points
| Component | EIP-7702 Role | ERC-4337 Role | Implementation |
|-----------|---------------|---------------|----------------|
| Storage | Deterministic slots across addresses | State persistence for UserOps | Fixed slot calculation |
| Validation | Code delegation verification | UserOperation signature validation | Unified signature routing |
| Execution | Direct EOA transactions | Bundled UserOperations | Same execution engine |
| Nonce Management | Replay protection | UserOp ordering | Shared nonce counter |

### Execution Contexts
The implementation handles both direct EOA calls (via EIP-7702 delegation) and bundled UserOperations (via ERC-4337 flow) through the same execution engine.

```mermaid
flowchart TD
    subgraph "Execution Contexts"
        DirectCall["Direct EOA Call<br/>msg.sender = EOA"]
        UserOpCall["UserOperation Call<br/>msg.sender = EntryPoint"]
        
        subgraph "Validation Layer"
            RequireAuth["_requireFromEntryPointOrOwner()<br/>Access control"]
            SigCheck["Signature validation<br/>Context-aware"]
        end
        
        subgraph "Execution Engine"
            ExecuteCall["_executeCall()<br/>Target contract interaction"]
            BatchExecution["Batch processing<br/>Multiple operations"]
        end
    end

    %% Flow connections
    DirectCall --> RequireAuth
    UserOpCall --> RequireAuth
    RequireAuth --> SigCheck
    SigCheck --> ExecuteCall
    ExecuteCall --> BatchExecution
```

