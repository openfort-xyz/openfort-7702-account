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
    EOA["EOA (delegator)"]
    SetCode["SET_CODE_TX<br/>authorizes implementation"]

    subgraph "Implementation Stack"
        OPFMain["OPFMain.sol<br/>layout at 0x…400"]
        OPFRecoverable["OPF7702Recoverable.sol"]
        OPF["OPF7702.sol"]
        Execution["Execution.sol"]
        KeysManager["KeysManager.sol"]
        BaseOPF["BaseOPF7702.sol"]
    end

    subgraph "Deterministic Storage"
        Slot["Base Slot<br/>keccak256(abi.encode(uint256(keccak256('openfort.baseAccount.7702.v1')) - 1)) & ~0xff"]
        Counters["id, idKeys"]
        Keys["keys[keyId] => KeyData"]
        Permissions["permissions[keyId] => ExecutePermissions"]
        Spend["spendStore[keyId] => SpendStorage"]
        Reentrancy["Reentrancy / Initializable state"]
    end

    EOA --> SetCode
    SetCode --> OPFMain
    OPFMain --> OPFRecoverable --> OPF --> Execution --> KeysManager --> BaseOPF
    BaseOPF --> Slot
    Slot --> Counters
    Slot --> Keys
    Slot --> Permissions
    Slot --> Spend
    Slot --> Reentrancy
```

## ERC-4337 Integration
The system implements the IAccount interface from ERC-4337 to enable UserOperation processing through bundlers and the EntryPoint contract.

```mermaid
flowchart LR
    subgraph "ERC-4337 Flow"
        Bundler["Bundler/Relayer"]
        EntryPoint["EntryPoint Contract<br/>0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108"]
        
        subgraph "OPF7702 Validation"
            ValidateUserOp["OPF7702.validateUserOp(...)"]
            SigValidation["_validateSignature()<br/>Key-type routing"]
            NonceValidation["BaseAccount._validateNonce()<br/>Replay protection"]
        end
        
        subgraph "Signature Handlers"
            EOAValidator["_validateKeyTypeEOA()<br/>ECDSA recovery"]
            WebAuthnValidator["_validateKeyTypeWEBAUTHN()<br/>WebAuthn verifier"]
            P256Validator["_validateKeyTypeP256()<br/>Raw / non-key P-256"]
            KeyGuards["KeysManager checks<br/>• _keyValidation<br/>• isValidKey<br/>• Gas policy (custodial)"]
        end
    end

    %% Flow connections
    Bundler --> EntryPoint
    EntryPoint --> ValidateUserOp
    ValidateUserOp --> SigValidation
    ValidateUserOp --> NonceValidation
    SigValidation --> EOAValidator
    SigValidation --> WebAuthnValidator
    SigValidation --> P256Validator
    EOAValidator --> KeyGuards
    WebAuthnValidator --> KeyGuards
    P256Validator --> KeyGuards
```

### IAccount Interface Implementation
The BaseOPF7702 contract implements the required ERC-4337 interface methods:
| Method | Implementation Location | Purpose |
|--------|-------------------------|---------|
| validateUserOp() | BaseOPF7702 | Validates UserOperation signatures and permissions |
| Signature validation | BaseOPF7702._validateSignature() | Routes to appropriate signature handler |

## Signature Validation Architecture
The system supports multiple signature schemes through a unified validation interface that routes signatures based on key type and context.

```mermaid
flowchart TD
    subgraph "Signature Validation Router"
        UserOpSig["UserOperation.signature"]
        SigLength["_checkValidSignatureLength()<br/>Gas griefing protection"]
        Decode["abi.decode(signature)<br/>KeyType + payload"]
        KeyType["Dispatch by KeyType<br/>EOA / WEBAUTHN / P256 / P256NONKEY"]
        
        subgraph "Validation Handlers"
            EOAPath["_validateKeyTypeEOA()<br/>ECDSA recover"]
            WebAuthnPath["_validateKeyTypeWEBAUTHN()<br/>WebAuthn verifier"]
            P256Path["_validateKeyTypeP256()<br/>Raw / pre-hashed P-256"]
        end

        KeyGuards["KeysManager checks<br/>• _keyValidation<br/>• isValidKey / _validateExecuteCall<br/>• Gas policy (custodial)"]
        Result["ValidationResult<br/>• SIG_VALIDATION_SUCCESS<br/>• SIG_VALIDATION_FAILED"]
    end

    %% Flow connections
    UserOpSig --> SigLength
    SigLength --> Decode --> KeyType
    KeyType -->|EOA| EOAPath
    KeyType -->|WEBAUTHN| WebAuthnPath
    KeyType -->|P256 / P256NONKEY| P256Path
    EOAPath --> KeyGuards
    WebAuthnPath --> KeyGuards
    P256Path --> KeyGuards
    KeyGuards --> Result
```

## EIP-7702 and ERC-4337 Interoperability
The system seamlessly integrates both standards to provide zero-deployment accounts with full account abstraction capabilities.

### Integration Points
| Component | EIP-7702 Role | ERC-4337 Role | Implementation |
|-----------|---------------|---------------|----------------|
| Storage | Deterministic slots across addresses | State persistence for UserOps | Fixed slot calculation |
| Validation | Code delegation verification | UserOperation signature validation | Unified signature routing |
| Execution | Direct EOA transactions | Bundled UserOperations | Same execution engine |

### Execution Contexts
The implementation handles both direct EOA calls (via EIP-7702 delegation) and bundled UserOperations (via ERC-4337 flow) through the same execution engine.

```mermaid
flowchart TD
    subgraph "Execution Contexts"
        DirectCall["Direct EOA Call<br/>msg.sender = delegating EOA"]
        UserOpCall["UserOperation<br/>msg.sender = EntryPoint"]

        subgraph "Access Control"
            RequireEP["BaseOPF7702._requireFromEntryPoint()<br/>EntryPoint-only paths"]
            RequireExecute["Execution._requireForExecute()<br/>msg.sender == self or EntryPoint"]
        end

        subgraph "Execution Engine"
            ExecuteEntry["OPF7702.execute(mode,data)"]
            RunWorker["Execution._run(mode,data,counter)"]
            LowLevel["Execution._execute(to,value,data)"]
        end
    end

    %% Flow connections
    DirectCall --> RequireExecute
    UserOpCall --> RequireEP --> RequireExecute
    RequireExecute --> ExecuteEntry --> RunWorker --> LowLevel
    RunWorker -->|mode 3 recursion| RunWorker

```
