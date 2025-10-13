# Session Keys & Permission System

This document covers the session key management and permission enforcement system within the Openfort EIP-7702 Smart Accounts. Session keys enable temporary, scoped access to smart accounts with granular permission controls including selector restrictions, spend caps, and time-based limits.

For information about the core account abstraction implementation, see Account Abstraction Implementation. For details about authentication mechanisms and WebAuthn integration, see WebAuthn Integration.

## Table of Contents

- [System Architecture](#system-architecture)
- [Key Types and Capabilities](#key-types-and-capabilities)
- [Permission Control Framework](#permission-control-framework)
- [Gas, Spend, and Selector Controls](#gas-spend-and-selector-controls)
- [Session Key Data Structure](#session-key-data-structure)
- [Key Management Lifecycle](#key-management-lifecycle)
- [Permission Validation Flow](#permission-validation-flow)
- [Validation and Enforcement](#validation-and-enforcement)
  - [Spending Limit Enforcement](#spending-limit-enforcement)
- [Security Model](#security-model)

## System Architecture
The session key system is built around three primary components that work together to provide secure, temporary access delegation:
```mermaid
flowchart TD
    subgraph "Key Management Layer"
        KeyStructures["IKey.sol<br/>• KeyData<br/>• KeyDataReg<br/>• KeyType<br/>• KeyControl"]
        KeysManager["KeysManager.sol<br/>• registerKey()<br/>• setCanCall()<br/>• setTokenSpend()<br/>• revokeKey()"]
    end
    
    subgraph "Permission Validation"
        ValidationCore["OPF7702.sol<br/>• _validateExecuteCall()<br/>• _validateCall()"]
        PermissionChecks["Execution.sol<br/>• execute(mode,data)<br/>• Call struct"]
    end
    
    subgraph "Storage Management"
        SessionKeyData["Key Storage<br/>• keys[keyId]<br/>• permissions[keyId]<br/>• spendStore[keyId]"]
    end
    
    subgraph "Execution Layer"
        ExecutionEngine["Execution.sol<br/>• execute()<br/>• executeBatch()<br/>• _executeCall()"]
        MainAccount["OPF7702.sol<br/>• Session key integration<br/>• Permission enforcement<br/>• Transaction routing"]
    end

    %% Separate components
    WebAuthnVerifier["WebAuthnVerifier.sol<br/>• verifySignature()<br/>• verifyP256Signature()"]
    GasPolicy["GasPolicy.sol<br/>• checkUserOpPolicy()"]

    %% Flow connections
    KeyStructures --> KeysManager
    KeysManager --> ValidationCore
    KeysManager --> SessionKeyData
    
    ValidationCore --> PermissionChecks
    SessionKeyData --> PermissionChecks
    
    PermissionChecks --> ExecutionEngine
    ExecutionEngine --> MainAccount
    MainAccount --> WebAuthnVerifier
    MainAccount --> GasPolicy
```

After registration, the account owner (or authorised automation) configures selector and spend permissions via `setCanCall`, `setTokenSpend`, `updateTokenSpend`, or clears them with the corresponding `clear*` helpers.

## Key Types and Capabilities
The system supports four distinct key types, each with different cryptographic properties and security characteristics:


| Key Type | Description | Use Cases | Validation Method |
|----------|-------------|-----------|-------------------|
| EOA | Traditional ECDSA keys | Standard wallets, development | ECDSA signature verification |
| WEBAUTHN | WebAuthn credentials | Biometrics, hardware keys | WebAuthn assertion validation |
| P256 | Standard P-256 keys | Extractable P-256 signatures | P-256 ECDSA verification |
| P256NONKEY | Hardware-bound P-256 | Non-extractable hardware keys | SHA-256 digest validation |

```mermaid
flowchart TD
    subgraph "Key Type Hierarchy"
        KeyType["KeyType enum<br/>EOA | WEBAUTHN | P256 | P256NONKEY"]
        
        EOAKey["EOA Keys<br/>• Traditional ECDSA<br/>• Private key based<br/>• Standard EOA support"]
        WebAuthnKey["WebAuthn Keys<br/>• Hardware security keys<br/>• FaceId authentication<br/>• Biometric authentication<br/>• Platform authenticators"]
        P256Key["P-256 Keys<br/>• Extractable P-256<br/>• Standard ECDSA flow<br/>• Cross-platform support"]
        P256NonKey["P-256 NonExtractable<br/>• Seamless signing keys<br/>• Prehashed digest flow<br/>• Maximum security"]
    end
    
    subgraph "Validation Paths"
        EOAValidation["_validateEOASignature()<br/>• ECDSA recovery<br/>• Address comparison"]
        WebAuthnValidation["_validateWebAuthnSignature()<br/>• Challenge verification<br/>• Client data validation<br/>• Authenticator data parsing"]
        P256Validation["P-256 Signature Verification<br/>• Point validation<br/>• Curve operations<br/>• Digest verification"]
    end

    %% Key type connections
    KeyType --> EOAKey
    KeyType --> WebAuthnKey
    KeyType --> P256Key
    KeyType --> P256NonKey
    
    %% Validation connections
    EOAKey --> EOAValidation
    WebAuthnKey --> WebAuthnValidation
    P256Key --> P256Validation
    P256NonKey --> P256Validation
```


## Permission Control Framework
Session key enforcement layers include:

- **Temporal bounds** – `validAfter` and `validUntil` must frame the current timestamp for a key to be considered active.
- **Execution quotas** – `limits` decrements through `consumeQuota()` on every authorised call; master keys set `limits == 0` and bypass quota exhaustion.
- **Selector permissions** – `setCanCall` maintains packed `(target, selector)` entries with wildcard rules (`ANY_TARGET`, `ANY_FN_SEL`, `EMPTY_CALLDATA_FN_SEL`) governing which contracts/functions a key may execute.
- **Spend policies** – Optional `setTokenSpend` rules and the `ethLimit` counter cap ERC‑20 transfers/approvals and native value forwarding per period.
- **Custodial gas policies** – Keys created with `KeyControl.Custodial` initialise a session envelope in `GasPolicy`, limiting how much validation/call gas the key may consume in ERC‑4337 flows.

## Gas, Spend, and Selector Controls
```mermaid
flowchart TD
    subgraph "Time Controls"
        TimeValidation["Time-based Permissions<br/>• validAfter timestamp<br/>• validUntil expiration"]
    end

    subgraph "Gas Policy"
        GasPolicy["Gas Policy<br/>• Custodial keys<br/>• initializeGasPolicy(configId)"]
    end

    subgraph "Spending Controls"
        EthLimits["ETH Spending Limits<br/>• ethLimit counter<br/>• consumeQuota on value"]
        TokenLimits["Token Spend Rules<br/>• spendStore entries<br/>• ERC-20 selectors"]
    end

    subgraph "Selector Permissions"
        SelectorSets["Selector Sets<br/>• packCanExecute()<br/>• Wildcards / empty calldata"]
    end

    subgraph "Usage Controls"
        TransactionLimits["Quota Enforcement<br/>• limits field<br/>• hasQuota() check"]
    end

    TimeValidation --> GasPolicy
    GasPolicy --> EthLimits
    EthLimits --> TokenLimits
    TokenLimits --> SelectorSets
    SelectorSets --> TransactionLimits
```

## Session Key Data Structure
The core session key storage structure contains all permission and metadata fields:
```mermaid
erDiagram
    KeyData {
        KeyType keyType
        bool isActive
        bool masterKey
        bool isDelegatedControl
        uint48 validUntil
        uint48 validAfter
        uint48 limits
        bytes key
    }

    ExecutePermissions {
        bytes32 packedEntry "Target + selector"
    }

    SpendStorage {
        address token
        uint256 limit
        uint256 spent
        uint256 lastUpdated
        SpendPeriod period
    }

    KeyData ||--o{ ExecutePermissions : allows
    KeyData ||--o{ SpendStorage : enforces
```

* `KeyData` – canonical on-chain metadata for each key (`keyType`, activity flags, temporal bounds, quota, encoded key bytes).
* `ExecutePermissions` – packed `(target, selector)` entries maintained through `setCanCall`; supports wildcard matching via sentinel addresses/selectors.
* `SpendStorage` – per-key spend configuration reset on period boundaries and enforced via `_isTokenSpend`/`_manageTokenSpend`.


## Key Management Lifecycle
Session keys follow a structured lifecycle from registration through usage to expiration:

Registration Process


```mermaid
sequenceDiagram
    participant Owner as Account Owner
    participant Account as OPF7702 Account
    participant KeysManager
    participant Storage as Key Storage
    participant GasPolicy as Gas Policy

    Owner->>Account: registerKey(keyDataReg)
    Account->>Account: _requireForExecute()
    Account->>KeysManager: registerKey(keyDataReg)
    KeysManager->>KeysManager: _addKey(keyDataReg)
    KeysManager->>Storage: Store KeyData / permissions
    alt keyControl == Custodial
        KeysManager->>GasPolicy: initializeGasPolicy(account, keyId, limits)
        GasPolicy-->>KeysManager: Gas envelope configured
    end
    KeysManager-->>Account: emit KeyRegistered
    Account-->>Owner: Registration complete

    Note over KeysManager, GasPolicy: Master keys: limits == 0 (no gas policy, bypass quotas)
    Note over KeysManager, GasPolicy: Session keys: configure selectors/spend via setCanCall & setTokenSpend
```

## Permission Validation Flow

```mermaid
flowchart TD
    subgraph "Transaction Initiation"
        UserOp["User Operation<br/>• Transaction data<br/>• Signature<br/>• Session key ID"]
    end
    
    subgraph "Signature Validation"
        SignatureCheck["_validateSignature()<br/>• Key type resolution<br/>• Cryptographic verification<br/>• Key existence check"]
        KeyTypeSwitch["Key Type Validation<br/>• EOA: ECDSA recovery<br/>• WebAuthn: assertion verification<br/>• P-256: curve validation"]
    end
    
    subgraph "Permission Enforcement"
        TimeCheck["Time Validation<br/>• validAfter <= now<br/>• now <= validUntil<br/>• Active status check"]
        GasPolicyCheck["Gas Policy Validation<br/>• checkUserOpPolicy()<br/>• Gas envelope calculation<br/>• Budget limit enforcement<br/>• Usage counter updates"]
        SelectorCheck["Selector Permissions<br/>• packCanExecute lookup<br/>• Wildcards + empty calldata"]
        SpendingCheck["Spending Validation<br/>• ETH limit check<br/>• Token spend enforcement"]
        QuotaCheck["Quota Consumption<br/>• hasQuota()<br/>• consumeQuota()"]
    end
    
    subgraph "Execution Authorization"
        ExecutionGrant["Permission Granted<br/>• All checks passed<br/>• Transaction authorized<br/>• State updated"]
    end

    %% Flow connections
    UserOp --> SignatureCheck
    SignatureCheck --> KeyTypeSwitch
    KeyTypeSwitch --> TimeCheck
    TimeCheck --> GasPolicyCheck
    GasPolicyCheck --> SelectorCheck
    SelectorCheck --> SpendingCheck
    SpendingCheck --> QuotaCheck
    QuotaCheck --> ExecutionGrant
```

## Validation and Enforcement
The permission system implements multiple validation layers to ensure secure execution:

### Spending Limit Enforcement
Token spending validation follows strict ERC-20 patterns with specific security constraints:

```mermaid
flowchart TD
    subgraph "Token Spend Validation"
        TokenCall["ERC-20 Function Call<br/>• transfer(address,uint256)<br/>• transferFrom(address,address,uint256)<br/>• approve(address,uint256)"]
        DataExtraction["_isTokenSpend()<br/>• LibBytes.load amount<br/>• Map empty calldata to ETH"]
        LimitCheck["_manageTokenSpend()<br/>• Start-of-period reset<br/>• spent + amount <= limit"]
    end
    
    subgraph "ETH Spend Validation"
        ETHTransfer["ETH Transfer<br/>• msg.value > 0<br/>• Native ETH spending<br/>• Direct transfers"]
        ETHValidation["_validateEthSpend()<br/>• Check ethLimit<br/>• Update ETH spending<br/>• Track cumulative usage"]
    end
    
    subgraph "Spending Constraints"
        PolicyEntry["SpendStorage rules<br/>• target => TokenSpendPeriod"]
        ERC20Only["ERC-20 selector support<br/>• transfer/transferFrom/approve"]
    end

    %% Flow connections
    TokenCall --> DataExtraction
    DataExtraction --> LimitCheck
    ETHTransfer --> ETHValidation
    LimitCheck --> PolicyEntry
    ETHValidation --> PolicyEntry
    PolicyEntry --> ERC20Only
```

Native ETH transfers reuse the same path by mapping empty calldata to `NATIVE_ADDRESS`, ensuring both value and token flows respect per-period limits.


## Security Model

The session key security model implements defense-in-depth through multiple validation layers:
| Security Layer | Purpose | Implementation |
|----------------|---------|----------------|
| Signature Validation | Cryptographic authenticity | Key type-specific signature verification |
| Time Bounds | Temporal access control | validAfter and validUntil timestamp checks |
| Usage Limits | Transaction count control | `limits` quota with `hasQuota()/consumeQuota()` |
| Value Caps | Financial risk mitigation | `ethLimit` plus `setTokenSpend` rules per period |
| Selector Permissions | Target/selector restriction | Packed `(target, selector)` permissions with wildcard support |
| Gas Policy | Resource usage control | Gas envelope calculation, budget enforcement, penalty handling |
| Gas Griefing Protection | DoS prevention | Signature length validation |

