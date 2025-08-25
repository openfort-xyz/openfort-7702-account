# Session Keys & Permission System

This document covers the session key management and permission enforcement system within the Openfort EIP-7702 Smart Accounts. Session keys enable temporary, scoped access to smart accounts with granular permission controls including spending limits, contract whitelisting, and time-based restrictions.

For information about the core account abstraction implementation, see Account Abstraction Implementation. For details about authentication mechanisms and WebAuthn integration, see WebAuthn Integration.

## System Architecture
The session key system is built around three primary components that work together to provide secure, temporary access delegation:
```mermaid
flowchart TD
    subgraph "Key Management Layer"
        KeyStructures["Key.sol<br/>• Key struct<br/>• KeyReg struct<br/>• SpendTokenInfo struct<br/>• KeyType enum"]
        KeysManager["KeysManager.sol<br/>• registerSessionKey()<br/>• revokeKey()<br/>• _addKey()<br/>• _validateKeyPermissions()"]
    end
    
    subgraph "Permission Validation"
        ValidationCore["IValidation.sol<br/>• Validation interfaces<br/>• Permission structures"]
        PermissionChecks["BaseOPF7702.sol<br/>• _checkSessionKeyPermissions()<br/>• _validateTokenSpend()<br/>• _validateEthSpend()"]
    end
    
    subgraph "Storage Management"
        SessionKeyData["SessionKey Storage<br/>• keyData mapping<br/>• activeKeys tracking<br/>• Permission states"]
    end
    
    subgraph "Execution Layer"
        ExecutionEngine["Execution.sol<br/>• execute()<br/>• executeBatch()<br/>• _executeCall()"]
        MainAccount["OPF7702.sol<br/>• Session key integration<br/>• Permission enforcement<br/>• Transaction routing"]
    end

    %% Separate components
    WebAuthnVerifier["WebAuthnVerifierV2.sol<br/>• verifySignature()<br/>• verifyP256Signature()"]
    GasPolicy["GasPolicy.sol<br/>• checkUserOpPolicy()"]

    %% Flow connections
    KeyStructures --> KeysManager
    KeysManager --> ValidationCore
    KeysManager --> SessionKeyData
    
    ValidationCore --> PermissionChecks
    SessionKeyData --> PermissionChecks
    
    PermissionChecks --> WebAuthnVerifier
    PermissionChecks --> GasPolicy
    PermissionChecks --> ExecutionEngine
    
    ExecutionEngine --> MainAccount
```

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
Session keys operate within a comprehensive permission framework that enforces multiple layers of access control:

```mermaid
flowchart TD
    subgraph "Time Controls"
        TimeValidation["Time-based Permissions<br/>• validAfter timestamp<br/>• validUntil expiration<br/>• Automatic cleanup"]
    end
    
    subgraph "Spending Controls"
        EthLimits["ETH Spending Limits<br/>• ethLimit field<br/>• Per-key tracking<br/>• Cumulative enforcement"]
        TokenLimits["Token Spending Limits<br/>• SpendTokenInfo struct<br/>• ERC-20 only support<br/>• Single token per key"]
    end
    
    subgraph "Access Controls"
        ContractWhitelist["Contract Whitelisting<br/>• whitelist mapping<br/>• Address-based filtering<br/>• Boolean permissions"]
        FunctionFilter["Function Selector Filtering<br/>• allowedSelectors array<br/>• bytes4 selector matching<br/>• Granular function control"]
    end
    
    subgraph "Usage Controls"
        TransactionLimits["Transaction Count Limits<br/>• limit field<br/>• Per-operation decrement<br/>• Usage exhaustion"]
        WhitelistingMode["Whitelisting Mode<br/>• whitelisting boolean<br/>• Enforce restrictions<br/>• Default allow/deny"]
    end

    %% Flow connections
    TimeValidation --> EthLimits
    EthLimits --> TokenLimits
    TokenLimits --> ContractWhitelist
    ContractWhitelist --> FunctionFilter
    FunctionFilter --> TransactionLimits
    TransactionLimits --> WhitelistingMode
```

## Permission Control Framework
Session keys operate within a comprehensive permission framework that enforces multiple layers of access control:

```mermaid
flowchart TD
    subgraph "Time Controls"
        TimeValidation["Time-based Permissions<br/>• validAfter timestamp<br/>• validUntil expiration<br/>• Automatic cleanup"]
    end

    subgraph "Gas Policy"
        GasPolicy["Gas Permissions<br/>• limits counter<br/>• manual/auto config<br/>• include penalty gas"]
    end

    subgraph "Spending Controls"
        EthLimits["ETH Spending Limits<br/>• ethLimit field<br/>• Per-key tracking<br/>• Cumulative enforcement"]
        TokenLimits["Token Spending Limits<br/>• SpendTokenInfo struct<br/>• ERC-20 only support<br/>• Single token per key"]
    end
    
    subgraph "Access Controls"
        ContractWhitelist["Contract Whitelisting<br/>• whitelist mapping<br/>• Address-based filtering<br/>• Boolean permissions"]
        FunctionFilter["Function Selector Filtering<br/>• allowedSelectors array<br/>• bytes4 selector matching<br/>• Granular function control"]
    end
    
    subgraph "Usage Controls"
        TransactionLimits["Transaction Count Limits<br/>• limit field<br/>• Per-operation decrement<br/>• Usage exhaustion"]
        WhitelistingMode["Whitelisting Mode<br/>• whitelisting boolean<br/>• Enforce restrictions<br/>• Default allow/deny"]
    end

    %% Flow connections
    TimeValidation --> GasPolicy
    GasPolicy --> EthLimits
    EthLimits --> TokenLimits
    TokenLimits --> ContractWhitelist
    ContractWhitelist --> FunctionFilter
    FunctionFilter --> TransactionLimits
    TransactionLimits --> WhitelistingMode
```

## Session Key Data Structure
The core session key storage structure contains all permission and metadata fields:
```mermaid
erDiagram
    SessionKey {
        PubKey pubKey "Public key data"
        bool isActive "Activation status"
        uint48 validUntil "Expiration timestamp"
        uint48 validAfter "Start timestamp"
        uint48 limit "Transaction count limit"
        bool masterSessionKey "Master key flag"
        bool whitelisting "Enable restrictions"
        uint256 ethLimit "ETH spending limit"
        SpendTokenInfo spendTokenInfo "Token spend data"
    }
    
    PubKey {
        uint256 x "X coordinate"
        uint256 y "Y coordinate"
    }
    
    SpendTokenInfo {
        address token "ERC-20 token address"
        uint256 limit "Token spending limit"
    }
    
    allowedSelectors {
        bytes4 selector "Function selectors"
    }
    
    whitelist {
        address target "Contract address"
        bool allowed "Permission flag"
    }

    SessionKey ||--|| PubKey : contains
    SessionKey ||--|| SpendTokenInfo : contains
    SessionKey ||--o{ allowedSelectors : has
    SessionKey ||--o{ whitelist : maintains
```


## Key Management Lifecycle
Session keys follow a structured lifecycle from registration through usage to expiration:

Registration Process


```mermaid
sequenceDiagram
    participant Owner as Account Owner
    participant Account as OPF7702 Account
    participant KeysManager
    participant Storage as Session Key Storage
    participant GasPolicy as Gas Policy

    Owner->>Account: registerSessionKey(key, permissions)
    Account->>Account: _requireFromEntryPointOrOwner()
    Account->>KeysManager: _addKey(keyReg)
    KeysManager->>KeysManager: _masterKeyValidation(keyReg)
    KeysManager->>KeysManager: _validateKeyPermissions(keyReg)
    KeysManager->>Storage: Store session key data
    KeysManager->>GasPolicy: initializeGasPolicy(account, configId, limit)
    GasPolicy->>GasPolicy: Calculate gas budgets and limits
    GasPolicy-->>KeysManager: Gas policy configured
    KeysManager->>Account: SessionKeyRegistered event
    Account-->>Owner: Registration complete

    Note over KeysManager, GasPolicy: Master keys: validUntil=max, validAfter=0, limit=0, whitelisting=false
    Note over KeysManager, GasPolicy: Session keys: whitelisting=true, bounded permissions
    Note over GasPolicy: Gas Policy: Per limits
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
        WhitelistCheck["Contract Whitelist<br/>• Target address validation<br/>• Whitelisting mode check<br/>• Address permissions"]
        SelectorCheck["Function Selector<br/>• Extract function selector<br/>• Check allowed selectors<br/>• Granular permissions"]
        SpendingCheck["Spending Validation<br/>• ETH limit check<br/>• Token limit validation<br/>• Usage count decrement"]
    end
    
    subgraph "Execution Authorization"
        ExecutionGrant["Permission Granted<br/>• All checks passed<br/>• Transaction authorized<br/>• State updated"]
    end

    %% Flow connections
    UserOp --> SignatureCheck
    SignatureCheck --> KeyTypeSwitch
    KeyTypeSwitch --> TimeCheck
    TimeCheck --> GasPolicyCheck
    GasPolicyCheck --> WhitelistCheck
    WhitelistCheck --> SelectorCheck
    SelectorCheck --> SpendingCheck
    SpendingCheck --> ExecutionGrant
```

## Validation and Enforcement
The permission system implements multiple validation layers to ensure secure execution:

### Spending Limit Enforcement
Token spending validation follows strict ERC-20 patterns with specific security constraints:

```mermaid
flowchart TD
    subgraph "Token Spend Validation"
        TokenCall["ERC-20 Function Call<br/>• transfer(address,uint256)<br/>• transferFrom(address,address,uint256)<br/>• approve(address,uint256)"]
        DataExtraction["_validateTokenSpend()<br/>• Extract value from calldata<br/>• Last 32 bytes = amount<br/>• Validate against limit"]
        LimitCheck["Spending Limit Check<br/>• Current spend + amount <= limit<br/>• Update spend tracking<br/>• Prevent overspend"]
    end
    
    subgraph "ETH Spend Validation"
        ETHTransfer["ETH Transfer<br/>• msg.value > 0<br/>• Native ETH spending<br/>• Direct transfers"]
        ETHValidation["_validateEthSpend()<br/>• Check ethLimit<br/>• Update ETH spending<br/>• Track cumulative usage"]
    end
    
    subgraph "Spending Constraints"
        SingleToken["Single Token Policy<br/>• One token per session key<br/>• Registered in SpendTokenInfo<br/>• No multi-token support"]
        ERC20Only["ERC-20 Only Support<br/>• Standard transfer functions<br/>• No ERC-777, ERC-1363<br/>• No vault tokens (ERC-4626)"]
    end

    %% Flow connections
    TokenCall --> DataExtraction
    DataExtraction --> LimitCheck
    ETHTransfer --> ETHValidation
    LimitCheck --> SingleToken
    ETHValidation --> SingleToken
    SingleToken --> ERC20Only
```


## Security Model
The session key security model implements defense-in-depth through multiple validation layers:
| Security Layer | Purpose | Implementation |
|----------------|---------|----------------|
| Signature Validation | Cryptographic authenticity | Key type-specific signature verification |
| Time Bounds | Temporal access control | validAfter and validUntil timestamp checks |
| Usage Limits | Transaction count control | limit field with per-operation decrement |
| Spending Caps | Financial risk mitigation | ETH and token spending limits |
| Contract Whitelisting | Target restriction | Address-based access control |
| Function Filtering | Operation-level control | Function selector validation |
| Gas Policy | Resource usage control | Gas envelope calculation, budget enforcement, penalty handling |
| Gas Griefing Protection | DoS prevention | Signature length validation |