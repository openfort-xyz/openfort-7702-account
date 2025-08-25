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








