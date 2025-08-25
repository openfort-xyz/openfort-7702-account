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
        WebAuthnVerifier["WebAuthnVerifierV2.sol<br/>• verifySignature()<br/>• verifyP256Signature()"]
    end
    
    subgraph "Storage Management"
        SessionKeyData["SessionKey Storage<br/>• keyData mapping<br/>• activeKeys tracking<br/>• Permission states"]
    end
    
    subgraph "Execution Layer"
        ExecutionEngine["Execution.sol<br/>• execute()<br/>• executeBatch()<br/>• _executeCall()"]
        GasPolicy["GasPolicy.sol<br/>• checkUserOpPolicy()"]
        MainAccount["OPF7702.sol<br/>• Session key integration<br/>• Permission enforcement<br/>• Transaction routing"]
    end

    %% Flow connections
    KeyStructures --> KeysManager
    KeysManager --> ValidationCore
    KeysManager --> SessionKeyData
    
    ValidationCore --> PermissionChecks
    SessionKeyData --> PermissionChecks
    
    PermissionChecks --> WebAuthnVerifier
    PermissionChecks --> ExecutionEngine
    
    ExecutionEngine --> GasPolicy
    ExecutionEngine --> MainAccount
```