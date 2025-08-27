# Recovery Module
The OPF7702Recoverable module implements a guardian-based social recovery system for EIP-7702 + ERC-4337 smart contract wallets. This enables users to recover their accounts if they lose access to their master key, using a network of trusted guardians.

## Table of Contents

- [Definitions](#definitions)
- [Invariants (checked in constructor)](#invariants)
- [How they’re used](#how-theyre-used)
  - [Guardian changes](#guardian-changes)
  - [Recovery flow](#recovery-flow)
- [Key Features](#key-features)
- [Guardian Management System](#guardian-management-system)
  - [Guardian Lifecycle](#guardian-lifecycle)
  - [Guardian Data Structure](#guardian-data-structure)
  - [Guardian Operations](#guardian-operations)
    - [Adding a Guardian](#adding-a-guardian)
    - [Removing a Guardian](#removing-a-guardian)
  - [Recovery Process](#recovery-process)
    - [Recovery Data Structure](#recovery-data-structure)
    - [Recovery Flow](#recovery-flow-1)
    - [Recovery Timeline](#recovery-timeline)
- [Security Features](#security-features)
  - [Time-based Security Parameters](#time-based-security-parameters)
  - [Security Validations](#security-validations)
- [Function Reference](#function-reference)
  - [Initialization](#initialization)
  - [Guardian Management Functions](#guardian-management-functions)
  - [Recovery Functions](#recovery-functions)
  - [EIP-712 Signature Schemas](#eip-712-signature-schemas)
    - [Recovery Signature](#recovery-signature)
    - [Initialization Signature](#initialization-signature)
  - [Recommended ranges (non-binding)](#recommended-ranges-non-binding)
  - [Edge cases & guarantees](#edge-cases--guarantees)
  - [Testing checklist](#testing-checklist)

### Definitions
- `recoveryPeriod` — **Seconds to wait** after `startRecovery` before `completeRecovery` is allowed.
- `lockPeriod` — **Seconds the wallet stays “locked”** after `startRecovery`. The lock is cleared early on `completeRecovery()` or `cancelRecovery()`.
- `securityPeriod` — **Timelock** (seconds) before a guardian add/remove can be confirmed.
- `securityWindow` — **Confirmation window** (seconds) after `securityPeriod` during which a pending add/remove **must** be confirmed, or it expires.

### Invariants 
(checked in constructor)
- `lockPeriod ≥ recoveryPeriod`  
- `recoveryPeriod ≥ securityPeriod + securityWindow`  
If either fails, the deploy reverts with `OPF7702Recoverable_InsecurePeriod()`.

### How they’re used

#### Guardian changes
- **Propose add**: `proposeGuardian(g)` sets `pending = now + securityPeriod`.
- **Confirm add**: `confirmGuardianProposal(g)` allowed only in  
  `now ∈ [pending, pending + securityWindow]`.  
  Before `pending` → `PendingProposalNotOver`. After the window → `PendingProposalExpired` (re-propose).
- **Cancel add**: `cancelGuardianProposal(g)` before confirmation.
- **Revoke**: symmetric to add (`revokeGuardian` → `confirmGuardianRevocation` / `cancelGuardianRevocation`).
- **During lock**: guardian mutations are blocked (`AccountLocked`).

#### Recovery flow
- **Start**: `startRecovery(newKey)` (guardian-only) sets:
  - `executeAfter = now + recoveryPeriod`
  - `lock = now + lockPeriod`
  - `guardiansRequired = ceil(guardianCount / 2)`
- **Complete**: `completeRecovery(signatures)` allowed when `now ≥ executeAfter` and signature count/ordering check passes. On success:
  - old master key is deleted; `newKey` becomes **master**
  - lock is **cleared** (`lock = 0`) even if `lockPeriod` hasn’t elapsed
- **Cancel**: `cancelRecovery()` (Owner/EntryPoint) clears recovery and lock.

## Key Features
* Guardian-based recovery with multi-signature thresholds
* Time-locked operations for security
* Multiple key types support (EOA, WebAuthn, P256)
* Progressive security periods for guardian management
* Account locking during recovery process

```mermaid
graph TB
    subgraph "Contract Inheritance"
        OPF7702Recoverable --> OPF7702
        OPF7702Recoverable --> EIP712
        OPF7702Recoverable --> ERC7201
        OPF7702 --> BaseAccount
    end

    subgraph "Key Components"
        GM[Guardian Management]
        RP[Recovery Process]
        TL[Timelock System]
        KM[Key Management]
    end

    subgraph "Security Layers"
        SP[Security Period]
        SW[Security Window]
        LP[Lock Period]
        RCP[Recovery Period]
    end

    GM --> SP
    GM --> SW
    RP --> LP
    RP --> RCP
    KM --> TL

    subgraph "Storage Structure"
        RD[RecoveryData]
        GD[GuardiansData]
        KD[KeyData]
    end

    RD --> |stores| RKey[Recovery Key]
    RD --> |stores| EA[ExecuteAfter]
    RD --> |stores| GR[Guardians Required]

    GD --> |contains| GA[Guardian Array]
    GD --> |maps| GI[Guardian Identity]
    GD --> |tracks| Lock[Lock Status]
```

## Guardian Management System

### Guardian Lifecycle
```mermaid
stateDiagram-v2
    [*] --> Proposed: proposeGuardian()
    Proposed --> Pending: Security Period Starts
    Pending --> Active: confirmGuardianProposal()
    Proposed --> Cancelled: cancelGuardianProposal()
    
    Active --> Revocation_Scheduled: revokeGuardian()
    Revocation_Scheduled --> Revocation_Pending: Security Period
    Revocation_Pending --> Removed: confirmGuardianRevocation()
    Revocation_Scheduled --> Active: cancelGuardianRevocation()
    
    Cancelled --> [*]
    Removed --> [*]
    
    note right of Pending
        Must confirm within
        Security Window
    end note
    
    note right of Revocation_Pending
        Must confirm within
        Security Window
    end note
```

### Guardian Data Structure
```ts
struct GuardianIdentity {
    bool isActive;      // Currently active guardian
    uint256 index;      // Position in guardians array
    uint256 pending;    // Timestamp for pending action
}

struct GuardiansData {
    bytes32[] guardians;                    // Active guardian hashes
    mapping(bytes32 => GuardianIdentity) data;  // Guardian metadata
    uint256 lock;                           // Global lock timestamp
}
```

### Guardian Operations
#### Adding a Guardian
```mermaid
sequenceDiagram
    participant Owner
    participant Contract
    participant Guardian
    participant Time

    Owner->>Contract: proposeGuardian(guardianHash)
    Contract->>Contract: Validate not duplicate
    Contract->>Contract: Set pending = now + securityPeriod
    Contract-->>Owner: GuardianProposed event
    
    Time->>Time: Security Period passes
    
    Owner->>Contract: confirmGuardianProposal(guardianHash)
    Contract->>Contract: Check: now >= pending
    Contract->>Contract: Check: now <= pending + securityWindow
    Contract->>Contract: Add to guardians array
    Contract->>Contract: Set isActive = true
    Contract-->>Owner: GuardianAdded event
    
    Note over Guardian: Guardian is now active
```
#### Removing a Guardian

```mermaid
sequenceDiagram
    participant Owner
    participant Contract
    participant Guardian
    participant Time

    Owner->>Contract: revokeGuardian(guardianHash)
    Contract->>Contract: Validate is active guardian
    Contract->>Contract: Set pending = now + securityPeriod
    Contract-->>Owner: GuardianRevocationScheduled event
    
    Time->>Time: Security Period passes
    
    Owner->>Contract: confirmGuardianRevocation(guardianHash)
    Contract->>Contract: Check: now >= pending
    Contract->>Contract: Check: now <= pending + securityWindow
    Contract->>Contract: Remove from guardians array
    Contract->>Contract: Delete guardian data
    Contract-->>Owner: GuardianRemoved event
    
    Note over Guardian: Guardian is removed
```

### Recovery Process
#### Recovery Data Structure
```ts
struct RecoveryData {
    Key key;                  // New master key to set
    uint64 executeAfter;      // Timestamp when recovery can execute
    uint32 guardiansRequired; // Number of signatures needed
}
```

#### Recovery Flow
```mermaid
sequenceDiagram
    participant Guardian
    participant Contract
    participant Owner
    participant Time

    Note over Guardian,Time: Recovery Initiation Phase
    Guardian->>Contract: startRecovery(newKey)
    Contract->>Contract: Validate guardian status
    Contract->>Contract: Check wallet not locked
    Contract->>Contract: Check no ongoing recovery
    Contract->>Contract: Validate recovery key
    Contract->>Contract: Calculate executeAfter = now + recoveryPeriod
    Contract->>Contract: Calculate guardiansRequired = ceil(guardianCount / 2)
    Contract->>Contract: Set lock = now + lockPeriod
    Contract-->>Guardian: RecoveryStarted event
    
    Note over Guardian,Time: Recovery Execution Phase
    Time->>Time: Recovery period passes
    
    Guardian->>Contract: completeRecovery(signatures[])
    Contract->>Contract: Check now >= executeAfter
    Contract->>Contract: Validate signature count
    Contract->>Contract: Verify guardian signatures
    Contract->>Contract: Check signatures are sorted/unique
    Contract->>Contract: Delete old master key
    Contract->>Contract: Set new master key
    Contract->>Contract: Clear lock (set to 0)
    Contract-->>Owner: RecoveryCompleted event
    
    Note over Owner,Contract: Alternative: Cancellation
    Owner->>Contract: cancelRecovery()
    Contract->>Contract: Clear recovery data
    Contract->>Contract: Clear lock
    Contract-->>Owner: RecoveryCancelled event
```

#### Recovery Timeline
```mermaid
gantt
    title Recovery Process Timeline
    dateFormat X
    axisFormat %d

    section Security Setup
    Security Period (Guardian Changes) :milestone, m1, 0, 1d
    Security Window (Confirm Changes)  :milestone, m2, 1d, 2d
    
    section Recovery Process
    Recovery Started                   :milestone, recovery_start, 0, 0
    Recovery Period (Wait)            :active, recovery_wait, 0, 5d
    Recovery Executable               :milestone, recovery_exec, 5d, 5d
    
    section Lock Period
    Account Locked                    :crit, lock_period, 0, 10d
    Lock Cleared on Success          :milestone, lock_clear, 5d, 5d
    Lock Auto-Expires               :milestone, lock_auto, 10d, 10d
    
    section Timeline Examples
    Example: recoveryPeriod = 5 days  :done, ex1, 0, 5d
    Example: lockPeriod = 10 days     :done, ex2, 0, 10d
    Example: securityPeriod = 1 day   :done, ex3, 0, 1d
    Example: securityWindow = 1 day   :done, ex4, 1d, 2d
```

### Security Features
#### Time-based Security Parameters
| Parameter         | Purpose                               | Typical Value | Constraint                                  |
|-------------------|---------------------------------------|---------------|---------------------------------------------|
| `recoveryPeriod`  | Delay before recovery can execute     | 2–7 days      | Must be > `securityPeriod + securityWindow` |
| `lockPeriod`      | Account lock duration during recovery | 7–14 days     | Must be > `recoveryPeriod`                  |
| `securityPeriod`  | Timelock for guardian changes         | 1–3 days      | Base security delay                         |
| `securityWindow`  | Window to confirm guardian changes    | 1–2 days      | Action expiry window                        |

#### Security Validations
```mermaid
flowchart TD
    Start([Function Called]) --> CheckLock{Is Wallet Locked?}
    
    CheckLock -->|Yes| LockError[❌ AccountLocked Error]
    CheckLock -->|No| CheckRecovery{Recovery State Check}
    
    CheckRecovery -->|Ongoing & Not Expected| RecoveryError[❌ OngoingRecovery Error]
    CheckRecovery -->|None & Expected| NoRecoveryError[❌ NoOngoingRecovery Error]
    CheckRecovery -->|Valid State| TimeCheck{Time Validation}
    
    TimeCheck --> SecurityPeriodCheck{Security Period<br/>Validation}
    SecurityPeriodCheck -->|Before Period| EarlyError[❌ PendingProposalNotOver Error]
    SecurityPeriodCheck -->|After Window| ExpiredError[❌ PendingProposalExpired Error]
    SecurityPeriodCheck -->|Within Window| ExecutionCheck{Execution Time<br/>Validation}
    
    ExecutionCheck -->|Too Early| ExecutionEarlyError[❌ OngoingRecovery Error]
    ExecutionCheck -->|Valid Time| SignatureCheck{Signature Validation}
    
    SignatureCheck --> CountCheck{Signature Count<br/>Matches Required?}
    CountCheck -->|No| CountError[❌ InvalidSignatureAmount Error]
    CountCheck -->|Yes| ValidGuardianCheck{All Signers<br/>Active Guardians?}
    
    ValidGuardianCheck -->|No| GuardianError[❌ InvalidRecoverySignatures Error]
    ValidGuardianCheck -->|Yes| SortedCheck{Signatures<br/>Sorted & Unique?}
    
    SortedCheck -->|No| SortError[❌ InvalidRecoverySignatures Error]
    SortedCheck -->|Yes| KeyValidation{Recovery Key<br/>Validation}
    
    KeyValidation --> KeyTypeCheck{Supported Key Type?}
    KeyTypeCheck -->|P256/P256NONKEY| UnsupportedError[❌ UnsupportedKeyType Error]
    KeyTypeCheck -->|EOA/WebAuthn| KeyActiveCheck{Key Already Active?}
    
    KeyActiveCheck -->|Yes| ActiveKeyError[❌ RecoverCannotBeActiveKey Error]
    KeyActiveCheck -->|No| GuardianKeyCheck{Key is Guardian?}
    
    GuardianKeyCheck -->|Yes| GuardianOwnerError[❌ GuardianCannotBeOwner Error]
    GuardianKeyCheck -->|No| ZeroCheck{Key is Zero Address?}
    
    ZeroCheck -->|Yes| ZeroError[❌ AddressCantBeZero Error]
    ZeroCheck -->|No| Success[✅ Validation Passed]

    subgraph "Invariant Checks (Constructor)"
        InvariantStart([Constructor]) --> InvariantCheck1{lockPeriod >=<br/>recoveryPeriod?}
        InvariantCheck1 -->|No| InvariantError1[❌ InsecurePeriod Error]
        InvariantCheck1 -->|Yes| InvariantCheck2{recoveryPeriod >=<br/>securityPeriod +<br/>securityWindow?}
        InvariantCheck2 -->|No| InvariantError2[❌ InsecurePeriod Error]
        InvariantCheck2 -->|Yes| InvariantSuccess[✅ Invariants Valid]
    end

    subgraph "Guardian-Specific Validations"
        GuardianStart([Guardian Operation]) --> DuplicateCheck{Guardian Already<br/>Active/Proposed?}
        DuplicateCheck -->|Yes| DuplicateError[❌ DuplicatedGuardian/<br/>DuplicatedProposal Error]
        DuplicateCheck -->|No| SelfCheck{Guardian is<br/>Contract Address?}
        SelfCheck -->|Yes| SelfError[❌ GuardianCannotBeAddressThis Error]
        SelfCheck -->|No| MasterKeyCheck{Guardian is<br/>Master Key?}
        MasterKeyCheck -->|Yes| MasterError[❌ GuardianCannotBeCurrentMasterKey Error]
        MasterKeyCheck -->|No| GuardianSuccess[✅ Guardian Valid]
    end

    style LockError fill:#ffcccc
    style RecoveryError fill:#ffcccc
    style NoRecoveryError fill:#ffcccc
    style EarlyError fill:#ffcccc
    style ExpiredError fill:#ffcccc
    style ExecutionEarlyError fill:#ffcccc
    style CountError fill:#ffcccc
    style GuardianError fill:#ffcccc
    style SortError fill:#ffcccc
    style UnsupportedError fill:#ffcccc
    style ActiveKeyError fill:#ffcccc
    style GuardianOwnerError fill:#ffcccc
    style ZeroError fill:#ffcccc
    style Success fill:#ccffcc
```

### Function Reference
#### Initialization
```ts
function initialize(
    Key calldata _key,
    KeyReg calldata _keyData,
    Key calldata _sessionKey,
    KeyReg calldata _sessionKeyData,
    bytes memory _signature,
    bytes32 _initialGuardian
) external initializer
```
**Purpose**: Initialize the wallet with a master key and first guardian
Parameters:

* `_key`: Master key structure
* `_keyData`: Master key permissions (must be unrestricted)
* `_sessionKey`: Optional session key
* `_sessionKeyData`: Session key permissions
* `_signature`: EIP-712 signature authorizing initialization
* `_initialGuardian`: First guardian hash (required)

### Guardian Management Functions
| Function                          | Purpose                      | Access Control    | Timelock                      |
|-----------------------------------|------------------------------|-------------------|-------------------------------|
| `proposeGuardian(bytes32)`        | Propose new guardian         | Owner/EntryPoint  | Yes — `securityPeriod`        |
| `confirmGuardianProposal(bytes32)`| Activate proposed guardian   | Owner/EntryPoint  | Within `securityWindow`       |
| `cancelGuardianProposal(bytes32)` | Cancel guardian proposal     | Owner/EntryPoint  | Before confirmation           |
| `revokeGuardian(bytes32)`         | Schedule guardian removal    | Owner/EntryPoint  | Yes — `securityPeriod`        |
| `confirmGuardianRevocation(bytes32)`| Remove guardian           | Owner/EntryPoint  | Within `securityWindow`       |
| `cancelGuardianRevocation(bytes32)`| Cancel removal             | Owner/EntryPoint  | Before confirmation           |

### Recovery Functions
| Function                      | Purpose            | Access Control   | Requirements                                   |
|-------------------------------|--------------------|------------------|-----------------------------------------------|
| `startRecovery(Key)`          | Initiate recovery  | Active Guardian  | Not locked, no ongoing recovery               |
| `completeRecovery(bytes[])`   | Execute recovery   | Anyone           | After `recoveryPeriod`, valid signatures      |
| `cancelRecovery()`            | Cancel recovery    | Owner/EntryPoint | Ongoing recovery exists                       |

###  EIP-712 Signature Schemas
#### Recovery Signature
```ts
bytes32 constant RECOVER_TYPEHASH = keccak256(
    "Recover(Key key,uint64 executeAfter,uint32 guardiansRequired)"
);

struct RecoverData {
    Key key;              // New master key
    uint64 executeAfter;  // Execution timestamp
    uint32 guardiansRequired; // Signature threshold
}
```

#### Initialization Signature
```ts
bytes32 constant INIT_TYPEHASH = keccak256(
    "Initialize(bytes key,bytes keyData,bytes sessionKey,bytes sessionKeyData,bytes32 guardian)"
);
```

### Recommended ranges (non-binding)
| Parameter         | Typical Value | Rationale |
|-------------------|---------------|-----------|
| `recoveryPeriod`  | 2–7 days      | Gives time to react to compromise before takeover. Must cover `securityPeriod + securityWindow`. |
| `lockPeriod`      | 7–14 days     | Longer than `recoveryPeriod` to dampen churn; clears early on successful completion. |
| `securityPeriod`  | 1–3 days      | Baseline delay to deter rushed guardian churn. |
| `securityWindow`  | 1–2 days      | Reasonable window to execute after timelock. |

### Edge cases & guarantees
- Proposals are **unique** per guardian; re-proposing within the live window reverts (`DuplicatedProposal` / `DuplicatedRevoke`).
- Confirmations require the proposal to be **known** and within the allowed window.
- Recovery cannot start if:
  - Wallet is already locked (`AccountLocked`), or
  - A recovery is ongoing (`_requireRecovery(false)`).
- Completion requires **sorted, unique** guardian signatures over the EIP-712 digest (`getDigestToSign()`), exactly `guardiansRequired` entries.

### Testing checklist
- Enforce constructor invariants with boundary values (equalities allowed).
- Guardian add/remove: confirm exactly at window edges; reject just outside.
- Recovery: reject completion at `executeAfter - 1`, accept at `executeAfter`.
- Lock behavior: locked right after `startRecovery`; auto-unlocks after `lockPeriod` if not completed; clears on success/cancel.