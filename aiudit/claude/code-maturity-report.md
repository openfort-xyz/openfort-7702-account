# Code Maturity Assessment: Openfort 7702 Account

**Framework**: Trail of Bits — Building Secure Contracts Code Maturity Evaluation v0.1.0
**Assessed**: 2026-02-19
**Scope**: `/src/` — 34 Solidity files, 5,746 lines
**Platform**: Solidity 0.8.29, Foundry, ERC-4337 + EIP-7702

---

## Executive Summary

**Overall Maturity: 2.6 / 4 (Moderate)**

### Top 3 Strengths
1. **Comprehensive event coverage** — Nearly every critical state change emits an indexed event with relevant parameters
2. **Layered session key permission model** — Four-level authorization (quota, canCall, tokenSpend, self-call block) with wildcard support
3. **Strong documentation suite** — 1,856 lines of architecture docs with Mermaid diagrams, sequence flows, and security considerations

### Top 3 Critical Gaps
1. **`forge test` is commented out in CI** — No automated test gating on PRs; breaking changes can be merged silently
2. **No timelocks on critical admin operations** — `upgradeProxyDelegation`, `setEntryPoint`, `setWebAuthnVerifier`, `setGasPolicy` execute instantly
3. **No formal verification** — No Certora, Halmos, or HEVM proofs for any invariant despite the contract managing key custody

### Priority Recommendations
1. **CRITICAL**: Re-enable `forge test` in CI immediately and increase fuzz runs to 10,000+
2. **HIGH**: Add timelocks (or at minimum events + monitoring alerts) for `upgradeProxyDelegation` and `setEntryPoint`
3. **HIGH**: Add `/// @solidity memory-safe-assembly` annotations and replace magic offset `+5` with a named constant

---

## Maturity Scorecard

| # | Category | Rating | Score | Key Finding |
|---|----------|--------|-------|-------------|
| 1 | Arithmetic | Moderate | 3/4 | Solidity 0.8.29 built-ins; 7 `unchecked` blocks all justified; minor `gasUsed` wrap edge case |
| 2 | Auditing (Events) | Moderate | 3/4 | Comprehensive events; `fallback()` and `upgradeProxyDelegation` missing events; interface mismatch |
| 3 | Authentication / Access Controls | Moderate | 3/4 | `_requireForExecute` uniformly applied; `completeRecovery()` intentionally open; P256 master-key bypass implicit |
| 4 | Complexity Management | Moderate | 2/4 | 3x duplicated validation pattern; `tokenAmout` typo; 6-level inheritance; floating pragma inconsistency |
| 5 | Decentralization | Moderate | 2/4 | EOA owner sovereignty; no timelocks on upgrades/address setters; single guardian can lock wallet |
| 6 | Documentation | Satisfactory | 3/4 | 1,856 lines of docs; stale `getDigestToInit` NatSpec; no glossary; no consolidated invariants doc |
| 7 | Transaction Ordering (MEV) | Moderate | 2/4 | Not a DeFi protocol; `completeRecovery` front-run risk undocumented; bundler quota race |
| 8 | Low-Level Manipulation | Satisfactory | 3/4 | Assembly justified and correct; missing `memory-safe` annotations; magic `+5` offset |
| 9 | Testing & Verification | Moderate | 2/4 | 9,674 test lines; 81-99% coverage; `forge test` commented out in CI; 256 fuzz runs; no formal verification |

---

## Detailed Analysis

---

### 1. ARITHMETIC — Moderate (3/4)

**Strengths:**
- Solidity `^0.8.29` provides built-in overflow protection across all contracts
- All 7 `unchecked` blocks are justified with preceding guard checks
- Ceiling-division BPS pattern in GasPolicy is correct (`BPS_CEIL_ROUNDING = 9999`)
- `SafeCast.toUint64/toUint32` used for recovery quorum and timestamps
- `rawDiv`/`rawMul` in `startOfSpendPeriod` are safe for timestamp flooring

**Gaps:**

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| A-1 | Low | `GasPolicy.sol:132-134` | `unchecked { cfg.gasUsed += uint128(envelopeUnits) }` — if `gasLimit == 0` (no cap) and cumulative sum crosses `uint128.max`, it silently wraps. The budget check at line 124 uses `cfg.gasUsed + envelopeUnits > cfg.gasLimit` which catches the normal case, but a zero gasLimit bypasses this. |
| A-2 | Info | `KeysManager.sol:270-272` | `unchecked { id++ }` has no explanatory comment. Risk is negligible but documentation should match other unchecked blocks. |
| A-3 | Info | — | No dedicated edge-case fuzz tests for arithmetic boundaries (e.g., `gasUsed` at max, `limits = 1` decremented twice, `tokenSpend.spent` at limit boundary). |

---

### 2. AUDITING (Events) — Moderate (3/4)

**Strengths:**
- 25+ distinct events across interfaces covering key lifecycle, guardian lifecycle, recovery flow, gas policy, and deposits
- Indexed parameters on key identifiers (`keyId`, `guardian`, `configId`, `account`)
- `GasPolicyAccounted` event tracks per-operation gas envelope for off-chain monitoring

**Gaps:**

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| E-1 | Medium | `BaseOPF7702.sol:75` | `fallback()` receives ETH silently — no `DepositAdded` event unlike `receive()`. Funds with unrecognized calldata are untracked. |
| E-2 | Medium | `OPFMain.sol:57-59` | `upgradeProxyDelegation()` emits no event. A delegation change is critical with no on-chain audit trail. |
| E-3 | Low | `IBaseOPF7702.sol:44-52` | Event signatures in `IBaseOPF7702` differ from what `UpgradeAddress` actually emits (1 vs 2 parameters). `GasPolicyUpdated` not declared in interface. |
| E-4 | Low | `OPF7702Recoverable.sol:160` + `SocialRecover.sol:361` | `RecoveryCompleted` emitted twice per recovery — once in each contract. Indexers must deduplicate. |
| E-5 | Info | `KeysManager.sol:190` | `updateTokenSpend` emits `TokenSpendSet` instead of a distinct `TokenSpendUpdated` — creation vs update indistinguishable off-chain. |

---

### 3. AUTHENTICATION / ACCESS CONTROLS — Moderate (3/4)

**Strengths:**
- `_requireForExecute()` uniformly applied to all 16+ state-changing functions
- `_requireFromEntryPoint()` correctly restricts `validateUserOp` to EntryPoint only
- Session keys blocked from self-calls (`call.target == address(this)` returns false)
- ERC-1271 intentionally excludes session keys to prevent Permit2 bypass
- `nonReentrant` guard on `execute()` covers the critical execution path
- Guardian management gated by `msg.sender == _account` consistently

**Gaps:**

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| C-1 | Medium | `OPF7702Recoverable.sol:137` | `completeRecovery()` has no access control — any EOA can call. Security relies entirely on immutable `RECOVERY_MANAGER`. Intentional by design but should be explicitly documented. |
| C-2 | Low | `OPF7702.sol:256-289` | `_validateKeyTypeP256` lacks the explicit master-key early-return present in EOA/WebAuthn paths. Currently safe because P256 is rejected as master key type at registration, but this is an implicit dependency. |
| C-3 | Low | `OPF7702Recoverable.sol:146-153` | `_deleteOldKeys()` only deletes `keys[keyId]` and `idKeys[0]` — does NOT clear `permissions` or `spendStore` for old keyId. Residual data persists in storage. |
| C-4 | Low | `OPF7702Recoverable.sol:158-173` | `_setNewMasterKey` bypasses `_addKey`, manually managing `idKeys[0]` without incrementing `id`. Creates silent divergence from normal registration path. |

---

### 4. COMPLEXITY MANAGEMENT — Moderate (2/4)

**Strengths:**
- Each contract in the inheritance chain has a clear single responsibility
- Function naming is generally descriptive (`_requireForExecute`, `_validateKeyTypeEOA`, `_isCanCall`)
- Library separation (`KeysManagerLib`, `KeyDataValidationLib`, `SigLengthLib`, `UpgradeAddress`) reduces contract size

**Gaps:**

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| X-1 | Medium | `OPF7702.sol:153-169, 224-239, 278-289` | Validation pattern (keyValidation → isDelegatedControl → gasPolicy → isValidKey → packValidationData) duplicated 3x across EOA/WebAuthn/P256. Should be extracted to a shared helper. |
| X-2 | Low | `OPF7702.sol:493` | `tokenAmout` typo used 9+ times throughout the file. Should be `tokenAmount`. |
| X-3 | Low | Multiple | Pragma inconsistency: `BaseOPF7702.sol`, `Execution.sol`, `OPF7702.sol` use `^0.8.29` (floating) while `KeysManager.sol`, `OPF7702Recoverable.sol`, `OPFMain.sol` use fixed `0.8.29`. |
| X-4 | Info | `OPF7702.sol:611-675` | `_validateWebAuthnSignature` has double nested try/catch (65 lines) — highest complexity function in the codebase. |
| X-5 | Info | Inheritance | 6-level inheritance depth (`OPFMain` → ... → `BaseOPF7702`). Each layer is justified but makes top-down reading difficult. |

---

### 5. DECENTRALIZATION — Moderate (2/4)

**Strengths:**
- EOA owner retains full sovereignty — no Openfort-controlled privileged address in the code path
- EIP-7702 provides clean opt-out: owner can `setCode` to `address(0)` to revert to standard EOA
- Social recovery uses timelocked guardian changes (`securityPeriod` + `securityWindow`)
- Recovery quorum is majority (`ceil(guardianCount / 2)`) — no single guardian can complete recovery
- Constructor enforces `lockPeriod >= recoveryPeriod >= securityPeriod + securityWindow`

**Gaps:**

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| D-1 | High | `OPFMain.sol:57-59` | No timelock on `upgradeProxyDelegation` — a compromised master key can immediately replace the implementation with arbitrary code. |
| D-2 | High | `BaseOPF7702.sol:91-127` | No timelock on `setEntryPoint`, `setWebAuthnVerifier`, `setGasPolicy` — these can instantly redirect trust to malicious contracts. |
| D-3 | Medium | `SocialRecover.sol:280` | Single guardian can lock wallet for full `lockPeriod` by calling `startRecovery`. Acknowledged tradeoff but not documented as a risk. |
| D-4 | Low | — | `RECOVERY_MANAGER` is immutable — bugs in `SocialRecover.sol` cannot be patched without full `upgradeProxyDelegation`. |

---

### 6. DOCUMENTATION — Satisfactory (3/4)

**Strengths:**
- 1,856 lines of documentation across `docs/` with Mermaid diagrams, sequence flows, Gantt timelines
- `docs/Recovery.md` (477 lines) includes state machine diagrams, invariants section, edge cases, testing checklist
- `docs/SessionKeys.md` covers permission system, validation pipeline, spend enforcement
- High NatSpec coverage — 333 `@notice`/`@dev`/`@param`/`@return` tags across core files
- Quickstart with TypeScript examples using viem/permissionless

**Gaps:**

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| DOC-1 | Medium | `OPF7702Recoverable.sol:196-210` | Stale `getDigestToInit` NatSpec lists removed fields (`eoaAddress`, `whitelisting`, `contractAddress`, `allowedSelectors`, `ethLimit`). Will cause off-chain signing failures for anyone following comments. |
| DOC-2 | Low | `docs/README.md:235` | References `clearTokenSpend(keyId)` — actual function is `clearSpendPermissions(keyId)`. |
| DOC-3 | Low | — | No consolidated invariants document — key system invariants scattered across NatSpec and individual docs. |
| DOC-4 | Low | — | No glossary for domain terms (`keyId`, `KeyControl`, `SpendPeriod`, `computeHash`, `ANY_TARGET`, etc.). |
| DOC-5 | Info | `OPF7702.sol:109` | Leftover `// Todo; No need to Revret` development comment with typo. |
| DOC-6 | Info | `OPF7702Recoverable.sol:88-90` | Stale references to `whitelisting`, `whitelistedContracts` from previous version. |

---

### 7. TRANSACTION ORDERING RISKS (MEV) — Moderate (2/4)

**Context**: This is a smart account, not a DeFi protocol. No AMM/oracle/liquidity exposure.

**Strengths:**
- No price-sensitive operations in the contract itself
- Recovery timelock provides mandatory waiting period before completion
- Session key quota is consumed atomically in validation phase

**Gaps:**

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| MEV-1 | Low | `OPF7702Recoverable.sol:137` | `completeRecovery` is permissionless — guardian signatures broadcast in mempool can be extracted and submitted by MEV bots. Outcome is identical but creates gas-griefing vector. |
| MEV-2 | Info | — | Bundler-level session-key quota race: two UserOps from the same session key can both pass validation in the same block if a bundler includes both. Structural ERC-4337 limitation. |
| MEV-3 | Info | — | `startRecovery` + `completeRecovery` asymmetry (guardian-only vs. permissionless) undocumented in NatSpec. |

---

### 8. LOW-LEVEL MANIPULATION — Satisfactory (3/4)

**Strengths:**
- Assembly in `_execute` (revert bubble-up) is standard pattern with `@solidity memory-safe-assembly`
- `UpgradeAddress` MSB-flag packing includes canonical address check (`a >> 160 != 0`)
- `_clearStorage` assembly accompanied by detailed storage layout table (lines 161-185)
- `packCanExecute`/`unpackCanExecute` use `("memory-safe")` qualifier correctly
- Cryptographic assembly (P256.sol, WebAuthn.sol) from audited Solady library — not modified

**Gaps:**

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| ASM-1 | Low | `OPF7702.sol:439, 486` | Missing `/// @solidity memory-safe-assembly` on selector-extraction blocks in `_isCanCall` and `_isTokenSpend`. |
| ASM-2 | Low | `BaseOPF7702.sol:158` | Magic offset `+5` for reentrancy guard (`sstore(add(baseSlot, 5), 0)`). Should be a named constant to prevent silent breakage on layout changes. |
| ASM-3 | Info | `KeysManagerLib.sol:125-129` | `computeKeyId` uses scratch space (`mstore(0x00, ...)`) without `memory-safe` qualifier or explanatory comment. |

---

### 9. TESTING & VERIFICATION — Moderate (2/4)

**Strengths:**
- 9,674 lines of tests across unit, fuzz, invariant, gas, integration, and storage categories
- Line coverage: 81-99% across all core contracts; function coverage: 90-100%
- Invariant tests use proper handler pattern with `StdInvariant`
- `vm.etch` correctly simulates EIP-7702 delegation in tests
- Prior professional audit with fix tracking (`audit/Progress/FixFile.txt` — 17 findings addressed)

**Gaps:**

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| T-1 | **Critical** | `.github/workflows/test.yml:53-56` | `forge test` is **commented out** in CI. No automated test gating on PRs. |
| T-2 | High | `foundry.toml:15` | Fuzz runs = 256 — below production standard (recommend 10,000+). |
| T-3 | High | `foundry.toml:20` | `fail_on_revert = false` in invariant config — unexpected reverts silently swallowed, masking bugs. |
| T-4 | Medium | — | No formal verification (Certora, Halmos, HEVM) for any invariant. |
| T-5 | Medium | `audit/Progress/FixFile.txt` | OPF-15 and OPF-16 have no documented resolution. |
| T-6 | Low | `coverage.txt` | `BaseOPF7702.sol` branch coverage: 71.43%; `GasPolicy.sol`: 73.33%. Critical paths partially untested. |
| T-7 | Low | `coverage.txt` | `OPFMain.sol` statement coverage: 50.00% — lowest in codebase. |

---

## Improvement Roadmap

### CRITICAL (Immediate)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 1 | **Re-enable `forge test` in CI** — uncomment lines 53-56 in `.github/workflows/test.yml` | 5 min | Prevents merging broken code |
| 2 | **Increase fuzz runs to 10,000+** for default profile, 50,000+ for CI profile | 5 min | Dramatically increases confidence in edge cases |
| 3 | **Set `fail_on_revert = true`** in invariant config (or add explicit `try/catch` in handlers) | 30 min | Surfaces hidden invariant violations |

### HIGH (1-2 months)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 4 | **Add timelocks** to `upgradeProxyDelegation`, `setEntryPoint`, `setWebAuthnVerifier`, `setGasPolicy` | 2-3 days | Prevents instant takeover on key compromise |
| 5 | **Emit events** for `upgradeProxyDelegation` and `fallback()` ETH deposits | 1 hour | Enables off-chain monitoring of critical operations |
| 6 | **Fix stale NatSpec** in `getDigestToInit` (OPF7702Recoverable.sol:196-210) | 30 min | Prevents off-chain signing failures |
| 7 | **Extract shared validation helper** from 3x duplicated pattern in `_validateKeyType*` | 2-3 hours | Reduces ~30 lines of duplication and maintenance risk |
| 8 | **Replace magic `+5` offset** in `_clearStorage` with a named constant | 15 min | Prevents silent breakage on storage layout changes |
| 9 | **Fix `tokenAmout` typo** across OPF7702.sol | 10 min | Code quality |
| 10 | **Resolve OPF-15 and OPF-16** audit findings or document as accepted risk | Variable | Closes audit trail |

### MEDIUM (2-4 months)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 11 | **Add formal verification** (Certora or Halmos) for key invariants: quota never negative, master key unique, recovery installs valid key | 2-4 weeks | Highest confidence for custody-critical logic |
| 12 | **Create consolidated invariants document** listing all system invariants with code references | 1-2 days | Serves auditors and maintainers |
| 13 | **Create domain glossary** for terms like `keyId`, `KeyControl`, `SpendPeriod`, `computeHash` | 1 day | Reduces onboarding time |
| 14 | **Increase branch coverage** for `BaseOPF7702.sol` (71%) and `GasPolicy.sol` (73%) to 90%+ | 1-2 days | Covers untested edge cases |
| 15 | **Standardize pragma** — use fixed `0.8.29` across all source files | 15 min | Eliminates compilation ambiguity |
| 16 | **Add `memory-safe` annotations** to assembly blocks in `_isCanCall` and `_isTokenSpend` | 10 min | Compiler optimization + documentation completeness |
| 17 | **Document `completeRecovery` permissionless design** in NatSpec and recovery docs as intentional | 30 min | Prevents future auditor confusion |

---

*Report generated using Trail of Bits Code Maturity Evaluation Framework v0.1.0*
