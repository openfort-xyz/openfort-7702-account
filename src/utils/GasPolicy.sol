// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "src/interfaces/IPolicy.sol";
import "lib/account-abstraction/contracts/core/UserOperationLib.sol";

/**
 * @title   7702/SCA Gas Policy Validator
 * @author  Openfort — @0xkoiner
 * @notice  Enforces per-session gas/cost/tx budgets for EIP-7702 accounts and ERC-4337
 *          Smart Contract Accounts (SCAs). Validates a UserOperation’s gas envelope and
 *          worst-case wei cost before allowing it to proceed, and atomically accounts
 *          usage against the caller’s configured limits.
 *
 * @dev
 * - Storage keying: budgets are stored per (configId, account). The `checkUserOpPolicy`
 *   call requires `msg.sender == userOp.sender` so that only the account whose budgets
 *   are mutated can invoke it (prevents third-party griefing).
 *
 */
contract GasPolicy is IUserOpPolicy {
    using UserOperationLib for PackedUserOperation;

    // ---------------------- Validation return codes ----------------------
    /// @notice Standardized status codes expected by the policy caller.
    uint256 private constant VALIDATION_FAILED = 1;
    uint256 private constant VALIDATION_SUCCESS = 0;

    // ---------------------- % and BPS helpers ----------------------
    // Percent arithmetic
    /// @dev Denominator for percent arithmetic (x * pct / 100).
    uint256 private constant PERCENT_DENOMINATOR = 100;
    /// @dev Fixed 70% helper.
    uint256 private constant PERCENT_70 = 70;

    // Basis-points arithmetic (x * bps / 10_000), often with ceil
    /// @dev Denominator for basis points arithmetic.
    uint256 private constant BPS_DENOMINATOR = 10_000;
    /// @dev Addend to achieve ceil division for positive integers in BPS math.
    uint256 private constant BPS_CEIL_ROUNDING = 9999;

    // -------- Defaults for auto-initialization --------
    uint256 private immutable DEFAULT_PVG; // packaging/bytes for P-256/WebAuthn signatures
    uint256 private immutable DEFAULT_VGL; // validation (session key checks, EIP-1271/P-256 parsing)
    uint256 private immutable DEFAULT_CGL; // ERC20 transfer/batch execution
    uint256 private immutable DEFAULT_PMV; // paymaster validate
    uint256 private immutable DEFAULT_PO; // postOp (token charge/refund)

    /// @dev Minimum gas price assumption in wei for auto-init.
    uint256 private constant DEFAULT_PRICE_FLOOR_WEI = 2 gwei; // at least 2 gwei assumed
    /// @dev Extra headroom on price, expressed in BPS (e.g., 11000 = +10%).
    uint256 private constant PRICE_SAFETY_BPS = 11_000; // +10% headroom on price

    // Safety margins
    /// @dev Safety multiplier on total per-op envelope, expressed in BPS (e.g., 12000 = +20%).
    uint256 private constant SAFETY_BPS = 12_000; // +20% on gas envelope
    /// @dev Default penalty in BPS applied to (CGL + PO) when over threshold (v0.8 semantics).
    uint16 private constant DEFAULT_PENALTY_BPS = 1000; // 10% v0.8 penalty on (CGL+PO) if >= threshold
    /// @dev Gas threshold after which penalty applies.
    uint32 private constant DEFAULT_PENALTY_THR = 40_000; // penalty threshold (v0.8)
    /// @dev Default priority fee to assume for worst-case pricing during auto-init.
    uint256 private constant DEFAULT_PRIORITY_FEE_WEI = 1 gwei; // assumed tip for pricing worst-case

    /// @notice Per-(configId, account) gas/cost/tx budget configuration and live counters.
    mapping(bytes32 id => mapping(address account => GasLimitConfig)) gasLimitConfigs;

    /**
     * @notice Construct the policy with default per-leg gas estimates.
     * @param _defaultPVG Default preVerificationGas leg.
     * @param _defaultVGL Default verificationGasLimit leg.
     * @param _defaultCGL Default callGasLimit leg.
     * @param _defaultPMV Default paymaster verification gas leg.
     * @param _defaultPO  Default postOp gas leg.
     * @dev Reverts if any default leg is zero to avoid nonsensical auto-init computations.
     */
    constructor(
        uint256 _defaultPVG,
        uint256 _defaultVGL,
        uint256 _defaultCGL,
        uint256 _defaultPMV,
        uint256 _defaultPO
    ) {
        if (_defaultPVG == 0 || _defaultVGL == 0 || _defaultCGL == 0 || _defaultPMV == 0 || _defaultPO == 0) {
            revert GasPolicy__InitializationIncorrect();
        }
        DEFAULT_PVG = _defaultPVG;
        DEFAULT_VGL = _defaultVGL;
        DEFAULT_CGL = _defaultCGL;
        DEFAULT_PMV = _defaultPMV;
        DEFAULT_PO = _defaultPO;
    }

    // ---------------------- POLICY CHECK ----------------------
    /**
     * @notice Validate a `PackedUserOperation` against configured budgets and account usage.
     * @param id     Session/policy identifier (e.g., keccak256 over session public key).
     * @param userOp The packed user operation being validated and accounted.
     * @return validationCode `0` on success, `1` on failure (to match AA policy semantics).
     * @dev
     * - Access: Only the account (`userOp.sender`) may call; prevents 3rd-party budget griefing.
     * - Behavior: Computes the gas envelope and worst-case wei cost using `userOp.gasPrice()`,
     *   applies penalty if above threshold, checks per-op and cumulative limits, and increments
     *   usage counters optimistically.
     * - Paymaster note: Only considered when `paymasterAndData.length >= PAYMASTER_DATA_OFFSET`.
     *   If `0 < length < OFFSET`, it is effectively ignored in this implementation.
     */
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp) external returns (uint256) {
        /// @dev Only the account itself may mutate its budgets
        if (msg.sender != userOp.sender) return VALIDATION_FAILED;
        GasLimitConfig storage cfg = gasLimitConfigs[id][userOp.sender];
        if (!cfg.initialized) return VALIDATION_FAILED;

        /// @dev Unpack gas envelope
        uint256 envelopeUnits = 0;

        envelopeUnits += userOp.preVerificationGas;
        envelopeUnits += UserOperationLib.unpackVerificationGasLimit(userOp);
        uint256 cgl = UserOperationLib.unpackCallGasLimit(userOp);

        uint256 postOp = 0;
        if (userOp.paymasterAndData.length >= UserOperationLib.PAYMASTER_DATA_OFFSET) {
            envelopeUnits += UserOperationLib.unpackPaymasterVerificationGasLimit(userOp);
            postOp = UserOperationLib.unpackPostOpGasLimit(userOp);
        }

        envelopeUnits += cgl + postOp;

        /// @dev Worst-case WEI (v0.8 semantics)
        uint256 price = userOp.gasPrice(); // min(maxFeePerGas, basefee + maxPriority)

        uint16 penaltyBps = cfg.penaltyBps == 0 ? DEFAULT_PENALTY_BPS : cfg.penaltyBps;
        uint32 threshold = cfg.penaltyThreshold == 0 ? DEFAULT_PENALTY_THR : cfg.penaltyThreshold;

        uint256 penaltyBasisGas = cgl + postOp;
        uint256 penaltyGas =
            penaltyBasisGas >= threshold ? (penaltyBasisGas * penaltyBps + BPS_CEIL_ROUNDING) / BPS_DENOMINATOR : 0;

        uint256 worstCaseWei = 0;
        if (price != 0) {
            /// @dev envelopeUnits * price
            if (envelopeUnits > type(uint256).max / price) return VALIDATION_FAILED;
            worstCaseWei = envelopeUnits * price;
            /// @dev penaltyGas * price + safe addition
            if (penaltyGas != 0) {
                if (penaltyGas > type(uint256).max / price) return VALIDATION_FAILED;
                uint256 penaltyWei = penaltyGas * price;
                if (worstCaseWei > type(uint256).max - penaltyWei) return VALIDATION_FAILED;
                worstCaseWei += penaltyWei;
            }
        }

        /// @dev Guards
        if (cfg.gasLimit > 0 && cfg.gasUsed + envelopeUnits > cfg.gasLimit) {
            return VALIDATION_FAILED;
        }
        if (cfg.costLimit > 0 && cfg.costUsed + worstCaseWei > cfg.costLimit) {
            return VALIDATION_FAILED;
        }
        if (cfg.perOpMaxCostWei > 0 && worstCaseWei > cfg.perOpMaxCostWei) return VALIDATION_FAILED;
        if (cfg.txLimit > 0 && cfg.txUsed + 1 > cfg.txLimit) return VALIDATION_FAILED;

        if (envelopeUnits > type(uint128).max || worstCaseWei > type(uint128).max) {
            return VALIDATION_FAILED;
        }

        /// @dev Account usage (optimistic)
        unchecked {
            cfg.gasUsed += uint128(envelopeUnits);
            cfg.costUsed += uint128(worstCaseWei);
            cfg.txUsed += 1;
        }

        return VALIDATION_SUCCESS;
    }

    // ---------------------- INITIALIZATION (MANUAL) ----------------------
    /**
     * @notice Initialize budgets manually for a given (configId, account).
     * @param account  The 7702 account or SCA whose budgets are being set. Must be the caller.
     * @param configId Session key / policy identifier.
     * @param initData ABI-encoded `InitData` struct with exact budget values and settings.
     * @dev Reverts if already initialized, or if `gasLimit`/`costLimit` are zero.
     */
    function initializeGasPolicy(address account, bytes32 configId, bytes calldata initData) external {
        require(account == msg.sender, GasPolicy__AccountMustBeSender());
        GasLimitConfig storage cfg = gasLimitConfigs[configId][account];
        if (cfg.initialized) revert GasPolicy__IdExistAlready();

        InitData memory d = abi.decode(initData, (InitData));
        require(d.gasLimit != 0 && d.costLimit != 0, GasPolicy__ZeroBudgets());

        _applyManualConfig(cfg, d);
    }

    // ---------------------- INITIALIZATION (AUTO / DEFAULTS) ----------------------
    /**
     * @notice Initialize budgets using conservative defaults scaled by a tx `limit`.
     * @param account  The 7702 account or SCA whose budgets are being set. Must be the caller.
     * @param configId Session key / policy identifier.
     * @param limit    Number of UserOperations allowed in this session (0 < limit ≤ 2^32-1).
     * @dev
     * - Derives per-op envelope by summing DEFAULT_* legs and applying `SAFETY_BPS`.
     * - Approximates penalty gas from max(70% of envelope, CGL+PO) if ≥ `DEFAULT_PENALTY_THR`.
     * - Prices at `max(block.basefee + DEFAULT_PRIORITY_FEE_WEI, DEFAULT_PRICE_FLOOR_WEI)` and
     *   adds `PRICE_SAFETY_BPS` headroom.
     * - Keeps an `unchecked` block by design; multiplications are guarded by subsequent checks.
     */
    function initializeGasPolicy(address account, bytes32 configId, uint256 limit) external {
        require(account == msg.sender, GasPolicy__AccountMustBeSender());
        GasLimitConfig storage cfg = gasLimitConfigs[configId][account];
        if (cfg.initialized) revert GasPolicy__IdExistAlready();
        require(limit > 0 && limit <= type(uint32).max, GasPolicy__BadLimit());

        /// @dev Envelope units per op with safety (includes PM legs so it also covers sponsored ops)
        uint256 rawEnvelope = DEFAULT_PVG + DEFAULT_VGL + DEFAULT_CGL + DEFAULT_PMV + DEFAULT_PO;
        uint256 perOpEnvelopeUnits = (rawEnvelope * SAFETY_BPS + BPS_CEIL_ROUNDING) / BPS_DENOMINATOR;

        /// @dev Conservative penalty basis: assume most of the envelope is execution/postOp
        ///      Use 70% of the envelope OR the DEFAULT_CGL+DEFAULT_PO, whichever is larger.
        uint256 seventyPct = (perOpEnvelopeUnits * PERCENT_70) / PERCENT_DENOMINATOR;
        uint256 execSideAssumed = seventyPct > (DEFAULT_CGL + DEFAULT_PO) ? seventyPct : (DEFAULT_CGL + DEFAULT_PO);

        uint256 perOpPenaltyGas = execSideAssumed >= DEFAULT_PENALTY_THR
            ? (execSideAssumed * DEFAULT_PENALTY_BPS + BPS_CEIL_ROUNDING) / BPS_DENOMINATOR
            : 0;

        /// @dev Price assumption: basefee + 1 gwei, but at least 2 gwei, then +10% safety
        uint256 priceAssumption = block.basefee + DEFAULT_PRIORITY_FEE_WEI;
        if (priceAssumption < DEFAULT_PRICE_FLOOR_WEI) priceAssumption = DEFAULT_PRICE_FLOOR_WEI;
        priceAssumption = (priceAssumption * PRICE_SAFETY_BPS + BPS_CEIL_ROUNDING) / BPS_DENOMINATOR;

        /// @dev Per-op max wei (overflow-checked)
        unchecked {
            uint256 unitsPlusPenalty = perOpEnvelopeUnits + perOpPenaltyGas;
            if (priceAssumption != 0 && unitsPlusPenalty > type(uint256).max / priceAssumption) {
                revert GasPolicy_PerOpCostOverflow();
            }
            uint256 perOpMaxCostWei256 = unitsPlusPenalty * priceAssumption;
            require(perOpMaxCostWei256 <= type(uint128).max, GasPolicy_PerOpCostHigh());

            // 5) Cumulative budgets
            uint256 gasLimit256 = perOpEnvelopeUnits * limit;
            uint256 costLimit256 = perOpMaxCostWei256 * limit;

            require(gasLimit256 <= type(uint128).max, GasPolicy_GasLimitHigh());
            require(costLimit256 <= type(uint128).max, GasPolicy_CostLimitHigh());

            _applyAutoConfig(
                cfg, uint128(gasLimit256), uint128(costLimit256), uint128(perOpMaxCostWei256), uint32(limit)
            );
        }
    }

    /**
     * @notice Apply manual configuration to a `GasLimitConfig` and mark initialized.
     * @param cfg Storage pointer to the target config.
     * @param d   Decoded InitData with explicit budgets and penalty settings.
     * @dev Sets defaults for penalty fields when zero; resets counters to zero.
     */
    function _applyManualConfig(GasLimitConfig storage cfg, InitData memory d) private {
        // Required budgets already checked by caller
        cfg.gasLimit = d.gasLimit;
        cfg.costLimit = d.costLimit;
        cfg.perOpMaxCostWei = d.perOpMaxCostWei; // 0 allowed (disables per-op cap)
        cfg.txLimit = d.txLimit; // 0 allowed (unlimited)

        // Penalty config with sane defaults
        cfg.penaltyBps = d.penaltyBps == 0 ? DEFAULT_PENALTY_BPS : d.penaltyBps;
        cfg.penaltyThreshold = d.penaltyThreshold == 0 ? DEFAULT_PENALTY_THR : d.penaltyThreshold;

        _resetCountersAndMarkInitialized(cfg);
    }

    /**
     * @notice Apply auto-derived configuration and mark initialized.
     * @param cfg              Storage pointer to the target config.
     * @param gasLimit         Total cumulative gas units allowed for the session.
     * @param costLimit        Total cumulative wei allowed for the session.
     * @param perOpMaxCostWei  Max wei per single operation (0 disables the cap).
     * @param txLimit          Max number of operations (0 means unlimited).
     * @dev Resets counters to zero and applies default penalty settings.
     */
    function _applyAutoConfig(
        GasLimitConfig storage cfg,
        uint128 gasLimit,
        uint128 costLimit,
        uint128 perOpMaxCostWei,
        uint32 txLimit
    )
        private
    {
        cfg.gasLimit = gasLimit;
        cfg.costLimit = costLimit;
        cfg.perOpMaxCostWei = perOpMaxCostWei;
        cfg.txLimit = txLimit;

        // Defaults for v0.8
        cfg.penaltyBps = DEFAULT_PENALTY_BPS;
        cfg.penaltyThreshold = DEFAULT_PENALTY_THR;

        _resetCountersAndMarkInitialized(cfg);
    }

    /**
     * @notice Zero out usage counters and set `initialized = true`.
     * @param cfg Storage pointer to the target config.
     */
    function _resetCountersAndMarkInitialized(GasLimitConfig storage cfg) private {
        cfg.gasUsed = 0;
        cfg.costUsed = 0;
        cfg.txUsed = 0;
        cfg.initialized = true;
    }

    // ---------------------- VIEWS ----------------------
    /**
     * @notice Read a compact view of the gas/cost budgets and usage for (configId, account).
     * @param configId  Session/policy identifier.
     * @param userOpSender The account address whose config is queried.
     * @return gasLimit  Cumulative gas units allowed.
     * @return gasUsed   Gas units consumed so far.
     * @return costLimit Cumulative wei allowed.
     * @return costUsed  Wei consumed so far.
     */
    function getGasConfig(
        bytes32 configId,
        address userOpSender
    )
        external
        view
        returns (uint128 gasLimit, uint128 gasUsed, uint128 costLimit, uint128 costUsed)
    {
        GasLimitConfig storage c = gasLimitConfigs[configId][userOpSender];
        return (c.gasLimit, c.gasUsed, c.costLimit, c.costUsed);
    }

    /**
     * @notice Read the full `GasLimitConfig` struct for (configId, account).
     * @param configId  Session/policy identifier.
     * @param userOpSender The account address whose config is queried.
     * @return The full GasLimitConfig stored at (configId, userOpSender).
     */
    function getGasConfigEx(bytes32 configId, address userOpSender) external view returns (GasLimitConfig memory) {
        return gasLimitConfigs[configId][userOpSender];
    }

    // ---------------------- InitData for manual path ----------------------
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
            || interfaceID == type(IUserOpPolicy).interfaceId;
    }
}

/**
 * - Gas envelope accounted per op:
 *     PVG (preVerificationGas)
 *   + VGL (verificationGasLimit)
 *   + PMV (paymasterVerificationGasLimit, if present)
 *   + CGL (callGasLimit)
 *   + PO  (postOpGasLimit, if present)
 *
 * - Pricing: computes worst-case wei using `userOp.gasPrice()` (min(maxFeePerGas,
 *   basefee + maxPriorityFee)), plus an optional v0.8 penalty on (CGL + PO) if above
 *   a threshold. Ceil division is used for BPS math.
 *
 * - Limits:
 *   * `gasLimit` / `costLimit` — cumulative ceilings across the session.
 *   * `perOpMaxCostWei` — single-op ceiling (0 disables).
 *   * `txLimit` — max number of ops (0 = unlimited).
 *
 * - Initialization:
 *   * Manual: supply exact budgets via `InitData`.
 *   * Auto: derives conservative defaults from provided DEFAULT_* legs, a safety BPS,
 *     penalty assumptions, and `block.basefee` (+priority fee with floor), then scales
 *     cumulatives by `limit`.
 *
 * - Arithmetic safety:
 *   * `checkUserOpPolicy` guards all mul/add overflows, including the final wei sum.
 *   * Auto-init keeps an `unchecked` block but pre-checks every addition/multiplication
 *     to prevent wraparound before casting to `uint128`.
 *
 * - Input validation:
 *   * Rejects malformed `paymasterAndData` where 0 < length < PAYMASTER_DATA_OFFSET.
 *   * Fails fast if config is not initialized.
 *
 * - Interfaces: supports IERC165, IPolicy, and IUserOpPolicy.
 *
 * @custom:terms
 * - account: The 7702 account or SCA whose `userOp.sender` matches `msg.sender` during
 *   `checkUserOpPolicy`.
 * - configId: Session key / policy identifier (e.g., keccak256(pubkey parts)).
 *
 * @custom:security
 * - No external calls in `checkUserOpPolicy`; only storage writes to the caller’s slot.
 * - Consider emitting events on init and accounting if off-chain reconciliation is needed.
 */
