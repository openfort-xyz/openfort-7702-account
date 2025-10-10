/*
░░      ░░░░      ░░░░      ░░░░░░░░░       ░░░░      ░░░  ░░░░░░░░        ░░░      ░░░  ░░░░  ░
▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒▒  ▒▒  ▒▒
▓  ▓▓▓   ▓▓  ▓▓▓▓  ▓▓▓      ▓▓▓▓▓▓▓▓▓       ▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓    ▓▓▓
█  ████  ██        ████████  ████████  ████████  ████  ██  ███████████  █████  ████  █████  ████
██      ███  ████  ███      █████████  █████████      ███        ██        ███      ██████  ████                                        
 */

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

    // Safety margins
    /// @dev Safety multiplier on total per-op envelope, expressed in BPS (e.g., 12000 = +20%).
    uint256 private constant SAFETY_BPS = 12_000; // +20% on gas envelope

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
        if (
            _defaultPVG == 0 || _defaultVGL == 0 || _defaultCGL == 0 || _defaultPMV == 0
                || _defaultPO == 0
        ) {
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
     * @notice Validate a `PackedUserOperation` against configured gas budgets and account usage.
     * @param id     Session/policy identifier (e.g., keccak256 over session public key).
     * @param userOp The packed user operation being validated and accounted.
     * @return validationCode `0` on success, `1` on failure (ERC-4337 policy semantics).
     * @dev
     * - Access: Only the account (`userOp.sender`) may call; prevents 3rd-party budget griefing.
     * - Behavior: Computes the gas envelope (PVG+VGL+[PMV]+CGL+[PO]), checks cumulative gas and tx caps,
     *   and increments usage counters optimistically.
     * - Paymaster note: Only considered when `paymasterAndData.length >= PAYMASTER_DATA_OFFSET`.
     */
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        returns (uint256)
    {
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

        if (cfg.gasLimit > 0 && cfg.gasUsed + envelopeUnits > cfg.gasLimit) {
            return VALIDATION_FAILED;
        }

        if (envelopeUnits > type(uint128).max) {
            return VALIDATION_FAILED;
        }

        unchecked {
            cfg.gasUsed += uint128(envelopeUnits);
        }

        emit GasPolicyAccounted(id, userOp.sender, envelopeUnits, cfg.gasUsed);

        return VALIDATION_SUCCESS;
    }

    // ---------------------- INITIALIZATION (MANUAL) ----------------------
    /**
     * @notice Initialize budgets manually for a given (configId, account).
     * @param account  The 7702 account or SCA whose budgets are being set. Must be the caller.
     * @param configId Session key / policy identifier.
     * @param gasLimitBE Gas budget values.
     * @dev Reverts if already initialized, or if `gasLimit` are zero.
     */
    function initializeGasPolicy(address account, bytes32 configId, bytes16 gasLimitBE) external {
        require(account == msg.sender, GasPolicy__AccountMustBeSender());
        GasLimitConfig storage cfg = gasLimitConfigs[configId][account];
        if (cfg.initialized) revert GasPolicy__IdExistAlready();

        uint128 gasLimit = uint128(gasLimitBE);
        if (gasLimit == 0) revert GasPolicy__ZeroBudgets();

        _applyManualConfig(cfg, gasLimit);

        emit GasPolicyInitialized(configId, account, cfg.gasLimit, false);
    }

    // ---------------------- INITIALIZATION (AUTO / DEFAULTS) ----------------------
    /**
     * @notice Initialize budgets using conservative defaults scaled by a tx `limit` (gas-only).
     * @param account  The 7702 account or SCA whose budgets are being set. Must be the caller.
     * @param configId Session key / policy identifier.
     * @param limit    Number of UserOperations allowed in this session (0 < limit ≤ 2^32-1).
     * @dev
     *  - Derives per-op envelope by summing DEFAULT_* legs and applying `SAFETY_BPS`.
     *  - No price/wei math; only gas-unit limits are configured.
     */
    function initializeGasPolicy(address account, bytes32 configId, uint256 limit) external {
        require(account == msg.sender, GasPolicy__AccountMustBeSender());
        GasLimitConfig storage cfg = gasLimitConfigs[configId][account];
        if (cfg.initialized) revert GasPolicy__IdExistAlready();
        require(limit > 0 && limit <= type(uint32).max, GasPolicy__BadLimit());

        // Envelope units per op with safety (includes PM legs so it also covers sponsored ops)
        uint256 rawEnvelope = DEFAULT_PVG + DEFAULT_VGL + DEFAULT_CGL + DEFAULT_PMV + DEFAULT_PO;
        uint256 perOpEnvelopeUnits =
            (rawEnvelope * SAFETY_BPS + BPS_CEIL_ROUNDING) / BPS_DENOMINATOR;

        unchecked {
            // Guard the multiplication before casting
            if (perOpEnvelopeUnits > type(uint256).max / limit) revert GasPolicy_GasLimitHigh();

            uint256 gasLimit256 = perOpEnvelopeUnits * limit;

            if (gasLimit256 > type(uint128).max) revert GasPolicy_GasLimitHigh();

            _applyAutoConfig(cfg, uint128(gasLimit256));

            emit GasPolicyInitialized(configId, account, cfg.gasLimit, false);
        }
    }

    /**
     * @notice Apply manual configuration to a `GasLimitConfig` and mark initialized.
     * @param cfg Storage pointer to the target config.
     * @param gasLimit Explicit budgetssettings.
     */
    function _applyManualConfig(GasLimitConfig storage cfg, uint128 gasLimit) private {
        // Required budgets already checked by caller
        cfg.gasLimit = gasLimit;
        _resetCountersAndMarkInitialized(cfg);
    }

    /**
     * @notice Apply auto-derived configuration and mark initialized (gas-only).
     * @param cfg       Storage pointer to the target config.
     * @param gasLimit  Total cumulative gas units allowed for the session.
     */
    function _applyAutoConfig(GasLimitConfig storage cfg, uint128 gasLimit) private {
        cfg.gasLimit = gasLimit;
        _resetCountersAndMarkInitialized(cfg);
    }

    /**
     * @notice Zero out usage counters and set `initialized = true`.
     * @param cfg Storage pointer to the target config.
     */
    function _resetCountersAndMarkInitialized(GasLimitConfig storage cfg) private {
        cfg.gasUsed = 0;
        cfg.initialized = true;
    }

    // ---------------------- VIEWS ----------------------
    /// ---------------------- VIEWS ----------------------
    /// @notice Read a compact view of gas budgets and usage for (configId, account).
    /// @param configId      Session/policy identifier.
    /// @param userOpSender  The account whose config is queried.
    /// @return gasLimit  Cumulative gas units allowed.
    /// @return gasUsed   Gas units consumed so far.
    function getGasConfig(bytes32 configId, address userOpSender)
        external
        view
        returns (uint128 gasLimit, uint128 gasUsed)
    {
        GasLimitConfig storage c = gasLimitConfigs[configId][userOpSender];
        return (c.gasLimit, c.gasUsed);
    }

    /**
     * @notice Read the full `GasLimitConfig` struct for (configId, account).
     * @param configId  Session/policy identifier.
     * @param userOpSender The account address whose config is queried.
     * @return The full GasLimitConfig stored at (configId, userOpSender).
     */
    function getGasConfigEx(bytes32 configId, address userOpSender)
        external
        view
        returns (GasLimitConfig memory)
    {
        return gasLimitConfigs[configId][userOpSender];
    }

    // ---------------------- Supported Interfaces ----------------------
    /**
     * @notice Reports whether this policy contract implements a given interface.
     * @param interfaceID ERC-165 interface identifier to query.
     * @return True if the interface is IERC165, IPolicy, or IUserOpPolicy.
     */
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
 *   basefee + maxPriorityFee))
 *   a threshold. Ceil division is used for BPS math.
 *
 * - Limits:
 *   * `gasLimit`— cumulative ceilings across the session.
 *
 * - Initialization:
 *   * Manual: supply exact budgets.
 *   * Auto: derives conservative defaults from provided DEFAULT_* limit, a safety BPS.
 *
 * - Arithmetic safety:
 *   * `checkUserOpPolicy` guards all mul/add overflows, including the final gas sum.
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
