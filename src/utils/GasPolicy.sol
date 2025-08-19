// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "src/interfaces/IPolicy.sol";
import "lib/account-abstraction/contracts/core/UserOperationLib.sol";

contract GasPolicy is IUserOpPolicy {
    using UserOperationLib for PackedUserOperation;

    // Validation output
    uint256 private constant VALIDATION_FAILED = 1;
    uint256 private constant VALIDATION_SUCCESS = 0;

    // -------- Defaults for auto-initialization (tweak to your stack) --------
    // Gas legs per op (units)
    uint256 private constant DEFAULT_PVG = 110_000; // packaging/bytes for P-256/WebAuthn-ish signatures
    uint256 private constant DEFAULT_VGL = 360_000; // validation (session key checks, EIP-1271/P-256 parsing)
    uint256 private constant DEFAULT_CGL = 240_000; // ERC20 transfer/batch-ish execution
    uint256 private constant DEFAULT_PMV = 60_000; // paymaster validate (if used)
    uint256 private constant DEFAULT_PO = 60_000; // postOp (token charge/refund)

    uint256 private constant DEFAULT_PRICE_FLOOR_WEI = 2 gwei; // at least 2 gwei assumed
    uint256 private constant PRICE_SAFETY_BPS = 11000; // +10% headroom on price

    // Safety margins
    uint256 private constant SAFETY_BPS = 12000; // +20% on gas envelope
    uint16 private constant DEFAULT_PENALTY_BPS = 1000; // 10% v0.8 penalty on (CGL+PO) if >= threshold
    uint32 private constant DEFAULT_PENALTY_THR = 40_000; // penalty threshold (v0.8)
    uint256 private constant DEFAULT_PRIORITY_FEE_WEI = 1 gwei; // assumed tip for pricing worst-case

    mapping(bytes32 id => mapping(address mux => mapping(address account => GasLimitConfig)))
        internal gasLimitConfigs;

    // ---------------------- POLICY CHECK ----------------------
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        returns (uint256)
    {
        GasLimitConfig storage cfg = gasLimitConfigs[id][msg.sender][userOp.sender];
        if (!cfg.initialized) return VALIDATION_FAILED;

        // 1) Unpack gas envelope
        uint256 pvg = userOp.preVerificationGas;
        uint256 vgl = UserOperationLib.unpackVerificationGasLimit(userOp);
        uint256 cgl = UserOperationLib.unpackCallGasLimit(userOp);

        uint256 pmVerif = 0;
        uint256 postOp = 0;
        if (userOp.paymasterAndData.length >= UserOperationLib.PAYMASTER_DATA_OFFSET) {
            pmVerif = UserOperationLib.unpackPaymasterVerificationGasLimit(userOp);
            postOp = UserOperationLib.unpackPostOpGasLimit(userOp);
        }

        uint256 envelopeUnits = pvg + vgl + cgl + pmVerif + postOp;

        // 2) Worst-case WEI (v0.8 semantics)
        uint256 price = userOp.gasPrice(); // min(maxFeePerGas, basefee + maxPriority)

        uint16 penaltyBps = cfg.penaltyBps == 0 ? DEFAULT_PENALTY_BPS : cfg.penaltyBps;
        uint32 threshold = cfg.penaltyThreshold == 0 ? DEFAULT_PENALTY_THR : cfg.penaltyThreshold;

        uint256 penaltyBasisGas = cgl + postOp;
        uint256 penaltyGas =
            penaltyBasisGas >= threshold ? (penaltyBasisGas * penaltyBps + 9999) / 10000 : 0;

        if (price != 0 && envelopeUnits > type(uint256).max / price) return VALIDATION_FAILED;
        uint256 worstCaseWei = envelopeUnits * price;
        if (penaltyGas != 0) {
            if (penaltyGas > type(uint256).max / price) return VALIDATION_FAILED;
            worstCaseWei += penaltyGas * price;
        }

        // 3) Guards
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

        // 4) Account usage (optimistic)
        unchecked {
            cfg.gasUsed += uint128(envelopeUnits);
            cfg.costUsed += uint128(worstCaseWei);
            cfg.txUsed += 1;
        }

        return VALIDATION_SUCCESS;
    }

    // ---------------------- INITIALIZATION (MANUAL) ----------------------
    /**
     * @notice Auto-initialize policy for a session key with a tx-count `limit`.
     * @param account   Should be the 7702 account; we enforce account == msg.sender.
     * @param configId  Session key id (e.g., keccak256(abi.encode(pubKey.x, pubKey.y))).
     * @param initData  Calldata
     */
    function initializeWithMultiplexer(address account, bytes32 configId, bytes calldata initData)
        external
    {
        require(account == msg.sender, GasPolicy__AccountMustBeSender());
        InitData memory d = abi.decode(initData, (InitData));
        require(d.gasLimit != 0 && d.costLimit != 0, GasPolicy__ZeroBudgets());

        GasLimitConfig storage cfg = gasLimitConfigs[configId][msg.sender][account];
        _applyManualConfig(cfg, d);
    }

    // ---------------------- INITIALIZATION (AUTO / DEFAULTS) ----------------------
    /**
     * @notice Auto-initialize policy for a session key with a tx-count `limit`.
     * @param account   Should be the 7702 account; we enforce account == msg.sender.
     * @param configId  Session key id (e.g., keccak256(abi.encode(pubKey.x, pubKey.y))).
     * @param limit     Number of UserOps this key is allowed to execute.
     *
     * Budgets are derived as:
     *  - perOpEnvelopeUnits = (DEFAULT_* gas legs) * SAFETY, including PM legs
     *  - perOpPenaltyGas    = 10% of (CGL+PO) if >= 40k
     *  - perOpMaxCostWei    = (perOpEnvelopeUnits + perOpPenaltyGas) * (block.basefee + 1 gwei)
     *  - gasLimit           = perOpEnvelopeUnits * limit
     *  - costLimit          = perOpMaxCostWei * limit
     */
    function initializeWithMultiplexer(address account, bytes32 configId, uint256 limit) external {
        require(account == msg.sender, GasPolicy__AccountMustBeSender());
        require(limit > 0 && limit <= type(uint32).max, GasPolicy__BadLimit());

        // 1) Envelope units per op with safety (includes PM legs so it also covers sponsored ops)
        uint256 rawEnvelope = DEFAULT_PVG + DEFAULT_VGL + DEFAULT_CGL + DEFAULT_PMV + DEFAULT_PO;
        uint256 perOpEnvelopeUnits = (rawEnvelope * SAFETY_BPS + 9999) / 10000;

        // 2) Conservative penalty basis: assume most of the envelope is execution/postOp
        //    Use 70% of the envelope OR the DEFAULT_CGL+DEFAULT_PO, whichever is larger.
        uint256 seventyPct = (perOpEnvelopeUnits * 70) / 100;
        uint256 execSideAssumed =
            seventyPct > (DEFAULT_CGL + DEFAULT_PO) ? seventyPct : (DEFAULT_CGL + DEFAULT_PO);

        uint256 perOpPenaltyGas = execSideAssumed >= DEFAULT_PENALTY_THR
            ? (execSideAssumed * DEFAULT_PENALTY_BPS + 9999) / 10000
            : 0;

        // 3) Price assumption: basefee + 1 gwei, but at least 2 gwei, then +10% safety
        uint256 priceAssumption = block.basefee + DEFAULT_PRIORITY_FEE_WEI;
        if (priceAssumption < DEFAULT_PRICE_FLOOR_WEI) priceAssumption = DEFAULT_PRICE_FLOOR_WEI;
        priceAssumption = (priceAssumption * PRICE_SAFETY_BPS + 9999) / 10000;

        // 4) Per-op max wei (overflow-checked)
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

            GasLimitConfig storage cfg = gasLimitConfigs[configId][msg.sender][account];
            _applyAutoConfig(
                cfg,
                uint128(gasLimit256),
                uint128(costLimit256),
                uint128(perOpMaxCostWei256),
                uint32(limit)
            );
        }
    }

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

    function _applyAutoConfig(
        GasLimitConfig storage cfg,
        uint128 gasLimit,
        uint128 costLimit,
        uint128 perOpMaxCostWei,
        uint32 txLimit
    ) private {
        cfg.gasLimit = gasLimit;
        cfg.costLimit = costLimit;
        cfg.perOpMaxCostWei = perOpMaxCostWei;
        cfg.txLimit = txLimit;

        // Defaults for v0.8
        cfg.penaltyBps = DEFAULT_PENALTY_BPS;
        cfg.penaltyThreshold = DEFAULT_PENALTY_THR;

        _resetCountersAndMarkInitialized(cfg);
    }

    function _resetCountersAndMarkInitialized(GasLimitConfig storage cfg) private {
        cfg.gasUsed = 0;
        cfg.costUsed = 0;
        cfg.txUsed = 0;
        cfg.initialized = true;
    }

    // ---------------------- VIEWS ----------------------
    function getGasConfig(bytes32 configId, address multiplexer, address userOpSender)
        external
        view
        returns (uint128 gasLimit, uint128 gasUsed, uint128 costLimit, uint128 costUsed)
    {
        GasLimitConfig storage c = gasLimitConfigs[configId][multiplexer][userOpSender];
        return (c.gasLimit, c.gasUsed, c.costLimit, c.costUsed);
    }

    function getGasConfigEx(bytes32 configId, address multiplexer, address userOpSender)
        external
        view
        returns (GasLimitConfig memory)
    {
        return gasLimitConfigs[configId][multiplexer][userOpSender];
    }

    // ---------------------- InitData for manual path ----------------------
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
            || interfaceID == type(IUserOpPolicy).interfaceId;
    }
}
