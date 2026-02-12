// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "lib/forge-std/src/StdJson.sol";
import {Constants} from "./Constants.sol";
import {OPFMain} from "src/core/OPFMain.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {RecoveryProofs} from "./RecoveryProofs.t.sol";
import {ERC7579Module} from "src/utils/ERC7579Module.sol";

abstract contract Data is RecoveryProofs {
    uint256 private __FORK_ID;

    // Environment variables are auto-loaded from .env via foundry.toml (dotenv = ".env")
    string internal __BASE_RPC_URL = vm.envString("BASE_RPC_URL");

    uint256 internal __OWNER_7702_PRIVATE_KEY = vm.envUint("OWNER_7702_PRIVATE_KEY");
    address internal __OWNER_7702_ADDRESS = vm.addr(__OWNER_7702_PRIVATE_KEY);

    uint256 internal __NEW_OWNER_7702_PRIVATE_KEY = vm.envUint("NEW_OWNER_PRIVATE_KEY");
    address internal __NEW_OWNER_7702_ADDRESS = vm.addr(__NEW_OWNER_7702_PRIVATE_KEY);

    uint256 internal __RELAYER_PRIVATE_KEY = vm.envUint("RELAYER_PRIVATE_KEY");
    address internal __RELAYER_ADDRESS = vm.addr(__RELAYER_PRIVATE_KEY);

    // Read guardian accountSalts from ProofsData.json (source of truth from ZK proofs)
    string public proofsJson = vm.readFile("test/unit/ZKEmailRecovery/data/proofs/ProofsDataGeneral.json");
    bytes32 internal __GUARDIAN_1_ACCOUNT_SALT =
        stdJson.readBytes32(proofsJson, ".Guardian1_Proof.account_salt");
    bytes32 internal __GUARDIAN_2_ACCOUNT_SALT =
        stdJson.readBytes32(proofsJson, ".Guardian2_Proof.account_salt");

    OPFMain internal implementation;
    GasPolicy public gasPolicy;

    ERC7579Module internal erc7579Module;

    function setUp() public virtual {
        _initExistContracts();
        _labelContracts();

        gasPolicy = new GasPolicy(
            Constants.DEFAULT_PVG,
            Constants.DEFAULT_VGL,
            Constants.DEFAULT_CGL,
            Constants.DEFAULT_PMV,
            Constants.DEFAULT_PO
        );
        implementation =
            new OPFMain(Constants.ENTRY_POINT_9, Constants.WEBAUTHN_VERIFIER, address(gasPolicy));
        erc7579Module = new ERC7579Module();
    }

    function _enableFork() internal {
        __FORK_ID = vm.createFork(__BASE_RPC_URL);
        vm.selectFork(__FORK_ID);
    }

    function _enableFork(string memory _rpcUrl) internal {
        __FORK_ID = vm.createFork(_rpcUrl);
        vm.selectFork(__FORK_ID);
    }
}
