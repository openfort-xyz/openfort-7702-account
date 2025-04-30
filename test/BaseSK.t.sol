        // SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {MockERC20} from "contracts/mocks/MockERC20.sol";
import {Test, console2 as console} from "forge-std/Test.sol";

abstract contract BaseSK is Test {
    string MAINNET_RPC_URL = vm.envString("SEPOLIA_RPC_URL");
    uint256 forkId;

    bytes4[] public _allowedSelectors;
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant FAILED_VALUE = 0xffffffff;
    bytes32 private constant USER_OP_TYPEHASH = 0xf81bea993d11db0909d00c3af86d2329d5a9069b5297725281150d0eca354139;
    uint256 private constant _TESTPLUS_RANDOMNESS_SLOT =
        0xd715531fe383f818c5f158c342925dcf01b954d24678ada4d07c36af0f20e1ee;
    bytes32 internal constant P256_VERIFIER = 0x2562256225622562256225622562256225622562256225622562256225622562;

    uint48 public LIMIT = uint48(3);

    uint256 public OWNER_PRIVATE_KEY;
    address public OWNER;

    uint256 public SESSION_KEY_PRIVATE_KEY;
    address public SESSION_KEY;

    uint256 public RANDOM_PRIVATE_KEY;
    address public RANDOM;

    address public CONTRACT = makeAddr("CONTRACT");

    uint48 public _validUntil = 1776404649;
    uint48 public _validAfter = 1776404649;

    address public TOKEN_ADDRESS = makeAddr("TOKEN");
    uint256 public SPEND_LIMIT = 10e18;
    uint256 public constant ETH_LIMIT = 1e18;

    bytes public constant CHALLENGE = hex"deadbeef";
    bytes32 public constant VALID_PUBLIC_KEY_X = 0x783b58590d44b361eaae9b52701000b3492ba3cfb417a24b90c3cf93550c9d00;
    bytes32 public constant VALID_PUBLIC_KEY_Y = 0x5a869d35e40c11a4bcfc83bffc25ea11f35d8e6fc04dc36a9cfeb267b97ccf6e;
    bytes32 public constant VALID_SIGNATURE_R = 0xb12c48e1e555eb7e76e87974d7eaf2c291dc0685cfd1554afb5b5c3ccc2e376a;
    bytes32 public constant VALID_SIGNATURE_S = 0x0de08bd1c6646f1d85f6ee8dc8a133c4de6566afd0ac65511019d1ebf7475fba;
    bytes public constant AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";
    string public constant CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"3q2-7w\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false,\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\"}";
    uint256 public constant CHALLENGE_INDEX = 23;
    uint256 public constant TYPE_INDEX = 1;
}