// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

/* ───────────────────────────────────────────────────────────── imports ──── */
import "lib/forge-std/src/StdJson.sol";
import {ISessionkey} from "src/interfaces/ISessionkey.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";

/* ──────────────────────────────────────────────────────────────── base ──── */
contract Base is Test, ISessionkey {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }
    /* ───────────────────────────────────────────────────────────── constants ── */

    address constant SEPOLIA_ENTRYPOINT = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address constant SEPOLIA_WEBAUTHN = 0xeD43b3a3D00d791BC0B353666b5780B0F9245CC1;
    address constant TOKEN = 0x9C0b94fb071Ed4066d7C18F4b68968e311A66209;
    address constant ETH_RECIVE = 0xCdB635ee58926769ee2789fA0942Ef04A4ae9d16;
    uint256 constant ETH_LIMIT = 1e18;

    /* ─────────────────────────────────────────────────────────── actors/keys ── */
    uint256 internal senderPk = vm.envUint("PRIVATE_KEY_SENDER");
    address internal sender = vm.addr(senderPk);

    uint256 internal ownerPk = vm.envUint("PRIVATE_KEY_OPENFORT_USER_7702");
    address internal owner = vm.addr(ownerPk);

    uint256 internal sessionKeyPk = vm.envUint("PRIVATE_KEY_SESSIONKEY");
    address internal sessionKey = vm.addr(sessionKeyPk);

    /* ───────────────────────────────────────────────────────────── master key ── */
    bytes32 constant VALID_PUBLIC_KEY_X =
        hex"f014cc9fb4edba3c439a22423f580ad29cb177dbd5af224e4d068ef6374df083";
    bytes32 constant VALID_PUBLIC_KEY_Y =
        hex"f4c5322095ffa8db8344b7675f82eeadd2a17af4d9db9d4d4c582e8839ca391e";

    bytes public constant CHALLENGE =
        hex"cea3e080968320575bc01fbe2293a690683e321ac28cfb95a234e4b959e4fcfa";

    bytes32 public constant VALID_SIGNATURE_R =
        hex"cf1d727573eee8b3d301ab94aec432c1b7953969dcdf71388d14385630378a80";
    bytes32 public constant VALID_SIGNATURE_S =
        hex"417d9bafa3acecdbba348f851c1efc93c7ed780e2eddc7046767a1998db4f0c8";

    bytes public constant AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";

    string public constant CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"zqPggJaDIFdbwB--IpOmkGg-MhrCjPuVojTkuVnk_Po\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    uint256 public constant CHALLENGE_INDEX = 23;
    uint256 public constant TYPE_INDEX = 1;

    /* ───────────────────────────────────────────────────────────── master key ── */
    bytes32 constant MINT_VALID_PUBLIC_KEY_X =
        hex"4d1a5e0a438f91389c9695b0c68c51840062c184710c7ac2c90a2e70a3aa21a7";
    bytes32 constant MINT_VALID_PUBLIC_KEY_Y =
        hex"c6df07a5b82c2c1751a58059f4477d91c15f17d173679560c52ff8aa5bc0ab4c";

    bytes32 public constant MINT_CHALLENGE =
        hex"04b322462d12d579d02558a0b54208c8cef6edbe848bd9cdce7b11dd93764698";

    bytes32 public constant MINT_VALID_SIGNATURE_R =
        hex"73b4561ba91fa50d8a27f554232b6b6958ba0ee475a5cf84248c13067e326074";
    bytes32 public constant MINT_VALID_SIGNATURE_S =
        hex"23d0ce3cd83eb8ab6a4e29f4dd4cb212061b21c73082651ad3af68a371286532";

    bytes public constant MINT_AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";

    string public constant MINT_CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"BLMiRi0S1XnQJVigtUIIyM727b6Ei9nNznsR3ZN2Rpg\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false,\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\"}";

    uint256 public constant MINT_CHALLENGE_INDEX = 23;
    uint256 public constant MINT_TYPE_INDEX = 1;

    /* ───────────────────────────────────────────────────────────── master key ── */
    bytes32 constant BATCH_VALID_PUBLIC_KEY_X =
        hex"542fcd9d956e7606b44fdc04f4c4bed80242241a72cbc45373d1853964e9e41c";
    bytes32 constant BATCH_VALID_PUBLIC_KEY_Y =
        hex"e8372aa28abb123a734e6947ab3ab8734606c8868065f25c63de755928eba332";

    bytes public constant BATCH_CHALLENGE =
        hex"d209d8f817b01a59e92fd4a68adf97d6952e0aeef9cab2db07ce23a84588d27a";

    bytes32 public constant BATCH_VALID_SIGNATURE_R =
        hex"d17c8f3c0d662a35f3ef6e7ce7359e0a49834b38d01814255f348557cb8ae66e";
    bytes32 public constant BATCH_VALID_SIGNATURE_S =
        hex"0ec703a1cf21b7556945a789b748c307bba5700a6f6571b7b55c2cf3945920bb";

    bytes public constant BATCH_AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";

    string public constant BATCH_CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"0gnY-BewGlnpL9Smit-X1pUuCu75yrLbB84jqEWI0no\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    uint256 public constant BATCH_CHALLENGE_INDEX = 23;
    uint256 public constant BATCH_TYPE_INDEX = 1;

    /* ───────────────────────────────────────────────────────────── master key ── */
    bytes32 constant ETH_PUBLIC_KEY_X =
        hex"19b1ff0e3454500e742c787ee88dcf7d941e2a2912c6ee079de0a0bc204d704c";
    bytes32 constant ETH_PUBLIC_KEY_Y =
        hex"ac91f829b0ce6be1500c7642017a7eea1973e35fbb5b4e0cb1f449d3be5db301";

    bytes public constant ETH_CHALLENGE =
        hex"cf7991c9fe3d4c592d6c7f32855b04a4460351ddadc93968c786b61ea39a0326";

    bytes32 public constant ETH_SIGNATURE_R =
        hex"e277ac875a6dd1248216bf8d225fa53c4bbe767a3f302376ff7a29505f65c2fe";
    bytes32 public constant ETH_SIGNATURE_S =
        hex"31b7918daca1431197de7ffdac001679fc9de9d9cbe9f636a70f68a450fb00bd";

    string public constant ETH_CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"z3mRyf49TFktbH8yhVsEpEYDUd2tyTlox4a2HqOaAyY\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    /* ──────────────────────────────────────────────────────────────── P256 ──── */
    string public json = vm.readFile("test/data/p256.json");

    bytes32 P256_PUBLIC_KEY_X = stdJson.readBytes32(json, ".result.P256_xHex");
    bytes32 P256_PUBLIC_KEY_Y = stdJson.readBytes32(json, ".result.P256_yHex");

    bytes32 P256_SIGNATURE_R = stdJson.readBytes32(json, ".result.P256_lowSR");
    bytes32 P256_SIGNATURE_S = stdJson.readBytes32(json, ".result.P256_lowSS");

    /* ──────────────────────────────────────────────────────────── P256NONKEY ──── */
    bytes32 P256NOKEY_PUBLIC_KEY_X = stdJson.readBytes32(json, ".result2.P256NONKEY_xHex");
    bytes32 P256NOKEY_PUBLIC_KEY_Y = stdJson.readBytes32(json, ".result2.P256NONKEY_yHex");

    bytes32 public P256NOKEY_SIGNATURE_R = stdJson.readBytes32(json, ".result2.P256NONKEY_rHex");
    bytes32 public P256NOKEY_SIGNATURE_S = stdJson.readBytes32(json, ".result2.P256NONKEY_sHex");

    // /* ──────────────────────────────────────────────────────────────── P256 ──── */
    string public json_eth = vm.readFile("test/data/p256_eth.json");

    bytes32 ETH_P256_PUBLIC_KEY_X = stdJson.readBytes32(json_eth, ".result.P256_xHex");
    bytes32 ETH_P256_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth, ".result.P256_yHex");

    bytes32 ETH_P256_SIGNATURE_R = stdJson.readBytes32(json_eth, ".result.P256_lowSR");
    bytes32 ETH_P256_SIGNATURE_S = stdJson.readBytes32(json_eth, ".result.P256_lowSS");

    /* ──────────────────────────────────────────────────────────── P256NONKEY ──── */
    bytes32 ETH_P256NOKEY_PUBLIC_KEY_X = stdJson.readBytes32(json_eth, ".result2.P256NONKEY_xHex");
    bytes32 ETH_P256NOKEY_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth, ".result2.P256NONKEY_yHex");

    bytes32 public ETH_P256NOKEY_SIGNATURE_R =
        stdJson.readBytes32(json_eth, ".result2.P256NONKEY_rHex");
    bytes32 public ETH_P256NOKEY_SIGNATURE_S =
        stdJson.readBytes32(json_eth, ".result2.P256NONKEY_sHex");

    // /* ──────────────────────────────────────────────────────────────── P256 ──── */
    string public json_single_mint = vm.readFile("test/data/p256_single_mint.json");

    bytes32 MINT_P256_PUBLIC_KEY_X = stdJson.readBytes32(json_single_mint, ".result.P256_xHex");
    bytes32 MINT_P256_PUBLIC_KEY_Y = stdJson.readBytes32(json_single_mint, ".result.P256_yHex");

    bytes32 MINT_P256_SIGNATURE_R = stdJson.readBytes32(json_single_mint, ".result.P256_lowSR");
    bytes32 MINT_P256_SIGNATURE_S = stdJson.readBytes32(json_single_mint, ".result.P256_lowSS");

    /* ──────────────────────────────────────────────────────────── P256NONKEY ──── */
    bytes32 MINT_P256NOKEY_PUBLIC_KEY_X =
        stdJson.readBytes32(json_single_mint, ".result2.P256NONKEY_xHex");
    bytes32 MINT_P256NOKEY_PUBLIC_KEY_Y =
        stdJson.readBytes32(json_single_mint, ".result2.P256NONKEY_yHex");

    bytes32 public MINT_P256NOKEY_SIGNATURE_R =
        stdJson.readBytes32(json_single_mint, ".result2.P256NONKEY_rHex");
    bytes32 public MINT_P256NOKEY_SIGNATURE_S =
        stdJson.readBytes32(json_single_mint, ".result2.P256NONKEY_sHex");

    function _allowedSelectors() internal pure returns (bytes4[] memory sel) {
        sel = new bytes4[](3);
        sel[0] = 0xa9059cbb;
        sel[1] = 0x40c10f19;
        sel[2] = 0x00000000;
    }

    function _allowedSelectorsEmpty() internal pure returns (bytes4[] memory sel) {
        sel = new bytes4[](3);
        sel[0] = 0x00000000;
    }

    function _packAccountGasLimits(uint256 callGasLimit, uint256 verificationGasLimit)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((callGasLimit << 128) | verificationGasLimit);
    }

    function _packGasFees(uint256 maxFeePerGas, uint256 maxPriorityFeePerGas)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((maxFeePerGas << 128) | maxPriorityFeePerGas);
    }

    function _deal() public {
        deal(owner, 10e18);
        deal(sender, 10e18);
    }
}
