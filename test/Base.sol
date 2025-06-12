// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

/* ───────────────────────────────────────────────────────────── imports ──── */
import "lib/forge-std/src/StdJson.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";

/* ──────────────────────────────────────────────────────────────── base ──── */
contract Base is Test, IKey {
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
    address constant WEBAUTHN_VERIFIER = 0xeD43b3a3D00d791BC0B353666b5780B0F9245CC1;
    uint256 constant ETH_LIMIT = 1e18;
    bytes32 constant RECOVER_TYPEHASH =
        0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;
    uint256 constant RECOVERY_PERIOD = 2 days;
    uint256 constant LOCK_PERIOD = 5 days;
    uint256 constant SECURITY_PERIOD = 1.5 days;
    uint256 constant SECURITY_WINDOW = 0.5 days;

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
    bytes32 constant REG_PUBLIC_KEY_X =
        hex"501fb34eb6c1abf6cc1bed2ca17583ffdcc6f5960a6e911ca4216ac079e8b2e5";
    bytes32 constant REG_PUBLIC_KEY_Y =
        hex"be9b21a967fddcdfbccedcca22776a7ceccd41d69a07babd03e9d8beb07e8acb";

    bytes public constant REG_CHALLENGE =
        hex"e4cfc8abe9df9aeb5263940761f875c535592beb2077cc8d5cc71b3fb3678410";

    bytes32 public constant REG_SIGNATURE_R =
        hex"f0869b1d903d9ee4143bcfea6f59397dcd358041ce223448893ec1654d4da940";
    bytes32 public constant REG_SIGNATURE_S =
        hex"629f6e0a70c674928bc41627bf598ee929668195910101c01d339c22cb900c94";

    bytes public constant REG_AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";

    string public constant REG_CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"5M_Iq-nfmutSY5QHYfh1xTVZK-sgd8yNXMcbP7NnhBA\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    uint256 public constant REG_CHALLENGE_INDEX = 23;
    uint256 public constant REG_TYPE_INDEX = 1;

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
        hex"7d3a11f8bb4621e5cee93578281af39f29f664cecdf112148bdd0521edf6f1a5";
    bytes32 constant BATCH_VALID_PUBLIC_KEY_Y =
        hex"1ee216c4fa03c5a4c7f8734c269f207ef69ca680b8526e8760dfde65aed62a9d";

    bytes public constant BATCH_CHALLENGE =
        hex"eb0fa64591728fbf1936d19425a78380d7bd7f9db785379b1574a01f6522aeeb";

    bytes32 public constant BATCH_VALID_SIGNATURE_R =
        hex"c4a08c123ab658fa677586e9eb9db44d8eb28f3536c9f64a06460e9d4672531f";
    bytes32 public constant BATCH_VALID_SIGNATURE_S =
        hex"7f98fe4c0b6b49ae8d1f78f3a50a382b350ed5aef0a0181831fe4ab24f2b809e";

    bytes public constant BATCH_AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";

    string public constant BATCH_CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"6w-mRZFyj78ZNtGUJaeDgNe9f523hTebFXSgH2Uirus\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    uint256 public constant BATCH_CHALLENGE_INDEX = 23;
    uint256 public constant BATCH_TYPE_INDEX = 1;

    /* ───────────────────────────────────────────────────────────── master key ── */
    bytes32 constant ETH_PUBLIC_KEY_X =
        hex"ec65a65c8cbec46650e4f008065d6fa8c93f6156fc2990f5ebe7b27088ed2fda";
    bytes32 constant ETH_PUBLIC_KEY_Y =
        hex"1ea4b778a2667647bd12fbe1cbbbac82e40f00c0490b89a6f46c4ebf997f0b49";

    bytes public constant ETH_CHALLENGE =
        hex"928c4b45b52c0798324822fe98769e84d2c7fdba555f1012b2b47aa7b9e624ce";

    bytes32 public constant ETH_SIGNATURE_R =
        hex"63918c9a2d7994c4fece2995758e901bf0de9c8c2cb069451e699f220e1c07c0";
    bytes32 public constant ETH_SIGNATURE_S =
        hex"79defe5f59ec65eb65cc43c8f1e5e18fa2be12193548b56d30ccd8b05305a498";

    string public constant ETH_CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"koxLRbUsB5gySCL-mHaehNLH_bpVXxASsrR6p7nmJM4\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

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

    /* ───────────────────────────────────────────────────────────── recovery key ── */
    Key internal keyGuardianEOA;
    PubKey internal pubKeyGuardianEOA;

    uint256 public GUARDIAN_EOA_PRIVATE_KEY = vm.envUint("GUARDIAN_EOA_PRIVATE_KEY");
    address internal GUARDIAN_EOA_ADDRESS = vm.addr(GUARDIAN_EOA_PRIVATE_KEY);

    address internal initialGuardian;
    uint256 internal guardianB_PK;
    address internal guardianB;

    Key internal keyGuardianWebAuthn;
    PubKey internal pubKeyGuardianWebAuthn;
    bytes32 constant GUARDIAN_PUBLIC_KEY_X =
        hex"e52e02ebbc3a44f64536b1fcd75912bdd10e60b81a266c85b5521ef70b14181a";
    bytes32 constant GUARDIAN_PUBLIC_KEY_Y =
        hex"750ee32269162f0bd710e4ed4820da9ef1265f7cf9c8f44ffc3235cf041d84fd";

    bytes public constant GUARDIAN_CHALLENGE =
        hex"dd901464b06d62c1602eac47f402261c733d97bed67bae107e6f783a28e3220c";

    bytes32 public constant GUARDIAN_SIGNATURE_R =
        hex"d28a5af88ed7b32eb2e1634c0bf7548fc6d731d8b732f05277f60f7dabf1abad";
    bytes32 public constant GUARDIAN_SIGNATURE_S =
        hex"5f4dae7d1683232fb1b070b90aa70583e69ca74d1356d904384a0347b039601a";

    bytes public constant GUARDIAN_AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";

    string public constant GUARDIAN_CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"3ZAUZLBtYsFgLqxH9AImHHM9l77We64Qfm94OijjIgw\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    uint256 public constant GUARDIAN_CHALLENGE_INDEX = 23;
    uint256 public constant GUARDIAN_TYPE_INDEX = 1;

    /* ───────────────────────────────────────────────────────────── master key ── */
    bytes32 constant G_VALID_PUBLIC_KEY_X =
        hex"a45baf6070dec66ca140b5152e6c9947c4a3fcec322e0626e6ce393e18b0ee81";
    bytes32 constant G_VALID_PUBLIC_KEY_Y =
        hex"a1a3260ee81d1036cf9fea854c55f1d02cc869d365340d900a1191a9e32e7eee";

    bytes32 public constant G_CHALLENGE =
        hex"ba609dbeed0e0f8c94f3c69042c0a1b93aab17685eadcb2e45ad95e066062b68";

    bytes32 public constant G_VALID_SIGNATURE_R =
        hex"546ac03d0190caab0cec299508e937e40fb0ef56a8794e368f806ed47aa19d29";
    bytes32 public constant G_VALID_SIGNATURE_S =
        hex"77c92c666860f01042879f72d7518fe7b5d03c0b79d5be0e4a0d0580d0e6c2c2";

    bytes public constant G_AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";

    string public constant G_CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"umCdvu0OD4yU88aQQsChuTqrF2hercsuRa2V4GYGK2g\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    uint256 public constant G_CHALLENGE_INDEX = 23;
    uint256 public constant G_TYPE_INDEX = 1;
    
    /* ───────────────────────────────────────────────────────────── master key ── */
    bytes32 constant BATCHS_VALID_PUBLIC_KEY_X =
        hex"0a41735f134021741ba97d2d9d4221191ecceae36625b7a3de56f473f666b594";
    bytes32 constant BATCHS_VALID_PUBLIC_KEY_Y =
        hex"f0895ae3805aff3f01b2f2b1290ef1ea1b5da9b555258823d1d74c1d2f2f174d";

    bytes public constant BATCHS_CHALLENGE =
        hex"333435f6f7baa44d7514bbab494707ec257a29bd254a6598d79869c68b226122";

    bytes32 public constant BATCHS_VALID_SIGNATURE_R =
        hex"8def964ff2ecbac75dfd5e8673e6638447875170ff0a138d1449d022fd3c3fa5";
    bytes32 public constant BATCHS_VALID_SIGNATURE_S =
        hex"0165baa2f550110f284695aa1d2c3c68f4579d7d1348eceb3795015e5a14f219";

    bytes public constant BATCHS_AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";

    string public constant BATCHS_CLIENT_DATA_JSON =
        "{\"type\":\"webauthn.get\",\"challenge\":\"MzQ19ve6pE11FLurSUcH7CV6Kb0lSmWY15hpxosiYSI\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    uint256 public constant BATCHS_CHALLENGE_INDEX = 23;
    uint256 public constant BATCHS_TYPE_INDEX = 1;


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

    function _createInitialGuradian() public {
        pubKeyGuardianEOA = PubKey({
            x: 0x0000000000000000000000000000000000000000000000000000000000000000,
            y: 0x0000000000000000000000000000000000000000000000000000000000000000
        });
        keyGuardianEOA =
            Key({pubKey: pubKeyGuardianEOA, eoaAddress: GUARDIAN_EOA_ADDRESS, keyType: KeyType.EOA});

        pubKeyGuardianWebAuthn = PubKey({x: GUARDIAN_PUBLIC_KEY_X, y: GUARDIAN_PUBLIC_KEY_Y});
        keyGuardianWebAuthn =
            Key({pubKey: pubKeyGuardianWebAuthn, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        initialGuardian = makeAddr("initialGuardian");
        (guardianB, guardianB_PK) = makeAddrAndKey("guardianB");
    }
}
