// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

/* ───────────────────────────────────────────────────────────── imports ──── */
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {ISessionKey}               from "src/interfaces/ISessionkey.sol";
import                                  "forge-std/StdJson.sol";

/* ──────────────────────────────────────────────────────────────── base ──── */
contract Base is Test, ISessionKey {
    /* ───────────────────────────────────────────────────────────── constants ── */
    address constant SEPOLIA_ENTRYPOINT     = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address constant SEPOLIA_WEBAUTHN       = 0xeD43b3a3D00d791BC0B353666b5780B0F9245CC1;
    address constant TOKEN                  = 0x9C0b94fb071Ed4066d7C18F4b68968e311A66209;
    address constant ETH_RECIVE             = 0xCdB635ee58926769ee2789fA0942Ef04A4ae9d16;
    uint256 constant ETH_LIMIT              = 1e18;

    /* ─────────────────────────────────────────────────────────── actors/keys ── */
    uint256 internal senderPk      = vm.envUint("PRIVATE_KEY_SENDER");
    address internal sender        = vm.addr(senderPk);

    uint256 internal ownerPk       = vm.envUint("PRIVATE_KEY_OPENFORT_USER_7702");
    address internal owner         = vm.addr(ownerPk);

    uint256 internal sessionKeyPk  = vm.envUint("PRIVATE_KEY_SESSIONKEY");
    address internal sessionKey    = vm.addr(sessionKeyPk);

    /* ───────────────────────────────────────────────────────────── master key ── */
    bytes32 constant VALID_PUBLIC_KEY_X         = hex"4ada96f06b4e3f3db9ca23d28f3197e643be29315e4c0401e4760bcd5c885f8f";
    bytes32 constant VALID_PUBLIC_KEY_Y         = hex"703d50715d723db90aef1d363e6342fe82ce04cba3c0c959445d1d3b26aa40e1";

    bytes public constant CHALLENGE             = hex"07e9d1cdf79ae1f7bb91f70d074812afde29e9d34b05dcb67304328360cd2c35";

    bytes32 public constant VALID_SIGNATURE_R   = hex"1e00b572138f5cbf39c486e6e01cf522643715c7ce718c55731ec6e53e3529fd";
    bytes32 public constant VALID_SIGNATURE_S   = hex"420a289ff162e1645b2cbf5e363e747ae62996b6e41927c5733be23be1a858b6";

    bytes public constant AUTHENTICATOR_DATA    = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";

    string public constant CLIENT_DATA_JSON     = "{\"type\":\"webauthn.get\",\"challenge\":\"B-nRzfea4fe7kfcNB0gSr94p6dNLBdy2cwQyg2DNLDU\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    uint256 public constant CHALLENGE_INDEX     = 23;
    uint256 public constant TYPE_INDEX          = 1;

    /* ───────────────────────────────────────────────────────────── master key ── */
    bytes32 constant ETH_PUBLIC_KEY_X         = hex"989ec43868cc759c0ade920a1440a31fb202d97830d34d41679f4fb14f9720e6";
    bytes32 constant ETH_PUBLIC_KEY_Y         = hex"c23e57ed0da1403d155480d89ef662cfcac99b67e3702b6bb0bec52c80eae170";

    bytes public constant ETH_CHALLENGE           = hex"cdb1960af7795cdb006deb92e6fe0fb3ef5f7cedd93b1894770f0116ea905386";

    bytes32 public constant ETH_SIGNATURE_R   = hex"ba49c2440945342824b499869aee2c8fd08ae28f61ba3c755b5f8fcfa2e51829";
    bytes32 public constant ETH_SIGNATURE_S   = hex"6fe423e06548c859358ec0f7630fee8fb2c9b4e24abdc099370f294217ae5838";

    string public constant ETH_CLIENT_DATA_JSON     = "{\"type\":\"webauthn.get\",\"challenge\":\"zbGWCvd5XNsAbeuS5v4Ps-9ffO3ZOxiUdw8BFuqQU4Y\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";

    /* ──────────────────────────────────────────────────────────────── P256 ──── */
    string public json        = vm.readFile("test/data/p256.json");

    bytes32 P256_PUBLIC_KEY_X = stdJson.readBytes32(json, ".result.P256_xHex");
    bytes32 P256_PUBLIC_KEY_Y = stdJson.readBytes32(json, ".result.P256_yHex");

    bytes32 P256_SIGNATURE_R  = stdJson.readBytes32(json, ".result.P256_lowSR");
    bytes32 P256_SIGNATURE_S  = stdJson.readBytes32(json, ".result.P256_lowSS");
    
    /* ──────────────────────────────────────────────────────────── P256NONKEY ──── */
    bytes32 P256NOKEY_PUBLIC_KEY_X       = stdJson.readBytes32(json, ".result2.P256NONKEY_xHex");
    bytes32 P256NOKEY_PUBLIC_KEY_Y       = stdJson.readBytes32(json, ".result2.P256NONKEY_yHex");

    bytes32 public P256NOKEY_SIGNATURE_R = stdJson.readBytes32(json, ".result2.P256NONKEY_rHex");
    bytes32 public P256NOKEY_SIGNATURE_S = stdJson.readBytes32(json, ".result2.P256NONKEY_sHex");


    // /* ──────────────────────────────────────────────────────────────── P256 ──── */
    string public json_eth            = vm.readFile("test/data/p256_eth.json");

    bytes32 ETH_P256_PUBLIC_KEY_X = stdJson.readBytes32(json_eth, ".result.P256_xHex");
    bytes32 ETH_P256_PUBLIC_KEY_Y = stdJson.readBytes32(json_eth, ".result.P256_yHex");

    bytes32 ETH_P256_SIGNATURE_R  = stdJson.readBytes32(json_eth, ".result.P256_lowSR");
    bytes32 ETH_P256_SIGNATURE_S  = stdJson.readBytes32(json_eth, ".result.P256_lowSS");

    /* ──────────────────────────────────────────────────────────── P256NONKEY ──── */
    bytes32 ETH_P256NOKEY_PUBLIC_KEY_X       = stdJson.readBytes32(json_eth, ".result2.P256NONKEY_xHex");
    bytes32 ETH_P256NOKEY_PUBLIC_KEY_Y       = stdJson.readBytes32(json_eth, ".result2.P256NONKEY_yHex");

    bytes32 public ETH_P256NOKEY_SIGNATURE_R = stdJson.readBytes32(json_eth, ".result2.P256NONKEY_rHex");
    bytes32 public ETH_P256NOKEY_SIGNATURE_S = stdJson.readBytes32(json_eth, ".result2.P256NONKEY_sHex");


    // /* ──────────────────────────────────────────────────────────────── P256 ──── */
    string public json_single_mint            = vm.readFile("test/data/p256_single_mint.json");

    bytes32 MINT_P256_PUBLIC_KEY_X = stdJson.readBytes32(json_single_mint, ".result.P256_xHex");
    bytes32 MINT_P256_PUBLIC_KEY_Y = stdJson.readBytes32(json_single_mint, ".result.P256_yHex");

    bytes32 MINT_P256_SIGNATURE_R  = stdJson.readBytes32(json_single_mint, ".result.P256_lowSR");
    bytes32 MINT_P256_SIGNATURE_S  = stdJson.readBytes32(json_single_mint, ".result.P256_lowSS");

    /* ──────────────────────────────────────────────────────────── P256NONKEY ──── */
    bytes32 MINT_P256NOKEY_PUBLIC_KEY_X       = stdJson.readBytes32(json_single_mint, ".result2.P256NONKEY_xHex");
    bytes32 MINT_P256NOKEY_PUBLIC_KEY_Y       = stdJson.readBytes32(json_single_mint, ".result2.P256NONKEY_yHex");

    bytes32 public MINT_P256NOKEY_SIGNATURE_R = stdJson.readBytes32(json_single_mint, ".result2.P256NONKEY_rHex");
    bytes32 public MINT_P256NOKEY_SIGNATURE_S = stdJson.readBytes32(json_single_mint, ".result2.P256NONKEY_sHex");

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