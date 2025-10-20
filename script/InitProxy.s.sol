// // SPDX-License-Identifier: MIT

// pragma solidity 0.8.29;

// import {Base} from "test/Base.sol";
// import "lib/forge-std/src/StdJson.sol";
// import {IKey} from "src/interfaces/IKey.sol";
// import {ISpendLimit} from "src/interfaces/ISpendLimit.sol";
// import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
// import {Script, console2 as console} from "lib/forge-std/src/Script.sol";
// import {MessageHashUtils} from
//     "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

// contract InitProxy is Script, IKey {
//     uint256 internal senderPk = vm.envUint("PRIVATE_KEY_SENDER");
//     address internal sender = vm.addr(senderPk);

//     uint256 internal ownerPk = vm.envUint("PRIVATE_KEY_PROXY");
//     address internal owner = vm.addr(ownerPk);

//     string public json_reg = vm.readFile("test/data/registration.json");
//     bytes32 public REG_PUBLIC_KEY_X = stdJson.readBytes32(json_reg, ".registration.x");
//     bytes32 public REG_PUBLIC_KEY_Y = stdJson.readBytes32(json_reg, ".registration.y");

//     string public json_single_mint = vm.readFile("test/data/p256_single_mint.json");

//     bytes32 MINT_P256_PUBLIC_KEY_X = stdJson.readBytes32(json_single_mint, ".result.P256_xHex");
//     bytes32 MINT_P256_PUBLIC_KEY_Y = stdJson.readBytes32(json_single_mint, ".result.P256_yHex");
//     address constant TOKEN = 0x9C0b94fb071Ed4066d7C18F4b68968e311A66209;

//     OPF7702 public opf;
//     address public proxy;
//     OPF7702 public account;

//     Key internal keyMK;
//     PubKey internal pubKeyMK;
//     KeyReg internal keyData;

//     Key internal keySK;
//     PubKey internal pubKeySK;
//     KeyReg internal keyDataSK;

//     bytes internal code;
//     bytes32 digest;

//     bytes32 private constant TYPE_HASH = keccak256(
//         "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
//     );

//     bytes32 constant RECOVER_TYPEHASH =
//         0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;

//     function run() public {
//         vm.startBroadcast();
//         opf = OPF7702(payable(owner));
//         pubKeyMK = PubKey({x: REG_PUBLIC_KEY_X, y: REG_PUBLIC_KEY_Y});
//         keyMK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});
//         ISpendLimit.SpendTokenInfo memory spendInfo =
//             ISpendLimit.SpendTokenInfo({token: TOKEN, limit: 0});

//         keyData = KeyReg({
//             validUntil: type(uint48).max,
//             validAfter: 0,
//             limit: 0,
//             whitelisting: false,
//             contractAddress: address(0),
//             spendTokenInfo: spendInfo,
//             allowedSelectors: _allowedSelectors(),
//             ethLimit: 0
//         });

//         pubKeySK = PubKey({x: MINT_P256_PUBLIC_KEY_X, y: MINT_P256_PUBLIC_KEY_Y});
//         keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256});
//         uint48 validUntil = uint48(1_795_096_759);
//         uint48 limit = uint48(20);

//         ISpendLimit.SpendTokenInfo memory spendInfoSK =
//             ISpendLimit.SpendTokenInfo({token: TOKEN, limit: 1000e18});

//         keyDataSK = KeyReg({
//             validUntil: validUntil,
//             validAfter: 0,
//             limit: limit,
//             whitelisting: true,
//             contractAddress: TOKEN,
//             spendTokenInfo: spendInfoSK,
//             allowedSelectors: _allowedSelectors(),
//             ethLimit: 1e18
//         });

//         bytes32 initialGuardian = keccak256(abi.encodePacked(sender));

//         bytes32 structHash = keccak256(
//             abi.encode(
//                 RECOVER_TYPEHASH,
//                 keyMK.pubKey.x,
//                 keyMK.pubKey.y,
//                 keyMK.eoaAddress,
//                 keyMK.keyType,
//                 initialGuardian
//             )
//         );

//         string memory name = "OPF7702Recoverable";
//         string memory version = "1";

//         bytes32 domainSeparator = keccak256(
//             abi.encode(
//                 TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner
//             )
//         );
//         digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
//         bytes memory sig = abi.encodePacked(r, s, v);

//         opf.initialize(keyMK, keyData, keySK, keyDataSK, sig, initialGuardian);

//         address impl = opf._OPENFORT_CONTRACT_ADDRESS();
//         console.log("impl", impl);
//         vm.stopBroadcast();

//         bytes[] memory callDatas = new bytes[](3);

//         callDatas[0] = abi.encodeWithSignature("id()");
//         callDatas[1] = abi.encodeWithSignature("guardianCount()");
//         callDatas[2] = abi.encodeWithSignature("getKeyById(uint256)", 0);

//         for (uint256 i = 0; i < callDatas.length; i++) {
//             (bool v2, bytes memory res) = owner.staticcall(callDatas[i]);
//             console.log("v2", v2);
//             console.logBytes(res);
//         }
//     }

//     function _allowedSelectors() internal pure returns (bytes4[] memory sel) {
//         sel = new bytes4[](3);
//         sel[0] = 0xa9059cbb;
//         sel[1] = 0x40c10f19;
//         sel[2] = 0x00000000;
//     }
// }
