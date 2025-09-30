// // SPDX-License-Identifier: MIT

// pragma solidity ^0.8.29;

// import {Test} from "lib/forge-std/src/Test.sol";
// import {GasPolicy} from "src/utils/GasPolicy.sol";
// import {OPFMain as OPF} from "src/core/OPFMain.sol";
// import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";

// import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
// import {MessageHashUtils} from
//     "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

// import "lib/forge-std/src/StdJson.sol";
// import {IKey} from "src/interfaces/IKey.sol";
// import "test/by-contract/EventsAndErrors.sol";
// import {ISpendLimit} from "src/interfaces/ISpendLimit.sol";

// contract Initialization is Test, IKey {
//     error KeyManager__InvalidMasterKeyReg(KeyReg _keyData);

//     /* ─────────────────────────────────────────────────────────────              ── */
//     address constant TOKEN = 0x9C0b94fb071Ed4066d7C18F4b68968e311A66209;
//     address constant ETH_RECIVE = 0xCdB635ee58926769ee2789fA0942Ef04A4ae9d16;
//     address constant ENTRYPOINT_V8 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
//     address constant SEPOLIA_WEBAUTHN = 0x83b7acb5A6aa8A34A97bdA13182aEA787AC3f10d;

//     /* ─────────────────────────────────────────────────────────────              ── */
//     bytes32 constant TYPE_HASH = keccak256(
//         "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
//     );
//     bytes32 constant RECOVER_TYPEHASH =
//         0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;
//     bytes32 constant INIT_TYPEHASH =
//         0x82dc6262fca76342c646d126714aa4005dfcd866448478747905b2e7b9837183;

//     /* ─────────────────────────────────────────────────────────────              ── */
//     uint256 constant RECOVERY_PERIOD = 2 days;
//     uint256 constant LOCK_PERIOD = 5 days;
//     uint256 constant SECURITY_PERIOD = 1.5 days;
//     uint256 constant SECURITY_WINDOW = 0.5 days;

//     /* ─────────────────────────────────────────────────────────────              ── */
//     uint256 constant DEFAULT_PVG = 110_000; // packaging/bytes for P-256/WebAuthn-ish signatures
//     uint256 constant DEFAULT_VGL = 360_000; // validation (session key checks, EIP-1271/P-256 parsing)
//     uint256 constant DEFAULT_CGL = 240_000; // ERC20 transfer/batch-ish execution
//     uint256 constant DEFAULT_PMV = 60_000; // paymaster validate (if used)
//     uint256 constant DEFAULT_PO = 60_000; // postOp (token charge/refund)

//     OPF opf;
//     GasPolicy gasPolicy;
//     IEntryPoint entryPoint;
//     WebAuthnVerifier webAuthn;

//     OPF public account;
//     OPF public implementation;

//     uint256 internal ownerPK;
//     address internal owner;

//     uint256 internal sessionKeyPK;
//     address internal sessionKey;

//     uint256 internal senderPK;
//     address internal sender;

//     bytes32 internal initialGuardian;
//     uint256 public GUARDIAN_EOA_PRIVATE_KEY;
//     address internal GUARDIAN_EOA_ADDRESS;

//     Key internal keyMK;
//     PubKey internal pubKeyMK;
//     Key internal keySK;
//     PubKey internal pubKeySK;

//     KeyReg internal keyDataMK;
//     KeyReg internal keyDataSKP256NonKey;

//     Key internal keyGuardianEOA;
//     PubKey internal pubKeyGuardianEOA;

//     string public json_path = vm.readFile("test/data/global.json");

//     bytes32 public PUBLIC_KEY_X = stdJson.readBytes32(json_path, ".global.x");
//     bytes32 public PUBLIC_KEY_Y = stdJson.readBytes32(json_path, ".global.y");

//     /* ─────────────────────────────────────────────────────────────              ── */
//     string public json_path_p256 = vm.readFile("test/data/p256_global.json");

//     bytes32 P256NOKEY_PUBLIC_KEY_X = stdJson.readBytes32(json_path_p256, ".result2.P256NONKEY_xHex");
//     bytes32 P256NOKEY_PUBLIC_KEY_Y = stdJson.readBytes32(json_path_p256, ".result2.P256NONKEY_yHex");

//     bytes32 public P256NOKEY_SIGNATURE_R =
//         stdJson.readBytes32(json_path_p256, ".result2.P256NONKEY_rHex");
//     bytes32 public P256NOKEY_SIGNATURE_S =
//         stdJson.readBytes32(json_path_p256, ".result2.P256NONKEY_sHex");

//     function setUp() public virtual {
//         vm.startPrank(sender);

//         (owner, ownerPK) = makeAddrAndKey("owner");
//         (sender, senderPK) = makeAddrAndKey("sender");
//         (sessionKey, sessionKeyPK) = makeAddrAndKey("sessionKey");
//         (GUARDIAN_EOA_ADDRESS, GUARDIAN_EOA_PRIVATE_KEY) = makeAddrAndKey("GUARDIAN_EOA_ADDRESS");

//         entryPoint = IEntryPoint(payable(ENTRYPOINT_V8));
//         webAuthn = WebAuthnVerifier(payable(SEPOLIA_WEBAUTHN));
//         gasPolicy = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);

//         opf = new OPF(
//             address(entryPoint),
//             SEPOLIA_WEBAUTHN,
//             RECOVERY_PERIOD,
//             LOCK_PERIOD,
//             SECURITY_PERIOD,
//             SECURITY_WINDOW,
//             address(gasPolicy)
//         );

//         implementation = opf;

//         _etch();

//         vm.stopPrank();

//         _deal();
//     }

//     function test_InitializationRevertBadMk() public {
//         _createMKData();
//         address initialAddr = makeAddr("initialGuardian");
//         initialGuardian = keccak256(abi.encodePacked(initialAddr));

//         bytes memory keyEnc =
//             abi.encode(keyMK.pubKey.x, keyMK.pubKey.y, keyMK.eoaAddress, keyMK.keyType);

//         bytes memory keyDataEnc = abi.encode(
//             keyDataMK.validUntil,
//             keyDataMK.validAfter,
//             keyDataMK.limit,
//             keyDataMK.whitelisting,
//             keyDataMK.contractAddress,
//             keyDataMK.spendTokenInfo.token,
//             keyDataMK.spendTokenInfo.limit,
//             keyDataMK.allowedSelectors,
//             keyDataMK.ethLimit
//         );

//         _createSKP256NonKeyData();

//         bytes memory skEnc =
//             abi.encode(keySK.pubKey.x, keySK.pubKey.y, keySK.eoaAddress, keySK.keyType);

//         bytes memory skDataEnc = abi.encode(
//             keyDataSKP256NonKey.validUntil,
//             keyDataSKP256NonKey.validAfter,
//             keyDataSKP256NonKey.limit,
//             keyDataSKP256NonKey.whitelisting,
//             keyDataSKP256NonKey.contractAddress,
//             keyDataSKP256NonKey.spendTokenInfo.token,
//             keyDataSKP256NonKey.spendTokenInfo.limit,
//             keyDataSKP256NonKey.allowedSelectors
//         );

//         bytes32 structHash = keccak256(
//             abi.encode(INIT_TYPEHASH, keyEnc, keyDataEnc, skEnc, skDataEnc, initialGuardian)
//         );

//         string memory name = "OPF7702Recoverable";
//         string memory version = "1";

//         bytes32 domainSeparator = keccak256(
//             abi.encode(
//                 TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner
//             )
//         );
//         bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, digest);
//         bytes memory sig = abi.encodePacked(r, s, v);

//         _etch();

//         vm.expectRevert(abi.encodeWithSelector(KeyManager__InvalidMasterKeyReg.selector, keyDataMK));
//         vm.prank(address(entryPoint));
//         account.initialize(keyMK, keyDataMK, keySK, keyDataSKP256NonKey, sig, initialGuardian);
//     }

//     function _createMKData() internal {
//         pubKeyMK = PubKey({x: PUBLIC_KEY_X, y: PUBLIC_KEY_Y});
//         keyMK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});
//         ISpendLimit.SpendTokenInfo memory spendInfo = _getSpendTokenInfo(address(0), 0);

//         keyDataMK = KeyReg({
//             validUntil: type(uint48).max,
//             validAfter: 0,
//             limit: 1,
//             whitelisting: true,
//             contractAddress: address(0),
//             spendTokenInfo: spendInfo,
//             allowedSelectors: _allowedSelectors(),
//             ethLimit: 0
//         });
//     }

//     function _createSKP256NonKeyData() internal {
//         pubKeySK = PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});
//         keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256NONKEY});
//         ISpendLimit.SpendTokenInfo memory spendInfo = _getSpendTokenInfo(TOKEN, 100e18);

//         uint48 validUntil = uint48(block.timestamp + 1 days);

//         keyDataSKP256NonKey = KeyReg({
//             validUntil: validUntil,
//             validAfter: 0,
//             limit: 10,
//             whitelisting: true,
//             contractAddress: ETH_RECIVE,
//             spendTokenInfo: spendInfo,
//             allowedSelectors: _allowedSelectors(),
//             ethLimit: 1e18
//         });
//     }

//     function _deal() internal {
//         deal(owner, 10e18);
//         deal(sender, 10e18);
//     }

//     function _getSpendTokenInfo(address _token, uint256 _limit)
//         internal
//         pure
//         returns (ISpendLimit.SpendTokenInfo memory spendInfo)
//     {
//         spendInfo = ISpendLimit.SpendTokenInfo({token: _token, limit: _limit});
//     }

//     function _allowedSelectors() internal pure returns (bytes4[] memory sel) {
//         sel = new bytes4[](3);
//         sel[0] = 0xa9059cbb;
//         sel[1] = 0x40c10f19;
//         sel[2] = 0x00000000;
//     }

//     function _etch() internal {
//         vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(implementation)));
//         account = OPF(payable(owner));
//     }
// }
