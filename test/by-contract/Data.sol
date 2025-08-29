// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import "lib/forge-std/src/StdJson.sol";
import {IKey} from "src/interfaces/IKey.sol";
import "test/by-contract/EventsAndErrors.sol";
import {ISpendLimit} from "src/interfaces/ISpendLimit.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract Data is Test, IKey, EventsAndErrors {
    /* ─────────────────────────────────────────────────────────────              ── */
    address constant TOKEN = 0x9C0b94fb071Ed4066d7C18F4b68968e311A66209;
    address constant ETH_RECIVE = 0xCdB635ee58926769ee2789fA0942Ef04A4ae9d16;
    address constant ENTRYPOINT_V8 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address constant SEPOLIA_WEBAUTHN = 0x83b7acb5A6aa8A34A97bdA13182aEA787AC3f10d;

    /* ─────────────────────────────────────────────────────────────              ── */
    bytes32 constant TYPE_HASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 constant RECOVER_TYPEHASH =
        0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;
    bytes32 constant INIT_TYPEHASH =
        0x82dc6262fca76342c646d126714aa4005dfcd866448478747905b2e7b9837183;

    /* ─────────────────────────────────────────────────────────────              ── */
    uint256 constant RECOVERY_PERIOD = 2 days;
    uint256 constant LOCK_PERIOD = 5 days;
    uint256 constant SECURITY_PERIOD = 1.5 days;
    uint256 constant SECURITY_WINDOW = 0.5 days;

    /* ─────────────────────────────────────────────────────────────              ── */
    uint256 constant DEFAULT_PVG = 110_000; // packaging/bytes for P-256/WebAuthn-ish signatures
    uint256 constant DEFAULT_VGL = 360_000; // validation (session key checks, EIP-1271/P-256 parsing)
    uint256 constant DEFAULT_CGL = 240_000; // ERC20 transfer/batch-ish execution
    uint256 constant DEFAULT_PMV = 60_000; // paymaster validate (if used)
    uint256 constant DEFAULT_PO = 60_000; // postOp (token charge/refund)

    /* ─────────────────────────────────────────────────────────────              ── */
    uint256 internal ownerPK;
    address internal owner;

    uint256 internal sessionKeyPK;
    address internal sessionKey;

    uint256 internal senderPK;
    address internal sender;

    bytes32 internal initialGuardian;
    uint256 public GUARDIAN_EOA_PRIVATE_KEY;
    address internal GUARDIAN_EOA_ADDRESS;

    /* ─────────────────────────────────────────────────────────────              ── */
    Key internal keyMK;
    PubKey internal pubKeyMK;
    Key internal keySK;
    PubKey internal pubKeySK;

    KeyReg internal keyDataMK;
    KeyReg internal keyDataSKP256NonKey;

    Key internal keyGuardianEOA;
    PubKey internal pubKeyGuardianEOA;

    /* ─────────────────────────────────────────────────────────────              ── */
    string public json_path = vm.readFile("test/data/global.json");

    bytes32 public PUBLIC_KEY_X = stdJson.readBytes32(json_path, ".global.x");
    bytes32 public PUBLIC_KEY_Y = stdJson.readBytes32(json_path, ".global.y");

    bytes32 public CHALLENGE = stdJson.readBytes32(json_path, ".global.challenge");

    bytes32 public SIGNATURE_R = stdJson.readBytes32(json_path, ".global.signature.r");
    bytes32 public SIGNATURE_S = stdJson.readBytes32(json_path, ".global.signature.s");

    bytes public AUTHENTICATOR_DATA =
        stdJson.readBytes(json_path, ".global.metadata.authenticatorData");

    string public CLIENT_DATA_JSON =
        stdJson.readString(json_path, ".global.metadata.clientDataJSON");

    /* ─────────────────────────────────────────────────────────────              ── */
    string public json_path_p256 = vm.readFile("test/data/p256_global.json");

    bytes32 P256NOKEY_PUBLIC_KEY_X = stdJson.readBytes32(json_path_p256, ".result2.P256NONKEY_xHex");
    bytes32 P256NOKEY_PUBLIC_KEY_Y = stdJson.readBytes32(json_path_p256, ".result2.P256NONKEY_yHex");

    bytes32 public P256NOKEY_SIGNATURE_R =
        stdJson.readBytes32(json_path_p256, ".result2.P256NONKEY_rHex");
    bytes32 public P256NOKEY_SIGNATURE_S =
        stdJson.readBytes32(json_path_p256, ".result2.P256NONKEY_sHex");

    /* ─────────────────────────────────────────────────────────────              ── */
    function _allowedSelectors() internal pure returns (bytes4[] memory sel) {
        sel = new bytes4[](3);
        sel[0] = 0xa9059cbb;
        sel[1] = 0x40c10f19;
        sel[2] = 0x00000000;
    }

    function _getSpendTokenInfo(address _token, uint256 _limit)
        internal
        pure
        returns (ISpendLimit.SpendTokenInfo memory spendInfo)
    {
        spendInfo = ISpendLimit.SpendTokenInfo({token: _token, limit: _limit});
    }

    function _createMKData() internal {
        pubKeyMK = PubKey({x: PUBLIC_KEY_X, y: PUBLIC_KEY_Y});
        keyMK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});
        ISpendLimit.SpendTokenInfo memory spendInfo = _getSpendTokenInfo(address(0), 0);

        keyDataMK = KeyReg({
            validUntil: type(uint48).max,
            validAfter: 0,
            limit: 0,
            whitelisting: false,
            contractAddress: address(0),
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 0
        });
    }

    function _createSKP256NonKeyData() internal {
        pubKeySK = PubKey({x: P256NOKEY_PUBLIC_KEY_X, y: P256NOKEY_PUBLIC_KEY_Y});
        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256NONKEY});
        ISpendLimit.SpendTokenInfo memory spendInfo = _getSpendTokenInfo(TOKEN, 100e18);

        uint48 validUntil = uint48(block.timestamp + 1 days);

        keyDataSKP256NonKey = KeyReg({
            validUntil: validUntil,
            validAfter: 0,
            limit: 10,
            whitelisting: true,
            contractAddress: ETH_RECIVE,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 1e18
        });
    }

    function _createAnyKey(
        bytes32 _x,
        bytes32 _y,
        address _eoaAddress,
        KeyType _keyType,
        address _token,
        uint256 _tokenLimit,
        uint48 _validUntil,
        uint48 _validAfter,
        uint48 _limit,
        address _contractAddress,
        uint256 _ethLimit,
        bytes4[] memory _allowedSelectorsArr
    ) internal pure returns (PubKey memory pk, Key memory k, KeyReg memory kReg) {
        pk = PubKey({x: _x, y: _y});
        k = Key({pubKey: pk, eoaAddress: _eoaAddress, keyType: _keyType});

        ISpendLimit.SpendTokenInfo memory spendInfo = _getSpendTokenInfo(_token, _tokenLimit);

        kReg = KeyReg({
            validUntil: _validUntil,
            validAfter: _validAfter,
            limit: _limit,
            whitelisting: true,
            contractAddress: _contractAddress,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectorsArr.length == 0
                ? _allowedSelectors()
                : _allowedSelectorsArr,
            ethLimit: _ethLimit
        });
    }

    function _createInitialGuradian() public {
        pubKeyGuardianEOA = PubKey({x: bytes32(0), y: bytes32(0)});
        keyGuardianEOA =
            Key({pubKey: pubKeyGuardianEOA, eoaAddress: GUARDIAN_EOA_ADDRESS, keyType: KeyType.EOA});

        address initialAddr = makeAddr("initialGuardian");
        initialGuardian = keccak256(abi.encodePacked(initialAddr));
    }

    function _getUserOpFresh() internal view returns (PackedUserOperation memory userOp) {
        userOp.sender = owner;
        userOp.initCode = hex"7702";
        userOp.callData = hex"";
        userOp.accountGasLimits = hex"";
        userOp.preVerificationGas = 0;
        userOp.gasFees = hex"";
        userOp.paymasterAndData = hex"";
        userOp.signature = hex"";
    }
}
