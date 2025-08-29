// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {GasPolicy} from "src/utils/GasPolicy.sol";
import {OPFMain as OPF} from "src/core/OPFMain.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

import {ERC721Mock} from "src/mocks/ERC721Mock.sol";
import {ERC1155Mock} from "src/mocks/ERC1155Mock.sol";
import {ERC20Mock} from "lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

import {Data} from "test/by-contract/Data.sol";

contract BaseContract is Data {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    OPF opf;
    GasPolicy gasPolicy;
    IEntryPoint entryPoint;
    WebAuthnVerifier webAuthn;

    OPF public account;
    OPF public implementation;

    ERC20Mock mockERC20;
    ERC721Mock mockERC721;
    ERC1155Mock mockERC1155;

    function setUp() public virtual {
        vm.startPrank(sender);

        (owner, ownerPK) = makeAddrAndKey("owner");
        (sender, senderPK) = makeAddrAndKey("sender");
        (sessionKey, sessionKeyPK) = makeAddrAndKey("sessionKey");
        (GUARDIAN_EOA_ADDRESS, GUARDIAN_EOA_PRIVATE_KEY) = makeAddrAndKey("GUARDIAN_EOA_ADDRESS");

        entryPoint = IEntryPoint(payable(ENTRYPOINT_V8));
        webAuthn = WebAuthnVerifier(payable(SEPOLIA_WEBAUTHN));
        gasPolicy = new GasPolicy(DEFAULT_PVG, DEFAULT_VGL, DEFAULT_CGL, DEFAULT_PMV, DEFAULT_PO);
        mockERC20 = new ERC20Mock();
        mockERC721 = new ERC721Mock("TestNFT", "TNFT");
        mockERC1155 = new ERC1155Mock("https://test.com/{id}.json");

        opf = new OPF(
            address(entryPoint),
            SEPOLIA_WEBAUTHN,
            RECOVERY_PERIOD,
            LOCK_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            address(gasPolicy)
        );

        implementation = opf;

        _etch();

        vm.stopPrank();

        _deal();
        _createInitialGuradian();
        _initializeAccount();
    }

    function test_CorrectInit() public view {
        Key memory k = account.getKeyById(0);
        console.log("/* --------------------------------- test_getKeyById_zero -------- */");

        assertEq(k.pubKey.x, pubKeyMK.x);
        assertEq(k.pubKey.y, pubKeyMK.y);

        Key memory kSk = account.getKeyById(1);

        assertEq(kSk.pubKey.x, pubKeySK.x);
        assertEq(kSk.pubKey.y, pubKeySK.y);

        (bool isActive, uint48 validUntil, uint48 validAfter, uint48 limit) =
            account.getKeyData(keccak256(abi.encodePacked(kSk.pubKey.x, kSk.pubKey.y)));

        assertEq(keyDataSKP256NonKey.limit, limit);
        assertEq(keyDataSKP256NonKey.validUntil, validUntil);
        assertEq(keyDataSKP256NonKey.validAfter, validAfter);
        assertTrue(isActive);

        console.log("/* --------------------------------- test_getKeyById_zero -------- */");
    }

    function _deal() internal {
        deal(owner, 10e18);
        deal(sender, 10e18);
    }

    function _initializeAccount() internal {
        _createMKData();

        bytes memory keyEnc =
            abi.encode(keyMK.pubKey.x, keyMK.pubKey.y, keyMK.eoaAddress, keyMK.keyType);

        bytes memory keyDataEnc = abi.encode(
            keyDataMK.validUntil,
            keyDataMK.validAfter,
            keyDataMK.limit,
            keyDataMK.whitelisting,
            keyDataMK.contractAddress,
            keyDataMK.spendTokenInfo.token,
            keyDataMK.spendTokenInfo.limit,
            keyDataMK.allowedSelectors,
            keyDataMK.ethLimit
        );

        _createSKP256NonKeyData();

        bytes memory skEnc =
            abi.encode(keySK.pubKey.x, keySK.pubKey.y, keySK.eoaAddress, keySK.keyType);

        bytes memory skDataEnc = abi.encode(
            keyDataSKP256NonKey.validUntil,
            keyDataSKP256NonKey.validAfter,
            keyDataSKP256NonKey.limit,
            keyDataSKP256NonKey.whitelisting,
            keyDataSKP256NonKey.contractAddress,
            keyDataSKP256NonKey.spendTokenInfo.token,
            keyDataSKP256NonKey.spendTokenInfo.limit,
            keyDataSKP256NonKey.allowedSelectors
        );

        bytes32 structHash = keccak256(
            abi.encode(INIT_TYPEHASH, keyEnc, keyDataEnc, skEnc, skDataEnc, initialGuardian)
        );

        string memory name = "OPF7702Recoverable";
        string memory version = "1";

        bytes32 domainSeparator = keccak256(
            abi.encode(
                TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        _etch();

        vm.prank(address(entryPoint));
        account.initialize(keyMK, keyDataMK, keySK, keyDataSKP256NonKey, sig, initialGuardian);
    }

    function _etch() internal {
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(implementation)));
        account = OPF(payable(owner));
    }
}
