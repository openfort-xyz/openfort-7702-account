// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Base} from "test/Base.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {WebAuthnVerifier} from "src/utils/WebAuthnVerifier.sol";
import {LibEIP7702} from "lib/solady/src/accounts/LibEIP7702.sol";
import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from
    "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

contract ProxyTest is Base {
    OPF7702 public opf;
    address public proxy;
    address public impl;
    IEntryPoint public entryPoint;
    WebAuthnVerifier public webAuthn;
    OPF7702 public account;

    Key internal keyMK;
    PubKey internal pubKeyMK;
    KeyReg internal keyData;

    Key internal keySK;
    PubKey internal pubKeySK;
    KeyReg internal keyDataSK;

    bytes internal code;

    bytes32 private constant TYPE_HASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    function setUp() public {
        vm.startPrank(sender);
        entryPoint = IEntryPoint(payable(SEPOLIA_ENTRYPOINT));
        webAuthn = WebAuthnVerifier(payable(SEPOLIA_WEBAUTHN));
        _createInitialGuradian();

        opf = new OPF7702(
            SEPOLIA_ENTRYPOINT,
            SEPOLIA_WEBAUTHN,
            RECOVERY_PERIOD,
            LOCK_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW
        );

        impl = address(opf);

        proxy = LibEIP7702.deployProxy(impl, address(0));

        code = abi.encodePacked(bytes3(0xef0100), proxy);

        vm.etch(owner, code);
        account = OPF7702(payable(owner));

        vm.stopPrank();
        _initializeAccount();

        // vm.prank(sender);
        // entryPoint.depositTo{value: 0.1e18}(owner);
    }

    function test_AfterInit() public {
        bytes[] memory callDatas = new bytes[](5);

        callDatas[0] = abi.encodeWithSignature("id()");
        callDatas[1] = abi.encodeWithSignature("guardianCount()");
        callDatas[2] = abi.encodeWithSignature(
            "isKeyActive(bytes32)", keccak256(abi.encodePacked(REG_PUBLIC_KEY_X, REG_PUBLIC_KEY_Y))
        );
        callDatas[3] = abi.encodeWithSignature("getKeyById(uint256)", 0);
        callDatas[4] = abi.encodeWithSignature(
            "getKeyData(bytes32)", keccak256(abi.encodePacked(REG_PUBLIC_KEY_X, REG_PUBLIC_KEY_Y))
        );

        for (uint256 i = 0; i < callDatas.length; i++) {
            (bool v, bytes memory res) = owner.call{value: 0e18}(callDatas[i]);
            console.log("v", v);
            console.logBytes(res);
        }
    }

    function _initializeAccount() internal {
        /* sample WebAuthn public key – replace with a real one if needed */
        pubKeyMK = PubKey({x: REG_PUBLIC_KEY_X, y: REG_PUBLIC_KEY_Y});

        keyMK = Key({pubKey: pubKeyMK, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});

        SpendLimit.SpendTokenInfo memory spendInfo =
            SpendLimit.SpendTokenInfo({token: TOKEN, limit: 0});

        keyData = KeyReg({
            validUntil: type(uint48).max,
            validAfter: 0,
            limit: 0,
            whitelisting: false,
            contractAddress: 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 0
        });

        pubKeySK = PubKey({x: MINT_P256_PUBLIC_KEY_X, y: MINT_P256_PUBLIC_KEY_Y});
        keySK = Key({pubKey: pubKeySK, eoaAddress: address(0), keyType: KeyType.P256});
        uint48 validUntil = uint48(1795096759);
        uint48 limit = uint48(20);

        keyDataSK = KeyReg({
            validUntil: validUntil,
            validAfter: 0,
            limit: limit,
            whitelisting: true,
            contractAddress: TOKEN,
            spendTokenInfo: spendInfo,
            allowedSelectors: _allowedSelectors(),
            ethLimit: 1e18
        });

        bytes32 initialGuardian = keccak256(abi.encodePacked(sender));

        bytes32 structHash = keccak256(
            abi.encode(
                RECOVER_TYPEHASH,
                keyMK.pubKey.x,
                keyMK.pubKey.y,
                keyMK.eoaAddress,
                keyMK.keyType,
                initialGuardian
            )
        );

        string memory name = "OPF7702Recoverable";
        string memory version = "1";

        bytes32 domainSeparator = keccak256(
            abi.encode(
                TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, owner
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        account.initialize(keyMK, keyData, keySK, keyDataSK, sig, initialGuardian);
    }
}
