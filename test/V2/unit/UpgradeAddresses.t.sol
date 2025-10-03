// SPDX-Lincese-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract UpgradeAddresses is Deploy {
    enum Addr {
        EP,
        VERIFIER,
        GAS
    }

    address[] addrToCompare;
    PubKey internal pK;

    function setUp() public override {
        super.setUp();
        _populateWebAuthn("upgrade.json", ".ep");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );
        _createQuickFreshKey(false);

        _initializeAccount();
    }

    function test_UpgradeEPWithRootKey() external {
        _getCurrectAddr(Addr.EP);
        assertEq(address(entryPoint), addrToCompare[0]);

        _etch();
        vm.prank(owner);
        account.setEntryPoint(address(123456));

        _getCurrectAddr(Addr.EP);
        assertEq(address(123456), addrToCompare[1]);
    }

    function test_UpgradeWebAuthVerifieWithRootKey() external {
        _getCurrectAddr(Addr.VERIFIER);
        assertEq(WEBAUTHN_VERIFIER, addrToCompare[0]);

        _etch();
        vm.prank(owner);
        account.setWebAuthnVerifier(address(123456));

        _getCurrectAddr(Addr.VERIFIER);
        assertEq(address(123456), addrToCompare[1]);
    }

    function test_UpgradeGasPolicyWithRootKey() external {
        _getCurrectAddr(Addr.GAS);
        assertEq(address(gasPolicy), addrToCompare[0]);

        _etch();
        vm.prank(owner);
        account.setGasPolicy(address(123456));

        _getCurrectAddr(Addr.GAS);
        assertEq(address(123456), addrToCompare[1]);
    }

    function test_UpgradeEPAAWithRootKey() external {
        _getCurrectAddr(Addr.EP);
        assertEq(address(entryPoint), addrToCompare[0]);

        bytes memory data = abi.encodeWithSelector(account.setEntryPoint.selector, address(123456));
        Call[] memory calls = _getCalls(1, owner, 0, data);
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getCurrectAddr(Addr.EP);
        assertEq(address(123456), addrToCompare[1]);
    }

    function test_UpgradeWebAuthVerifieAAWithRootKey() external {
        _getCurrectAddr(Addr.VERIFIER);
        assertEq(WEBAUTHN_VERIFIER, addrToCompare[0]);

        bytes memory data =
            abi.encodeWithSelector(account.setWebAuthnVerifier.selector, address(123456));
        Call[] memory calls = _getCalls(1, owner, 0, data);
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getCurrectAddr(Addr.VERIFIER);
        assertEq(address(123456), addrToCompare[1]);
    }

    function test_UpgradeGasPolicyAAWithRootKey() external {
        _getCurrectAddr(Addr.GAS);
        assertEq(address(gasPolicy), addrToCompare[0]);

        bytes memory data = abi.encodeWithSelector(account.setGasPolicy.selector, address(123456));
        Call[] memory calls = _getCalls(1, owner, 0, data);
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _getCurrectAddr(Addr.GAS);
        assertEq(address(123456), addrToCompare[1]);
    }

    function test_UpgradeEPAAWithMK() external {
        _getCurrectAddr(Addr.EP);
        assertEq(address(entryPoint), addrToCompare[0]);

        bytes memory data = abi.encodeWithSelector(account.setEntryPoint.selector, address(123456));
        Call[] memory calls = _getCalls(1, owner, 0, data);
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Upgrade EP:", vm.toString(userOpHash));

        _populateWebAuthn("upgrade.json", ".ep");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _getCurrectAddr(Addr.EP);
        assertEq(address(123456), addrToCompare[1]);
    }

    function test_UpgradeWebAuthVerifieAAWithMK() external {
        _getCurrectAddr(Addr.VERIFIER);
        assertEq(WEBAUTHN_VERIFIER, addrToCompare[0]);

        bytes memory data =
            abi.encodeWithSelector(account.setWebAuthnVerifier.selector, address(123456));
        Call[] memory calls = _getCalls(1, owner, 0, data);
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Upgrade WAV:", vm.toString(userOpHash));

        _populateWebAuthn("upgrade.json", ".wav");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _getCurrectAddr(Addr.VERIFIER);
        assertEq(address(123456), addrToCompare[1]);
    }

    function test_UpgradeGasPolicyAAWithRootMK() external {
        _getCurrectAddr(Addr.GAS);
        assertEq(address(gasPolicy), addrToCompare[0]);

        bytes memory data = abi.encodeWithSelector(account.setGasPolicy.selector, address(123456));
        Call[] memory calls = _getCalls(1, owner, 0, data);
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            800_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Upgrade GAS:", vm.toString(userOpHash));

        _populateWebAuthn("upgrade.json", ".gas");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _getCurrectAddr(Addr.GAS);
        assertEq(address(123456), addrToCompare[1]);
    }

    function _relayUserOp(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }

    function _getCurrectAddr(Addr _addr) internal {
        if (_addr == Addr.EP) {
            addrToCompare.push(address(account.entryPoint()));
        } else if (_addr == Addr.VERIFIER) {
            addrToCompare.push((account.webAuthnVerifier()));
        } else if (_addr == Addr.GAS) {
            addrToCompare.push(account.gasPolicy());
        }
    }
}
