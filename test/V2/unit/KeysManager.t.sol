// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "./../Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract KeysManager is Deploy {
    PubKey internal pK;
    address[] tokens;
    KeyDataReg[] sKsEOA;
    KeyDataReg[] sKsWebAuthn;
    KeyDataReg[] sKsP256;
    KeyDataReg[] sKsP256NONKEY;

    modifier createKeys(uint256 _indx) {
        _createSKEOAs(_indx);
        _createSKWebAuthns(_indx);
        _createSKP256s(_indx);
        _createSKP256Nons(_indx);
        _;
    }

    function setUp() public override {
        super.setUp();
        _populateWebAuthn("keysmanager.json", ".keys_register");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(pK), KeyControl.Self
        );
        _createQuickFreshKey(false);

        _initializeAccount();
    }

    function test_RegisterKeyWithRootKey() external createKeys(5) {
        _registerKeys(sKsEOA);
        _registerKeys(sKsWebAuthn);
        _registerKeys(sKsP256);
        _registerKeys(sKsP256NONKEY);

        uint256 id = account.id();
        assertEq(id, 22);
        _assertRegisteredKKeys(sKsEOA, 2);
        _assertRegisteredKKeys(sKsWebAuthn, 7);
        _assertRegisteredKKeys(sKsP256, 12);
        _assertRegisteredKKeys(sKsP256NONKEY, 17);
    }

    function test_RevokeKeyWithRootKey() external createKeys(5) {
        _registerKeys(sKsEOA);
        _registerKeys(sKsWebAuthn);
        _registerKeys(sKsP256);
        _registerKeys(sKsP256NONKEY);

        uint256 id = account.id();
        assertEq(id, 22);
        _assertRegisteredKKeys(sKsEOA, 2);
        _assertRegisteredKKeys(sKsWebAuthn, 7);
        _assertRegisteredKKeys(sKsP256, 12);
        _assertRegisteredKKeys(sKsP256NONKEY, 17);

        _revokeKeys(sKsEOA);
        _revokeKeys(sKsWebAuthn);
        _revokeKeys(sKsP256);
        _revokeKeys(sKsP256NONKEY);

        _assertRevokedKKeys(sKsEOA, 2);
        _assertRevokedKKeys(sKsWebAuthn, 7);
        _assertRevokedKKeys(sKsP256, 12);
        _assertRevokedKKeys(sKsP256NONKEY, 17);
    }

    function test_UpdateKeyWithRootKey() external createKeys(5) {
        _registerKeys(sKsEOA);
        _registerKeys(sKsWebAuthn);
        _registerKeys(sKsP256);
        _registerKeys(sKsP256NONKEY);

        uint256 id = account.id();
        assertEq(id, 22);
        _assertRegisteredKKeys(sKsEOA, 2);
        _assertRegisteredKKeys(sKsWebAuthn, 7);
        _assertRegisteredKKeys(sKsP256, 12);
        _assertRegisteredKKeys(sKsP256NONKEY, 17);

        _updateKeyData(sKsEOA);
        _updateKeyData(sKsWebAuthn);
        _updateKeyData(sKsP256);
        _updateKeyData(sKsP256NONKEY);

        _assertUpdteKeys(sKsEOA, 2);
        _assertUpdteKeys(sKsWebAuthn, 7);
        _assertUpdteKeys(sKsP256, 12);
        _assertUpdteKeys(sKsP256NONKEY, 17);
    }

    function test_RegisterKeyAAwithRootKey() external createKeys(1) {
        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        uint256 id = account.id();
        assertEq(id, 6);
        _assertRegisteredKKeys(sKsEOA, 2);
        _assertRegisteredKKeys(sKsWebAuthn, 3);
        _assertRegisteredKKeys(sKsP256, 4);
        _assertRegisteredKKeys(sKsP256NONKEY, 5);
    }

    function test_RevokeKeyAAwithRootKey() external createKeys(1) {
        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        uint256 id = account.id();
        assertEq(id, 6);
        _assertRegisteredKKeys(sKsEOA, 2);
        _assertRegisteredKKeys(sKsWebAuthn, 3);
        _assertRegisteredKKeys(sKsP256, 4);
        _assertRegisteredKKeys(sKsP256NONKEY, 5);

        calls = _createStaticCallsRevoke();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertRevokedKKeys(sKsEOA, 2);
        _assertRevokedKKeys(sKsWebAuthn, 3);
        _assertRevokedKKeys(sKsP256, 4);
        _assertRevokedKKeys(sKsP256NONKEY, 5);
    }

    function test_UpdateKeyAAwithRootKey() external createKeys(1) {
        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        uint256 id = account.id();
        assertEq(id, 6);
        _assertRegisteredKKeys(sKsEOA, 2);
        _assertRegisteredKKeys(sKsWebAuthn, 3);
        _assertRegisteredKKeys(sKsP256, 4);
        _assertRegisteredKKeys(sKsP256NONKEY, 5);

        calls = _createStaticCallsUpdate();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertUpdteKeys(sKsEOA, 2);
        _assertUpdteKeys(sKsWebAuthn, 3);
        _assertUpdteKeys(sKsP256, 4);
        _assertUpdteKeys(sKsP256NONKEY, 5);
    }

    function test_RegisterKeyAAwithMK() external {
        _createStaticKeys();

        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_register");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        uint256 id = account.id();
        assertEq(id, 6);
        _assertRegisteredKKeys(sKsEOA, 2);
        _assertRegisteredKKeys(sKsWebAuthn, 3);
        _assertRegisteredKKeys(sKsP256, 4);
        _assertRegisteredKKeys(sKsP256NONKEY, 5);
    }

    function test_RevokeKeyAAwithMK() external {
        _createStaticKeys();

        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_register");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        uint256 id = account.id();
        assertEq(id, 6);
        _assertRegisteredKKeys(sKsEOA, 2);
        _assertRegisteredKKeys(sKsWebAuthn, 3);
        _assertRegisteredKKeys(sKsP256, 4);
        _assertRegisteredKKeys(sKsP256NONKEY, 5);

        calls = _createStaticCallsRevoke();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Revoke:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_revoke");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _assertRevokedKKeys(sKsEOA, 2);
        _assertRevokedKKeys(sKsWebAuthn, 3);
        _assertRevokedKKeys(sKsP256, 4);
        _assertRevokedKKeys(sKsP256NONKEY, 5);
    }

    function test_UpdateKeyAAwithMK() external {
        _createStaticKeys();

        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_register");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        uint256 id = account.id();
        assertEq(id, 6);
        _assertRegisteredKKeys(sKsEOA, 2);
        _assertRegisteredKKeys(sKsWebAuthn, 3);
        _assertRegisteredKKeys(sKsP256, 4);
        _assertRegisteredKKeys(sKsP256NONKEY, 5);

        calls = _createStaticCallsUpdate();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Update Key:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_update_key");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _assertUpdteKeys(sKsEOA, 2);
        _assertUpdteKeys(sKsWebAuthn, 3);
        _assertUpdteKeys(sKsP256, 4);
        _assertUpdteKeys(sKsP256NONKEY, 5);
    }

    function test_SetTokenSpendWithRootKey() external createKeys(1) {
        _registerKeys(sKsEOA);
        _registerKeys(sKsWebAuthn);
        _registerKeys(sKsP256);
        _registerKeys(sKsP256NONKEY);

        _createTokens(4);

        _setTokenSpend(sKsEOA, 0);
        _setTokenSpend(sKsWebAuthn, sKsEOA.length); // 1
        _setTokenSpend(sKsP256, sKsEOA.length + sKsWebAuthn.length); // 2
        _setTokenSpend(sKsP256NONKEY, sKsEOA.length + sKsWebAuthn.length + sKsP256.length);

        _assertTokenSpend(sKsEOA, 0, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsWebAuthn, 1, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256, 2, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256NONKEY, 3, 100e18, SpendPeriod.Month);
    }

    function test_SetTokenSpendAAWithRootKey() external createKeys(1) {
        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _createTokens(4);

        calls = _createStaticCallsSetTokenSpend();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertTokenSpend(sKsEOA, 0, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsWebAuthn, 1, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256, 2, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256NONKEY, 3, 100e18, SpendPeriod.Month);
    }

    function test_SetTokenSpendAAWithMK() external {
        _createStaticKeys();

        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_register");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _createTokens(4);

        calls = _createStaticCallsSetTokenSpend();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Set Token Spend:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_token");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _assertTokenSpend(sKsEOA, 0, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsWebAuthn, 1, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256, 2, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256NONKEY, 3, 100e18, SpendPeriod.Month);
    }

    function test_UpdateTokenSpendWithRootKey() external createKeys(1) {
        _registerKeys(sKsEOA);
        _registerKeys(sKsWebAuthn);
        _registerKeys(sKsP256);
        _registerKeys(sKsP256NONKEY);

        _createTokens(4);

        _setTokenSpend(sKsEOA, 0);
        _setTokenSpend(sKsWebAuthn, sKsEOA.length); // 1
        _setTokenSpend(sKsP256, sKsEOA.length + sKsWebAuthn.length); // 2
        _setTokenSpend(sKsP256NONKEY, sKsEOA.length + sKsWebAuthn.length + sKsP256.length);

        _assertTokenSpend(sKsEOA, 0, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsWebAuthn, 1, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256, 2, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256NONKEY, 3, 100e18, SpendPeriod.Month);

        _updateTokenSpend(sKsEOA, 0);
        _updateTokenSpend(sKsWebAuthn, sKsEOA.length); // 1
        _updateTokenSpend(sKsP256, sKsEOA.length + sKsWebAuthn.length); // 2
        _updateTokenSpend(sKsP256NONKEY, sKsEOA.length + sKsWebAuthn.length + sKsP256.length);

        _assertTokenSpend(sKsEOA, 0, 1000e18, SpendPeriod.Year);
        _assertTokenSpend(sKsWebAuthn, 1, 1000e18, SpendPeriod.Year);
        _assertTokenSpend(sKsP256, 2, 1000e18, SpendPeriod.Year);
        _assertTokenSpend(sKsP256NONKEY, 3, 1000e18, SpendPeriod.Year);
    }

    function test_UpdateTokenSpendAAWithRootKey() external createKeys(1) {
        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _createTokens(4);

        calls = _createStaticCallsSetTokenSpend();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertTokenSpend(sKsEOA, 0, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsWebAuthn, 1, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256, 2, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256NONKEY, 3, 100e18, SpendPeriod.Month);

        calls = _createStaticCallsUpdateTokenSpend();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertTokenSpend(sKsEOA, 0, 1000e18, SpendPeriod.Year);
        _assertTokenSpend(sKsWebAuthn, 1, 1000e18, SpendPeriod.Year);
        _assertTokenSpend(sKsP256, 2, 1000e18, SpendPeriod.Year);
        _assertTokenSpend(sKsP256NONKEY, 3, 1000e18, SpendPeriod.Year);
    }

    function test_UpdateTokenSpendAAWithMK() external {
        _createStaticKeys();

        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_register");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _createTokens(4);

        calls = _createStaticCallsSetTokenSpend();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Set Token Spend:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_token");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _assertTokenSpend(sKsEOA, 0, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsWebAuthn, 1, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256, 2, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256NONKEY, 3, 100e18, SpendPeriod.Month);

        calls = _createStaticCallsUpdateTokenSpend();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Update Token Spend:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_token_update");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _assertTokenSpend(sKsEOA, 0, 1000e18, SpendPeriod.Year);
        _assertTokenSpend(sKsWebAuthn, 1, 1000e18, SpendPeriod.Year);
        _assertTokenSpend(sKsP256, 2, 1000e18, SpendPeriod.Year);
        _assertTokenSpend(sKsP256NONKEY, 3, 1000e18, SpendPeriod.Year);
    }

    function test_RemoveTokenSpendWithRootKey() external createKeys(1) {
        _registerKeys(sKsEOA);
        _registerKeys(sKsWebAuthn);
        _registerKeys(sKsP256);
        _registerKeys(sKsP256NONKEY);

        _createTokens(4);

        _setTokenSpend(sKsEOA, 0);
        _setTokenSpend(sKsWebAuthn, sKsEOA.length); // 1
        _setTokenSpend(sKsP256, sKsEOA.length + sKsWebAuthn.length); // 2
        _setTokenSpend(sKsP256NONKEY, sKsEOA.length + sKsWebAuthn.length + sKsP256.length);

        _assertTokenSpend(sKsEOA, 0, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsWebAuthn, 1, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256, 2, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256NONKEY, 3, 100e18, SpendPeriod.Month);

        _removeTokenSpend(sKsEOA, 0);
        _removeTokenSpend(sKsWebAuthn, sKsEOA.length); // 1
        _removeTokenSpend(sKsP256, sKsEOA.length + sKsWebAuthn.length); // 2
        _removeTokenSpend(sKsP256NONKEY, sKsEOA.length + sKsWebAuthn.length + sKsP256.length);

        _assertTokenSpendAfterRemove(sKsEOA, 0);
        _assertTokenSpendAfterRemove(sKsWebAuthn, 1);
        _assertTokenSpendAfterRemove(sKsP256, 2);
        _assertTokenSpendAfterRemove(sKsP256NONKEY, 3);
    }

    function test_RemoveTokenSpendAAWithRootKey() external createKeys(1) {
        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _createTokens(4);

        calls = _createStaticCallsSetTokenSpend();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertTokenSpend(sKsEOA, 0, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsWebAuthn, 1, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256, 2, 100e18, SpendPeriod.Month);
        _assertTokenSpend(sKsP256NONKEY, 3, 100e18, SpendPeriod.Month);

        calls = _createStaticCallsRemoveTokenSpend();

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertTokenSpendAfterRemove(sKsEOA, 0);
        _assertTokenSpendAfterRemove(sKsWebAuthn, 1);
        _assertTokenSpendAfterRemove(sKsP256, 2);
        _assertTokenSpendAfterRemove(sKsP256NONKEY, 3);
    }

    function test_SetCanCallWithRootKey() external createKeys(1) {
        _registerKeys(sKsEOA);
        _registerKeys(sKsWebAuthn);
        _registerKeys(sKsP256);
        _registerKeys(sKsP256NONKEY);

        _createTokens(4);

        _setTokenSpend(sKsEOA, 0);
        _setTokenSpend(sKsWebAuthn, sKsEOA.length); // 1
        _setTokenSpend(sKsP256, sKsEOA.length + sKsWebAuthn.length); // 2
        _setTokenSpend(sKsP256NONKEY, sKsEOA.length + sKsWebAuthn.length + sKsP256.length);

        _setCanCall(sKsEOA, 0, true);
        _setCanCall(sKsWebAuthn, sKsEOA.length, true); // 1
        _setCanCall(sKsP256, sKsEOA.length + sKsWebAuthn.length, true); // 2
        _setCanCall(sKsP256NONKEY, sKsEOA.length + sKsWebAuthn.length + sKsP256.length, true);

        _assertCanCall(sKsEOA, 0, ANY_FN_SEL);
        _assertCanCall(sKsWebAuthn, 1, ANY_FN_SEL);
        _assertCanCall(sKsP256, 2, ANY_FN_SEL);
        _assertCanCall(sKsP256NONKEY, 3, ANY_FN_SEL);
    }

    function test_SetCanCallAAWithRootKey() external createKeys(1) {
        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _createTokens(4);

        calls = _createStaticCallsSetOrRemoveCanCall(true);

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertCanCall(sKsEOA, 0, ANY_FN_SEL);
        _assertCanCall(sKsWebAuthn, 1, ANY_FN_SEL);
        _assertCanCall(sKsP256, 2, ANY_FN_SEL);
        _assertCanCall(sKsP256NONKEY, 3, ANY_FN_SEL);
    }

    function test_RemoveCanCallWithRootKey() external createKeys(1) {
        _registerKeys(sKsEOA);
        _registerKeys(sKsWebAuthn);
        _registerKeys(sKsP256);
        _registerKeys(sKsP256NONKEY);

        _createTokens(4);

        _setTokenSpend(sKsEOA, 0);
        _setTokenSpend(sKsWebAuthn, sKsEOA.length); // 1
        _setTokenSpend(sKsP256, sKsEOA.length + sKsWebAuthn.length); // 2
        _setTokenSpend(sKsP256NONKEY, sKsEOA.length + sKsWebAuthn.length + sKsP256.length);

        _setCanCall(sKsEOA, 0, true);
        _setCanCall(sKsWebAuthn, sKsEOA.length, true); // 1
        _setCanCall(sKsP256, sKsEOA.length + sKsWebAuthn.length, true); // 2
        _setCanCall(sKsP256NONKEY, sKsEOA.length + sKsWebAuthn.length + sKsP256.length, true);

        _assertCanCall(sKsEOA, 0, ANY_FN_SEL);
        _assertCanCall(sKsWebAuthn, 1, ANY_FN_SEL);
        _assertCanCall(sKsP256, 2, ANY_FN_SEL);
        _assertCanCall(sKsP256NONKEY, 3, ANY_FN_SEL);

        _setCanCall(sKsEOA, 0, false);
        _setCanCall(sKsWebAuthn, sKsEOA.length, false); // 1
        _setCanCall(sKsP256, sKsEOA.length + sKsWebAuthn.length, false); // 2
        _setCanCall(sKsP256NONKEY, sKsEOA.length + sKsWebAuthn.length + sKsP256.length, false);

        _assertCanCallAfterRemove(sKsEOA, 0, ANY_FN_SEL);
        _assertCanCallAfterRemove(sKsWebAuthn, 1, ANY_FN_SEL);
        _assertCanCallAfterRemove(sKsP256, 2, ANY_FN_SEL);
        _assertCanCallAfterRemove(sKsP256NONKEY, 3, ANY_FN_SEL);
    }

    function test_RemoveCanCallAAWithRootKey() external createKeys(1) {
        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes memory signature = _signUserOp(userOp);
        userOp.signature = _encodeEOASignature(signature);

        _relayUserOp(userOp);

        _createTokens(4);

        calls = _createStaticCallsSetOrRemoveCanCall(true);

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertCanCall(sKsEOA, 0, ANY_FN_SEL);
        _assertCanCall(sKsWebAuthn, 1, ANY_FN_SEL);
        _assertCanCall(sKsP256, 2, ANY_FN_SEL);
        _assertCanCall(sKsP256NONKEY, 3, ANY_FN_SEL);

        calls = _createStaticCallsSetOrRemoveCanCall(false);

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        _relayUserOp(userOp);

        _assertCanCallAfterRemove(sKsEOA, 0, ANY_FN_SEL);
        _assertCanCallAfterRemove(sKsWebAuthn, 1, ANY_FN_SEL);
        _assertCanCallAfterRemove(sKsP256, 2, ANY_FN_SEL);
        _assertCanCallAfterRemove(sKsP256NONKEY, 3, ANY_FN_SEL);
    }

    function test_SetCanCallAAWithMK() external {
        _createStaticKeys();

        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_register");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _createTokens(4);

        calls = _createStaticCallsSetOrRemoveCanCall(true);

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Set Can Call:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_can_call");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _assertCanCall(sKsEOA, 0, ANY_FN_SEL);
        _assertCanCall(sKsWebAuthn, 1, ANY_FN_SEL);
        _assertCanCall(sKsP256, 2, ANY_FN_SEL);
        _assertCanCall(sKsP256NONKEY, 3, ANY_FN_SEL);
    }

    function test_RemoveCanCallAAWithMK() external {
        _createStaticKeys();

        Call[] memory calls = _createStaticCallsRegister();

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(800_000, 600_000),
            900_000,
            _packGasFees(80 gwei, 15 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_register");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _createTokens(4);

        calls = _createStaticCallsSetOrRemoveCanCall(true);

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Set Can Call:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_can_call");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _assertCanCall(sKsEOA, 0, ANY_FN_SEL);
        _assertCanCall(sKsWebAuthn, 1, ANY_FN_SEL);
        _assertCanCall(sKsP256, 2, ANY_FN_SEL);
        _assertCanCall(sKsP256NONKEY, 3, ANY_FN_SEL);

        calls = _createStaticCallsSetOrRemoveCanCall(false);

        userOp.nonce = _getNonce();
        userOp.callData = _packCallData(mode_1, calls);

        userOpHash = _getUserOpHash(userOp);
        console.log("userOpHash Remove Can Call:", vm.toString(userOpHash));

        _populateWebAuthn("keysmanager.json", ".keys_can_call_remove");
        pK = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});

        userOp.signature = _getSignedUserOpByWebAuthn(DEF_WEBAUTHN, pK);

        _relayUserOp(userOp);

        _assertCanCallAfterRemove(sKsEOA, 0, ANY_FN_SEL);
        _assertCanCallAfterRemove(sKsWebAuthn, 1, ANY_FN_SEL);
        _assertCanCallAfterRemove(sKsP256, 2, ANY_FN_SEL);
        _assertCanCallAfterRemove(sKsP256NONKEY, 3, ANY_FN_SEL);
    }

    function _relayUserOp(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }

    function _assertRegisteredKKeys(KeyDataReg[] memory _keys, uint256 _startFrom) internal view {
        for (uint256 i = 0; i < _keys.length;) {
            (bytes32 keyId, KeyData memory data) = account.keyAt(_startFrom + i);
            assertTrue(data.isActive);
            assertFalse(data.masterKey);
            assertFalse(data.isDelegatedControl);
            assertEq(data.key, _keys[i].key);
            assertEq(uint8(data.keyType), uint8(_keys[i].keyType));
            assertEq(data.limits, _keys[i].limits);
            assertEq(data.validAfter, _keys[i].validAfter);
            assertEq(data.validUntil, _keys[i].validUntil);
            assertEq(keyId, _computeKeyId(_keys[i]));

            unchecked {
                ++i;
            }
        }
    }

    function _assertUpdteKeys(KeyDataReg[] memory _keys, uint256 _startFrom) internal view {
        for (uint256 i = 0; i < _keys.length;) {
            (bytes32 keyId, KeyData memory data) = account.keyAt(_startFrom + i);
            assertTrue(data.isActive);
            assertFalse(data.masterKey);
            assertFalse(data.isDelegatedControl);
            assertEq(data.key, _keys[i].key);
            assertEq(uint8(data.keyType), uint8(_keys[i].keyType));
            assertEq(data.limits, 20);
            assertEq(data.validAfter, _keys[i].validAfter);
            assertEq(data.validUntil, uint48(1790949874));
            assertEq(keyId, _computeKeyId(_keys[i]));

            unchecked {
                ++i;
            }
        }
    }

    function _assertRevokedKKeys(KeyDataReg[] memory _keys, uint256 _startFrom) internal view {
        for (uint256 i = 0; i < _keys.length;) {
            (bytes32 keyId, KeyData memory data) = account.keyAt(_startFrom + i);
            assertFalse(data.isActive);
            assertFalse(data.masterKey);
            assertFalse(data.isDelegatedControl);
            assertEq(data.key, hex"");
            assertEq(uint8(data.keyType), uint8(0));
            assertEq(data.limits, 0);
            assertEq(data.validAfter, 0);
            assertEq(data.validUntil, 0);
            assertEq(keyId, _computeKeyId(_keys[i]));

            unchecked {
                ++i;
            }
        }
    }

    function _assertTokenSpend(
        KeyDataReg[] memory _keys,
        uint256 start,
        uint256 _limits,
        SpendPeriod _sP
    ) internal view {
        for (uint256 i; i < _keys.length;) {
            bytes32 kid = _computeKeyId(_keys[i]);
            address tok = tokens[start + i];

            assertTrue(account.hasTokenSpend(kid, tok));
            (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated) =
                account.tokenSpend(kid, tok);

            assertEq(uint8(period), uint8(_sP));
            assertEq(limit, _limits);
            assertEq(spent, 0);
            assertEq(lastUpdated, 0);
            unchecked {
                ++i;
            }
        }
    }

    function _assertTokenSpendAfterRemove(KeyDataReg[] memory _keys, uint256 start) internal view {
        for (uint256 i; i < _keys.length;) {
            bytes32 kid = _computeKeyId(_keys[i]);
            address tok = tokens[start + i];

            assertFalse(account.hasTokenSpend(kid, tok));
            (SpendPeriod period, uint256 limit, uint256 spent, uint256 lastUpdated) =
                account.tokenSpend(kid, tok);

            assertEq(uint8(period), uint8(0));
            assertEq(limit, 0);
            assertEq(spent, 0);
            assertEq(lastUpdated, 0);
            unchecked {
                ++i;
            }
        }
    }

    function _assertCanCall(KeyDataReg[] memory _keys, uint256 start, bytes4 _funSel)
        internal
        view
    {
        for (uint256 i; i < _keys.length;) {
            bytes32 kid = _computeKeyId(_keys[i]);
            address tok = tokens[start + i];

            assertTrue(account.hasCanCall(kid, tok, _funSel));
            (address target, bytes4 fnSel) = account.canExecuteAt(kid, 0);

            assertEq(target, tok);
            assertEq(fnSel, _funSel);
            unchecked {
                ++i;
            }
        }
    }

    function _assertCanCallAfterRemove(KeyDataReg[] memory _keys, uint256 start, bytes4 _funSel)
        internal
        view
    {
        for (uint256 i; i < _keys.length;) {
            bytes32 kid = _computeKeyId(_keys[i]);
            address tok = tokens[start + i];
            assertFalse(account.hasCanCall(kid, tok, _funSel));

            unchecked {
                ++i;
            }
        }
    }

    function _registerKeys(KeyDataReg[] memory _keys) internal {
        for (uint256 i = 0; i < _keys.length;) {
            _etch();
            vm.prank(owner);
            account.registerKey(_keys[i]);
            unchecked {
                ++i;
            }
        }
    }

    function _revokeKeys(KeyDataReg[] memory _keys) internal {
        for (uint256 i = 0; i < _keys.length;) {
            _etch();
            vm.prank(owner);
            account.revokeKey(_computeKeyId(_keys[i]));
            unchecked {
                ++i;
            }
        }
    }

    function _updateKeyData(KeyDataReg[] memory _keys) internal {
        for (uint256 i = 0; i < _keys.length;) {
            _etch();
            vm.prank(owner);
            account.updateKeyData(_computeKeyId(_keys[i]), uint48(1790949874), 20);
            unchecked {
                ++i;
            }
        }
    }

    function _setTokenSpend(KeyDataReg[] memory _keys, uint256 start) internal {
        for (uint256 i; i < _keys.length;) {
            _etch();
            vm.prank(owner);
            account.setTokenSpend(
                _computeKeyId(_keys[i]), tokens[start + i], 100e18, SpendPeriod.Month
            );
            unchecked {
                ++i;
            }
        }
    }

    function _updateTokenSpend(KeyDataReg[] memory _keys, uint256 start) internal {
        for (uint256 i; i < _keys.length;) {
            _etch();
            vm.prank(owner);
            account.updateTokenSpend(
                _computeKeyId(_keys[i]), tokens[start + i], 1000e18, SpendPeriod.Year
            );
            unchecked {
                ++i;
            }
        }
    }

    function _removeTokenSpend(KeyDataReg[] memory _keys, uint256 start) internal {
        for (uint256 i; i < _keys.length;) {
            _etch();
            vm.prank(owner);
            account.removeTokenSpend(_computeKeyId(_keys[i]), tokens[start + i]);
            unchecked {
                ++i;
            }
        }
    }

    function _setCanCall(KeyDataReg[] memory _keys, uint256 start, bool _can) internal {
        for (uint256 i; i < _keys.length;) {
            _etch();
            vm.prank(owner);
            account.setCanCall(_computeKeyId(_keys[i]), tokens[start + i], ANY_FN_SEL, _can);
            unchecked {
                ++i;
            }
        }
    }

    function _createSKEOAs(uint256 _indx) internal {
        for (uint256 i = 0; i < _indx;) {
            _createCustomFreshKey(
                false,
                KeyType.EOA,
                uint48(block.timestamp + (i + 1 * 86400)),
                0,
                uint48(i + 1),
                _getKeyEOA(makeAddr(vm.toString(i))),
                KeyControl.Self
            );
            sKsEOA.push(skReg);
            unchecked {
                ++i;
            }
        }
    }

    function _createSKWebAuthns(uint256 _indx) internal {
        for (uint256 i = 0; i < _indx;) {
            pK = PubKey({x: keccak256(abi.encode("x", i)), y: keccak256(abi.encode("y", i))});
            _createCustomFreshKey(
                false,
                KeyType.WEBAUTHN,
                uint48(block.timestamp + (i + 1 * 86400)),
                0,
                uint48(i + 1),
                _getKeyP256(pK),
                KeyControl.Self
            );
            sKsWebAuthn.push(skReg);
            unchecked {
                ++i;
            }
        }
    }

    function _createSKP256s(uint256 _indx) internal {
        for (uint256 i = 0; i < _indx;) {
            pK = PubKey({x: keccak256(abi.encode("x", i)), y: keccak256(abi.encode("y", i))});
            _createCustomFreshKey(
                false,
                KeyType.P256,
                uint48(block.timestamp + (i + 1 * 86400)),
                0,
                uint48(i + 1),
                _getKeyP256(pK),
                KeyControl.Self
            );
            sKsP256.push(skReg);
            unchecked {
                ++i;
            }
        }
    }

    function _createSKP256Nons(uint256 _indx) internal {
        for (uint256 i = 0; i < _indx;) {
            pK = PubKey({x: keccak256(abi.encode("x", i)), y: keccak256(abi.encode("y", i))});
            _createCustomFreshKey(
                false,
                KeyType.P256NONKEY,
                uint48(block.timestamp + (i + 1 * 86400)),
                0,
                uint48(i + 1),
                _getKeyP256(pK),
                KeyControl.Self
            );
            sKsP256NONKEY.push(skReg);
            unchecked {
                ++i;
            }
        }
    }

    function _createStaticKeys() internal {
        _createCustomFreshKey(
            false,
            KeyType.EOA,
            uint48(1764665153),
            0,
            uint48(10),
            _getKeyEOA(makeAddr("1")),
            KeyControl.Self
        );

        sKsEOA.push(skReg);

        pK = PubKey({x: keccak256(abi.encode("x", 1)), y: keccak256(abi.encode("y", 1))});
        _createCustomFreshKey(
            false,
            KeyType.WEBAUTHN,
            uint48(1764665153),
            0,
            uint48(10),
            _getKeyP256(pK),
            KeyControl.Self
        );
        sKsWebAuthn.push(skReg);

        pK = PubKey({x: keccak256(abi.encode("x", 2)), y: keccak256(abi.encode("y", 2))});
        _createCustomFreshKey(
            false, KeyType.P256, uint48(1764665153), 0, uint48(10), _getKeyP256(pK), KeyControl.Self
        );
        sKsP256.push(skReg);

        pK = PubKey({x: keccak256(abi.encode("x", 3)), y: keccak256(abi.encode("y", 3))});
        _createCustomFreshKey(
            false,
            KeyType.P256NONKEY,
            uint48(1764665153),
            0,
            uint48(10),
            _getKeyP256(pK),
            KeyControl.Self
        );
        sKsP256NONKEY.push(skReg);
    }

    function _createTokens(uint256 _indx) internal {
        for (uint256 i = 0; i < _indx;) {
            tokens.push(makeAddr(vm.toString(abi.encode("erc20", i))));
            unchecked {
                ++i;
            }
        }
    }

    function _createStaticCallsRegister() internal view returns (Call[] memory calls) {
        calls = new Call[](4);
        calls[0] = _createCall(
            address(account), 0, abi.encodeWithSelector(account.registerKey.selector, sKsEOA[0])
        );
        calls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.registerKey.selector, sKsWebAuthn[0])
        );
        calls[2] = _createCall(
            address(account), 0, abi.encodeWithSelector(account.registerKey.selector, sKsP256[0])
        );
        calls[3] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.registerKey.selector, sKsP256NONKEY[0])
        );
    }

    function _createStaticCallsRevoke() internal view returns (Call[] memory calls) {
        calls = new Call[](4);
        calls[0] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.revokeKey.selector, _computeKeyId(sKsEOA[0]))
        );
        calls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.revokeKey.selector, _computeKeyId(sKsWebAuthn[0]))
        );
        calls[2] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.revokeKey.selector, _computeKeyId(sKsP256[0]))
        );
        calls[3] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(account.revokeKey.selector, _computeKeyId(sKsP256NONKEY[0]))
        );
    }

    function _createStaticCallsUpdate() internal view returns (Call[] memory calls) {
        calls = new Call[](4);
        calls[0] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.updateKeyData.selector, _computeKeyId(sKsEOA[0]), uint48(1790949874), 20
            )
        );
        calls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.updateKeyData.selector,
                _computeKeyId(sKsWebAuthn[0]),
                uint48(1790949874),
                20
            )
        );
        calls[2] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.updateKeyData.selector, _computeKeyId(sKsP256[0]), uint48(1790949874), 20
            )
        );
        calls[3] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.updateKeyData.selector,
                _computeKeyId(sKsP256NONKEY[0]),
                uint48(1790949874),
                20
            )
        );
    }

    function _createStaticCallsSetTokenSpend() internal view returns (Call[] memory calls) {
        calls = new Call[](4);
        calls[0] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setTokenSpend.selector,
                _computeKeyId(sKsEOA[0]),
                tokens[0],
                100e18,
                SpendPeriod.Month
            )
        );
        calls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setTokenSpend.selector,
                _computeKeyId(sKsWebAuthn[0]),
                tokens[1],
                100e18,
                SpendPeriod.Month
            )
        );
        calls[2] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setTokenSpend.selector,
                _computeKeyId(sKsP256[0]),
                tokens[2],
                100e18,
                SpendPeriod.Month
            )
        );
        calls[3] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setTokenSpend.selector,
                _computeKeyId(sKsP256NONKEY[0]),
                tokens[3],
                100e18,
                SpendPeriod.Month
            )
        );
    }

    function _createStaticCallsUpdateTokenSpend() internal view returns (Call[] memory calls) {
        calls = new Call[](4);
        calls[0] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.updateTokenSpend.selector,
                _computeKeyId(sKsEOA[0]),
                tokens[0],
                1000e18,
                SpendPeriod.Year
            )
        );
        calls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.updateTokenSpend.selector,
                _computeKeyId(sKsWebAuthn[0]),
                tokens[1],
                1000e18,
                SpendPeriod.Year
            )
        );
        calls[2] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.updateTokenSpend.selector,
                _computeKeyId(sKsP256[0]),
                tokens[2],
                1000e18,
                SpendPeriod.Year
            )
        );
        calls[3] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.updateTokenSpend.selector,
                _computeKeyId(sKsP256NONKEY[0]),
                tokens[3],
                1000e18,
                SpendPeriod.Year
            )
        );
    }

    function _createStaticCallsRemoveTokenSpend() internal view returns (Call[] memory calls) {
        calls = new Call[](4);
        calls[0] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.removeTokenSpend.selector, _computeKeyId(sKsEOA[0]), tokens[0]
            )
        );
        calls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.removeTokenSpend.selector, _computeKeyId(sKsWebAuthn[0]), tokens[1]
            )
        );
        calls[2] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.removeTokenSpend.selector, _computeKeyId(sKsP256[0]), tokens[2]
            )
        );
        calls[3] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.removeTokenSpend.selector, _computeKeyId(sKsP256NONKEY[0]), tokens[3]
            )
        );
    }

    function _createStaticCallsSetOrRemoveCanCall(bool _can)
        internal
        view
        returns (Call[] memory calls)
    {
        calls = new Call[](4);
        calls[0] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setCanCall.selector, _computeKeyId(sKsEOA[0]), tokens[0], ANY_FN_SEL, _can
            )
        );
        calls[1] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setCanCall.selector,
                _computeKeyId(sKsWebAuthn[0]),
                tokens[1],
                ANY_FN_SEL,
                _can
            )
        );
        calls[2] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setCanCall.selector, _computeKeyId(sKsP256[0]), tokens[2], ANY_FN_SEL, _can
            )
        );
        calls[3] = _createCall(
            address(account),
            0,
            abi.encodeWithSelector(
                account.setCanCall.selector,
                _computeKeyId(sKsP256NONKEY[0]),
                tokens[3],
                ANY_FN_SEL,
                _can
            )
        );
    }
}
