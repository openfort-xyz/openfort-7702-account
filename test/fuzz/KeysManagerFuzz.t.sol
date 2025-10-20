// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "../Deploy.t.sol";
import {IKey} from "src/interfaces/IKey.sol";

contract KeysManagerFuzz is Deploy {
    PubKey internal masterPk;

    function setUp() public override {
        super.setUp();

        _populateWebAuthn("keysmanager.json", ".keys_register");

        masterPk = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(masterPk), KeyControl.Self
        );

        _createQuickFreshKey(false);
        _initializeAccount();
    }

    function testFuzz_updateKeyData(uint48 extendByRaw, uint48 newLimitRaw) external {
        (bytes32 keyId, IKey.KeyData memory keyData) = account.keyAt(1);
        vm.assume(keyData.isActive && !keyData.masterKey);

        uint256 extendBy = bound(uint256(extendByRaw), 1, 30 days);
        uint256 proposedValidUntil = uint256(keyData.validUntil) + extendBy;
        vm.assume(proposedValidUntil < type(uint48).max);
        uint48 newValidUntil = uint48(proposedValidUntil);

        uint48 newLimit = uint48(bound(uint256(newLimitRaw), 1, type(uint48).max - 1));

        vm.prank(owner);
        account.updateKeyData(keyId, newValidUntil, newLimit);

        (, IKey.KeyData memory updated) = account.keyAt(1);
        assertEq(updated.validUntil, newValidUntil);
        assertEq(updated.limits, newLimit);
    }
}
