// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Base} from "test/Base.sol";
import "lib/forge-std/src/StdJson.sol";
import {IKey} from "src/interfaces/IKey.sol";
import {SpendLimit} from "src/utils/SpendLimit.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {Script, console2 as console} from "lib/forge-std/src/Script.sol";

contract Init is Script, IKey {
    uint256 internal senderPk = vm.envUint("PRIVATE_KEY_SENDER");
    address internal sender = vm.addr(senderPk);

    string public json_reg = vm.readFile("test/data/registration.json");
    bytes32 public REG_PUBLIC_KEY_X = stdJson.readBytes32(json_reg, ".registration.x");
    bytes32 public REG_PUBLIC_KEY_Y = stdJson.readBytes32(json_reg, ".registration.y");

    OPF7702 opf;
    uint256 internal ownerPk = vm.envUint("PRIVATE_KEY_PROXY");
    address internal owner = vm.addr(ownerPk);
    Key _key;
    PubKey pubKey;
    KeyReg _keyData;

    bytes32 digest;
    bytes32 _initialGuardian;

    function run() public {
        vm.startBroadcast();
        opf = OPF7702(payable(owner));
        pubKey = PubKey({x: REG_PUBLIC_KEY_X, y: REG_PUBLIC_KEY_Y});
        _key = Key({pubKey: pubKey, eoaAddress: address(0), keyType: KeyType.WEBAUTHN});
        _initialGuardian = keccak256(abi.encodePacked(sender));

        bytes4[] memory allowedSelectors = new bytes4[](1);
        allowedSelectors[0] = 0xdeedbeef;

        _keyData = KeyReg({
            validAfter: 0,
            validUntil: 0,
            limit: 0,
            whitelisting: false,
            contractAddress: address(0),
            spendTokenInfo: SpendLimit.SpendTokenInfo({token: address(0), limit: 0}),
            allowedSelectors: allowedSelectors,
            ethLimit: 0
        });

        digest = opf.getDigestToInit(_key, _initialGuardian);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        opf.initialize(_key, _keyData, sig, _initialGuardian);
        vm.stopBroadcast();
    }
}
