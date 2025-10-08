// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import "lib/forge-std/src/StdJson.sol";
import {Test} from "lib/forge-std/src/Test.sol";

contract SignersData is Test {
    struct WebAuthn {
        bool UVR;
        bytes AUTHENTICATOR_DATA;
        string CLIENT_DATA_JSON;
        uint256 CHALLENGE_INDEX;
        uint256 TYPE_INDEX;
        bytes32 R;
        bytes32 S;
        bytes32 X;
        bytes32 Y;
    }

    struct P256 {
        bytes32 R;
        bytes32 S;
        bytes32 X;
        bytes32 Y;
    }

    WebAuthn internal DEF_WEBAUTHN;
    P256 internal DEF_P256;

    function _getPath(string memory _path) internal pure returns (string memory path) {
        string memory defPath = "test/data/";
        path = string.concat(defPath, _path);
    }

    function _populateWebAuthn(string memory _path, string memory _key) internal {
        string memory path = _getPath(_path);
        string memory json = vm.readFile(path);

        string memory meta = string.concat(_key, ".metadata");
        string memory sig = string.concat(_key, ".signature");

        DEF_WEBAUTHN = WebAuthn({
            UVR: stdJson.readBool(json, string.concat(meta, ".userVerificationRequired")),
            AUTHENTICATOR_DATA: stdJson.readBytes(json, string.concat(meta, ".authenticatorData")),
            CLIENT_DATA_JSON: stdJson.readString(json, string.concat(meta, ".clientDataJSON")),
            CHALLENGE_INDEX: stdJson.readUint(json, string.concat(meta, ".challengeIndex")),
            TYPE_INDEX: stdJson.readUint(json, string.concat(meta, ".typeIndex")),
            R: stdJson.readBytes32(json, string.concat(sig, ".r")),
            S: stdJson.readBytes32(json, string.concat(sig, ".s")),
            X: stdJson.readBytes32(json, string.concat(_key, ".x")),
            Y: stdJson.readBytes32(json, string.concat(_key, ".y"))
        });
    }

    function _populateP256(string memory _path, string memory _key) internal {
        string memory path = _getPath(_path);
        string memory json = vm.readFile(path);

        DEF_P256 = P256({
            R: stdJson.readBytes32(json, string.concat(_key, ".P256_lowSR")),
            S: stdJson.readBytes32(json, string.concat(_key, ".P256_lowSS")),
            X: stdJson.readBytes32(json, string.concat(_key, ".P256_xHex")),
            Y: stdJson.readBytes32(json, string.concat(_key, ".P256_yHex"))
        });
    }

    function _populateP256NON(string memory _path, string memory _key) internal {
        string memory path = _getPath(_path);
        string memory json = vm.readFile(path);

        DEF_P256 = P256({
            R: stdJson.readBytes32(json, string.concat(_key, ".P256NONKEY_rHex")),
            S: stdJson.readBytes32(json, string.concat(_key, ".P256NONKEY_sHex")),
            X: stdJson.readBytes32(json, string.concat(_key, ".P256NONKEY_xHex")),
            Y: stdJson.readBytes32(json, string.concat(_key, ".P256NONKEY_yHex"))
        });
    }
}
