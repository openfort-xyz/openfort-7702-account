// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Data} from "././Data.t.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {GasPolicy} from "src/utils/GasPolicy.sol";
import {SocialRecoveryManager} from "src/utils/SocialRecover.sol";
import {OPFMain as OPF7702} from "src/core/OPFMain.sol";
import {WebAuthnVerifierV2} from "src/utils/WebAuthnVerifierV2.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract BaseData is Data {
    uint256 internal ownerPK;
    address internal owner;

    uint256 internal sessionKeyPK;
    address internal sessionKey;

    uint256 internal senderPK;
    address internal sender;

    uint256 internal guardianPK;
    address internal guardian;

    MockERC20 erc20;

    KeyDataReg internal mkReg;
    KeyDataReg internal skReg;
    bytes32 internal _initialGuardian;

    GasPolicy public gasPolicy;
    IEntryPoint public entryPoint;
    WebAuthnVerifierV2 public webAuthn;
    SocialRecoveryManager public recoveryManager;

    OPF7702 public implementation;
    OPF7702 public account;

    function _createQuickFreshKey(bool _isMK) internal {
        if (_isMK) {
            mkReg = KeyDataReg({
                keyType: KeyType.WEBAUTHN,
                validUntil: type(uint48).max,
                validAfter: 0,
                limits: 0,
                key: abi.encode(keccak256("x.WebAuthn"), keccak256("y.WebAuthn")),
                keyControl: KeyControl.Self
            });
        } else if (!_isMK) {
            skReg = KeyDataReg({
                keyType: KeyType.P256NONKEY,
                validUntil: uint48(block.timestamp + 10 days),
                validAfter: 0,
                limits: 10,
                key: abi.encode(keccak256("x.P256"), keccak256("y.P256")),
                keyControl: KeyControl.Self
            });
        }
    }

    function _createCustomFreshKey(
        bool _isMK,
        KeyType _kT,
        uint48 _vU,
        uint48 _vA,
        uint48 _l,
        bytes memory _key,
        KeyControl _kC
    ) internal {
        if (_isMK) {
            mkReg = KeyDataReg({
                keyType: _kT,
                validUntil: _vU,
                validAfter: _vA,
                limits: _l,
                key: _key,
                keyControl: _kC
            });
        } else if (!_isMK) {
            skReg = KeyDataReg({
                keyType: _kT,
                validUntil: _vU,
                validAfter: _vA,
                limits: _l,
                key: _key,
                keyControl: _kC
            });
        }
    }

    function _getKeyEOA(address _eoa) internal pure returns (bytes memory _key) {
        _key = abi.encode(_eoa);
    }

    function _getKeyP256(PubKey memory _pK) internal pure returns (bytes memory _key) {
        _key = abi.encode(_pK.x, _pK.y);
    }

    function _packAccountGasLimits(uint256 callGasLimit, uint256 verificationGasLimit)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((callGasLimit << 128) | verificationGasLimit);
    }

    function _packGasFees(uint256 maxFeePerGas, uint256 maxPriorityFeePerGas)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((maxFeePerGas << 128) | maxPriorityFeePerGas);
    }

    function _deal() public {
        deal(owner, 10e18);
        deal(sender, 10e18);
    }

    function _createInitialGuradian() internal {
        _initialGuardian = keccak256(abi.encode(guardian));
    }

    function _computeKeyId(KeyType _keyType, bytes memory _key)
        internal
        pure
        returns (bytes32 result)
    {
        uint256 v0 = uint8(_keyType);
        uint256 v1 = uint256(keccak256(_key));
        assembly {
            mstore(0x00, v0)
            mstore(0x20, v1)
            result := keccak256(0x00, 0x40)
        }
    }

    function _computeKeyId(KeyDataReg memory _keyData) internal pure returns (bytes32) {
        return _computeKeyId(_keyData.keyType, _keyData.key);
    }

    function _createCall(address _target, uint256 _value, bytes memory _data)
        internal
        pure
        returns (Call memory call)
    {
        call = Call({target: _target, value: _value, data: _data});
    }

    function _packCallData(bytes32 _mode, Call[] memory _calls)
        internal
        pure
        returns (bytes memory callData)
    {
        bytes memory executionData = abi.encode(_calls);
        callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(bytes32,bytes)")), _mode, executionData
        );
    }

    function _getFreshUserOp() internal view returns (PackedUserOperation memory userOp) {
        userOp = PackedUserOperation({
            sender: owner,
            nonce: 0,
            initCode: hex"7702",
            callData: hex"",
            accountGasLimits: hex"",
            preVerificationGas: 0,
            gasFees: hex"",
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _getCalls(uint256 _indx, address _target, uint256 _value, bytes memory _data)
        internal
        pure
        returns (Call[] memory calls)
    {
        calls = new Call[](_indx);
        for (uint256 i = 0; i < _indx;) {
            calls[i] = _createCall(_target, _value, _data);
            unchecked {
                ++i;
            }
        }
    }
}
