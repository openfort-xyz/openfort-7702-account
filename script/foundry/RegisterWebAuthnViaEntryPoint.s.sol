// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {OpenfortBaseAccount7702V1SessionKey} from "contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol";
import {SpendLimit} from "contracts/utils/SpendLimit.sol";
import {ISessionKey} from "contracts/interfaces/ISessionkey.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract RegisterWebAuthnViaEntryPoint is Script {
    address constant SMART_ACCOUNT = 0x6386b339C3DEc11635C5829025eFE8964DE03b05;
    address constant ENTRY_POINT = 0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B;
    address constant TOKEN_ADDRESS = 0x51fCe89b9f6D4c530698f181167043e1bB4abf89;
    address constant CONTRACT = 0x51fCe89b9f6D4c530698f181167043e1bB4abf89;
    address constant BURN_ADDRESS = address(0);

    bytes32 constant VALID_PUBLIC_KEY_X = 0x77119a0ee8a2fae7ee70cd13a111759327955cf51e88993447920b399882c64c;
    bytes32 constant VALID_PUBLIC_KEY_Y = 0x5a869d35e40c11a4bcfc83bffc25ea11f35d8e6fc04dc36a9cfeb267b97ccf6e;

    uint256 constant SPEND_LIMIT = 10 ether;
    uint256 constant ETH_LIMIT = 0.5 ether;
    uint48 constant LIMIT = 3;

    function run() external {
        vm.startBroadcast(SMART_ACCOUNT);

        // Build key
        ISessionKey.PubKey memory pubKey = ISessionKey.PubKey({ x: VALID_PUBLIC_KEY_X, y: VALID_PUBLIC_KEY_Y });
        ISessionKey.Key memory key = ISessionKey.Key({ pubKey: pubKey, eoaAddress: BURN_ADDRESS, keyType: ISessionKey.KeyType.WEBAUTHN });
        SpendLimit.SpendTokenInfo memory spendTokenInfo = SpendLimit.SpendTokenInfo({
            token: TOKEN_ADDRESS,
            limit: SPEND_LIMIT
        });

        // Encode calldata for registerSessionKey
        bytes memory callData = abi.encodeWithSelector(
            OpenfortBaseAccount7702V1SessionKey.registerSessionKey.selector,
            key,
            uint48(block.timestamp + 3600),
            0,
            LIMIT,
            true,
            CONTRACT,
            spendTokenInfo,
            getSelectors(),
            ETH_LIMIT
        );

        // Set EntryPoint and nonce
        IEntryPoint entryPoint = IEntryPoint(payable(ENTRY_POINT));
        uint256 nonce = entryPoint.getNonce(SMART_ACCOUNT, 1);

        // Construct the PackedUserOperation
        PackedUserOperation memory op = PackedUserOperation({
            sender: SMART_ACCOUNT,
            nonce: nonce,
            initCode: hex"7702", // unused for deployed account
            callData: callData,
            accountGasLimits: packAccountGasLimits(200_000, 150_000),
            preVerificationGas: 80_000,
            gasFees: packGasFees(50 gwei, 2 gwei),
            paymasterAndData: "",
            signature: ""
        });

        // Etch the implementation (optional safety)
        bytes memory code = abi.encodePacked(
            bytes3(0xef0100),
            address(new OpenfortBaseAccount7702V1SessionKey(ENTRY_POINT, 0xc3F5De14f8925cAB747a531B53FE2094C2C5f597))
        );
        vm.etch(SMART_ACCOUNT, code);

        // Sign the userOp
        OpenfortBaseAccount7702V1SessionKey smartAccount = OpenfortBaseAccount7702V1SessionKey(payable(SMART_ACCOUNT));
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes32 digest = smartAccount.getDigestToSign(userOpHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(vm.envUint("PRIVATE_KEY_OPENFORT_USER_7702"), digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        op.signature = abi.encode(ISessionKey.KeyType.WEBAUTHN, sig); // KeyType.EOA = 0

        // HandleOps
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        entryPoint.handleOps(ops, payable(SMART_ACCOUNT));

        vm.stopBroadcast();
    }

    function getSelectors() internal pure returns (bytes4[] memory arr) {
        arr = new bytes4[](1) ;
        arr[0] = 0xa9059cbb; // transfer(address,uint256)
    }

    function packAccountGasLimits(uint256 callGasLimit, uint256 verificationGasLimit) internal pure returns (bytes32) {
        return bytes32((callGasLimit << 128) | verificationGasLimit);
    }

    function packGasFees(uint256 maxFeePerGas, uint256 maxPriorityFeePerGas) internal pure returns (bytes32) {
        return bytes32((maxFeePerGas << 128) | maxPriorityFeePerGas);
    }
}