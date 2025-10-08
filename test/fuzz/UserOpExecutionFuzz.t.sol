// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "../Deploy.t.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {PackedUserOperation} from
    "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract UserOpExecutionFuzz is Deploy {
    address internal recipient;

    function setUp() public override {
        super.setUp();

        recipient = makeAddr("recipient");

        _populateWebAuthn("execution.json", ".batch");
        PubKey memory mk = PubKey({x: DEF_WEBAUTHN.X, y: DEF_WEBAUTHN.Y});
        _createCustomFreshKey(
            true, KeyType.WEBAUTHN, type(uint48).max, 0, 0, _getKeyP256(mk), KeyControl.Self
        );

        _createCustomFreshKey(
            false,
            KeyType.EOA,
            uint48(block.timestamp + 30 days),
            0,
            10,
            _getKeyEOA(sessionKey),
            KeyControl.Self
        );

        _initializeAccount();
    }

    function testFuzz_userOpWithMasterKey(
        uint256 amountRaw,
        uint256 callCountRaw,
        uint256 gasPriceRaw
    ) external {
        uint256 amount = bound(amountRaw, 1, 10e18);
        uint256 callCount = bound(callCountRaw, 1, 5);
        uint256 gasPrice = bound(gasPriceRaw, 1 gwei, 100 gwei);

        Call[] memory calls = _mintCalls(recipient, amount, callCount);

        PackedUserOperation memory userOp = _freshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            600_000,
            _packGasFees(gasPrice, gasPrice / 2),
            hex""
        );

        userOp.signature = _encodeEOASignature(_signUserOp(userOp));

        uint256 balBefore = IERC20(address(erc20)).balanceOf(recipient);
        _relayUserOp(userOp);
        uint256 balAfter = IERC20(address(erc20)).balanceOf(recipient);

        assertEq(balAfter - balBefore, amount * callCount);
    }

    function testFuzz_userOpWithSessionKey(
        uint256 amountRaw,
        uint256 callCountRaw,
        uint256 gasPriceRaw
    ) external {
        uint256 amount = bound(amountRaw, 1, 10e18);
        uint256 callCount = bound(callCountRaw, 1, 3);
        uint256 gasPrice = bound(gasPriceRaw, 1 gwei, 100 gwei);

        bytes32 sessionKeyId = _registerSessionEOA();
        _configureSessionRestrictions(sessionKeyId, callCount, amount);

        Call[] memory calls = _mintCalls(recipient, amount, callCount);

        PackedUserOperation memory userOp = _freshUserOp();
        userOp = _populateUserOp(
            userOp,
            _packCallData(mode_1, calls),
            _packAccountGasLimits(600_000, 400_000),
            600_000,
            _packGasFees(gasPrice, gasPrice / 2),
            hex""
        );

        userOp.signature = _encodeEOASignature(_signUserOpWithSK(userOp));

        uint256 balBefore = IERC20(address(erc20)).balanceOf(recipient);
        _relayUserOp(userOp);
        uint256 balAfter = IERC20(address(erc20)).balanceOf(recipient);

        assertEq(balAfter - balBefore, amount * callCount);
    }

    function _registerSessionEOA() internal returns (bytes32 sessionKeyId) {
        sessionKeyId = _computeKeyId(skReg);

        if (!account.isKeyActive(sessionKeyId)) {
            _etch();
            vm.prank(owner);
            account.registerKey(skReg);
        }
    }

    function _configureSessionRestrictions(bytes32 sessionKeyId, uint256 callCount, uint256 amount)
        internal
    {
        _etch();
        vm.prank(owner);
        account.setCanCall(sessionKeyId, address(erc20), MockERC20.mint.selector, true);

        _etch();
        vm.prank(owner);
        account.setTokenSpend(sessionKeyId, address(erc20), amount * callCount, SpendPeriod.Day);
    }

    function _freshUserOp() internal view returns (PackedUserOperation memory userOp) {
        userOp = _getFreshUserOp();
        userOp.nonce = entryPoint.getNonce(owner, 1);
        return userOp;
    }

    function _mintCalls(address to, uint256 amount, uint256 count)
        internal
        view
        returns (Call[] memory calls)
    {
        calls = new Call[](count);
        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, to, amount);
        for (uint256 i; i < count; ++i) {
            calls[i] = _createCall(address(erc20), 0, data);
        }
    }

    function _relayUserOp(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        _etch();
        vm.prank(sender);
        entryPoint.handleOps(ops, payable(sender));
    }
}
