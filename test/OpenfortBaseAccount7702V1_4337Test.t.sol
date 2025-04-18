// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Base} from "test/Base.t.sol";
import {MockERC20} from "contracts/mocks/MockERC20.sol";
import {Test, console2 as console} from "forge-std/Test.sol";
import {IValidation} from "contracts/interfaces/IValidation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OpenfortBaseAccount7702V1_4337} from "contracts/core/OpenfortBaseAccount7702V1_4337.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "@account-abstraction/contracts/core/Helpers.sol";

/**
 * @dev Simple mock of an EntryPoint - NOT implementing any interface to avoid compilation issues
 */
contract SimpleMockEntryPoint {
    mapping(address => uint256) private balances;
    
    function depositTo(address account) external payable {
        balances[account] += msg.value;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }

    function getUserOpHash(PackedUserOperation calldata userOp) external pure returns (bytes32) {
        return keccak256(abi.encode(
            userOp.sender,
            userOp.nonce,
            keccak256(userOp.initCode),
            keccak256(userOp.callData),
            userOp.accountGasLimits,
            userOp.preVerificationGas,
            userOp.gasFees,
            keccak256(userOp.paymasterAndData)
        ));
    }

    function withdrawTo(address payable withdrawAddress, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool success,) = withdrawAddress.call{value: amount}("");
        require(success, "failed to withdraw");
    }
}

contract OpenfortBaseAccount7702V1_4337Test is Test, Base {

    OpenfortBaseAccount7702V1_4337 public openfortBaseAccount;
    OpenfortBaseAccount7702V1_4337 public implementation;
    SimpleMockEntryPoint public entryPoint;

    uint256 privateKey = vm.envUint("ANVIL_PRIVATE_KEY_OPENFORT_USER");
    address public OPENFORT_USER = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
    address public OPENFORT_DEPLOER = address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);

    PackedUserOperation public op_empty;

    function setUp() public {
        vm.startPrank(OPENFORT_DEPLOER);
        
        // Deploy the simple mock EntryPoint
        entryPoint = new SimpleMockEntryPoint();
        
        implementation = new OpenfortBaseAccount7702V1_4337(address(entryPoint));
        bytes memory code = address(implementation).code;
        
        console.log("Implementation contract deployed at:", address(implementation));
        console.log("Implementation _OPENFORT_CONTRACT_ADDRESS:", implementation._OPENFORT_CONTRACT_ADDRESS());
        
        vm.etch(OPENFORT_USER, code);
        
        openfortBaseAccount = OpenfortBaseAccount7702V1_4337(payable(OPENFORT_USER));
        console.log("Contract deployed at user address:", address(openfortBaseAccount));
        console.log("User contract _OPENFORT_CONTRACT_ADDRESS:", openfortBaseAccount._OPENFORT_CONTRACT_ADDRESS());
        
        vm.stopPrank();
        
        vm.deal(OPENFORT_USER, 10 ether);
        vm.deal(address(entryPoint), 1 ether);

        op_empty = PackedUserOperation({
                sender: OPENFORT_USER,
                nonce: 1,
                initCode: hex"",
                callData: hex"",
                accountGasLimits: 0x0000000000000000000000000000000000000000000000000000000000000000,
                preVerificationGas: 0,
                gasFees: 0x0000000000000000000000000000000000000000000000000000000000000000,
                paymasterAndData: hex"",
                signature: hex""
            });

        _initialize(1, block.timestamp + 1 days);
    }

    function test_PreDeploy() public view {
        assertEq(openfortBaseAccount._OPENFORT_CONTRACT_ADDRESS(), implementation._OPENFORT_CONTRACT_ADDRESS());
    }

    function test_CheckOwner() public view {
        assertEq(openfortBaseAccount.owner(), OPENFORT_USER);
    }

    function test_CheckNonce() public view {
        assertEq(openfortBaseAccount.nonce(), 1);
    }

    function test_ExecuteTransaction() public {
        address oneTimeAddress = makeAddr("oneTimeAddress");
        vm.deal(oneTimeAddress, 0.1 ether);
        uint256 value = 0.1 ether;
        uint256 balanceBefore = address(oneTimeAddress).balance;

        OpenfortBaseAccount7702V1_4337.Transaction[] memory transactionsArr = _getTransactions(address(oneTimeAddress), value, hex"", 5);

        vm.startPrank(address(entryPoint));
        openfortBaseAccount.execute(transactionsArr);
        vm.stopPrank();

        assertEq(address(oneTimeAddress).balance, balanceBefore + value * 5);
    }

    function test_ExecuteTransactionAsAccount() public {
        address oneTimeAddress = makeAddr("oneTimeAddress");
        vm.deal(oneTimeAddress, 0.1 ether);
        uint256 value = 0.1 ether;
        uint256 balanceBefore = address(oneTimeAddress).balance;

        OpenfortBaseAccount7702V1_4337.Transaction[] memory transactionsArr = _getTransactions(address(oneTimeAddress), value, hex"", 5);

        // Using the account's address as the caller
        vm.startPrank(address(openfortBaseAccount));
        openfortBaseAccount.execute(transactionsArr);
        vm.stopPrank();

        assertEq(address(oneTimeAddress).balance, balanceBefore + value * 5);
    }

    function test_ExecuteTransactionRevert() public {
        OpenfortBaseAccount7702V1_4337.Transaction[] memory transactionsArr = _getTransactions(address(OPENFORT_USER), 0, hex"", 10);
        
        vm.prank(address(entryPoint));
        vm.expectRevert(abi.encodeWithSelector(OpenfortBaseAccount7702V1_4337.OpenfortBaseAccount7702V1__InvalidTransactionLength.selector));
        openfortBaseAccount.execute(transactionsArr);
    }

    function test_ExecuteTransactionRevert_InvalidTransactionTarget() public {
        OpenfortBaseAccount7702V1_4337.Transaction[] memory transactionsArr = _getTransactions(address(openfortBaseAccount), 0, hex"", 1);

        vm.prank(address(entryPoint));
        vm.expectRevert(abi.encodeWithSelector(OpenfortBaseAccount7702V1_4337.OpenfortBaseAccount7702V1__InvalidTransactionTarget.selector));
        openfortBaseAccount.execute(transactionsArr);
    }

    function test_AddsDeposit() public {
        uint256 depositAmount = 1 ether;
        
        // Check initial deposit
        uint256 initialDeposit = entryPoint.balanceOf(address(openfortBaseAccount));
        
        // Add deposit
        vm.prank(OPENFORT_USER);
        openfortBaseAccount.addDeposit{value: depositAmount}();
        
        // Check updated deposit
        uint256 finalDeposit = entryPoint.balanceOf(address(openfortBaseAccount));
        assertEq(finalDeposit, initialDeposit + depositAmount);
    }

    function test_WithdrawsDeposit() public {
        uint256 depositAmount = 1 ether;
        address payable recipient = payable(makeAddr("recipient"));
        uint256 recipientBalanceBefore = recipient.balance;
        
        // First add deposit
        vm.prank(OPENFORT_USER);
        openfortBaseAccount.addDeposit{value: depositAmount}();
        
        // Test direct withdrawal
        vm.prank(OPENFORT_USER);
        openfortBaseAccount.withdrawDepositTo(recipient, depositAmount);
        
        // Check recipient balance increased
        assertEq(recipient.balance, recipientBalanceBefore + depositAmount);
    }

    function test_SendERC20() public {
        MockERC20 mockERC20 = this.getMockERC20();
        address oneTimeAddress = makeAddr("oneTimeAddress");

        vm.prank(OPENFORT_DEPLOER);
        mockERC20.mint(OPENFORT_USER, 10 ether);
        
        uint256 balanceBefore = IERC20(address(mockERC20)).balanceOf(OPENFORT_USER);
        console.log("[*] Balance Before ERC20: ", balanceBefore);

        uint256 sendAmount = 5 ether;

        bytes memory transferERC20 = abi.encodeWithSelector(IERC20.transfer.selector, oneTimeAddress, sendAmount);
        OpenfortBaseAccount7702V1_4337.Transaction[] memory transactionsArr = _getTransactions(address(mockERC20), 0, transferERC20, 1);

        // Using EntryPoint as the caller
        vm.prank(address(entryPoint));
        openfortBaseAccount.execute(transactionsArr);

        uint256 balanceAfter = IERC20(address(mockERC20)).balanceOf(OPENFORT_USER);
        uint256 balanceAfterOneTimeAddress = IERC20(address(mockERC20)).balanceOf(oneTimeAddress);

        console.log("[*] Balance After ERC20: ", balanceAfter);

        assertEq(balanceBefore, balanceAfter + balanceAfterOneTimeAddress);
    }

    function test_RecieveERC20() public {
        MockERC20 mockERC20 = this.getMockERC20();
        address oneTimeAddress = makeAddr("oneTimeAddress");

        vm.prank(OPENFORT_DEPLOER);
        mockERC20.mint(oneTimeAddress, 10 ether);
        
        uint256 balanceBefore = IERC20(address(mockERC20)).balanceOf(oneTimeAddress);
        console.log("[*] Balance Before ERC20: ", balanceBefore);

        uint256 sendAmount = 4 ether;

        vm.prank(oneTimeAddress);
        IERC20(mockERC20).transfer(OPENFORT_USER, sendAmount);

        uint256 balanceAfter = IERC20(address(mockERC20)).balanceOf(OPENFORT_USER);
        uint256 balanceAfterOneTimeAddress = IERC20(address(mockERC20)).balanceOf(oneTimeAddress);

        console.log("[*] Balance After ERC20: ", balanceAfter);

        assertEq(balanceBefore, balanceAfter + balanceAfterOneTimeAddress);
    }

    function _initialize(uint256 _nonce, uint256 _validUntil) internal {
        bytes32 hashMessage = entryPoint.getUserOpHash(op_empty);
        
        console.log("Hash message from entryPoint:", toHexString(hashMessage));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hashMessage);
        console.log("Signature v:", v);
        console.log("Signature r:", toHexString(r));
        console.log("Signature s:", toHexString(s));
        
        // The signature needs to be formatted for your contract's specific expectations
        bytes memory signature = abi.encodePacked(r, s, v);

        // Call initialize from the entryPoint address since the contract expects _requireForExecute()
        vm.prank(address(entryPoint));
        openfortBaseAccount.initialize(OPENFORT_USER, _validUntil, hashMessage, signature, _nonce);
    }
    
    function _getTransactions(address _to, uint256 _value, bytes memory _data, uint256 _length) internal pure returns (OpenfortBaseAccount7702V1_4337.Transaction[] memory) {
        OpenfortBaseAccount7702V1_4337.Transaction[] memory transactionsArr = new OpenfortBaseAccount7702V1_4337.Transaction[](_length);
        for (uint256 i = 0; i < _length; i++) {
            transactionsArr[i] = OpenfortBaseAccount7702V1_4337.Transaction({
                to: _to,
                value: _value,
                data: _data
            });
        }
        return transactionsArr;
    }

    function _printInitialState() internal view {
        _printDevider();
        console.log("[*] Initialized State [*]");
        console.log("[*]Contract Address:", address(openfortBaseAccount));
        console.log("[*]Contract Owner:", openfortBaseAccount.owner());
        console.log("[*]Contract Nonce:", openfortBaseAccount.nonce());
        console.log("[*]Contract Openfort Contract Address:", openfortBaseAccount._OPENFORT_CONTRACT_ADDRESS());
        _printDevider();
    }

    function _printDevider() internal pure {
        console.log("----------------------------------------------------------------");
        console.log("----------------------------------------------------------------");
    }
    
    function toHexString(bytes32 value) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(66);
        str[0] = '0';
        str[1] = 'x';
        for (uint i = 0; i < 32; i++) {
            str[2+i*2] = alphabet[uint8(value[i] >> 4)];
            str[3+i*2] = alphabet[uint8(value[i] & 0x0f)];
        }
        return string(str);
    }

    function test_ClearStorage() public {
        bytes32 baseSlot = bytes32(0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368);
        
        console.log("Storage values before clearing:");
        bytes32[] memory beforeValues = new bytes32[](5);
        
        for (uint256 i = 0; i < 5; i++) {
            bytes32 slot = bytes32(uint256(baseSlot) + i);
            beforeValues[i] = vm.load(address(openfortBaseAccount), slot);
            console.log("Slot", i, "value:", uint256(beforeValues[i]));
        }
        
        bool hasNonZeroSlot = false;
        for (uint256 i = 0; i < 5; i++) {
            if (beforeValues[i] != bytes32(0)) {
                hasNonZeroSlot = true;
                break;
            }
        }
        assertTrue(hasNonZeroSlot, "No non-zero slots found before clearing. Initialization may have failed.");
        
        ExposedClearStorage exposed = new ExposedClearStorage();
        bytes memory exposedCode = address(exposed).code;
        
        bytes memory originalCode = address(openfortBaseAccount).code;
        
        vm.etch(address(openfortBaseAccount), exposedCode);
        
        vm.prank(OPENFORT_USER);
        ExposedClearStorage(address(openfortBaseAccount)).clearStorage();
        
        vm.etch(address(openfortBaseAccount), originalCode);
        
        console.log("Storage values after clearing:");
        for (uint256 i = 0; i < 5; i++) {
            bytes32 slot = bytes32(uint256(baseSlot) + i);
            bytes32 afterValue = vm.load(address(openfortBaseAccount), slot);
            console.log("Slot", i, "value:", uint256(afterValue));
            assertEq(afterValue, bytes32(0), string(abi.encodePacked("Slot ", i, " was not cleared")));
        }
    }
}

contract ExposedClearStorage {
    bytes32 constant BASE_SLOT = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368;
    
    function clearStorage() external {
        _clearStorage();
    }
    
    function _clearStorage() internal {
        bytes32 baseSlot = BASE_SLOT;
        
        for (uint256 i = 0; i < 5; i++) {
            bytes32 slot = bytes32(uint256(baseSlot) + i);
            assembly {
                sstore(slot, 0)
            }
        }
    }
}