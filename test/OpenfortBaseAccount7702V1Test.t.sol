// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Test, console2 as console} from "forge-std/Test.sol";
import {IValidation} from "contracts/interfaces/IValidation.sol";
import {OpenfortBaseAccount7702V1} from "contracts/core/OpenfortBaseAccount7702V1.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract OpenfortBaseAccount7702V1Test is Test {

    OpenfortBaseAccount7702V1 public openfortBaseAccount;
    OpenfortBaseAccount7702V1 public implementation;

    uint256 privateKey = vm.envUint("ANVIL_PRIVATE_KEY_OPENFORT_USER");
    address public OPENFORT_USER = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
    address public OPENFORT_DEPLOER = address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);

    function setUp() public {
        vm.startPrank(OPENFORT_DEPLOER);
        
        implementation = new OpenfortBaseAccount7702V1();
        bytes memory code = address(implementation).code;
        
        console.log("Implementation contract deployed at:", address(implementation));
        console.log("Implementation _OPENFORT_CONTRACT_ADDRESS:", implementation._OPENFORT_CONTRACT_ADDRESS());
        
        vm.etch(OPENFORT_USER, code);
        
        openfortBaseAccount = OpenfortBaseAccount7702V1(payable(OPENFORT_USER));
        console.log("Contract deployed at user address:", address(openfortBaseAccount));
        console.log("User contract _OPENFORT_CONTRACT_ADDRESS:", openfortBaseAccount._OPENFORT_CONTRACT_ADDRESS());
        
        vm.stopPrank();
        
        vm.deal(OPENFORT_USER, 10 ether);

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

        OpenfortBaseAccount7702V1.Transaction[] memory transactionsArr = _getTransactions(address(oneTimeAddress), value, hex"", 5);

        vm.prank(OPENFORT_USER);
        openfortBaseAccount.execute(transactionsArr);

        assertEq(address(oneTimeAddress).balance, balanceBefore + value * 5);
    }

    function test_ExecuteTransactionRevert() public {
        OpenfortBaseAccount7702V1.Transaction[] memory transactionsArr = _getTransactions(address(OPENFORT_USER), 0, hex"", 10);
        
        vm.prank(OPENFORT_USER);
        vm.expectRevert(abi.encodeWithSelector(OpenfortBaseAccount7702V1.OpenfortBaseAccount7702V1__InvalidTransactionLength.selector));
        openfortBaseAccount.execute(transactionsArr);
    }

    function test_ExecuteTransactionRevert_InvalidTransactionTarget() public {
        OpenfortBaseAccount7702V1.Transaction[] memory transactionsArr = _getTransactions(address(OPENFORT_USER), 0, hex"", 1);

        vm.prank(OPENFORT_USER);
        vm.expectRevert(abi.encodeWithSelector(OpenfortBaseAccount7702V1.OpenfortBaseAccount7702V1__InvalidTransactionTarget.selector));
        openfortBaseAccount.execute(transactionsArr);
    }

    function _initialize(uint256 _nonce, uint256 _validUntil) internal {
        bytes32 messageHash = keccak256(
            abi.encode(
                OPENFORT_USER, 
                _nonce, 
                _validUntil, 
                keccak256("initialize"), 
                implementation._OPENFORT_CONTRACT_ADDRESS(), 
                block.chainid
            )
        );
        
        console.log("Message Hash:", toHexString(messageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        
        IValidation.Validation memory validation = IValidation.Validation({
            nonce: _nonce,
            validUntil: _validUntil,
            v: v,
            r: r,
            s: s
        });
        
        vm.prank(OPENFORT_USER);
        openfortBaseAccount.initialize(OPENFORT_USER, validation);
    }
    
    
    function _getTransactions(address _to, uint256 _value, bytes memory _data, uint256 _length) internal pure returns (OpenfortBaseAccount7702V1.Transaction[] memory) {
        OpenfortBaseAccount7702V1.Transaction[] memory transactionsArr = new OpenfortBaseAccount7702V1.Transaction[](_length);
        for (uint256 i = 0; i < _length; i++) {
            transactionsArr[i] = OpenfortBaseAccount7702V1.Transaction({
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
}