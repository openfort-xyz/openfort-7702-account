// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Base} from "test/Base.t.sol";
import {MockERC20} from "contracts/mocks/MockERC20.sol";
import {Test, console2 as console} from "forge-std/Test.sol";
import {IValidation} from "contracts/interfaces/IValidation.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OpenfortBaseAccount7702V1_712} from "contracts/core/OpenfortBaseAccount7702V1_712.sol";

contract OpenfortBaseAccount7702V1Test is Test, Base {

    OpenfortBaseAccount7702V1_712 public openfortBaseAccount;
    OpenfortBaseAccount7702V1_712 public implementation;

    uint256 privateKey = vm.envUint("ANVIL_PRIVATE_KEY_OPENFORT_USER");
    address public OPENFORT_USER = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
    address public OPENFORT_DEPLOER = address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);

    function setUp() public {
        vm.startPrank(OPENFORT_DEPLOER);
        
        implementation = new OpenfortBaseAccount7702V1_712();
        bytes memory code = address(implementation).code;
        
        console.log("Implementation contract deployed at:", address(implementation));
        console.log("Implementation _OPENFORT_CONTRACT_ADDRESS:", implementation._OPENFORT_CONTRACT_ADDRESS());
        
        vm.etch(OPENFORT_USER, code);
        
        openfortBaseAccount = OpenfortBaseAccount7702V1_712(payable(OPENFORT_USER));
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

        OpenfortBaseAccount7702V1_712.Transaction[] memory transactionsArr = _getTransactions(address(oneTimeAddress), value, hex"", 5);

        vm.prank(OPENFORT_USER);
        openfortBaseAccount.execute(transactionsArr);

        assertEq(address(oneTimeAddress).balance, balanceBefore + value * 5);
    }

    function test_ExecuteTransactionRevert() public {
        OpenfortBaseAccount7702V1_712.Transaction[] memory transactionsArr = _getTransactions(address(OPENFORT_USER), 0, hex"", 10);
        
        vm.prank(OPENFORT_USER);
        vm.expectRevert(abi.encodeWithSelector(OpenfortBaseAccount7702V1_712.OpenfortBaseAccount7702V1__InvalidTransactionLength.selector));
        openfortBaseAccount.execute(transactionsArr);
    }

    function test_ExecuteTransactionRevert_InvalidTransactionTarget() public {
        OpenfortBaseAccount7702V1_712.Transaction[] memory transactionsArr = _getTransactions(address(OPENFORT_USER), 0, hex"", 1);

        vm.prank(OPENFORT_USER);
        vm.expectRevert(abi.encodeWithSelector(OpenfortBaseAccount7702V1_712.OpenfortBaseAccount7702V1__InvalidTransactionTarget.selector));
        openfortBaseAccount.execute(transactionsArr);
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
        OpenfortBaseAccount7702V1_712.Transaction[] memory transactionsArr = _getTransactions(address(mockERC20), 0, transferERC20, 1);

        vm.prank(OPENFORT_USER);
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
        bytes32 hashMessage = openfortBaseAccount.getHashMessage(IValidation.Validation({
            nonce: _nonce,
            validUntil: _validUntil,
            v: 0,
            r: bytes32(0),
            s: bytes32(0)
        }));
        
        console.log("Hash message from contract:", toHexString(hashMessage));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hashMessage);
        console.log("Signature v:", v);
        console.log("Signature r:", toHexString(r));
        console.log("Signature s:", toHexString(s));
        
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

    function _signMessage(uint256 _nonce, uint256 _validUntil) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 hashMessage = openfortBaseAccount.getHashMessage(IValidation.Validation({
            nonce: _nonce,
            validUntil: _validUntil,
            v: 0,
            r: bytes32(0),
            s: bytes32(0)
        }));
        
        (v, r, s) = vm.sign(privateKey, hashMessage);
    }
    
    function _getTransactions(address _to, uint256 _value, bytes memory _data, uint256 _length) internal pure returns (OpenfortBaseAccount7702V1_712.Transaction[] memory) {
        OpenfortBaseAccount7702V1_712.Transaction[] memory transactionsArr = new OpenfortBaseAccount7702V1_712.Transaction[](_length);
        for (uint256 i = 0; i < _length; i++) {
            transactionsArr[i] = OpenfortBaseAccount7702V1_712.Transaction({
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