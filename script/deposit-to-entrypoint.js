import { ethers } from 'ethers';

// Constants
const PRIVATE_KEY = process.env.PRIVATE_KEY_OPENFORT_USER_7702;
const HOLESKY_RPC = process.env.SEPOLIA_RPC_URL;
const SMART_ACCOUNT_ADDRESS = process.env.ADDRESS_OPENFORT_USER_ADDRESS_7702;
const ENTRY_POINT_ADDRESS = process.env.SEPOLIA_ENTRYPOINT_ADDRESS;

// Create a wallet from the private key
const wallet = new ethers.Wallet(PRIVATE_KEY);
console.log('Wallet created with address:', wallet.address);

// Connect to the provider
const provider = new ethers.providers.JsonRpcProvider(HOLESKY_RPC);
const connectedWallet = wallet.connect(provider);

// Define EntryPoint ABI (only the functions we need)
const entryPointAbi = [
  'function depositTo(address account) external payable',
  'function balanceOf(address account) external view returns (uint256)',
  'function getDepositInfo(address account) external view returns (uint112 deposit, bool staked, uint112 stake, uint32 unstakeDelaySec, uint48 withdrawTime)'
];

// Create EntryPoint contract instance
const entryPointContract = new ethers.Contract(ENTRY_POINT_ADDRESS, entryPointAbi, provider);
const entryPointWithSigner = entryPointContract.connect(connectedWallet);

async function depositToEntryPoint() {
  try {
    console.log('=== Depositing to EntryPoint ===');
    
    // Check current balance
    const currentBalance = await entryPointContract.balanceOf(SMART_ACCOUNT_ADDRESS);
    console.log('Current balance in EntryPoint:', ethers.utils.formatEther(currentBalance), 'ETH');
    
    // Deposit amount (0.01 ETH)
    const depositAmount = ethers.utils.parseEther('0.1');
    console.log('Depositing:', ethers.utils.formatEther(depositAmount), 'ETH to EntryPoint');
    
    // Send the deposit transaction
    const tx = await entryPointWithSigner.depositTo(SMART_ACCOUNT_ADDRESS, {
      value: depositAmount
    });
    
    console.log('Deposit transaction sent:', tx.hash);
    console.log('Waiting for confirmation...');
    
    // Wait for the transaction to be confirmed
    const receipt = await tx.wait();
    console.log('Transaction confirmed in block:', receipt.blockNumber);
    
    // Check new balance
    const newBalance = await entryPointContract.balanceOf(SMART_ACCOUNT_ADDRESS);
    console.log('New balance in EntryPoint:', ethers.utils.formatEther(newBalance), 'ETH');
    
    // Try to get more detailed deposit info
    try {
      const depositInfo = await entryPointContract.getDepositInfo(SMART_ACCOUNT_ADDRESS);
      console.log('Deposit info:', depositInfo);
    } catch (error) {
      console.log('Could not get detailed deposit info:', error.message);
    }
    
    return receipt;
  } catch (error) {
    console.error('Error depositing to EntryPoint:', error);
    throw error;
  }
}

// Execute the deposit function
depositToEntryPoint()
  .then(() => process.exit(0))
  .catch(error => {
    console.error('Unhandled error:', error);
    process.exit(1);
  });