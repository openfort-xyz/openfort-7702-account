import 'dotenv/config';
import { createWalletClient, http } from 'viem';
import { sepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { eip7702Actions } from 'viem/experimental';

// Replace with your actual Holesky RPC URL
const SEPOLIA_RPC = process.env.SEPOLIA_RPC_URL;

// Replace with your implementation contract address
const IMPLEMENTATION_CONTRACT = '0xA97Ca015ACe1F3eD63EAE764336dB62258B84E5F';

// Initialize account from private key
const account = privateKeyToAccount('0x2034ba1358e16504666dfb260d238f4ca77f471f47ba7e5a6bca5eb5fa108957');

// Create a wallet client with EIP-7702 support
const walletClient = createWalletClient({
  account,
  chain: sepolia,
  transport: http(SEPOLIA_RPC),
}).extend(eip7702Actions);

console.log(account.address)
async function sendSelfExecutingTx() {
  try {
    // Sign the authorization to delegate execution to the implementation contract
    const authorization = await walletClient.signAuthorization({
      contractAddress: IMPLEMENTATION_CONTRACT,
      executor: 'self',
    });

    // Send the transaction to the EOA's own address with the authorization
    const txHash = await walletClient.sendTransaction({
      to: walletClient.account.address,
      authorizationList: [authorization],
    });

    console.log('✅ Transaction sent:', txHash);
  } catch (error) {
    console.error('❌ Error sending transaction:', error);
  }
}

sendSelfExecutingTx();