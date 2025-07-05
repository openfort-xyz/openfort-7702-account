import 'dotenv/config';
import { createWalletClient, http } from 'viem';
import { sepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { eip7702Actions } from 'viem/experimental';

// Replace with your actual Holesky RPC URL
const SEPOLIA_RPC = process.env.SEPOLIA_RPC_URL;

// Replace with your implementation contract address
const IMPLEMENTATION_CONTRACT = '0x890Dc43F75F5E33116ec5674594AdbCB9aF49412';

// Initialize account from private key
const account = privateKeyToAccount('0xb3421076f70762dc95955aa58a137e707d7150e3c82201a3997ee60b7e9999b0');

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