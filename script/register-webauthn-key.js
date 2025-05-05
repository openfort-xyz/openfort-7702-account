import { createWalletClient, http, parseEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';
import { abi } from './abi.js'; // Replace with your contract's ABI
import { checksumAddress } from 'viem';

const SMART_ACCOUNT = checksumAddress('0x6386b339c3dec11635c5829025efe8964de03b05');
const PRIVATE_KEY = '0x77119a0ee8a2fae7ee70cd13a111759327955cf51e88993447920b399882c64c';
const TOKEN_ADDRESS = '0x51fCe89b9f6D4c530698f181167043e1bB4abf89';
const CONTRACT_ADDRESS = '0x51fCe89b9f6D4c530698f181167043e1bB4abf89';

const account = privateKeyToAccount(PRIVATE_KEY);

const client = createWalletClient({
  account,
  chain: sepolia,
  transport: http(process.env.SEPOLIA_RPC_URL),
});

async function main() {
  const txHash = await client.writeContract({
    address: SMART_ACCOUNT,
    abi,
    functionName: 'registerSessionKey',
    args: [
      {
        pubKey: {
          x: '0x77119a0ee8a2fae7ee70cd13a111759327955cf51e88993447920b399882c64c',
          y: '0x5a869d35e40c11a4bcfc83bffc25ea11f35d8e6fc04dc36a9cfeb267b97ccf6e',
        },
        eoaAddress: '0x0000000000000000000000000000000000000000',
        keyType: 0,
      },
      Math.floor(Date.now() / 1000 + 3600), // validUntil (1 hour from now)
      0, // validAfter
      3, // limit
      true, // whitelisting
      CONTRACT_ADDRESS,
      {
        token: TOKEN_ADDRESS,
        limit: parseEther('10'),
      },
      ['0xa9059cbb'], // allowedSelectors
      parseEther('0.5'), // ethLimit
    ],
  });

  console.log(`✅ Transaction sent: ${txHash}`);
}

main().catch(console.error);