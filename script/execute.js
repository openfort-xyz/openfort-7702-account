import { ethers } from 'ethers';

// ---------- Constants ----------
const PRIVATE_KEY = process.env.PRIVATE_KEY_OPENFORT_USER_7702;
const HOLESKY_RPC = process.env.SEPOLIA_RPC_URL;
const SMART_ACCOUNT_ADDRESS = process.env.ADDRESS_OPENFORT_USER_ADDRESS_7702;
const TO_ADDRESS = '0xA84E4F9D72cb37A8276090D3FC50895BD8E5Aaf1';
const AMOUNT_ETH = '0.01';

// ---------- ABI ----------
const smartAccountAbi = [
  'function execute((address to, uint256 value, bytes data)[]) external payable'
];

// ---------- Main ----------
async function main() {
  const provider = new ethers.providers.JsonRpcProvider(HOLESKY_RPC);
  const signer = new ethers.Wallet(PRIVATE_KEY, provider);

  const smartAccount = new ethers.Contract(SMART_ACCOUNT_ADDRESS, smartAccountAbi, signer);

  const txStruct = [{
    to: TO_ADDRESS,
    value: ethers.utils.parseEther(AMOUNT_ETH),
    data: '0x',
  }];

  const tx = await smartAccount.execute(txStruct, {
    gasLimit: 150_000,
  });

  console.log('✅ Tx sent:', tx.hash);
  await tx.wait();
  console.log(`🎉 ${AMOUNT_ETH} ETH sent from smart account to ${TO_ADDRESS} via execute()`);
}

main().catch(console.error);