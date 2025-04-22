import 'dotenv/config'
import { ethers } from 'ethers';
// ---------- Config ----------
const HOLESKY_RPC = process.env.HOLESKY_RPC_URL;
const SMART_ACCOUNT_ADDRESS = process.env.ADDRESS_OPENFORT_USER_ADDRESS_7702;

// ---------- ABI ----------
const abi = [
  'function owner() view returns (address)',
  'function nonce() view returns (uint256)',
];

// ---------- Main ----------
async function main() {
  const provider = new ethers.providers.JsonRpcProvider(HOLESKY_RPC);
  const smartAccount = new ethers.Contract(SMART_ACCOUNT_ADDRESS, abi, provider);

  const owner = await smartAccount.owner();
  const nonce = await smartAccount.nonce();

  console.log('🧠 Smart Account State');
  console.log('----------------------');
  console.log('owner():', owner);
  console.log('nonce  :', nonce.toString());
}

main().catch(console.error);