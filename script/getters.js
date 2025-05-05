import 'dotenv/config'
import { ethers } from 'ethers';


// ---------- Config ----------
const HOLESKY_RPC = process.env.SEPOLIA_RPC_URL;
const SMART_ACCOUNT_ADDRESS = process.env.ADDRESS_OPENFORT_USER_ADDRESS_7702;
const PUBLIC_KEY_X = '0xf03e98af7cae9db7b92fcda32babdb1fc641a3700246a578b6d72b055c3cd521';
const PUBLIC_KEY_Y = '0x8aefd582dd60ad24e4c12c59ea5013cf24e8847f2d024e64feab5a327c404c74';

// ---------- ABI ----------
const abi = [
  'function owner() view returns (address)',
  'function nonce() view returns (uint256)',
  'function getSessionKeyData(bytes32 _keyHash) external view returns (bool, uint48, uint48, uint48)'
];

// ---------- Main ----------
async function main() {
  const provider = new ethers.providers.JsonRpcProvider(HOLESKY_RPC);
  const smartAccount = new ethers.Contract(SMART_ACCOUNT_ADDRESS, abi, provider);

  const owner = await smartAccount.owner();
  const nonce = await smartAccount.nonce();

  const keyHash = ethers.utils.keccak256(
    ethers.utils.solidityPack(['bytes32', 'bytes32'], [PUBLIC_KEY_X, PUBLIC_KEY_Y])
  );

  const [isActive, validUntil, validAfter, limit] = await smartAccount.getSessionKeyData(keyHash);
  console.log('🧠 Smart Account State');
  console.log('----------------------');
  console.log('owner():', owner);
  console.log('nonce  :', nonce.toString());
  console.log('keyHash:      ', keyHash);
  console.log('isActive:     ', isActive);
  console.log('validUntil:   ', new Date(validUntil * 1000).toISOString());
  console.log('validAfter:   ', new Date(validAfter * 1000).toISOString());
  console.log('usageLimit:   ', limit.toString());
}

main().catch(console.error);