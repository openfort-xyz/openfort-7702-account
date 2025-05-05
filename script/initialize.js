import 'dotenv/config';
import { ethers } from 'ethers';

// ---------- Constants ----------
const PRIVATE_KEY = process.env.PRIVATE_KEY_OPENFORT_USER_7702;
const HOLESKY_RPC = process.env.SEPOLIA_RPC_URL;
const ENTRY_POINT_ADDRESS = process.env.SEPOLIA_ENTRYPOINT_ADDRESS;

// ---------- ABIs ----------
const smartAccountAbi = [
  'function initialize(address _owner, uint256 _validUntil, bytes32 _hash, bytes memory _signature, uint256 _nonce) external',
  'function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature)) view returns (bytes32)',
];

// ---------- Main ----------
async function main() {
  const provider = new ethers.providers.JsonRpcProvider(HOLESKY_RPC);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
  const SMART_ACCOUNT_ADDRESS = wallet.address;

  console.log('Wallet address:', wallet.address);
  console.log('ENTRY_POINT_ADDRESS:', ENTRY_POINT_ADDRESS);

  const smartAccount = new ethers.Contract(SMART_ACCOUNT_ADDRESS, smartAccountAbi, wallet);

  const validUntil = Math.floor(Date.now() / 1000) + 86400; // +1 day
  const nonce = 1;

  // Dummy callData to get hash
  const dummyUserOp = {
    sender: SMART_ACCOUNT_ADDRESS,
    nonce,
    initCode: '0x',
    callData: '0x',
    accountGasLimits: ethers.constants.HashZero,
    preVerificationGas: 0,
    gasFees: ethers.constants.HashZero,
    paymasterAndData: '0x',
    signature: '0x',
  };

  const userOpHash = await smartAccount.getUserOpHash(dummyUserOp);
  console.log('userOpHash:', userOpHash);

  const signature = await wallet._signingKey().signDigest(userOpHash);
  const packedSignature = ethers.utils.hexConcat([
    signature.r,
    signature.s,
    ethers.utils.hexlify(signature.v),
  ]);

  // Encode initialize() as callData
  const iface = new ethers.utils.Interface(smartAccountAbi);

  console.log("userOpHash", userOpHash);
  console.log("packedSignature", packedSignature);

  const tx = await smartAccount.initialize(SMART_ACCOUNT_ADDRESS, 1778996649, userOpHash, packedSignature, 1,{
    gasLimit: 600_000,
  });

  console.log('✅ Tx sent:', tx.hash);
  await tx.wait();
  console.log('🎉 Account initialized successfully!');
}

main().catch((err) => {
  console.error('💥 Error occurred:', err);
});