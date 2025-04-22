import { ethers } from 'ethers';

// ---------- Constants ----------
const ACCOUNT_PRIVATE_KEY = process.env.PRIVATE_KEY_OPENFORT_USER_7702;
const SENDER_PRIVATE_KEY = process.env.SENDER_PRIVATE_KEY;
const RPC_URL = process.env.HOLESKY_RPC_URL;
const SMART_ACCOUNT_ADDRESS = process.env.ADDRESS_OPENFORT_USER_ADDRESS_7702;
const TO_ADDRESS = '0xA84E4F9D72cb37A8276090D3FC50895BD8E5Aaf1';
const ENTRY_POINT_ADDRESS = process.env.HOLESKY_ENTRYPOINT_ADDRESS;
const AMOUNT_ETH = '0.001';

// ---------- ABIs ----------
const entryPointAbi = [
  "function handleOps(tuple(address sender, uint256 nonce, bytes initCode, bytes callData, uint256 callGasLimit, uint256 verificationGasLimit, uint256 preVerificationGas, uint256 maxFeePerGas, uint256 maxPriorityFeePerGas, bytes paymasterAndData, bytes signature)[] calldata ops, address payable beneficiary) external"
];

const smartAccountAbi = [
  'function execute((address to, uint256 value, bytes data)[]) external payable',
  'function nonce() external view returns (uint256)',
  'function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature)) view returns (bytes32)'
];

// ---------- Main ----------
async function main() {
  console.log('🚀 Targeted Fix Attempts');
  
  // Set up provider and wallets
  const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
  const accountWallet = new ethers.Wallet(ACCOUNT_PRIVATE_KEY, provider);
  const senderWallet = new ethers.Wallet(SENDER_PRIVATE_KEY, provider);
  
  console.log(`Account wallet: ${accountWallet.address}`);
  console.log(`Sender wallet: ${senderWallet.address}`);
  
  // Create contract instances
  const entryPoint = new ethers.Contract(ENTRY_POINT_ADDRESS, entryPointAbi, senderWallet);
  const smartAccount = new ethers.Contract(SMART_ACCOUNT_ADDRESS, smartAccountAbi, provider);
  
  // Get the contract nonce
  const contractNonce = await smartAccount.nonce();
  console.log(`Contract nonce: ${contractNonce.toString()}`);
  
  // Use a different nonce strategy - try the EntryPoint nonce directly
  const nonceToUse = contractNonce.add(1);
  console.log(`Using nonce: ${nonceToUse.toString()}`);
  
  // Prepare transaction data - use the EXACT same calldata that works with direct execution
  const value = ethers.utils.parseEther(AMOUNT_ETH);
  const txStruct = [{
    to: TO_ADDRESS,
    value: value,
    data: '0x',
  }];
  
  const iface = new ethers.utils.Interface(smartAccountAbi);
  const callData = iface.encodeFunctionData('execute', [txStruct]);
  console.log(`Encoded callData: ${callData.slice(0, 66)}...`);
  
  // Create UserOperation with moderate gas values - not too high not too low
  const userOp = {
    sender: SMART_ACCOUNT_ADDRESS,
    nonce: nonceToUse,
    initCode: '0x',
    callData: callData,
    callGasLimit: ethers.BigNumber.from(5000000),
    verificationGasLimit: ethers.BigNumber.from(5000000),
    preVerificationGas: ethers.BigNumber.from(1000000),
    maxFeePerGas: ethers.utils.parseUnits('40', 'gwei'),
    maxPriorityFeePerGas: ethers.utils.parseUnits('8', 'gwei'),
    paymasterAndData: '0x',
    signature: '0x' // Will be filled later
  };
  
  // Create packed UserOp format for hash calculation
  const packedUserOp = {
    sender: userOp.sender,
    nonce: userOp.nonce,
    initCode: userOp.initCode,
    callData: userOp.callData,
    accountGasLimits: ethers.utils.hexZeroPad(
      ethers.utils.hexlify(
        (userOp.callGasLimit.shl(128)).add(userOp.verificationGasLimit)
      ),
      32
    ),
    preVerificationGas: userOp.preVerificationGas,
    gasFees: ethers.utils.hexZeroPad(
      ethers.utils.hexlify(
        (userOp.maxFeePerGas.shl(128)).add(userOp.maxPriorityFeePerGas)
      ),
      32
    ),
    paymasterAndData: userOp.paymasterAndData,
    signature: '0x'
  };
  
  const userOpHash = await smartAccount.getUserOpHash(packedUserOp);
  console.log(`UserOpHash from contract: ${userOpHash}`);
  
  // Try EIP-712 signature format
  console.log('Generating EIP-712 signature...');
  const domainSeparator = {
    name: "OpenfortBaseAccount7702V1",
    version: "1",
    chainId: (await provider.getNetwork()).chainId,
    verifyingContract: SMART_ACCOUNT_ADDRESS
  };
  
  const types = {
    UserOperation: [
      { name: "sender", type: "address" },
      { name: "nonce", type: "uint256" },
      { name: "initCode", type: "bytes" },
      { name: "callData", type: "bytes" },
      { name: "callGasLimit", type: "uint256" },
      { name: "verificationGasLimit", type: "uint256" },
      { name: "preVerificationGas", type: "uint256" },
      { name: "maxFeePerGas", type: "uint256" },
      { name: "maxPriorityFeePerGas", type: "uint256" },
      { name: "paymasterAndData", type: "bytes" }
    ]
  };
  
  const eip712Message = {
    sender: userOp.sender,
    nonce: userOp.nonce.toString(),
    initCode: userOp.initCode,
    callData: userOp.callData,
    callGasLimit: userOp.callGasLimit.toString(),
    verificationGasLimit: userOp.verificationGasLimit.toString(),
    preVerificationGas: userOp.preVerificationGas.toString(),
    maxFeePerGas: userOp.maxFeePerGas.toString(),
    maxPriorityFeePerGas: userOp.maxPriorityFeePerGas.toString(),
    paymasterAndData: userOp.paymasterAndData
  };
  
  let signatureToUse;
  try {
    const eip712Signature = await accountWallet._signTypedData(domainSeparator, types, eip712Message);
    console.log(`EIP-712 signature: ${eip712Signature.slice(0, 40)}...`);
    signatureToUse = eip712Signature;
  } catch (error) {
    console.log(`Error with EIP-712 signing: ${error.message}`);
    
    // Fall back to standard signature
    const signingKey = accountWallet._signingKey();
    const signature = signingKey.signDigest(ethers.utils.arrayify(userOpHash));
    signatureToUse = ethers.utils.hexConcat([
      signature.r,
      signature.s,
      ethers.utils.hexlify(signature.v)
    ]);
    console.log(`Standard signature: ${signatureToUse.slice(0, 40)}...`);
  }
  
  userOp.signature = signatureToUse;
  
  // IMPORTANT CHANGE: Use a different beneficiary
  const differentBeneficiary = ethers.constants.AddressZero; // Use zero address
  
  // Submit the UserOperation
  console.log(`Submitting UserOperation with beneficiary: ${differentBeneficiary}`);
  
  try {
    const tx = await entryPoint.handleOps([userOp], differentBeneficiary, {
      gasLimit: 3000000, // Moderate gas limit
    });
    
    console.log(`✅ Transaction sent! Hash: ${tx.hash}`);
    console.log('Waiting for transaction confirmation...');
    
    const receipt = await tx.wait();
    
    if (receipt.status === 1) {
      console.log(`🎉 Success! Transaction confirmed in block ${receipt.blockNumber}`);
      console.log(`Gas used: ${receipt.gasUsed.toString()}`);
    } else {
      console.log(`❌ Transaction reverted on-chain`);
    }
  } catch (error) {
    console.error('Error submitting UserOperation:');
    console.error(error.message);
  }
}

main().catch(console.error);