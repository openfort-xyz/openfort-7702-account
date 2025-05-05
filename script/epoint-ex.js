import { createPublicClient, createWalletClient, http, parseEther, parseGwei, formatGwei, formatEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet, sepolia, optimism, arbitrum, base } from 'viem/chains';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { writeFileSync, existsSync } from 'fs';

// Load environment variables
dotenv.config();

// Configure network and RPC endpoint
const NETWORK = process.env.NETWORK || 'sepolia';
const RPC_URL = process.env.SEPOLIA_RPC_URL || '';

// Network selection
const getChain = (network) => {
  switch (network.toLowerCase()) {
    case 'mainnet': return mainnet;
    case 'sepolia': return sepolia;
    case 'optimism': return optimism;
    case 'arbitrum': return arbitrum;
    case 'base': return base;
    default: return sepolia;
  }
};

const chain = getChain(NETWORK);
console.log(`Using network: ${chain.name}`);

// Constants from your Solidity script
const SMART_ACCOUNT = process.env.SMART_ACCOUNT || '0x6386b339C3DEc11635C5829025eFE8964DE03b05';
const ENTRY_POINT = process.env.ENTRY_POINT || '0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B';
const CONTRACT = process.env.CONTRACT || '0xd1F228d963E6910412a021aF009583B239b4aA77';

// WebAuthn constants
const VALID_PUBLIC_KEY_X = '0xf03e98af7cae9db7b92fcda32babdb1fc641a3700246a578b6d72b055c3cd521';
const VALID_PUBLIC_KEY_Y = '0x8aefd582dd60ad24e4c12c59ea5013cf24e8847f2d024e64feab5a327c404c74';
const CHALLENGE = '0xdeadbeef';
const VALID_SIGNATURE_R = '0x785267b9ba39fc0e26f4030d98796b2d7a7c721594dba7d4a86ce2c4c740bbaf';
const VALID_SIGNATURE_S = '0x763fe34267a6e7c0225b640b81daa2bf88b329783d0b858ab6347004f372a0a7';
const AUTHENTICATOR_DATA = '0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000';
const CLIENT_DATA_JSON = '{"type":"webauthn.get","challenge":"3q2-7w","origin":"http://localhost:5173","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}';
const CHALLENGE_INDEX = 23;
const TYPE_INDEX = 1;

// Gas settings (can be overridden with env variables)
const MAX_FEE_PER_GAS = parseGwei(process.env.MAX_FEE_PER_GAS || '50'); // Increase from 30
const MAX_PRIORITY_FEE_PER_GAS = parseGwei(process.env.MAX_PRIORITY_FEE_PER_GAS || '5'); // Increase from 2
const GAS_LIMIT = BigInt(process.env.GAS_LIMIT || '1000000'); // Default 1M gas

// Create transport with the specified RPC URL or fallback
const getTransport = () => {
  if (RPC_URL) {
    console.log(`Using custom RPC URL: ${RPC_URL}`);
    return http(RPC_URL);
  }
  
  // Fallback to public RPC endpoints if no custom URL provided
  switch (NETWORK.toLowerCase()) {
    case 'mainnet': 
      console.log('Warning: Using public RPC endpoint for mainnet (not recommended for production)');
      return http('https://eth.llamarpc.com');
    case 'sepolia': 
      console.log('Using public RPC endpoint for Sepolia');
      return http('https://rpc.sepolia.org');
    case 'optimism': 
      return http('https://mainnet.optimism.io');
    case 'arbitrum': 
      return http('https://arb1.arbitrum.io/rpc');
    case 'base': 
      return http('https://mainnet.base.org');
    default:
      console.log('Using public RPC endpoint for Sepolia');
      return http('https://rpc.sepolia.org');
  }
};

const transport = getTransport();

// Create clients
const publicClient = createPublicClient({
  chain,
  transport
});

// Load your private key (use environment variables in production)
const PRIVATE_KEY = process.env.BURNER_KEY || '0x0000000000000000000000000000000000000000000000000000000000000000';
if (!process.env.BURNER_KEY) {
  console.warn('WARNING: No BURNER_KEY provided in environment variables');
}
const account = privateKeyToAccount(PRIVATE_KEY);

// Create wallet client
const walletClient = createWalletClient({
  account,
  chain,
  transport
});

// ABI fragments for the contracts we're interacting with
const EntryPointABI = [
  {
    inputs: [
      { name: 'sender', type: 'address' },
      { name: 'key', type: 'uint192' }
    ],
    name: 'getNonce',
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function'
  },
  {
    inputs: [
      { name: 'ops', type: 'tuple[]', components: [
        { name: 'sender', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'initCode', type: 'bytes' },
        { name: 'callData', type: 'bytes' },
        { name: 'accountGasLimits', type: 'bytes32' },
        { name: 'preVerificationGas', type: 'uint256' },
        { name: 'gasFees', type: 'bytes32' },
        { name: 'paymasterAndData', type: 'bytes' },
        { name: 'signature', type: 'bytes' }
      ]},
      { name: 'beneficiary', type: 'address' }
    ],
    name: 'handleOps',
    outputs: [],
    stateMutability: 'payable',
    type: 'function'
  }
];

const SmartAccountABI = [
  {
    inputs: [
      { name: 'challenge', type: 'bytes' },
      { name: 'requireUserVerification', type: 'bool' },
      { name: 'authenticatorData', type: 'bytes' },
      { name: 'clientDataJSON', type: 'string' },
      { name: 'challengeIndex', type: 'uint256' },
      { name: 'typeIndex', type: 'uint256' },
      { name: 'r', type: 'bytes32' },
      { name: 's', type: 'bytes32' },
      { name: 'pubKey', type: 'tuple', components: [
        { name: 'x', type: 'bytes32' },
        { name: 'y', type: 'bytes32' }
      ]}
    ],
    name: 'encodeWebAuthnSignature',
    outputs: [{ name: '', type: 'bytes' }],
    stateMutability: 'pure',
    type: 'function'
  }
];

// Helper functions
function packAccountGasLimits(callGasLimit, verificationGasLimit) {
  const callGasLimitBigInt = BigInt(callGasLimit);
  const verificationGasLimitBigInt = BigInt(verificationGasLimit);
  return `0x${(callGasLimitBigInt << 128n | verificationGasLimitBigInt).toString(16).padStart(64, '0')}`;
}

function packGasFees(maxFeePerGas, maxPriorityFeePerGas) {
  const maxFeePerGasBigInt = BigInt(maxFeePerGas);
  const maxPriorityFeePerGasBigInt = BigInt(maxPriorityFeePerGas);
  return `0x${(maxFeePerGasBigInt << 128n | maxPriorityFeePerGasBigInt).toString(16).padStart(64, '0')}`;
}

// Function to execute the operation
async function executeWebAuthnOperation() {
  try {
    console.log('Deployer address:', account.address);
    
    // Check account balance first
    const balance = await publicClient.getBalance({ address: account.address });
    console.log(`Account balance: ${formatEther(balance)} ETH`);
    
    if (balance < parseEther('0.01')) {
      console.warn(`WARNING: Low account balance - you may not have enough funds for this transaction`);
    }

    // Get the WebAuthn signature
    const pubKey = {
      x: VALID_PUBLIC_KEY_X,
      y: VALID_PUBLIC_KEY_Y
    };

    console.log('Getting WebAuthn signature...');
    // Get the WebAuthn signature by calling the smart account's function
    const signature = await publicClient.readContract({
      address: SMART_ACCOUNT,
      abi: SmartAccountABI,
      functionName: 'encodeWebAuthnSignature',
      args: [
        CHALLENGE,
        true,
        AUTHENTICATOR_DATA,
        CLIENT_DATA_JSON,
        CHALLENGE_INDEX,
        TYPE_INDEX,
        VALID_SIGNATURE_R,
        VALID_SIGNATURE_S,
        pubKey
      ]
    });
    console.log('WebAuthn signature received successfully');

    // Get the nonce from EntryPoint
    console.log('Getting nonce from EntryPoint...');
    const rawNonce = await publicClient.readContract({
      address: ENTRY_POINT,
      abi: EntryPointABI,
      functionName: 'getNonce',
      args: [SMART_ACCOUNT, 1]
    });
    console.log('Raw nonce from contract:', rawNonce.toString());

    // In ERC-4337, the nonce might need special handling
    // If the nonce is too large, it might be a special representation
    const nonce = rawNonce <= BigInt(1000000000) ? rawNonce : 0n;
    console.log('Using nonce:', nonce.toString());


    // Prepare callData - token approval (0x095ea7b3 is the selector for "approve")
    console.log('Preparing callData for token approval...');
    const callData = '0xb61d27f6' + // execute(address,uint256,bytes) selector
                     CONTRACT.slice(2).padStart(64, '0') + // to address
                     '0'.padStart(64, '0') + // value (0)
                     '0000000000000000000000000000000000000000000000000000000000000060' + // offset to bytes data
                     '0000000000000000000000000000000000000000000000000000000000000044' + // length of bytes data
                     '095ea7b3' + // approve selector
                     'abcdefabcdef1234567890abcdef123456789012'.padStart(64, '0') + // spender address
                     '0'.padStart(64, '0'); // amount (0)

    // Display gas parameters being used
    console.log(`Gas parameters:`);
    console.log(`- Max fee per gas: ${formatGwei(MAX_FEE_PER_GAS)} gwei`);
    console.log(`- Max priority fee: ${formatGwei(MAX_PRIORITY_FEE_PER_GAS)} gwei`);
    
    // Create the UserOperation
    console.log('Creating UserOperation...');
    const userOp = {
      sender: SMART_ACCOUNT,
      nonce: nonce,
      initCode: '0x7702',
      callData: callData,
      accountGasLimits: packAccountGasLimits(200000, 150000),
      preVerificationGas: 80000,
      gasFees: packGasFees(MAX_FEE_PER_GAS, MAX_PRIORITY_FEE_PER_GAS),
      paymasterAndData: '0x',
      signature: signature
    };
    
    console.log('UserOperation created successfully');
    console.log('Sending transaction to EntryPoint...');

    try {
      // Send the UserOperation to EntryPoint with specific gas settings
      const hash = await walletClient.writeContract({
        address: ENTRY_POINT,
        abi: EntryPointABI,
        functionName: 'handleOps',
        args: [[userOp], account.address],
        gas: GAS_LIMIT,
        maxFeePerGas: MAX_FEE_PER_GAS,
        maxPriorityFeePerGas: MAX_PRIORITY_FEE_PER_GAS,
        value: 0n
      });

            // After submitting the transaction
      console.log('Waiting for transaction confirmation...');
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      console.log('Transaction confirmed in block:', receipt.blockNumber);
      console.log('Transaction status:', receipt.status === 'success' ? 'Success' : 'Failed');

      console.log('Transaction submitted successfully!');
      console.log('Transaction hash:', hash);
      return hash;
    } catch (txError) {
      if (txError.message && txError.message.includes('insufficient funds')) {
        console.error('\n\n===== INSUFFICIENT FUNDS ERROR =====');
        console.error('Your account does not have enough ETH to cover gas costs.');
        console.error(`Current balance: ${formatEther(balance)} ETH`);
        console.error('Possible solutions:');
        console.error('1. Fund your account with more ETH');
        console.error('2. Lower gas settings in the .env file (MAX_FEE_PER_GAS, MAX_PRIORITY_FEE_PER_GAS)');
        console.error('3. Use a paymaster service to sponsor the transaction');
        console.error('=====================================\n\n');
      } else {
        console.error('Transaction failed:', txError);
      }
      throw txError;
    }
  } catch (error) {
    console.error('Operation failed:', error);
    throw error;
  }
}

// Add a function to create a .env file template if one doesn't exist
function createEnvFileTemplate() {
  // Get current file's directory
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  
  const envPath = join(process.cwd(), '.env');
  
  // Check if .env already exists
  if (!existsSync(envPath)) {
    const template = `# Network configuration
NETWORK=sepolia
RPC_URL=

# Contract addresses
SMART_ACCOUNT=0x6386b339C3DEc11635C5829025eFE8964DE03b05
ENTRY_POINT=0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B
CONTRACT=0xd1F228d963E6910412a021aF009583B239b4aA77

# Wallet configuration (IMPORTANT: Use a dedicated testing wallet with minimal funds)
BURNER_KEY=

# Gas settings
MAX_FEE_PER_GAS=30
MAX_PRIORITY_FEE_PER_GAS=2
GAS_LIMIT=1000000
`;

    try {
      writeFileSync(envPath, template);
      console.log(`Created .env template file at ${envPath}`);
      console.log('Please fill in your environment variables before running the script again.');
      return true;
    } catch (err) {
      console.error('Failed to create .env template:', err);
      return false;
    }
  }
  return false;
}

// Check if this is the main module being executed
const isMainModule = import.meta.url === `file://${process.argv[1]}`;

// Main execution
if (isMainModule) {
  // Check if we need to create the .env file first
  const envCreated = createEnvFileTemplate();
  
  if (envCreated) {
    console.log('Please configure your .env file before running this script again.');
    process.exit(0);
  } else {
    executeWebAuthnOperation()
      .then(hash => {
        console.log('Operation completed successfully');
        process.exit(0);
      })
      .catch(error => {
        console.error('Operation failed');
        process.exit(1);
      });
  }
} else {
  console.log('Module loaded, but not executed (imported as a module)');
}

// Export the function for use in other modules
export { executeWebAuthnOperation };