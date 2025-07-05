import { createPublicClient, createWalletClient, http, zeroAddress } from 'viem'
import { sepolia } from 'viem/chains'
import { privateKeyToAccount } from 'viem/accounts'
import { abi } from './abi.js'

// Constants
const ADDR_7702 = '0x5f41D7672CB83996CCC5E8C9Ce60Ba2a3D2DeaAe'
const INITIAL_GUARDIAN = '0x5b9ce7e7c27dde72ccc1b4949bc5c5e8db37f64aa3b1b2ad2b4d82db76f9b25e'

const key = {
  pubKey: {
    x: '0x349f670ed4e7cd75f89f1a253d3794b1c52be51a9b03579f7160ae88121e7878',
    y: '0x0a0e01b7c0626be1b8dc3846d145ef31287a555873581ad6f8bee21914ee5eb1'
  },
  eoaAddress: zeroAddress,
  keyType: 1
}

// Create client
const client = createPublicClient({
  chain: sepolia,
  transport: http(process.env.SEPOLIA_RPC_URL)
})

// Main function
async function getDigest() {
  try {
    const result = await client.readContract({
      address: ADDR_7702,
      abi,
      functionName: 'getDigestToInit',
      args: [key, INITIAL_GUARDIAN]
    })
    
    console.log('Digest:', result)
    return result
  } catch (error) {
    console.error('Error getting digest:', error)
    throw error
  }
}

// Sign the digest
async function signDigest(digest) {
  const privateKey = '0x63025b26af29ab000059987f81f3f4327c743a8d6c21d3718dbb55183d89172d'
  const account = privateKeyToAccount(privateKey)
  
  const signature = await account.signMessage({
    message: { raw: digest }
  })
  
  console.log('Signature:', signature)
  console.log('Signer address:', account.address)
  return signature
}

// Initialize contract
async function initializeContract(signature) {
  const walletClient = createWalletClient({
    account: privateKeyToAccount('0x63025b26af29ab000059987f81f3f4327c743a8d6c21d3718dbb55183d89172d'),
    chain: sepolia,
    transport: http(process.env.SEPOLIA_RPC_URL)
  })

  // KeyReg data structure
  const keyData = {
    validUntil: 0n,
    validAfter: 0n,
    limit: 0n,
    whitelisting: false,
    contractAddress: zeroAddress,
    spendTokenInfo: {
      token: zeroAddress,
      limit: 0n
    },
    allowedSelectors: ['0xdeedbeef'],
    ethLimit: 0n
  }

  const txHash = await walletClient.writeContract({
    address: ADDR_7702,
    abi,
    functionName: 'initialize',
    args: [key, keyData, signature, INITIAL_GUARDIAN]
  })

  console.log('Transaction hash:', txHash)
  return txHash
}

// Execute all steps
async function main() {
  const digest = await getDigest()
  const signature = await signDigest(digest)
  const txHash = await initializeContract(signature)
  return { digest, signature, txHash }
}

main()